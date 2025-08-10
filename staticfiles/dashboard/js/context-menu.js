// Right-click context menu for table cells
(function() {
    'use strict';
    
    let contextMenu = null;
    let selectedCell = null;
    
    function createContextMenu(columnInfo) {
        if (contextMenu) {
            contextMenu.remove();
        }
        
        contextMenu = document.createElement('div');
        contextMenu.className = 'context-menu';
        
        let menuHTML = `
            <div class="context-menu-item" data-action="search">
                <i class="fas fa-search"></i>
                <span>Search for this value</span>
            </div>
            <div class="context-menu-item" data-action="exclude">
                <i class="fas fa-ban"></i>
                <span>Exclude from search</span>
            </div>
        `;
        
        // Add subnet options for IP fields
        if (columnInfo.isIP && columnInfo.suggestedSubnets.length > 0) {
            menuHTML += `<div class="context-menu-divider"></div>`;
            menuHTML += `<div class="context-menu-subtitle">Search Subnets:</div>`;
            
            columnInfo.suggestedSubnets.forEach(subnet => {
                menuHTML += `
                    <div class="context-menu-item subnet-item" data-action="search-subnet" data-subnet="${subnet}">
                        <i class="fas fa-network-wired"></i>
                        <span>${subnet}</span>
                    </div>
                `;
            });
        }
        
        menuHTML += `
            <div class="context-menu-divider"></div>
            <div class="context-menu-item" data-action="copy">
                <i class="fas fa-copy"></i>
                <span>Copy value</span>
            </div>
        `;
        
        contextMenu.innerHTML = menuHTML;
        document.body.appendChild(contextMenu);
        return contextMenu;
    }
    
    function showContextMenu(e, cell) {
        e.preventDefault();
        
        const columnInfo = getColumnInfo(cell);
        const menu = createContextMenu(columnInfo);
        selectedCell = cell;
        
        // Position the menu
        const x = e.pageX;
        const y = e.pageY;
        
        menu.style.left = x + 'px';
        menu.style.top = y + 'px';
        menu.style.display = 'block';
        
        // Adjust position if menu goes off screen
        const rect = menu.getBoundingClientRect();
        const windowWidth = window.innerWidth;
        const windowHeight = window.innerHeight;
        
        if (x + rect.width > windowWidth) {
            menu.style.left = (x - rect.width) + 'px';
        }
        
        if (y + rect.height > windowHeight) {
            menu.style.top = (y - rect.height) + 'px';
        }
    }
    
    function hideContextMenu() {
        if (contextMenu) {
            contextMenu.style.display = 'none';
        }
        selectedCell = null;
    }
    
    function getColumnInfo(cell) {
        const table = cell.closest('table');
        const row = cell.parentNode;
        const cellIndex = Array.from(row.children).indexOf(cell);
        const headers = table.querySelectorAll('thead th');
        const headerText = headers[cellIndex] ? headers[cellIndex].textContent.trim() : '';
        
        // Map header text to search field names
        const fieldMapping = {
            'Source IP': 'srcip',
            'Destination IP': 'dstip', 
            'Destination Port': 'dstport',
            'Protocol': 'protocol'
        };
        
        const value = cell.textContent.trim();
        const isIP = headerText.includes('IP');
        
        return {
            headerText,
            fieldName: fieldMapping[headerText],
            value,
            isSearchable: !!fieldMapping[headerText],
            isIP,
            suggestedSubnets: isIP ? generateSubnetSuggestions(value) : []
        };
    }
    
    function generateSubnetSuggestions(ip) {
        if (!isValidIP(ip)) return [];
        
        const parts = ip.split('.');
        if (parts.length !== 4) return [];
        
        return [
            `${parts[0]}.${parts[1]}.${parts[2]}.0/24`, // /24 subnet
            `${parts[0]}.${parts[1]}.0.0/16`,           // /16 subnet  
            `${parts[0]}.0.0.0/8`                       // /8 subnet
        ];
    }
    
    function isValidIP(ip) {
        const parts = ip.split('.');
        if (parts.length !== 4) return false;
        return parts.every(part => {
            const num = parseInt(part, 10);
            return num >= 0 && num <= 255 && part === num.toString();
        });
    }
    
    function addToSearch(fieldName, displayName, value, isExclude = false) {
        // Check if tag-search functionality exists
        if (typeof window.addSearchTag === 'function') {
            // Use the existing tag-search system
            window.addSearchTag(displayName, fieldName, value, isExclude);
            const action = isExclude ? 'exclude' : 'filter';
            showNotification(`Added ${action}: ${displayName}: ${value}`);
        } else {
            // Fallback: add to URL parameters directly
            const url = new URL(window.location);
            const paramName = isExclude ? `exclude_${fieldName}` : fieldName;
            url.searchParams.set(paramName, value);
            window.location.href = url.toString();
        }
    }
    
    function copyToClipboard(text) {
        if (navigator.clipboard) {
            navigator.clipboard.writeText(text).then(() => {
                showNotification('Copied to clipboard: ' + text);
            }).catch(() => {
                fallbackCopy(text);
            });
        } else {
            fallbackCopy(text);
        }
    }
    
    function fallbackCopy(text) {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        document.body.appendChild(textarea);
        textarea.select();
        try {
            document.execCommand('copy');
            showNotification('Copied to clipboard: ' + text);
        } catch (err) {
            console.error('Failed to copy text:', err);
        }
        document.body.removeChild(textarea);
    }
    
    function showNotification(message) {
        const notification = document.createElement('div');
        notification.className = 'copy-notification';
        notification.textContent = message;
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.classList.add('show');
        }, 100);
        
        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => {
                if (notification.parentNode) {
                    document.body.removeChild(notification);
                }
            }, 300);
        }, 2000);
    }
    
    function initContextMenu() {
        const table = document.querySelector('.logs-table');
        if (!table) {
            setTimeout(initContextMenu, 100);
            return;
        }
        
        console.log('Context menu initialized for table');
        
        // Add right-click event to table cells
        table.addEventListener('contextmenu', function(e) {
            const cell = e.target.closest('td');
            if (cell) {
                const columnInfo = getColumnInfo(cell);
                if (columnInfo.isSearchable && columnInfo.value && columnInfo.value !== 'N/A') {
                    showContextMenu(e, cell);
                } else {
                    e.preventDefault(); // Still prevent default context menu for non-searchable cells
                }
            }
        });
        
        // Handle context menu clicks
        document.addEventListener('click', function(e) {
            if (e.target.closest('.context-menu-item')) {
                const action = e.target.closest('.context-menu-item').dataset.action;
                
                if (selectedCell) {
                    const columnInfo = getColumnInfo(selectedCell);
                    
                    if (action === 'search' && columnInfo.isSearchable) {
                        addToSearch(columnInfo.fieldName, columnInfo.headerText, columnInfo.value, false);
                    } else if (action === 'exclude' && columnInfo.isSearchable) {
                        addToSearch(columnInfo.fieldName, columnInfo.headerText, columnInfo.value, true);
                    } else if (action === 'search-subnet' && columnInfo.isSearchable) {
                        const subnet = e.target.closest('.context-menu-item').dataset.subnet;
                        addToSearch(columnInfo.fieldName, columnInfo.headerText, subnet, false);
                    } else if (action === 'copy') {
                        copyToClipboard(columnInfo.value);
                    }
                }
                
                hideContextMenu();
            } else if (!e.target.closest('.context-menu')) {
                hideContextMenu();
            }
        });
        
        // Hide context menu on scroll
        document.addEventListener('scroll', hideContextMenu);
        window.addEventListener('resize', hideContextMenu);
    }
    
    // Start initialization
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initContextMenu);
    } else {
        initContextMenu();
    }
})();