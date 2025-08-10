// Tag-based Search functionality
(function() {
    'use strict';
    
    function initTagSearch() {
        const sourceIpSearch = document.getElementById('sourceIpSearch');
        const suggestionsDiv = document.getElementById('searchSuggestions');
        const searchTags = document.getElementById('searchTags');
        const searchContainer = document.querySelector('.search-container');
        
        if (!sourceIpSearch || !suggestionsDiv || !searchTags) {
            setTimeout(initTagSearch, 100);
            return;
        }
        
        console.log('Tag-based search initialized');
        let selectedIndex = -1;
        let currentTags = new Map(); // Store current filter tags
        
        // Define all search options
        const searchOptions = [
            { key: 'Source IP', field: 'srcip', icon: 'fas fa-network-wired', desc: 'Filter by source IP address or subnet (e.g., 192.168.1.1 or 192.168.1.0/24)' },
            { key: 'Destination IP', field: 'dstip', icon: 'fas fa-network-wired', desc: 'Filter by destination IP address or subnet (e.g., 10.0.0.1 or 10.0.0.0/8)' },
            { key: 'Destination Port', field: 'dstport', icon: 'fas fa-plug', desc: 'Filter by destination port' },
            { key: 'Protocol', field: 'protocol', icon: 'fas fa-layer-group', desc: 'Filter by protocol (TCP/UDP/ICMP)' }
        ];
        
        // Initialize tags from URL parameters
        function initializeFromURL() {
            const urlParams = new URLSearchParams(window.location.search);
            
            searchOptions.forEach(option => {
                // Check for include filter (handle comma-separated values)
                const value = urlParams.get(option.field);
                if (value) {
                    const values = value.split(',').map(v => v.trim()).filter(v => v);
                    values.forEach(v => addTag(option.key, option.field, v, false));
                }
                
                // Check for exclude filter (handle comma-separated values)
                const excludeValue = urlParams.get(`exclude_${option.field}`);
                if (excludeValue) {
                    const excludeValues = excludeValue.split(',').map(v => v.trim()).filter(v => v);
                    excludeValues.forEach(v => addTag(option.key, option.field, v, true));
                }
            });
            
            updateTagsDisplay();
        }
        
        function addTag(key, field, value, isExclude = false) {
            // Create unique tag ID to allow multiple values per field
            const timestamp = Date.now();
            const random = Math.random().toString(36).substr(2, 9);
            const tagId = `${isExclude ? 'exclude_' : ''}${field}_${timestamp}_${random}`;
            const isSubnet = isSubnetValue(value);
            currentTags.set(tagId, { key, field, value, isExclude, tagId, isSubnet });
        }
        
        function isSubnetValue(value) {
            return value.includes('/') && value.match(/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/);
        }
        
        function removeTag(tagId) {
            currentTags.delete(tagId);
            updateTagsDisplay();
            applyFilters();
        }
        
        function updateTagsDisplay() {
            if (currentTags.size === 0) {
                searchTags.innerHTML = '';
                searchContainer.classList.remove('has-tags');
            } else {
                searchContainer.classList.add('has-tags');
                searchTags.innerHTML = Array.from(currentTags.values()).map(tag => {
                    let tagClass = 'search-tag';
                    if (tag.isExclude) tagClass += ' search-tag-exclude';
                    if (tag.isSubnet) tagClass += ' search-tag-subnet';
                    
                    const prefix = tag.isExclude ? 'NOT ' : '';
                    const icon = tag.isSubnet ? '<i class="fas fa-sitemap subnet-icon"></i>' : '';
                    
                    return `
                        <div class="${tagClass}" data-field="${tag.tagId}">
                            <span>${icon}${prefix}${tag.key}: ${tag.value}</span>
                            <span class="tag-remove" onclick="removeSearchTag('${tag.tagId}')" title="Remove filter">×</span>
                        </div>
                    `;
                }).join('');
            }
        }
        
        // Make removeTag function global so it can be called from onclick
        window.removeSearchTag = function(tagId) {
            removeTag(tagId);
        };
        
        // Expose functions for context menu integration
        window.addSearchTag = function(key, field, value, isExclude = false) {
            addTag(key, field, value, isExclude);
            updateTagsDisplay();
            applyFilters();
        };
        
        function applyFilters() {
            const url = new URL(window.location);
            
            // Clear existing filter parameters (including exclude parameters)
            ['srcip', 'dstip', 'dstport', 'protocol', 'exclude_srcip', 'exclude_dstip', 'exclude_dstport', 'exclude_protocol'].forEach(param => {
                url.searchParams.delete(param);
            });
            
            // Group tags by field and exclude type
            const includeParams = {};
            const excludeParams = {};
            
            currentTags.forEach(tag => {
                if (tag.isExclude) {
                    if (!excludeParams[tag.field]) excludeParams[tag.field] = [];
                    excludeParams[tag.field].push(tag.value);
                } else {
                    if (!includeParams[tag.field]) includeParams[tag.field] = [];
                    includeParams[tag.field].push(tag.value);
                }
            });
            
            // Add include parameters (comma-separated for multiple values)
            Object.keys(includeParams).forEach(field => {
                url.searchParams.set(field, includeParams[field].join(','));
            });
            
            // Add exclude parameters (comma-separated for multiple values)
            Object.keys(excludeParams).forEach(field => {
                url.searchParams.set(`exclude_${field}`, excludeParams[field].join(','));
            });
            
            window.location.href = url.toString();
        }
        
        function showSuggestions(input) {
            const value = input.trim().toLowerCase();
            let suggestions = [];
            
            if (value === '') {
                suggestions = searchOptions;
            } else {
                suggestions = searchOptions.filter(option => 
                    option.key.toLowerCase().includes(value) || 
                    option.key.toLowerCase().startsWith(value)
                );
            }
            
            if (suggestions.length > 0) {
                suggestionsDiv.innerHTML = suggestions.map((option, index) => `
                    <div class="search-suggestion-item" data-index="${index}" data-key="${option.key}" data-field="${option.field}">
                        <i class="${option.icon}" style="color: #667eea; margin-right: 8px;"></i>
                        <span><strong>${option.key}</strong> - ${option.desc}</span>
                    </div>
                `).join('');
                suggestionsDiv.style.display = 'block';
            } else {
                suggestionsDiv.style.display = 'none';
            }
        }
        
        function hideSuggestions() {
            suggestionsDiv.style.display = 'none';
            selectedIndex = -1;
        }
        
        // Event listeners
        sourceIpSearch.addEventListener('input', function(e) {
            showSuggestions(this.value);
        });
        
        sourceIpSearch.addEventListener('focus', function(e) {
            showSuggestions(this.value);
        });
        
        sourceIpSearch.addEventListener('blur', function() {
            setTimeout(hideSuggestions, 200);
        });
        
        // Handle clicks on suggestions
        suggestionsDiv.addEventListener('click', function(e) {
            const item = e.target.closest('.search-suggestion-item');
            if (item) {
                const selectedKey = item.dataset.key;
                sourceIpSearch.value = selectedKey + ':';
                hideSuggestions();
                sourceIpSearch.focus();
                sourceIpSearch.setSelectionRange(sourceIpSearch.value.length, sourceIpSearch.value.length);
            }
        });
        
        // Handle Enter key
        sourceIpSearch.addEventListener('keydown', function(e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                let value = this.value.trim();
                let paramName = '';
                let displayName = '';
                
                // Parse different prefixes and extract the value
                const lowerValue = value.toLowerCase();
                if (lowerValue.startsWith('source ip:')) {
                    paramName = 'srcip';
                    displayName = 'Source IP';
                    value = value.substring(10).trim();
                } else if (lowerValue.startsWith('destination ip:')) {
                    paramName = 'dstip';
                    displayName = 'Destination IP';
                    value = value.substring(15).trim();
                } else if (lowerValue.startsWith('destination port:')) {
                    paramName = 'dstport';
                    displayName = 'Destination Port';
                    value = value.substring(17).trim();
                } else if (lowerValue.startsWith('protocol:')) {
                    paramName = 'protocol';
                    displayName = 'Protocol';
                    value = value.substring(9).trim();
                }
                
                if (value && paramName) {
                    // Validate subnet format for IP fields
                    if ((paramName === 'srcip' || paramName === 'dstip') && value.includes('/')) {
                        if (!isValidSubnet(value)) {
                            showValidationError('Invalid subnet format. Use format like 192.168.1.0/24');
                            return;
                        }
                    }
                    
                    // Add tag and clear input
                    addTag(displayName, paramName, value);
                    sourceIpSearch.value = '';
                    updateTagsDisplay();
                    applyFilters();
                }
            }
        });
        
        function isValidSubnet(subnet) {
            const match = subnet.match(/^(\d{1,3}\.){3}\d{1,3}\/(\d{1,2})$/);
            if (!match) return false;
            
            const [network, cidr] = subnet.split('/');
            const cidrNum = parseInt(cidr, 10);
            
            // Validate CIDR range
            if (cidrNum < 0 || cidrNum > 32) return false;
            
            // Validate IP parts
            const parts = network.split('.');
            return parts.every(part => {
                const num = parseInt(part, 10);
                return num >= 0 && num <= 255 && part === num.toString();
            });
        }
        
        function showValidationError(message) {
            // Create temporary error message
            const errorDiv = document.createElement('div');
            errorDiv.className = 'validation-error';
            errorDiv.textContent = message;
            searchContainer.appendChild(errorDiv);
            
            setTimeout(() => {
                if (errorDiv.parentNode) {
                    errorDiv.parentNode.removeChild(errorDiv);
                }
            }, 3000);
        }
        
        // Initialize from current URL
        initializeFromURL();
    }
    
    // Start initialization
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initTagSearch);
    } else {
        initTagSearch();
    }
})();