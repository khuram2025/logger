/**
 * Logs Table JavaScript Module
 * 
 * Handles table-specific functionality including:
 * - Log row expansion/collapse for detailed view
 * - Table sorting and interaction
 * - Row selection and bulk operations
 * 
 * Dependencies:
 * - Font Awesome icons for expand/collapse buttons
 * 
 * Author: Network Analyzer Team
 * Version: 2.0
 * Created: 2025-01-10
 */

/**
 * Initialize table functionality when DOM is ready
 */
document.addEventListener('DOMContentLoaded', function() {
    initializeLogTable();
});

/**
 * Initialize log table functionality
 */
function initializeLogTable() {
    attachExpandHandlers();
    initializeTableSorting();
}

/**
 * Attach click handlers to expand/collapse buttons
 */
function attachExpandHandlers() {
    const expandButtons = document.querySelectorAll('.expand-log-button');
    
    expandButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            const logIndex = this.getAttribute('data-log-index');
            toggleLogDetails(this, logIndex);
        });
    });
}

/**
 * Toggle detailed log view for a specific log entry
 * @param {HTMLElement} button - The expand button element
 * @param {string} logIndex - Index of the log entry
 */
function toggleLogDetails(button, logIndex) {
    const row = button.closest('tr');
    const icon = button.querySelector('i');
    
    // Check if details row already exists
    let detailsRow = row.nextElementSibling;
    const isDetailsRow = detailsRow && detailsRow.classList.contains('log-details-row');
    
    if (isDetailsRow) {
        // Collapse: Remove details row
        detailsRow.remove();
        icon.className = 'fas fa-plus';
        button.setAttribute('title', 'Expand log details');
        button.classList.remove('expanded');
    } else {
        // Expand: Create and insert details row
        const detailsRowHtml = createLogDetailsRow(row, logIndex);
        row.insertAdjacentHTML('afterend', detailsRowHtml);
        icon.className = 'fas fa-minus';
        button.setAttribute('title', 'Collapse log details');
        button.classList.add('expanded');
        
        // Add animation to the new row
        const newDetailsRow = row.nextElementSibling;
        newDetailsRow.style.opacity = '0';
        newDetailsRow.style.transform = 'translateY(-10px)';
        
        requestAnimationFrame(() => {
            newDetailsRow.style.transition = 'all 0.3s ease';
            newDetailsRow.style.opacity = '1';
            newDetailsRow.style.transform = 'translateY(0)';
        });
    }
}

/**
 * Create detailed log information row HTML
 * @param {HTMLElement} mainRow - The main log row element
 * @param {string} logIndex - Index of the log entry
 * @returns {string} HTML string for the details row
 */
function createLogDetailsRow(mainRow, logIndex) {
    const cells = mainRow.querySelectorAll('td');
    
    // Extract data from the main row (adjust indices based on table structure)
    const timestamp = cells[0]?.textContent?.trim() || 'N/A';
    const action = cells[1]?.textContent?.trim() || 'N/A';
    const srcip = cells[2]?.textContent?.trim() || 'N/A';
    const dstip = cells[3]?.textContent?.trim() || 'N/A';
    const dstport = cells[4]?.textContent?.trim() || 'N/A';
    const protocol = cells[5]?.textContent?.trim() || 'N/A';
    const device = cells[6]?.textContent?.trim() || 'N/A';
    const rcvdbytes = cells[7]?.textContent?.trim() || 'N/A';
    const sentbytes = cells[8]?.textContent?.trim() || 'N/A';
    const duration = cells[9]?.textContent?.trim() || 'N/A';
    
    return `
        <tr class="log-details-row" data-log-index="${logIndex}">
            <td colspan="11" class="log-details-cell">
                <div class="log-details-container">
                    <!-- Basic Information Section -->
                    <div class="details-section">
                        <h4><i class="fas fa-info-circle"></i> Basic Information</h4>
                        <div class="details-grid">
                            <div class="detail-item">
                                <span class="detail-label">Timestamp:</span>
                                <span class="detail-value">${timestamp}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Action:</span>
                                <span class="detail-value">${action}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Protocol:</span>
                                <span class="detail-value">${protocol}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Device:</span>
                                <span class="detail-value">${device}</span>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Network Information Section -->
                    <div class="details-section">
                        <h4><i class="fas fa-network-wired"></i> Network Details</h4>
                        <div class="details-grid">
                            <div class="detail-item">
                                <span class="detail-label">Source IP:</span>
                                <span class="detail-value">${srcip}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Destination IP:</span>
                                <span class="detail-value">${dstip}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Destination Port:</span>
                                <span class="detail-value">${dstport}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Duration:</span>
                                <span class="detail-value">${duration}</span>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Traffic Statistics Section -->
                    <div class="details-section">
                        <h4><i class="fas fa-chart-bar"></i> Traffic Statistics</h4>
                        <div class="details-grid">
                            <div class="detail-item">
                                <span class="detail-label">Received Bytes:</span>
                                <span class="detail-value">${rcvdbytes}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Transmitted Bytes:</span>
                                <span class="detail-value">${sentbytes}</span>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Actions Section -->
                    <div class="details-section">
                        <h4><i class="fas fa-tools"></i> Actions</h4>
                        <div class="detail-actions">
                            <button class="detail-action-btn" onclick="copyLogDetails('${logIndex}')">
                                <i class="fas fa-copy"></i> Copy Details
                            </button>
                            <button class="detail-action-btn" onclick="exportLogEntry('${logIndex}')">
                                <i class="fas fa-download"></i> Export
                            </button>
                            <button class="detail-action-btn" onclick="viewRelatedLogs('${srcip}', '${dstip}')">
                                <i class="fas fa-search"></i> View Related
                            </button>
                        </div>
                    </div>
                </div>
            </td>
        </tr>
    `;
}

/**
 * Initialize table sorting functionality
 */
function initializeTableSorting() {
    const tableHeaders = document.querySelectorAll('.logs-table th');
    
    tableHeaders.forEach((header, index) => {
        // Skip the last column (expand button column)
        if (index < tableHeaders.length - 1) {
            header.style.cursor = 'pointer';
            header.setAttribute('title', 'Click to sort');
            
            header.addEventListener('click', function() {
                sortTableByColumn(index);
            });
        }
    });
}

/**
 * Sort table by column index
 * @param {number} columnIndex - Index of the column to sort by
 */
function sortTableByColumn(columnIndex) {
    // This would typically integrate with backend sorting
    // For now, we'll show a visual indicator that sorting was requested
    const headers = document.querySelectorAll('.logs-table th');
    const header = headers[columnIndex];
    
    // Remove sorting indicators from other headers
    headers.forEach(h => h.classList.remove('sort-asc', 'sort-desc'));
    
    // Toggle sorting direction
    if (header.classList.contains('sort-asc')) {
        header.classList.remove('sort-asc');
        header.classList.add('sort-desc');
    } else {
        header.classList.remove('sort-desc');
        header.classList.add('sort-asc');
    }
    
    // In a real implementation, you would:
    // 1. Get current URL parameters
    // 2. Add/update sort parameter
    // 3. Reload the page or make AJAX request
    console.log(`Sort requested for column ${columnIndex}`);
}

/**
 * Copy log details to clipboard
 * @param {string} logIndex - Index of the log entry
 */
function copyLogDetails(logIndex) {
    const detailsRow = document.querySelector(`.log-details-row[data-log-index="${logIndex}"]`);
    if (!detailsRow) return;
    
    const details = detailsRow.querySelectorAll('.detail-item');
    let text = `Log Details (Index: ${logIndex})\n`;
    text += '='.repeat(30) + '\n';
    
    details.forEach(item => {
        const label = item.querySelector('.detail-label')?.textContent || '';
        const value = item.querySelector('.detail-value')?.textContent || '';
        text += `${label} ${value}\n`;
    });
    
    navigator.clipboard.writeText(text).then(() => {
        showNotification('Log details copied to clipboard', 'success');
    }).catch(() => {
        showNotification('Failed to copy to clipboard', 'error');
    });
}

/**
 * Export single log entry
 * @param {string} logIndex - Index of the log entry
 */
function exportLogEntry(logIndex) {
    // This would integrate with backend export functionality
    showNotification(`Export requested for log ${logIndex}`, 'info');
    console.log(`Export log entry: ${logIndex}`);
}

/**
 * View logs related to specific IP addresses
 * @param {string} srcip - Source IP address
 * @param {string} dstip - Destination IP address
 */
function viewRelatedLogs(srcip, dstip) {
    // Build URL with IP filters
    const currentUrl = new URL(window.location);
    currentUrl.searchParams.set('srcip', srcip);
    currentUrl.searchParams.set('dstip', dstip);
    currentUrl.searchParams.delete('page'); // Reset to first page
    
    // Navigate to filtered view
    window.location.href = currentUrl.toString();
}

/**
 * Show notification to user
 * @param {string} message - Notification message
 * @param {string} type - Notification type (success, error, info)
 */
function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <i class="fas fa-${type === 'success' ? 'check' : type === 'error' ? 'times' : 'info'}"></i>
        ${message}
    `;
    
    // Add to page
    document.body.appendChild(notification);
    
    // Show with animation
    requestAnimationFrame(() => {
        notification.classList.add('show');
    });
    
    // Auto-remove after 3 seconds
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 300);
    }, 3000);
}

/**
 * Expand all log details
 */
function expandAllLogs() {
    const expandButtons = document.querySelectorAll('.expand-log-button:not(.expanded)');
    expandButtons.forEach(button => {
        button.click();
    });
}

/**
 * Collapse all log details
 */
function collapseAllLogs() {
    const expandButtons = document.querySelectorAll('.expand-log-button.expanded');
    expandButtons.forEach(button => {
        button.click();
    });
}