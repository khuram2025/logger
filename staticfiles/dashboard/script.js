/**
 * FortiGate Logs Dashboard JavaScript
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize expand/collapse functionality
    initExpandCollapse();
    
    // Initialize sorting
    initSorting();
    
    // Initialize export buttons
    initExport();
    
    // Initialize print button
    initPrint();
});

/**
 * Initialize expand/collapse functionality for log details
 */
function initExpandCollapse() {
    const expandButtons = document.querySelectorAll('.expand-btn');
    
    expandButtons.forEach(button => {
        button.addEventListener('click', function() {
            const icon = this.querySelector('i');
            
            if (icon.classList.contains('bi-chevron-right')) {
                icon.classList.remove('bi-chevron-right');
                icon.classList.add('bi-chevron-down');
            } else {
                icon.classList.remove('bi-chevron-down');
                icon.classList.add('bi-chevron-right');
            }
        });
    });
}

/**
 * Initialize sorting functionality
 */
function initSorting() {
    const sortableHeaders = document.querySelectorAll('th[data-sort]');
    
    // Get current sort parameters from URL
    const urlParams = new URLSearchParams(window.location.search);
    const currentSort = urlParams.get('sort');
    const currentOrder = urlParams.get('order');
    
    // Add sort indicators to currently sorted column
    if (currentSort) {
        const sortedHeader = document.querySelector(`th[data-sort="${currentSort}"]`);
        if (sortedHeader) {
            const icon = sortedHeader.querySelector('i');
            icon.classList.remove('bi-arrow-down-up');
            icon.classList.add(currentOrder === 'desc' ? 'bi-arrow-down' : 'bi-arrow-up');
        }
    }
    
    // Add click handlers to sortable headers
    sortableHeaders.forEach(header => {
        header.addEventListener('click', function() {
            const sort = this.dataset.sort;
            let newOrder = 'asc';
            
            // If already sorted by this column, toggle order
            if (sort === currentSort && currentOrder === 'asc') {
                newOrder = 'desc';
            }
            
            // Update URL with sort parameters
            const url = new URL(window.location.href);
            url.searchParams.set('sort', sort);
            url.searchParams.set('order', newOrder);
            window.location.href = url.toString();
        });
    });
}

/**
 * Initialize export functionality
 */
function initExport() {
    // Export to CSV
    document.getElementById('exportCSV').addEventListener('click', function() {
        exportToCSV();
    });
    
    // Export to JSON
    document.getElementById('exportJSON').addEventListener('click', function() {
        exportToJSON();
    });
}

/**
 * Export table data to CSV
 */
function exportToCSV() {
    const table = document.querySelector('.logs-table');
    const rows = table.querySelectorAll('tr.log-row');
    
    // Get headers (excluding the details column)
    const headers = [];
    table.querySelectorAll('thead th:not(.details-col)').forEach(th => {
        headers.push(th.textContent.trim().split(' ')[0]); // Remove sort icon text
    });
    
    // Get data
    let csvContent = headers.join(',') + '\n';
    
    rows.forEach(row => {
        const cells = row.querySelectorAll('td:not(.details-cell)');
        if (cells.length === 0) return; // Skip empty rows
        
        const rowData = [];
        cells.forEach(cell => {
            // Escape quotes and wrap in quotes
            const cellText = cell.textContent.trim().replace(/"/g, '""');
            rowData.push(`"${cellText}"`);
        });
        
        csvContent += rowData.join(',') + '\n';
    });
    
    // Create download link
    downloadFile(csvContent, 'fortigate_logs.csv', 'text/csv');
}

/**
 * Export log data to JSON
 */
function exportToJSON() {
    const rows = document.querySelectorAll('.log-row');
    const logs = [];
    
    rows.forEach((row, index) => {
        const logData = {};
        const cells = row.querySelectorAll('td:not(.details-cell)');
        const headers = document.querySelectorAll('thead th:not(.details-col)');
        
        cells.forEach((cell, i) => {
            const header = headers[i].textContent.trim().split(' ')[0]; // Remove sort icon text
            logData[header.toLowerCase()] = cell.textContent.trim();
        });
        
        // Get additional details if available
        const detailsId = `#details-${index+1}`;
        const detailsRow = document.querySelector(detailsId);
        
        if (detailsRow) {
            detailsRow.querySelectorAll('.detail-item').forEach(item => {
                const key = item.querySelector('.detail-label').textContent.replace(':', '').trim();
                const value = item.querySelector('.detail-value').textContent.trim();
                
                // Only add if not already in the log data
                if (!logData[key.toLowerCase()]) {
                    logData[key.toLowerCase()] = value;
                }
            });
        }
        
        logs.push(logData);
    });
    
    // Create download link
    const jsonContent = JSON.stringify(logs, null, 2);
    downloadFile(jsonContent, 'fortigate_logs.json', 'application/json');
}

/**
 * Helper function to download a file
 */
function downloadFile(content, filename, contentType) {
    const blob = new Blob([content], { type: contentType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    
    link.setAttribute('href', url);
    link.setAttribute('download', filename);
    link.style.display = 'none';
    
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

/**
 * Initialize print functionality
 */
function initPrint() {
    document.getElementById('printBtn').addEventListener('click', function() {
        window.print();
    });
}

/**
 * Clear a specific filter
 */
function clearFilter(field) {
    const url = new URL(window.location.href);
    url.searchParams.delete(field);
    window.location.href = url.toString();
}

/**
 * Clear all filters
 */
function clearAllFilters() {
    const url = new URL(window.location.href);
    url.search = 'page=1';
    window.location.href = url.toString();
}
