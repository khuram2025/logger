// Filter Sidebar Functionality
function toggleFilters() {
    const sidebar = document.getElementById('filterSidebar');
    const mainContent = document.querySelector('.logs-main-content');
    
    sidebar.classList.toggle('hidden');
    mainContent.classList.toggle('sidebar-hidden');
}

function applyFilters() {
    const form = document.createElement('form');
    form.method = 'GET';
    form.action = window.location.pathname;

    // Collect all filter values
    const filterInputs = document.querySelectorAll('.filter-input:not(.hidden)');
    filterInputs.forEach(input => {
        if (input.value.trim()) {
            const hiddenInput = document.createElement('input');
            hiddenInput.type = 'hidden';
            hiddenInput.name = input.name;
            hiddenInput.value = input.value.trim();
            form.appendChild(hiddenInput);
        }
    });

    // Include external_only parameter if set
    const externalOnlyValue = document.getElementById('external_only_filter')?.value;
    if (externalOnlyValue && externalOnlyValue.trim()) {
        const externalOnlyInput = document.createElement('input');
        externalOnlyInput.type = 'hidden';
        externalOnlyInput.name = 'external_only';
        externalOnlyInput.value = externalOnlyValue.trim();
        form.appendChild(externalOnlyInput);
    }
    
    // Always include time range parameter
    const timeRange = document.getElementById('timeRangeFilter');
    if (timeRange) {
        const timeRangeInput = document.createElement('input');
        timeRangeInput.type = 'hidden';
        timeRangeInput.name = 'time_range';
        timeRangeInput.value = timeRange.value;
        form.appendChild(timeRangeInput);
    }
    
    // Check for custom time range
    if (timeRange && timeRange.value === 'custom') {
        const timeFrom = document.getElementById('timeFrom');
        const timeTo = document.getElementById('timeTo');
        if (timeFrom && timeFrom.value) {
            const fromInput = document.createElement('input');
            fromInput.type = 'hidden';
            fromInput.name = 'time_from';
            fromInput.value = timeFrom.value;
            form.appendChild(fromInput);
        }
        if (timeTo && timeTo.value) {
            const toInput = document.createElement('input');
            toInput.type = 'hidden';
            toInput.name = 'time_to';
            toInput.value = timeTo.value;
            form.appendChild(toInput);
        }
    }

    // Preserve current page if exists
    const urlParams = new URLSearchParams(window.location.search);
    const currentPage = urlParams.get('page');
    if (currentPage && currentPage !== '1') {
        const pageInput = document.createElement('input');
        pageInput.type = 'hidden';
        pageInput.name = 'page';
        pageInput.value = '1'; // Reset to first page when filtering
        form.appendChild(pageInput);
    }

    document.body.appendChild(form);
    form.submit();
}

function resetFilters() {
    // Clear all filter inputs
    const filterInputs = document.querySelectorAll('.filter-input');
    filterInputs.forEach(input => {
        if (input.type === 'select-one') {
            input.selectedIndex = 0;
        } else {
            input.value = '';
        }
    });
    
    // Clear quick filter buttons
    document.querySelectorAll('.quick-filter-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    
    if (typeof activeQuickFilters !== 'undefined') {
        activeQuickFilters.clear();
    }
    
    // Redirect to clean URL
    window.location.href = window.location.pathname;
}

function clearAllFilters() {
    resetFilters();
}

function refreshLogs() {
    window.location.reload();
}

// Global variable for quick filters
let activeQuickFilters = new Set();

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    console.log('Filter functions loaded successfully');
    
    // Initialize time range tabs functionality
    const timeTabs = document.querySelectorAll('.time-tab');
    const timeRangeSelect = document.getElementById('timeRangeFilter');
    const customTimeRange = document.getElementById('customTimeRange');
    
    if (timeTabs.length > 0 && timeRangeSelect) {
        // Set active tab based on current selection
        const currentTimeRange = timeRangeSelect.value;
        timeTabs.forEach(tab => {
            if (tab.dataset.range === currentTimeRange) {
                tab.classList.add('active');
            } else {
                tab.classList.remove('active');
            }
        });
        
        // Show custom time range if selected
        if (currentTimeRange === 'custom' && customTimeRange) {
            customTimeRange.style.display = 'block';
        }
        
        // Add click handlers to time tabs
        timeTabs.forEach(tab => {
            tab.addEventListener('click', function() {
                // Remove active class from all tabs
                timeTabs.forEach(t => t.classList.remove('active'));
                // Add active class to clicked tab
                this.classList.add('active');
                
                // Update hidden select value
                const range = this.dataset.range;
                timeRangeSelect.value = range;
                
                // Show/hide custom time range
                if (range === 'custom' && customTimeRange) {
                    customTimeRange.style.display = 'block';
                } else {
                    if (customTimeRange) {
                        customTimeRange.style.display = 'none';
                    }
                    // Auto-apply filters for non-custom ranges
                    applyFilters();
                }
            });
        });
        
        console.log('Time range tabs initialized with', timeTabs.length, 'tabs');
    }
    
    // Initialize quick filter functionality
    initializeQuickFilters();
});

// Quick filters initialization
function initializeQuickFilters() {
    const quickFilterBtns = document.querySelectorAll('.quick-filter-btn');
    
    // Initialize based on current filter values
    const urlParams = new URLSearchParams(window.location.search);
    const actionValue = urlParams.get('action');
    const externalOnlyValue = urlParams.get('external_only');
    const minBytesValue = urlParams.get('min_bytes');
    const minDurationValue = urlParams.get('min_duration');
    
    if (actionValue === 'deny') {
        const deniedBtn = document.querySelector("button[data-filter='denied']");
        if (deniedBtn) {
            deniedBtn.classList.add('active');
            activeQuickFilters.add('denied');
        }
    }
    
    if (externalOnlyValue === 'true') {
        const externalBtn = document.querySelector("button[data-filter='external']");
        if (externalBtn) {
            externalBtn.classList.add('active');
            activeQuickFilters.add('external');
        }
    }
    
    if (minBytesValue === '1000000') {
        const highTrafficBtn = document.querySelector("button[data-filter='high-traffic']");
        if (highTrafficBtn) {
            highTrafficBtn.classList.add('active');
            activeQuickFilters.add('high-traffic');
        }
    }
    
    if (minDurationValue === '10000' && actionValue === 'deny') {
        const suspiciousBtn = document.querySelector("button[data-filter='suspicious']");
        if (suspiciousBtn) {
            suspiciousBtn.classList.add('active');
            activeQuickFilters.add('suspicious');
        }
    }
    
    // Add event listeners to quick filter buttons
    quickFilterBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const filterType = this.dataset.filter;
            
            // Toggle active state
            if (this.classList.contains('active')) {
                this.classList.remove('active');
                activeQuickFilters.delete(filterType);
                
                // Remove this specific filter
                switch(filterType) {
                    case 'denied':
                        if (!activeQuickFilters.has('suspicious')) {
                            const actionSelect = document.querySelector('select[name="action"]');
                            if (actionSelect) actionSelect.value = '';
                        }
                        break;
                    case 'high-traffic':
                        const minBytesInput = document.querySelector('input[name="min_bytes"]');
                        if (minBytesInput) minBytesInput.value = '';
                        break;
                    case 'suspicious':
                        const minDurationInput = document.querySelector('input[name="min_duration"]');
                        if (minDurationInput) minDurationInput.value = '';
                        if (!activeQuickFilters.has('denied')) {
                            const actionSelect = document.querySelector('select[name="action"]');
                            if (actionSelect) actionSelect.value = '';
                        }
                        break;
                    case 'external':
                        const externalFilter = document.getElementById('external_only_filter');
                        if (externalFilter) externalFilter.value = '';
                        break;
                }
            } else {
                this.classList.add('active');
                activeQuickFilters.add(filterType);
                
                // Apply this specific filter
                switch(filterType) {
                    case 'denied':
                        const actionSelect = document.querySelector('select[name="action"]');
                        if (actionSelect) actionSelect.value = 'deny';
                        break;
                    case 'high-traffic':
                        const minBytesInput = document.querySelector('input[name="min_bytes"]');
                        if (minBytesInput) minBytesInput.value = '1000000';
                        break;
                    case 'suspicious':
                        const minDurationInput = document.querySelector('input[name="min_duration"]');
                        if (minDurationInput) minDurationInput.value = '10000';
                        const actionSelect2 = document.querySelector('select[name="action"]');
                        if (actionSelect2 && actionSelect2.value === '') {
                            actionSelect2.value = 'deny';
                        }
                        break;
                    case 'external':
                        const externalFilter = document.getElementById('external_only_filter');
                        if (externalFilter) externalFilter.value = 'true';
                        break;
                }
            }
            
            // Apply filters
            applyFilters();
        });
    });
}