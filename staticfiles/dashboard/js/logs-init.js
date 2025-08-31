/**
 * Logs Initialization JavaScript Module
 * 
 * Main initialization script for the logs page that:
 * - Coordinates all other modules
 * - Handles page load setup
 * - Manages global state
 * - Provides utility functions
 * 
 * Dependencies:
 * - filters.js
 * - logs-table.js
 * - logs-validation.js
 * 
 * Author: Network Analyzer Team
 * Version: 2.0
 * Created: 2025-01-10
 */

/**
 * Global state management for the logs page
 */
const LogsState = {
    isLoading: false,
    currentFilters: {},
    autoRefresh: false,
    autoRefreshInterval: null,
    expandedLogs: new Set(),
    lastUpdateTime: null
};

/**
 * Initialize the entire logs page when DOM is ready
 */
document.addEventListener('DOMContentLoaded', function() {
    initializeLogsPage();
});

/**
 * Main initialization function
 */
function initializeLogsPage() {
    console.log('Initializing logs page...');
    
    try {
        // Initialize core components
        initializeGlobalHandlers();
        initializeKeyboardShortcuts();
        initializeAutoRefresh();
        initializeLoadingStates();
        initializeNotificationSystem();
        
        // Parse current URL parameters
        parseCurrentFilters();
        
        // Set up periodic updates
        startPeriodicUpdates();
        
        console.log('Logs page initialized successfully');
        
        // Show initialization complete notification
        showToast('Logs page loaded', 'info', 2000);
        
    } catch (error) {
        console.error('Error initializing logs page:', error);
        showToast('Error loading page. Please refresh.', 'error', 5000);
    }
}

/**
 * Initialize global event handlers
 */
function initializeGlobalHandlers() {
    // Filter toggle button
    const filterToggleBtn = document.querySelector('[onclick*="toggleFilters"]');
    if (filterToggleBtn) {
        // Remove inline onclick and add proper event listener
        filterToggleBtn.removeAttribute('onclick');
        filterToggleBtn.addEventListener('click', function(e) {
            e.preventDefault();
            toggleFilters();
        });
    }
    
    // Escape key to close modals/sidebars
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            closeModals();
        }
    });
    
    // Handle browser back/forward navigation
    window.addEventListener('popstate', function(e) {
        if (e.state && e.state.filters) {
            LogsState.currentFilters = e.state.filters;
            updateFiltersFromState();
        }
    });
    
    // Save scroll position
    window.addEventListener('beforeunload', function() {
        sessionStorage.setItem('logsScrollPosition', window.scrollY.toString());
    });
    
    // Restore scroll position
    const savedScrollPosition = sessionStorage.getItem('logsScrollPosition');
    if (savedScrollPosition) {
        window.scrollTo(0, parseInt(savedScrollPosition));
        sessionStorage.removeItem('logsScrollPosition');
    }
}

/**
 * Initialize keyboard shortcuts
 */
function initializeKeyboardShortcuts() {
    document.addEventListener('keydown', function(e) {
        // Only process shortcuts if not typing in an input
        if (document.activeElement.tagName === 'INPUT' || 
            document.activeElement.tagName === 'TEXTAREA' ||
            document.activeElement.tagName === 'SELECT') {
            return;
        }
        
        switch(e.key.toLowerCase()) {
            case 'f':
                if (e.ctrlKey || e.metaKey) {
                    e.preventDefault();
                    focusFilterSearch();
                }
                break;
                
            case 'r':
                if (e.ctrlKey || e.metaKey) {
                    e.preventDefault();
                    refreshLogs();
                }
                break;
                
            case 'c':
                if (e.ctrlKey || e.metaKey) {
                    e.preventDefault();
                    resetFilters();
                }
                break;
                
            case 't':
                e.preventDefault();
                toggleFilters();
                break;
                
            case 'e':
                e.preventDefault();
                toggleExpandAll();
                break;
                
            case 'a':
                if (e.ctrlKey || e.metaKey) {
                    e.preventDefault();
                    // Show keyboard shortcuts help
                    showKeyboardShortcuts();
                }
                break;
        }
    });
    
    // Add visual indicators for keyboard shortcuts
    addKeyboardShortcutHints();
}

/**
 * Initialize auto-refresh functionality
 */
function initializeAutoRefresh() {
    const autoRefreshCheckbox = document.getElementById('autoRefresh');
    const refreshInterval = document.getElementById('refreshInterval');
    
    if (autoRefreshCheckbox) {
        autoRefreshCheckbox.addEventListener('change', function() {
            if (this.checked) {
                startAutoRefresh(refreshInterval ? refreshInterval.value : 30);
            } else {
                stopAutoRefresh();
            }
        });
    }
    
    if (refreshInterval) {
        refreshInterval.addEventListener('change', function() {
            if (LogsState.autoRefresh) {
                stopAutoRefresh();
                startAutoRefresh(this.value);
            }
        });
    }
}

/**
 * Initialize loading states and indicators
 */
function initializeLoadingStates() {
    // Create global loading indicator
    const loadingIndicator = document.createElement('div');
    loadingIndicator.id = 'globalLoadingIndicator';
    loadingIndicator.className = 'loading-indicator hidden';
    loadingIndicator.innerHTML = `
        <div class="loading-spinner"></div>
        <span>Loading...</span>
    `;
    document.body.appendChild(loadingIndicator);
    
    // Override form submission to show loading
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function() {
            showLoading('Applying filters...');
        });
    });
}

/**
 * Initialize notification system
 */
function initializeNotificationSystem() {
    // Create notification container
    const notificationContainer = document.createElement('div');
    notificationContainer.id = 'notificationContainer';
    notificationContainer.className = 'notification-container';
    document.body.appendChild(notificationContainer);
    
    // Add CSS for notifications if not already present
    if (!document.getElementById('notification-styles')) {
        const style = document.createElement('style');
        style.id = 'notification-styles';
        style.textContent = `
            .notification-container {
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 9999;
            }
            
            .notification {
                background: white;
                border-left: 4px solid #007bff;
                border-radius: 4px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.15);
                padding: 12px 16px;
                margin-bottom: 8px;
                display: flex;
                align-items: center;
                gap: 8px;
                min-width: 250px;
                opacity: 0;
                transform: translateX(100%);
                transition: all 0.3s ease;
            }
            
            .notification.show {
                opacity: 1;
                transform: translateX(0);
            }
            
            .notification-success { border-left-color: #28a745; }
            .notification-error { border-left-color: #dc3545; }
            .notification-warning { border-left-color: #ffc107; }
            .notification-info { border-left-color: #17a2b8; }
        `;
        document.head.appendChild(style);
    }
}

/**
 * Parse current URL parameters into state
 */
function parseCurrentFilters() {
    const urlParams = new URLSearchParams(window.location.search);
    LogsState.currentFilters = {};
    
    // Parse all filter parameters
    for (const [key, value] of urlParams.entries()) {
        if (value && value.trim()) {
            LogsState.currentFilters[key] = value.trim();
        }
    }
    
    // Update browser history state
    if (Object.keys(LogsState.currentFilters).length > 0) {
        history.replaceState(
            { filters: LogsState.currentFilters }, 
            '', 
            window.location.href
        );
    }
}

/**
 * Start periodic updates for real-time data
 */
function startPeriodicUpdates() {
    // Update last refresh time
    updateLastRefreshTime();
    
    // Set up periodic time updates
    setInterval(updateLastRefreshTime, 60000); // Every minute
}

/**
 * Update the last refresh time display
 */
function updateLastRefreshTime() {
    LogsState.lastUpdateTime = new Date();
    const timeElement = document.getElementById('lastUpdateTime');
    if (timeElement) {
        timeElement.textContent = LogsState.lastUpdateTime.toLocaleTimeString();
    }
}

/**
 * Start auto-refresh functionality
 * @param {number} intervalSeconds - Refresh interval in seconds
 */
function startAutoRefresh(intervalSeconds = 30) {
    LogsState.autoRefresh = true;
    
    LogsState.autoRefreshInterval = setInterval(() => {
        if (!LogsState.isLoading) {
            refreshLogs();
        }
    }, intervalSeconds * 1000);
    
    showToast(`Auto-refresh enabled (${intervalSeconds}s)`, 'info', 3000);
}

/**
 * Stop auto-refresh functionality
 */
function stopAutoRefresh() {
    LogsState.autoRefresh = false;
    
    if (LogsState.autoRefreshInterval) {
        clearInterval(LogsState.autoRefreshInterval);
        LogsState.autoRefreshInterval = null;
    }
    
    showToast('Auto-refresh disabled', 'info', 2000);
}

/**
 * Refresh logs data
 */
function refreshLogs() {
    if (LogsState.isLoading) return;
    
    showLoading('Refreshing logs...');
    
    // Preserve current scroll position
    const scrollPosition = window.scrollY;
    
    // Reload the page with current parameters
    window.location.reload();
}

/**
 * Show loading indicator
 * @param {string} message - Loading message
 */
function showLoading(message = 'Loading...') {
    LogsState.isLoading = true;
    const indicator = document.getElementById('globalLoadingIndicator');
    if (indicator) {
        indicator.querySelector('span').textContent = message;
        indicator.classList.remove('hidden');
    }
}

/**
 * Hide loading indicator
 */
function hideLoading() {
    LogsState.isLoading = false;
    const indicator = document.getElementById('globalLoadingIndicator');
    if (indicator) {
        indicator.classList.add('hidden');
    }
}

/**
 * Show toast notification
 * @param {string} message - Notification message
 * @param {string} type - Notification type
 * @param {number} duration - Duration in milliseconds
 */
function showToast(message, type = 'info', duration = 3000) {
    const container = document.getElementById('notificationContainer');
    if (!container) return;
    
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <i class="fas fa-${getIconForType(type)}"></i>
        <span>${message}</span>
    `;
    
    container.appendChild(notification);
    
    // Show with animation
    requestAnimationFrame(() => {
        notification.classList.add('show');
    });
    
    // Auto-remove
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 300);
    }, duration);
}

/**
 * Get icon for notification type
 * @param {string} type - Notification type
 * @returns {string} Font Awesome icon name
 */
function getIconForType(type) {
    const icons = {
        success: 'check',
        error: 'exclamation-triangle',
        warning: 'exclamation-triangle',
        info: 'info-circle'
    };
    return icons[type] || 'info-circle';
}

/**
 * Close any open modals or sidebars
 */
function closeModals() {
    // Close filter sidebar on mobile
    const sidebar = document.getElementById('filterSidebar');
    if (sidebar && window.innerWidth <= 768) {
        sidebar.classList.add('hidden');
    }
    
    // Close any expanded log details
    collapseAllLogs();
}

/**
 * Focus on filter search input
 */
function focusFilterSearch() {
    const searchInput = document.querySelector('.filter-search-box input');
    if (searchInput) {
        searchInput.focus();
    }
}

/**
 * Toggle expand/collapse all logs
 */
function toggleExpandAll() {
    const expandedButtons = document.querySelectorAll('.expand-log-button.expanded');
    const collapsedButtons = document.querySelectorAll('.expand-log-button:not(.expanded)');
    
    if (expandedButtons.length > collapsedButtons.length) {
        collapseAllLogs();
        showToast('All logs collapsed', 'info', 2000);
    } else {
        expandAllLogs();
        showToast('All logs expanded', 'info', 2000);
    }
}

/**
 * Show keyboard shortcuts help
 */
function showKeyboardShortcuts() {
    const shortcuts = [
        { key: 'Ctrl/Cmd + F', action: 'Focus filter search' },
        { key: 'Ctrl/Cmd + R', action: 'Refresh logs' },
        { key: 'Ctrl/Cmd + C', action: 'Clear filters' },
        { key: 'T', action: 'Toggle filter sidebar' },
        { key: 'E', action: 'Expand/collapse all logs' },
        { key: 'Esc', action: 'Close modals/sidebars' }
    ];
    
    const helpHtml = shortcuts
        .map(s => `<div><kbd>${s.key}</kbd> - ${s.action}</div>`)
        .join('');
    
    showToast(`Keyboard Shortcuts:<br>${helpHtml}`, 'info', 8000);
}

/**
 * Add visual hints for keyboard shortcuts
 */
function addKeyboardShortcutHints() {
    // Add tooltips to buttons that have keyboard shortcuts
    const toggleBtn = document.querySelector('[onclick*="toggleFilters"]');
    if (toggleBtn && !toggleBtn.title) {
        toggleBtn.title = 'Toggle filters (T)';
    }
    
    const refreshBtn = document.querySelector('.refresh-btn, [onclick*="refresh"]');
    if (refreshBtn && !refreshBtn.title) {
        refreshBtn.title = 'Refresh logs (Ctrl+R)';
    }
}

/**
 * Update filters from current state
 */
function updateFiltersFromState() {
    Object.keys(LogsState.currentFilters).forEach(key => {
        const input = document.querySelector(`[name="${key}"]`);
        if (input) {
            input.value = LogsState.currentFilters[key];
        }
    });
}

/**
 * Export global functions for other modules
 */
window.LogsInit = {
    showLoading,
    hideLoading,
    showToast,
    refreshLogs,
    LogsState
};

// Also export individual functions for backward compatibility
window.showLoading = showLoading;
window.hideLoading = hideLoading;
window.showToast = showToast;