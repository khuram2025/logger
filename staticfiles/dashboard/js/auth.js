/**
 * Authentication JavaScript Module
 * Handles form validation, interactive features, and user management
 */

class AuthManager {
    constructor() {
        this.init();
        this.bindEvents();
        this.setupKeyboardShortcuts();
    }

    init() {
        // Initialize theme
        this.initializeTheme();
        
        // Initialize notification system
        this.initializeNotifications();
        
        // Initialize form validation
        this.initializeFormValidation();
        
        // Auto-hide alerts after 5 seconds
        this.autoHideAlerts();
    }

    bindEvents() {
        // Notification events (for custom notifications panel if needed)
        document.addEventListener('click', (e) => {
            if (e.target.id === 'notifications-btn' || e.target.closest('#notifications-btn')) {
                this.toggleNotifications();
            } else if (!e.target.closest('#notifications-panel')) {
                this.hideNotifications();
            }
        });

        // Daisy UI dropdowns are handled automatically, but we can add custom behavior
        document.addEventListener('click', (e) => {
            // Handle user menu toggle
            if (e.target.closest('#user-menu-toggle')) {
                // Daisy UI handles this automatically with tabindex
                console.log('User menu toggled');
            }
        });

        // Form events
        document.addEventListener('submit', (e) => {
            if (e.target.classList.contains('auth-form')) {
                this.handleFormSubmit(e);
            }
        });

        // Real-time validation
        document.addEventListener('input', (e) => {
            if (e.target.type === 'password' && e.target.name === 'password1') {
                this.validatePasswordStrength(e.target);
            }
            if (e.target.type === 'password' && e.target.name === 'password2') {
                this.validatePasswordMatch(e.target);
            }
            if (e.target.type === 'email') {
                this.validateEmail(e.target);
            }
        });

        // Session management
        this.initializeSessionTimeout();
    }

    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            // Global shortcuts (Ctrl/Cmd + key)
            if (e.ctrlKey || e.metaKey) {
                switch(e.key) {
                    case 'k':
                        e.preventDefault();
                        this.focusSearch();
                        break;
                    case 'n':
                        e.preventDefault();
                        this.toggleNotifications();
                        break;
                    case 'u':
                        e.preventDefault();
                        this.openUserMenu();
                        break;
                    case '/':
                        e.preventDefault();
                        this.showKeyboardShortcuts();
                        break;
                }
            }

            // Escape key
            if (e.key === 'Escape') {
                this.closeAllModals();
                this.closeAllDropdowns();
                this.hideNotifications();
            }
        });
    }

    // Theme Management
    initializeTheme() {
        const savedTheme = localStorage.getItem('theme');
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        
        if (savedTheme) {
            this.setTheme(savedTheme);
        } else if (prefersDark) {
            this.setTheme('dark');
        }

        // Listen for system theme changes
        window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
            if (!localStorage.getItem('theme')) {
                this.setTheme(e.matches ? 'dark' : 'light');
            }
        });
    }

    setTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('theme', theme);
        
        const themeIcon = document.getElementById('theme-icon');
        const themeText = document.getElementById('theme-text');
        
        if (themeIcon && themeText) {
            if (theme === 'dark') {
                themeIcon.className = 'fas fa-sun mr-2';
                themeText.textContent = 'Light Mode';
            } else {
                themeIcon.className = 'fas fa-moon mr-2';
                themeText.textContent = 'Dark Mode';
            }
        }
    }

    toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        this.setTheme(currentTheme === 'dark' ? 'light' : 'dark');
    }

    // Notification Management
    initializeNotifications() {
        this.notificationCount = document.getElementById('notification-count');
        this.notificationsPanel = document.getElementById('notifications-panel');
        
        // Check for new notifications periodically
        if (this.isAuthenticated()) {
            setInterval(() => this.checkNotifications(), 30000); // Every 30 seconds
        }
    }

    toggleNotifications() {
        if (this.notificationsPanel) {
            this.notificationsPanel.classList.toggle('hidden');
            
            if (!this.notificationsPanel.classList.contains('hidden')) {
                this.markNotificationsAsRead();
            }
        }
    }

    hideNotifications() {
        if (this.notificationsPanel && !this.notificationsPanel.classList.contains('hidden')) {
            this.notificationsPanel.classList.add('hidden');
        }
    }

    async checkNotifications() {
        try {
            const response = await fetch('/auth/notifications/check/', {
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });
            
            if (response.ok) {
                const data = await response.json();
                this.updateNotificationCount(data.unread_count);
                
                if (data.new_notifications && data.new_notifications.length > 0) {
                    data.new_notifications.forEach(notification => {
                        this.showToast(notification.message, notification.type || 'info');
                    });
                }
            }
        } catch (error) {
            console.error('Failed to check notifications:', error);
        }
    }

    updateNotificationCount(count) {
        if (this.notificationCount) {
            this.notificationCount.textContent = count || 0;
            this.notificationCount.style.display = count > 0 ? 'block' : 'none';
        }
    }

    async markNotificationsAsRead() {
        try {
            await fetch('/auth/notifications/mark-read/', {
                method: 'POST',
                headers: {
                    'X-CSRFToken': this.getCSRFToken(),
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });
            this.updateNotificationCount(0);
        } catch (error) {
            console.error('Failed to mark notifications as read:', error);
        }
    }

    // Form Validation
    initializeFormValidation() {
        // Add validation classes to forms
        const forms = document.querySelectorAll('form');
        forms.forEach(form => {
            const inputs = form.querySelectorAll('input[required], select[required], textarea[required]');
            inputs.forEach(input => {
                input.addEventListener('blur', () => this.validateField(input));
                input.addEventListener('invalid', (e) => {
                    e.preventDefault();
                    this.showFieldError(input, input.validationMessage);
                });
            });
        });
    }

    validateField(field) {
        const isValid = field.checkValidity();
        
        if (isValid) {
            this.showFieldSuccess(field);
        } else {
            this.showFieldError(field, field.validationMessage);
        }
        
        return isValid;
    }

    validatePasswordStrength(passwordField) {
        const password = passwordField.value;
        const strengthBar = document.getElementById('password-strength');
        const strengthText = document.getElementById('password-strength-text');
        
        if (!strengthBar || !strengthText) return;

        const strength = this.calculatePasswordStrength(password);
        
        strengthBar.className = `password-strength strength-${strength.level}`;
        strengthText.textContent = strength.message;
        strengthText.className = `text-sm mt-1 ${this.getStrengthColor(strength.level)}`;

        // Update field validation
        if (strength.score >= 3) {
            this.showFieldSuccess(passwordField);
        } else {
            this.showFieldError(passwordField, 'Password is too weak');
        }
    }

    calculatePasswordStrength(password) {
        let score = 0;
        const checks = {
            length: password.length >= 8,
            lowercase: /[a-z]/.test(password),
            uppercase: /[A-Z]/.test(password),
            numbers: /\d/.test(password),
            symbols: /[^A-Za-z0-9]/.test(password)
        };
        
        score = Object.values(checks).filter(check => check).length;
        
        const levels = {
            0: { level: 'weak', message: 'Very weak password', score: 0 },
            1: { level: 'weak', message: 'Weak password', score: 1 },
            2: { level: 'fair', message: 'Fair password', score: 2 },
            3: { level: 'good', message: 'Good password', score: 3 },
            4: { level: 'good', message: 'Good password', score: 4 },
            5: { level: 'strong', message: 'Strong password', score: 5 }
        };
        
        return levels[score] || levels[0];
    }

    getStrengthColor(level) {
        const colors = {
            weak: 'text-red-600',
            fair: 'text-yellow-600',
            good: 'text-blue-600',
            strong: 'text-green-600'
        };
        return colors[level] || colors.weak;
    }

    validatePasswordMatch(confirmField) {
        const passwordField = document.querySelector('input[name="password1"], input[name="new_password1"]');
        const matchIcon = document.getElementById('password-match-icon');
        
        if (!passwordField || !matchIcon) return;

        const password = passwordField.value;
        const confirm = confirmField.value;
        const match = password && confirm && password === confirm;

        if (confirm) {
            matchIcon.innerHTML = match
                ? '<i class="fas fa-check text-green-500"></i>'
                : '<i class="fas fa-times text-red-500"></i>';
                
            if (match) {
                this.showFieldSuccess(confirmField);
            } else {
                this.showFieldError(confirmField, 'Passwords do not match');
            }
        } else {
            matchIcon.innerHTML = '';
        }
    }

    validateEmail(emailField) {
        const email = emailField.value;
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        
        if (email && !emailRegex.test(email)) {
            this.showFieldError(emailField, 'Please enter a valid email address');
        } else if (email) {
            this.showFieldSuccess(emailField);
        }
    }

    showFieldError(field, message) {
        field.classList.add('input-error');
        field.classList.remove('input-success');
        
        // Show error message
        const errorElement = field.parentElement.querySelector('.field-error') || 
                           this.createErrorElement(message);
        
        if (!field.parentElement.querySelector('.field-error')) {
            field.parentElement.appendChild(errorElement);
        } else {
            errorElement.textContent = message;
        }
    }

    showFieldSuccess(field) {
        field.classList.remove('input-error');
        field.classList.add('input-success');
        
        // Remove error message
        const errorElement = field.parentElement.querySelector('.field-error');
        if (errorElement) {
            errorElement.remove();
        }
    }

    createErrorElement(message) {
        const errorElement = document.createElement('div');
        errorElement.className = 'field-error text-red-600 text-sm mt-1';
        errorElement.textContent = message;
        return errorElement;
    }

    // Form Submission
    async handleFormSubmit(e) {
        const form = e.target;
        const submitBtn = form.querySelector('button[type="submit"]');
        
        // Validate all fields
        const isValid = this.validateForm(form);
        
        if (!isValid) {
            e.preventDefault();
            this.showToast('Please correct the errors in the form', 'error');
            return;
        }

        // Show loading state
        if (submitBtn) {
            this.setButtonLoading(submitBtn, true);
        }

        // Additional form-specific validation
        if (form.id === 'password-form') {
            const newPassword = form.querySelector('input[name="new_password1"]');
            const confirmPassword = form.querySelector('input[name="new_password2"]');
            
            if (newPassword && confirmPassword && newPassword.value !== confirmPassword.value) {
                e.preventDefault();
                this.showToast('Passwords do not match', 'error');
                this.setButtonLoading(submitBtn, false);
                return;
            }
        }
    }

    validateForm(form) {
        const inputs = form.querySelectorAll('input[required], select[required], textarea[required]');
        let isValid = true;
        
        inputs.forEach(input => {
            if (!this.validateField(input)) {
                isValid = false;
            }
        });
        
        return isValid;
    }

    setButtonLoading(button, loading) {
        if (loading) {
            button.disabled = true;
            button.setAttribute('data-original-text', button.innerHTML);
            button.innerHTML = '<span class="loading loading-spinner loading-sm mr-2"></span>Loading...';
        } else {
            button.disabled = false;
            button.innerHTML = button.getAttribute('data-original-text') || button.innerHTML;
        }
    }

    // Session Management
    initializeSessionTimeout() {
        if (!this.isAuthenticated()) return;

        const WARNING_TIME = 5 * 60 * 1000; // 5 minutes before timeout
        const SESSION_TIMEOUT = 30 * 60 * 1000; // 30 minutes

        let warningShown = false;
        let lastActivity = Date.now();

        // Reset activity timer on user interaction
        ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart', 'click'].forEach(event => {
            document.addEventListener(event, () => {
                lastActivity = Date.now();
                warningShown = false;
            }, { passive: true });
        });

        // Check session status
        setInterval(() => {
            const timeSinceActivity = Date.now() - lastActivity;
            
            if (timeSinceActivity > SESSION_TIMEOUT - WARNING_TIME && !warningShown) {
                this.showSessionWarning();
                warningShown = true;
            } else if (timeSinceActivity > SESSION_TIMEOUT) {
                this.handleSessionTimeout();
            }
        }, 60000); // Check every minute
    }

    showSessionWarning() {
        const modal = this.createSessionWarningModal();
        document.body.appendChild(modal);
        modal.showModal();
    }

    createSessionWarningModal() {
        const modal = document.createElement('dialog');
        modal.className = 'modal';
        modal.innerHTML = `
            <div class="modal-box">
                <h3 class="font-bold text-lg text-warning">
                    <i class="fas fa-clock mr-2"></i>Session Timeout Warning
                </h3>
                <p class="py-4">
                    Your session will expire in 5 minutes due to inactivity. 
                    Click "Stay Logged In" to continue your session.
                </p>
                <div class="modal-action">
                    <button class="btn btn-outline" onclick="window.location.href='/auth/logout/'">
                        Log Out Now
                    </button>
                    <button class="btn btn-primary" onclick="this.closest('.modal').remove()">
                        Stay Logged In
                    </button>
                </div>
            </div>
        `;
        return modal;
    }

    handleSessionTimeout() {
        this.showToast('Your session has expired. Please log in again.', 'warning');
        setTimeout(() => {
            window.location.href = '/auth/login/';
        }, 2000);
    }

    // Utility Functions
    isAuthenticated() {
        return document.body.classList.contains('authenticated') || 
               document.querySelector('meta[name="user-authenticated"]')?.content === 'true';
    }

    getCSRFToken() {
        return document.querySelector('[name=csrfmiddlewaretoken]')?.value ||
               document.querySelector('meta[name="csrf-token"]')?.content;
    }

    focusSearch() {
        const searchInput = document.querySelector('#search-filter, #user-search, input[type="search"]');
        if (searchInput) {
            searchInput.focus();
            searchInput.select();
        }
    }

    openUserMenu() {
        const userMenu = document.getElementById('user-menu-toggle');
        if (userMenu) {
            userMenu.focus(); // Focus to open Daisy UI dropdown
        }
    }

    closeAllModals() {
        document.querySelectorAll('.modal[open]').forEach(modal => {
            modal.close();
        });
    }

    closeAllDropdowns() {
        // Close Daisy UI dropdowns by removing focus and blur active elements
        document.querySelectorAll('.dropdown [tabindex]').forEach(dropdown => {
            dropdown.blur();
        });
        document.querySelectorAll('details[open]').forEach(details => {
            details.open = false;
        });
    }

    autoHideAlerts() {
        document.querySelectorAll('.alert').forEach(alert => {
            if (!alert.classList.contains('alert-permanent')) {
                setTimeout(() => {
                    alert.style.opacity = '0';
                    alert.style.transform = 'translateY(-10px)';
                    setTimeout(() => alert.remove(), 300);
                }, 5000);
            }
        });
    }

    // Toast Notifications
    showToast(message, type = 'info', duration = 3000) {
        const toast = document.createElement('div');
        toast.className = 'toast toast-end';
        toast.innerHTML = `
            <div class="alert alert-${type}" style="animation: slideInRight 0.3s ease-out;">
                <div class="flex items-center">
                    <i class="fas fa-${this.getToastIcon(type)} mr-2"></i>
                    <span>${message}</span>
                    <button class="ml-auto btn btn-ghost btn-sm" onclick="this.closest('.toast').remove()">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
            </div>
        `;
        
        document.body.appendChild(toast);
        
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(100%)';
            setTimeout(() => toast.remove(), 300);
        }, duration);
    }

    getToastIcon(type) {
        const icons = {
            success: 'check-circle',
            error: 'exclamation-circle',
            warning: 'exclamation-triangle',
            info: 'info-circle'
        };
        return icons[type] || icons.info;
    }

    // Keyboard Shortcuts Help
    showKeyboardShortcuts() {
        const modal = this.createKeyboardShortcutsModal();
        document.body.appendChild(modal);
        modal.showModal();
    }

    createKeyboardShortcutsModal() {
        const modal = document.createElement('dialog');
        modal.className = 'modal';
        modal.innerHTML = `
            <div class="modal-box max-w-2xl">
                <h3 class="font-bold text-lg mb-4">
                    <i class="fas fa-keyboard mr-2"></i>Keyboard Shortcuts
                </h3>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                        <h4 class="font-semibold mb-2">Navigation</h4>
                        <div class="space-y-2 text-sm">
                            <div class="flex justify-between">
                                <span>Search</span>
                                <kbd class="kbd kbd-sm">Ctrl+K</kbd>
                            </div>
                            <div class="flex justify-between">
                                <span>Notifications</span>
                                <kbd class="kbd kbd-sm">Ctrl+N</kbd>
                            </div>
                            <div class="flex justify-between">
                                <span>User Menu</span>
                                <kbd class="kbd kbd-sm">Ctrl+U</kbd>
                            </div>
                        </div>
                    </div>
                    <div>
                        <h4 class="font-semibold mb-2">General</h4>
                        <div class="space-y-2 text-sm">
                            <div class="flex justify-between">
                                <span>Close Modal/Dropdown</span>
                                <kbd class="kbd kbd-sm">Esc</kbd>
                            </div>
                            <div class="flex justify-between">
                                <span>Show Shortcuts</span>
                                <kbd class="kbd kbd-sm">Ctrl+/</kbd>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="modal-action">
                    <button class="btn" onclick="this.closest('.modal').remove()">Close</button>
                </div>
            </div>
        `;
        return modal;
    }

    // About Modal
    showAbout() {
        const modal = this.createAboutModal();
        document.body.appendChild(modal);
        modal.showModal();
    }

    createAboutModal() {
        const modal = document.createElement('dialog');
        modal.className = 'modal';
        modal.innerHTML = `
            <div class="modal-box">
                <h3 class="font-bold text-lg mb-4">
                    <i class="fas fa-info-circle mr-2"></i>About Network Analyzer
                </h3>
                <div class="space-y-4">
                    <p class="text-sm text-gray-600">
                        Network Analyzer is a comprehensive log analysis and monitoring platform
                        for network security professionals.
                    </p>
                    <div class="stats stats-vertical lg:stats-horizontal shadow">
                        <div class="stat">
                            <div class="stat-title">Version</div>
                            <div class="stat-value text-sm">2.0.0</div>
                        </div>
                        <div class="stat">
                            <div class="stat-title">Build</div>
                            <div class="stat-value text-sm">${new Date().getFullYear()}</div>
                        </div>
                    </div>
                </div>
                <div class="modal-action">
                    <button class="btn" onclick="this.closest('.modal').remove()">Close</button>
                </div>
            </div>
        `;
        return modal;
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.authManager = new AuthManager();
});

// Global helper functions for backward compatibility
window.toggleTheme = () => window.authManager?.toggleTheme();
window.toggleNotifications = () => window.authManager?.toggleNotifications();
window.toggleHelp = () => window.authManager?.showKeyboardShortcuts();
window.showKeyboardShortcuts = () => window.authManager?.showKeyboardShortcuts();
window.showAbout = () => window.authManager?.showAbout();
window.markAllAsRead = () => window.authManager?.markNotificationsAsRead();

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = AuthManager;
}