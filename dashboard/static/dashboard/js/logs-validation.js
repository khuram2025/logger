/**
 * Logs Validation JavaScript Module
 * 
 * Handles client-side validation for filter inputs including:
 * - IP address validation
 * - Port number validation
 * - Date/time range validation
 * - Real-time input feedback
 * 
 * Dependencies:
 * - None (vanilla JavaScript)
 * 
 * Author: Network Analyzer Team
 * Version: 2.0
 * Created: 2025-01-10
 */

/**
 * Initialize validation when DOM is ready
 */
document.addEventListener('DOMContentLoaded', function() {
    initializeValidation();
});

/**
 * Initialize all validation handlers
 */
function initializeValidation() {
    attachIPValidation();
    attachPortValidation();
    attachDateTimeValidation();
    attachNumericValidation();
}

/**
 * Attach IP address validation to IP input fields
 */
function attachIPValidation() {
    const ipInputs = document.querySelectorAll('input[name="srcip"], input[name="dstip"]');
    
    ipInputs.forEach(input => {
        input.addEventListener('input', function() {
            validateIPAddress(this);
        });
        
        input.addEventListener('blur', function() {
            validateIPAddress(this, true);
        });
    });
}

/**
 * Attach port validation to port input fields
 */
function attachPortValidation() {
    const portInputs = document.querySelectorAll('input[name="srcport"], input[name="dstport"]');
    
    portInputs.forEach(input => {
        input.addEventListener('input', function() {
            validatePort(this);
        });
        
        input.addEventListener('blur', function() {
            validatePort(this, true);
        });
    });
}

/**
 * Attach date/time validation to datetime inputs
 */
function attachDateTimeValidation() {
    const timeFrom = document.getElementById('timeFrom');
    const timeTo = document.getElementById('timeTo');
    
    if (timeFrom && timeTo) {
        timeFrom.addEventListener('change', function() {
            validateDateTimeRange(timeFrom, timeTo);
        });
        
        timeTo.addEventListener('change', function() {
            validateDateTimeRange(timeFrom, timeTo);
        });
    }
}

/**
 * Attach numeric validation to byte/duration inputs
 */
function attachNumericValidation() {
    const numericInputs = document.querySelectorAll(
        'input[name="min_bytes"], input[name="max_bytes"], ' +
        'input[name="min_duration"], input[name="max_duration"]'
    );
    
    numericInputs.forEach(input => {
        input.addEventListener('input', function() {
            validateNumericRange(this);
        });
    });
}

/**
 * Validate IP address format
 * @param {HTMLElement} input - The IP input element
 * @param {boolean} showError - Whether to show error messages
 * @returns {boolean} True if valid
 */
function validateIPAddress(input, showError = false) {
    const value = input.value.trim();
    
    // Empty is valid (optional field)
    if (!value) {
        setInputState(input, 'neutral');
        return true;
    }
    
    // Check for CIDR notation
    const isCIDR = value.includes('/');
    let ipPart = value;
    let cidrPart = '';
    
    if (isCIDR) {
        const parts = value.split('/');
        if (parts.length !== 2) {
            setInputState(input, 'invalid');
            if (showError) showValidationError(input, 'Invalid CIDR format');
            return false;
        }
        ipPart = parts[0];
        cidrPart = parts[1];
    }
    
    // Validate IP address part
    const ipPattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const isValidIP = ipPattern.test(ipPart);
    
    if (!isValidIP) {
        setInputState(input, 'invalid');
        if (showError) showValidationError(input, 'Invalid IP address format');
        return false;
    }
    
    // Validate CIDR part if present
    if (isCIDR) {
        const cidr = parseInt(cidrPart);
        if (isNaN(cidr) || cidr < 0 || cidr > 32) {
            setInputState(input, 'invalid');
            if (showError) showValidationError(input, 'Invalid CIDR range (0-32)');
            return false;
        }
    }
    
    setInputState(input, 'valid');
    hideValidationError(input);
    return true;
}

/**
 * Validate port number
 * @param {HTMLElement} input - The port input element
 * @param {boolean} showError - Whether to show error messages
 * @returns {boolean} True if valid
 */
function validatePort(input, showError = false) {
    const value = input.value.trim();
    
    // Empty is valid (optional field)
    if (!value) {
        setInputState(input, 'neutral');
        return true;
    }
    
    const port = parseInt(value);
    
    if (isNaN(port) || port < 1 || port > 65535) {
        setInputState(input, 'invalid');
        if (showError) showValidationError(input, 'Port must be between 1 and 65535');
        return false;
    }
    
    setInputState(input, 'valid');
    hideValidationError(input);
    return true;
}

/**
 * Validate date/time range
 * @param {HTMLElement} fromInput - Start time input
 * @param {HTMLElement} toInput - End time input
 * @returns {boolean} True if valid
 */
function validateDateTimeRange(fromInput, toInput) {
    const fromValue = fromInput.value;
    const toValue = toInput.value;
    
    // Both empty is valid
    if (!fromValue && !toValue) {
        setInputState(fromInput, 'neutral');
        setInputState(toInput, 'neutral');
        return true;
    }
    
    // Both must be provided if one is provided
    if ((fromValue && !toValue) || (!fromValue && toValue)) {
        setInputState(fromInput, fromValue ? 'invalid' : 'neutral');
        setInputState(toInput, toValue ? 'invalid' : 'neutral');
        
        const errorInput = fromValue ? toInput : fromInput;
        showValidationError(errorInput, 'Both start and end times are required');
        return false;
    }
    
    // Validate date range
    if (fromValue && toValue) {
        const fromDate = new Date(fromValue);
        const toDate = new Date(toValue);
        const now = new Date();
        
        // Check if dates are valid
        if (isNaN(fromDate.getTime()) || isNaN(toDate.getTime())) {
            setInputState(fromInput, 'invalid');
            setInputState(toInput, 'invalid');
            showValidationError(toInput, 'Invalid date format');
            return false;
        }
        
        // Check if from date is before to date
        if (fromDate >= toDate) {
            setInputState(fromInput, 'invalid');
            setInputState(toInput, 'invalid');
            showValidationError(toInput, 'End time must be after start time');
            return false;
        }
        
        // Check if dates are not in the future
        if (fromDate > now || toDate > now) {
            setInputState(fromInput, 'invalid');
            setInputState(toInput, 'invalid');
            showValidationError(toInput, 'Dates cannot be in the future');
            return false;
        }
        
        // Check if range is reasonable (not more than 1 year)
        const oneYear = 365 * 24 * 60 * 60 * 1000;
        if (toDate - fromDate > oneYear) {
            setInputState(fromInput, 'invalid');
            setInputState(toInput, 'invalid');
            showValidationError(toInput, 'Date range cannot exceed 1 year');
            return false;
        }
        
        setInputState(fromInput, 'valid');
        setInputState(toInput, 'valid');
        hideValidationError(fromInput);
        hideValidationError(toInput);
        return true;
    }
    
    return true;
}

/**
 * Validate numeric range inputs
 * @param {HTMLElement} input - The numeric input element
 * @returns {boolean} True if valid
 */
function validateNumericRange(input) {
    const value = input.value.trim();
    const name = input.name;
    
    // Empty is valid
    if (!value) {
        setInputState(input, 'neutral');
        return true;
    }
    
    const number = parseInt(value);
    
    if (isNaN(number) || number < 0) {
        setInputState(input, 'invalid');
        showValidationError(input, 'Must be a positive number');
        return false;
    }
    
    // Check range limits
    if (name.includes('bytes') && number > 1000000000) { // 1GB limit
        setInputState(input, 'invalid');
        showValidationError(input, 'Bytes cannot exceed 1GB');
        return false;
    }
    
    if (name.includes('duration') && number > 86400000) { // 24 hours limit
        setInputState(input, 'invalid');
        showValidationError(input, 'Duration cannot exceed 24 hours');
        return false;
    }
    
    // Validate min/max relationships
    validateMinMaxPair(input);
    
    setInputState(input, 'valid');
    hideValidationError(input);
    return true;
}

/**
 * Validate min/max input pairs
 * @param {HTMLElement} input - The input that changed
 */
function validateMinMaxPair(input) {
    const name = input.name;
    let pairName = '';
    
    if (name.includes('min_')) {
        pairName = name.replace('min_', 'max_');
    } else if (name.includes('max_')) {
        pairName = name.replace('max_', 'min_');
    } else {
        return;
    }
    
    const pairInput = document.querySelector(`input[name="${pairName}"]`);
    if (!pairInput) return;
    
    const currentValue = parseInt(input.value);
    const pairValue = parseInt(pairInput.value);
    
    if (isNaN(currentValue) || isNaN(pairValue)) return;
    
    const isMinInput = name.includes('min_');
    
    if (isMinInput && currentValue >= pairValue) {
        setInputState(input, 'invalid');
        showValidationError(input, 'Minimum must be less than maximum');
    } else if (!isMinInput && currentValue <= pairValue) {
        setInputState(input, 'invalid');
        showValidationError(input, 'Maximum must be greater than minimum');
    } else {
        // Re-validate both inputs
        validateNumericRange(input);
        validateNumericRange(pairInput);
    }
}

/**
 * Set visual state of input field
 * @param {HTMLElement} input - The input element
 * @param {string} state - State: 'valid', 'invalid', 'neutral'
 */
function setInputState(input, state) {
    input.classList.remove('valid', 'invalid', 'filtering');
    
    if (state === 'valid') {
        input.classList.add('valid');
    } else if (state === 'invalid') {
        input.classList.add('invalid');
    }
}

/**
 * Show validation error message
 * @param {HTMLElement} input - The input element
 * @param {string} message - Error message
 */
function showValidationError(input, message) {
    // Remove existing error
    hideValidationError(input);
    
    // Create error element
    const errorElement = document.createElement('div');
    errorElement.className = 'validation-error';
    errorElement.textContent = message;
    
    // Insert after the input
    input.parentNode.insertBefore(errorElement, input.nextSibling);
    
    // Add ARIA attributes for accessibility
    const errorId = `error-${input.name}-${Date.now()}`;
    errorElement.id = errorId;
    input.setAttribute('aria-describedby', errorId);
    input.setAttribute('aria-invalid', 'true');
}

/**
 * Hide validation error message
 * @param {HTMLElement} input - The input element
 */
function hideValidationError(input) {
    const existingError = input.parentNode.querySelector('.validation-error');
    if (existingError) {
        existingError.remove();
    }
    
    input.removeAttribute('aria-describedby');
    input.removeAttribute('aria-invalid');
}

/**
 * Validate all filter inputs before submission
 * @returns {boolean} True if all inputs are valid
 */
function validateAllFilters() {
    let isValid = true;
    
    // Validate all IP inputs
    const ipInputs = document.querySelectorAll('input[name="srcip"], input[name="dstip"]');
    ipInputs.forEach(input => {
        if (!validateIPAddress(input, true)) {
            isValid = false;
        }
    });
    
    // Validate all port inputs
    const portInputs = document.querySelectorAll('input[name="srcport"], input[name="dstport"]');
    portInputs.forEach(input => {
        if (!validatePort(input, true)) {
            isValid = false;
        }
    });
    
    // Validate date range
    const timeFrom = document.getElementById('timeFrom');
    const timeTo = document.getElementById('timeTo');
    if (timeFrom && timeTo) {
        if (!validateDateTimeRange(timeFrom, timeTo)) {
            isValid = false;
        }
    }
    
    // Validate numeric inputs
    const numericInputs = document.querySelectorAll(
        'input[name="min_bytes"], input[name="max_bytes"], ' +
        'input[name="min_duration"], input[name="max_duration"]'
    );
    numericInputs.forEach(input => {
        if (!validateNumericRange(input)) {
            isValid = false;
        }
    });
    
    return isValid;
}

/**
 * Reset all validation states
 */
function resetValidation() {
    // Remove all validation classes
    const inputs = document.querySelectorAll('.filter-input');
    inputs.forEach(input => {
        setInputState(input, 'neutral');
        hideValidationError(input);
    });
}

/**
 * Export validation functions for use by other modules
 */
window.LogsValidation = {
    validateAllFilters,
    resetValidation,
    validateIPAddress,
    validatePort,
    validateDateTimeRange,
    validateNumericRange
};