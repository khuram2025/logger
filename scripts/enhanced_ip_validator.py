#!/usr/bin/env python3
"""
Enhanced IP address validator for log parsers.
Handles various edge cases and malformed IP addresses.
"""

import re
import logging

class IPValidator:
    """Validate and fix IP addresses from log files"""
    
    # Common IP regex pattern
    IP_PATTERN = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
    
    # Known problematic patterns
    TRUNCATED_IP_PATTERN = re.compile(r'^(\d{1,3})\.(\d{1,3})(?:\.(\d{1,3}))?$')
    IPV6_PATTERN = re.compile(r'^[0-9a-fA-F:]+$')
    
    @staticmethod
    def validate_and_fix_ip(ip_str, field_name="IP"):
        """
        Validate and attempt to fix an IP address.
        Returns a valid IP or '0.0.0.0' for invalid ones.
        """
        if not ip_str or not isinstance(ip_str, str):
            logging.debug(f"{field_name}: Empty or non-string value")
            return '0.0.0.0'
        
        ip_str = ip_str.strip()
        
        # Handle empty strings
        if not ip_str:
            return '0.0.0.0'
        
        # Check for IPv6 (not supported in current schema)
        if ':' in ip_str:
            logging.debug(f"{field_name}: IPv6 address detected: {ip_str}")
            return '0.0.0.0'
        
        # Check for valid IPv4
        match = IPValidator.IP_PATTERN.match(ip_str)
        if match:
            octets = [int(match.group(i)) for i in range(1, 5)]
            if all(0 <= octet <= 255 for octet in octets):
                return ip_str
            else:
                logging.warning(f"{field_name}: Octet out of range in {ip_str}")
                return '0.0.0.0'
        
        # Check for truncated IPs (e.g., "10.1" or "172.20.152")
        truncated_match = IPValidator.TRUNCATED_IP_PATTERN.match(ip_str)
        if truncated_match:
            parts = [g for g in truncated_match.groups() if g is not None]
            if len(parts) == 2:
                # Add .0.0 for two octets
                fixed_ip = f"{parts[0]}.{parts[1]}.0.0"
                logging.info(f"{field_name}: Fixed truncated IP {ip_str} -> {fixed_ip}")
                return fixed_ip
            elif len(parts) == 3:
                # Add .0 for three octets
                fixed_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.0"
                logging.info(f"{field_name}: Fixed truncated IP {ip_str} -> {fixed_ip}")
                return fixed_ip
        
        # Handle IPs with extra characters
        clean_ip = re.sub(r'[^0-9.]', '', ip_str)
        if clean_ip != ip_str:
            logging.debug(f"{field_name}: Cleaned IP {ip_str} -> {clean_ip}")
            # Recursively validate the cleaned IP
            return IPValidator.validate_and_fix_ip(clean_ip, field_name)
        
        # If all else fails
        logging.warning(f"{field_name}: Invalid IP format: {ip_str}")
        return '0.0.0.0'
    
    @staticmethod
    def extract_ip_from_field(field_value, field_name="field"):
        """
        Extract IP address from a field that might contain additional data.
        E.g., "192.168.1.1:8080" -> "192.168.1.1"
        """
        if not field_value:
            return '0.0.0.0'
        
        field_value = str(field_value).strip()
        
        # Extract IP from IP:PORT format
        if ':' in field_value and not IPValidator.IPV6_PATTERN.match(field_value):
            ip_part = field_value.split(':')[0]
            return IPValidator.validate_and_fix_ip(ip_part, field_name)
        
        # Extract IP from IP/MASK format
        if '/' in field_value:
            ip_part = field_value.split('/')[0]
            return IPValidator.validate_and_fix_ip(ip_part, field_name)
        
        return IPValidator.validate_and_fix_ip(field_value, field_name)


# Example usage and tests
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    test_cases = [
        "192.168.1.1",      # Valid
        "10.1",             # Truncated
        "172.20.152",       # Truncated
        "216.239.3",        # Truncated
        "192.168.1.300",    # Invalid octet
        "192.168.1.1:8080", # With port
        "10.0.0.1/24",      # With subnet
        "",                 # Empty
        None,               # None
        "not.an.ip",        # Invalid
        "2001:db8::1",      # IPv6
    ]
    
    validator = IPValidator()
    for test in test_cases:
        result = validator.validate_and_fix_ip(test, f"Test({test})")
        print(f"{test} -> {result}")