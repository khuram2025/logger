#!/usr/bin/env python3
"""
Web-optimized Network Scanner
Fast scanner specifically for web interface usage.
"""

import subprocess
import socket
import os
import re
from datetime import datetime
import ipaddress

class WebNetworkScanner:
    def __init__(self):
        self.scan_results = []
        
    def quick_discover(self):
        """
        Quick discovery from existing log files - optimized for web interface
        """
        self.scan_results = []
        
        # Only check the main log files we know exist
        log_files = [
            '/var/log/fortigate.log',
            '/var/log/paloalto-1004.log'
        ]
        
        detected_ips = set()
        
        for log_file in log_files:
            try:
                if not os.path.exists(log_file):
                    continue
                    
                # Get just the last 50 lines for speed
                cmd = ['tail', '-50', log_file]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
                
                # Look for device source patterns
                for line in result.stdout.split('\n')[:30]:  # Process max 30 lines
                    # FortiGate pattern: extract devname and source IPs
                    if 'devname=' in line and 'srcip=' in line:
                        # Extract source IP from FortiGate logs
                        srcip_match = re.search(r'srcip=([0-9.]+)', line)
                        if srcip_match:
                            ip = srcip_match.group(1)
                            if self._is_valid_private_ip(ip) and ip not in detected_ips:
                                detected_ips.add(ip)
                                self._add_source(ip, 'fortigate', line)
                    
                    # PaloAlto pattern: comma-separated format
                    elif ',TRAFFIC,' in line or ',THREAT,' in line:
                        parts = line.split(',')
                        if len(parts) > 8:
                            src_ip = parts[7] if len(parts) > 7 else None
                            if src_ip and self._is_valid_private_ip(src_ip) and src_ip not in detected_ips:
                                detected_ips.add(src_ip)
                                self._add_source(src_ip, 'paloalto', line)
                                
            except Exception as e:
                print(f"Error processing {log_file}: {e}")
                continue
                
        return self.scan_results
    
    def _is_valid_private_ip(self, ip):
        """Check if IP is valid and in private ranges"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private and not ip_obj.is_loopback
        except:
            return False
    
    def _add_source(self, ip, device_type, sample_log):
        """Add a discovered source to results"""
        try:
            # Try to get hostname quickly
            hostname = None
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                pass
            
            result = {
                'ip': ip,
                'hostname': hostname,
                'device_type': device_type,
                'status': 'new',
                'in_database': False,
                'detected_time': datetime.now().isoformat(),
                'sample_log': sample_log[:100] if sample_log else None
            }
            
            self.scan_results.append(result)
            
        except Exception as e:
            print(f"Error adding source {ip}: {e}")

def main():
    scanner = WebNetworkScanner()
    results = scanner.quick_discover()
    print(f"Found {len(results)} sources:")
    for result in results:
        print(f"  - {result['ip']} ({result['device_type']}) - {result.get('hostname', 'Unknown')}")

if __name__ == "__main__":
    main()