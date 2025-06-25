#!/usr/bin/env python3
"""
Simple Network Scanner - Django-free version for use within Django views
"""

import subprocess
import socket
import threading
import time
import json
import os
from datetime import datetime, timedelta
import ipaddress
import re

class SimpleNetworkScanner:
    def __init__(self):
        self.scan_results = []
        self.scan_in_progress = False
        
    def quick_scan(self, duration=30):
        """
        Quick scan for active log sources by monitoring port 514 traffic
        """
        self.scan_results = []
        self.scan_in_progress = True
        
        try:
            # Use tcpdump to capture traffic for specified duration
            cmd = [
                'timeout', str(duration), 'tcpdump', '-i', 'any', '-n',
                'port', '514', '-c', '100', '2>/dev/null'
            ]
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            detected_ips = set()
            
            for line in process.stdout:
                # Extract source IPs from tcpdump output
                if ' > ' in line and '.514' in line:
                    parts = line.split()
                    for part in parts:
                        if '.' in part and not '.514' in part:
                            ip_parts = part.split('.')
                            if len(ip_parts) >= 4:
                                ip = '.'.join(ip_parts[0:4])
                                if self._is_valid_ip(ip) and ip not in detected_ips:
                                    detected_ips.add(ip)
                                    self._check_source(ip, line)
                                    
            process.wait()
            
        except Exception as e:
            print(f"Scan error: {e}")
        finally:
            self.scan_in_progress = False
            
        return self.scan_results
        
    def discover_from_logs(self, hours=24):
        """
        Discover sources from existing log files
        """
        self.scan_results = []
        
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            # Check main log files for recent syslog activity (limited for web interface)
            log_files = [
                '/var/log/fortigate.log',
                '/var/log/paloalto-1004.log'
            ]
            
            detected_ips = set()
            
            for log_file in log_files:
                try:
                    if not os.path.exists(log_file):
                        continue
                        
                    # Get recent entries with timeout
                    cmd = ['tail', '-200', log_file]  # Reduce from 1000 to 200 lines
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                    
                    # Look for syslog-like patterns and extract source IPs
                    lines = result.stdout.split('\n')
                    for line in lines:
                        # Look for lines that might be from network devices
                        if any(keyword in line.lower() for keyword in ['devname=', 'logid=', 'type=', 'traffic', 'threat']):
                            # Extract IPs from syslog lines
                            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                            ips = re.findall(ip_pattern, line)
                            
                            for ip in ips:
                                if self._is_valid_ip(ip) and ip not in detected_ips:
                                    # Skip local/reserved IPs
                                    if not self._is_reserved_ip(ip):
                                        detected_ips.add(ip)
                                        self._check_source(ip, line)
                                
                except Exception as e:
                    print(f"Error checking {log_file}: {e}")
                    
        except Exception as e:
            print(f"Discovery error: {e}")
            
        return self.scan_results
        
    def _is_valid_ip(self, ip):
        """Check if string is valid IP"""
        try:
            ipaddress.ip_address(ip)
            return True
        except:
            return False
            
    def _is_reserved_ip(self, ip):
        """Check if IP is reserved/local"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            # For log source detection, we're mainly interested in private networks
            # but also some public IPs that might be legitimate log sources
            if ip_obj.is_private:
                return False  # Private IPs are good candidates
            if ip_obj.is_loopback or ip_obj.is_multicast or str(ip).startswith('169.254.'):
                return True   # Skip these
            # For public IPs, be more selective
            return True  # Skip public IPs for now to reduce noise
        except:
            return True
            
    def _check_source(self, ip, sample_log=None):
        """Check if IP is a log source and gather info"""
        try:
            # Try to get hostname
            hostname = None
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                pass
                
            # Try to detect device type from sample log
            device_type = self._detect_device_type(sample_log) if sample_log else 'unknown'
            
            result = {
                'ip': ip,
                'hostname': hostname,
                'status': 'new',
                'device_type': device_type,
                'in_database': False,  # Will be checked by Django view
                'detected_time': datetime.now().isoformat(),
                'sample_log': sample_log[:200] if sample_log else None  # First 200 chars
            }
                
            self.scan_results.append(result)
            
        except Exception as e:
            print(f"Error checking source {ip}: {e}")
            
    def _detect_device_type(self, log_sample):
        """Detect device type from log sample"""
        if not log_sample:
            return 'unknown'
        
        log_lower = log_sample.lower()
        
        # FortiGate detection
        if any(keyword in log_lower for keyword in ['fortigate', 'fortios', 'logid=', 'devname=']):
            return 'fortigate'
        
        # Palo Alto detection
        if any(keyword in log_lower for keyword in ['palo alto', 'pan-os', ',1,', 'traffic,1,']):
            return 'paloalto'
        
        # Cisco detection
        if any(keyword in log_lower for keyword in ['cisco', '%asa-', '%fwsm-', '%pix-']):
            return 'cisco'
        
        # Check Point detection
        if any(keyword in log_lower for keyword in ['checkpoint', 'splat', 'fw-1']):
            return 'checkpoint'
        
        return 'unknown'

    def get_scan_status(self):
        """Get current scan status"""
        return {
            'in_progress': self.scan_in_progress,
            'results_count': len(self.scan_results),
            'results': self.scan_results
        }

def main():
    scanner = SimpleNetworkScanner()
    
    # Quick test discovery
    print("Testing discovery from logs...")
    results = scanner.discover_from_logs(hours=1)
    print(f"Found {len(results)} potential sources:")
    for result in results:
        print(f"  - {result['ip']} ({result.get('hostname', 'Unknown')})")

if __name__ == "__main__":
    main()