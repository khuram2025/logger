#!/usr/bin/env python3
"""
Proper Log Source Scanner
Identifies actual devices sending logs to rsyslog, not IPs within log messages.
"""

import os
import re
import socket
import subprocess
from datetime import datetime, timedelta

class ProperLogSourceScanner:
    def __init__(self):
        self.scan_results = []
        
    def discover_log_sources(self):
        """
        Discover actual log source devices by analyzing:
        1. Existing rsyslog configurations
        2. Active network connections to port 514
        3. Recent log activity
        """
        self.scan_results = []
        
        # Method 1: Extract from existing rsyslog configurations
        configured_sources = self._get_configured_sources()
        
        # Method 2: Check for active connections to port 514
        active_sources = self._get_active_connections()
        
        # Method 3: Analyze recent log patterns for new sources
        recent_sources = self._analyze_recent_logs()
        
        # Combine and deduplicate
        all_sources = {}
        
        # Add configured sources (these are verified)
        for source in configured_sources:
            # Check if this source has recent activity
            source['last_activity'] = self._check_recent_activity(source['log_file'])
            if source['last_activity']:
                source['status'] = 'active'
            all_sources[source['ip']] = source
            
        # Add active connections (these are live)
        for source in active_sources:
            if source['ip'] in all_sources:
                all_sources[source['ip']]['status'] = 'active'
                all_sources[source['ip']]['last_seen'] = datetime.now()
            else:
                all_sources[source['ip']] = source
                
        # Add recent log sources (potential new devices)
        for source in recent_sources:
            if source['ip'] not in all_sources:
                all_sources[source['ip']] = source
        
        self.scan_results = list(all_sources.values())
        return self.scan_results
    
    def _get_configured_sources(self):
        """Extract log sources from rsyslog configuration files"""
        sources = []
        rsyslog_dir = '/etc/rsyslog.d'
        
        try:
            for filename in os.listdir(rsyslog_dir):
                if filename.endswith('.conf'):
                    filepath = os.path.join(rsyslog_dir, filename)
                    try:
                        with open(filepath, 'r') as f:
                            content = f.read()
                            
                        # Look for $fromhost-ip patterns
                        ip_patterns = re.findall(r'\$fromhost-ip\s*==\s*[\'"]([0-9.]+)[\'"]', content)
                        
                        for ip in ip_patterns:
                            if self._is_valid_ip(ip):
                                # Determine device type from filename or content
                                device_type = self._detect_device_type_from_config(filename, content)
                                
                                # Extract log file path
                                log_file = self._extract_log_file(content, ip)
                                
                                source = {
                                    'ip': ip,
                                    'device_type': device_type,
                                    'status': 'configured',
                                    'source': 'rsyslog_config',
                                    'config_file': filename,
                                    'log_file': log_file,
                                    'hostname': self._get_hostname(ip),
                                    'in_database': False,
                                    'detected_time': datetime.now().isoformat()
                                }
                                sources.append(source)
                                
                    except Exception as e:
                        print(f"Error reading {filepath}: {e}")
                        
        except Exception as e:
            print(f"Error reading rsyslog directory: {e}")
            
        return sources
    
    def _get_active_connections(self):
        """Check for active connections to port 514"""
        sources = []
        
        try:
            # Check if rsyslog is listening on port 514
            cmd = ['ss', '-u', '-l', '-n']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            listening_on_514 = False
            for line in result.stdout.split('\n'):
                if ':514' in line and 'UNCONN' in line:
                    listening_on_514 = True
                    break
            
            if not listening_on_514:
                print("Warning: No service listening on UDP port 514")
                
            # For UDP, we can't see "connections" like TCP, but we can check recent traffic
            # This is handled better in the recent logs analysis
                                
        except Exception as e:
            print(f"Error checking active connections: {e}")
            
        return sources
    
    def _analyze_recent_logs(self):
        """Analyze recent system logs to find potential new log sources"""
        sources = []
        
        try:
            # Check system logs for syslog activity
            cmd = ['journalctl', '-u', 'rsyslog', '--since', '1 hour ago', '-o', 'short-iso']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            # Look for patterns indicating new log sources
            for line in result.stdout.split('\n'):
                # Look for rsyslog messages about receiving logs
                if 'imudp' in line.lower() or 'received' in line.lower():
                    # Extract IP addresses from the line
                    ip_matches = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                    for ip in ip_matches:
                        if self._is_valid_ip(ip) and not ip.startswith('127.'):
                            source = {
                                'ip': ip,
                                'device_type': 'unknown',
                                'status': 'detected',
                                'source': 'system_logs',
                                'hostname': self._get_hostname(ip),
                                'in_database': False,
                                'detected_time': datetime.now().isoformat()
                            }
                            sources.append(source)
                            
        except Exception as e:
            print(f"Error analyzing recent logs: {e}")
            
        return sources
    
    def _detect_device_type_from_config(self, filename, content):
        """Detect device type from configuration filename or content"""
        filename_lower = filename.lower()
        content_lower = content.lower()
        
        if 'fortigate' in filename_lower or 'fortigate' in content_lower:
            return 'fortigate'
        elif 'paloalto' in filename_lower or 'palo' in filename_lower:
            return 'paloalto'
        elif 'cisco' in filename_lower:
            return 'cisco'
        elif 'checkpoint' in filename_lower:
            return 'checkpoint'
        else:
            return 'unknown'
    
    def _extract_log_file(self, content, ip):
        """Extract log file path from rsyslog configuration"""
        # Look for file="/path/to/log" in the same block as the IP
        lines = content.split('\n')
        in_block = False
        
        for line in lines:
            if ip in line:
                in_block = True
            elif in_block and 'file=' in line:
                match = re.search(r'file="([^"]+)"', line)
                if match:
                    return match.group(1)
            elif in_block and '}' in line:
                in_block = False
                
        return None
    
    def _is_valid_ip(self, ip):
        """Check if string is a valid IP address"""
        try:
            parts = ip.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except:
            return False
    
    def _get_hostname(self, ip):
        """Try to get hostname for IP"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return None
    
    def _check_recent_activity(self, log_file):
        """Check if log file has recent activity"""
        if not log_file or not os.path.exists(log_file):
            return None
            
        try:
            # Get file modification time
            mtime = os.path.getmtime(log_file)
            last_modified = datetime.fromtimestamp(mtime)
            
            # Consider recent if modified in last hour
            cutoff = datetime.now() - timedelta(hours=1)
            
            if last_modified > cutoff:
                return last_modified
            else:
                return None
                
        except Exception as e:
            return None

def main():
    scanner = ProperLogSourceScanner()
    sources = scanner.discover_log_sources()
    
    print(f"Found {len(sources)} actual log source devices:")
    print()
    
    for source in sources:
        status_icon = {
            'configured': '🔧',
            'active': '🟢', 
            'detected': '🔍'
        }.get(source['status'], '❓')
        
        type_icon = {
            'fortigate': '🛡️',
            'paloalto': '🔥',
            'cisco': '🌐',
            'unknown': '❓'
        }.get(source['device_type'], '📡')
        
        print(f"{status_icon} {type_icon} {source['ip']} ({source['device_type']})")
        if source['hostname']:
            print(f"    Hostname: {source['hostname']}")
        if source.get('log_file'):
            print(f"    Log file: {source['log_file']}")
        print(f"    Status: {source['status']} (via {source['source']})")
        print()

if __name__ == "__main__":
    main()