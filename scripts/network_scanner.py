#!/usr/bin/env python3
"""
Network Scanner for Log Sources
Scans for active syslog sources and provides a quick discovery mechanism.
"""

import subprocess
import socket
import threading
import time
import json
from datetime import datetime, timedelta
import ipaddress
import os
import sys

# Add Django environment
analyzer_dir = '/home/net/analyzer'
if analyzer_dir not in sys.path:
    sys.path.insert(0, analyzer_dir)
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'analyzer.settings')

# Set up Django
try:
    import django
    django.setup()
    django_available = True
except Exception as e:
    print(f"Warning: Django setup failed: {e}")
    django_available = False

if django_available:
    from dashboard.models import LogSource, LogSourceEvent
else:
    # Mock models for when Django is not available
    class LogSource:
        @staticmethod
        def detect_device_type(log_sample):
            return 'unknown'
        
        @staticmethod
        def objects():
            return None
    
    class LogSourceEvent:
        pass

class NetworkScanner:
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
                'sudo', 'timeout', str(duration), 'tcpdump', '-i', 'any', '-n',
                'port', '514', '-c', '1000'
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
                                    self._check_source(ip)
                                    
            process.wait()
            
        except Exception as e:
            print(f"Scan error: {e}")
        finally:
            self.scan_in_progress = False
            
        return self.scan_results
        
    def active_scan(self, network_range=None):
        """
        Active scan - check which IPs have port 514 open
        Note: This requires appropriate permissions
        """
        self.scan_results = []
        self.scan_in_progress = True
        
        # If no range specified, try to detect local network
        if not network_range:
            network_range = self._get_local_network()
            
        try:
            # Use nmap for active scanning
            cmd = [
                'sudo', 'nmap', '-sU', '-p', '514', '--open',
                '-oG', '-', network_range
            ]
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            for line in process.stdout:
                if 'Host:' in line and 'open' in line:
                    parts = line.split()
                    if len(parts) > 1:
                        ip = parts[1]
                        if self._is_valid_ip(ip):
                            self._check_source(ip)
                            
        except FileNotFoundError:
            # nmap not installed, fall back to basic port check
            self._basic_port_scan(network_range)
        except Exception as e:
            print(f"Active scan error: {e}")
        finally:
            self.scan_in_progress = False
            
        return self.scan_results
        
    def _basic_port_scan(self, network_range):
        """Basic port scan without nmap"""
        try:
            network = ipaddress.ip_network(network_range, strict=False)
            
            def check_host(ip):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(0.5)
                    sock.sendto(b'<14>Test', (str(ip), 514))
                    sock.close()
                    self._check_source(str(ip))
                except:
                    pass
                    
            # Check up to 254 hosts in parallel
            threads = []
            for ip in list(network.hosts())[:254]:
                thread = threading.Thread(target=check_host, args=(ip,))
                thread.start()
                threads.append(thread)
                
            for thread in threads:
                thread.join()
                
        except Exception as e:
            print(f"Basic scan error: {e}")
            
    def _get_local_network(self):
        """Try to detect local network range"""
        try:
            # Get local IP
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            # Assume /24 network
            ip_parts = local_ip.split('.')
            if len(ip_parts) == 4:
                return f"{'.'.join(ip_parts[:3])}.0/24"
        except:
            pass
            
        return "192.168.1.0/24"  # Default fallback
        
    def _is_valid_ip(self, ip):
        """Check if string is valid IP"""
        try:
            ipaddress.ip_address(ip)
            return True
        except:
            return False
            
    def _check_source(self, ip):
        """Check if IP is a log source and gather info"""
        try:
            # Check if already in database (only if Django is available)
            existing = None
            if django_available:
                try:
                    existing = LogSource.objects.filter(ip_address=ip).first()
                except:
                    existing = None
            
            # Try to get hostname
            hostname = None
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                pass
                
            result = {
                'ip': ip,
                'hostname': hostname,
                'status': 'existing' if existing else 'new',
                'device_type': existing.device_type if existing else 'unknown',
                'in_database': existing is not None,
                'detected_time': datetime.now().isoformat()
            }
            
            if existing:
                result['name'] = existing.name
                result['current_status'] = existing.status
                
            self.scan_results.append(result)
            
        except Exception as e:
            print(f"Error checking source {ip}: {e}")
            
    def discover_from_logs(self, hours=24):
        """
        Discover sources from existing log files
        """
        self.scan_results = []
        
        log_dir = '/var/log'
        detected_ips = set()
        
        # Check rsyslog stats
        try:
            # Parse rsyslog stats if available
            stats_file = '/var/log/rsyslog-stats.log'
            if os.path.exists(stats_file):
                with open(stats_file, 'r') as f:
                    content = f.read()
                    # Extract IPs from stats (implementation depends on stats format)
                    
        except Exception as e:
            print(f"Error reading stats: {e}")
            
        # Check system logs for syslog activity
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            # Use journalctl to find recent syslog activity
            cmd = [
                'sudo', 'journalctl', '-u', 'rsyslog',
                '--since', cutoff_time.strftime('%Y-%m-%d %H:%M:%S'),
                '-o', 'json'
            ]
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            for line in process.stdout:
                try:
                    entry = json.loads(line)
                    message = entry.get('MESSAGE', '')
                    
                    # Look for IPs in message
                    import re
                    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                    ips = re.findall(ip_pattern, message)
                    
                    for ip in ips:
                        if self._is_valid_ip(ip) and ip not in detected_ips:
                            detected_ips.add(ip)
                            self._check_source(ip)
                            
                except:
                    continue
                    
        except Exception as e:
            print(f"Error checking journals: {e}")
            
        return self.scan_results
        
    def get_scan_status(self):
        """Get current scan status"""
        return {
            'in_progress': self.scan_in_progress,
            'results_count': len(self.scan_results),
            'results': self.scan_results
        }


# Command-line interface
def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Network Scanner for Log Sources')
    parser.add_argument('--quick', action='store_true', help='Quick scan (monitor traffic)')
    parser.add_argument('--active', action='store_true', help='Active scan (port scan)')
    parser.add_argument('--discover', action='store_true', help='Discover from logs')
    parser.add_argument('--network', help='Network range for active scan (e.g., 192.168.1.0/24)')
    parser.add_argument('--duration', type=int, default=30, help='Duration for quick scan (seconds)')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    
    args = parser.parse_args()
    
    scanner = NetworkScanner()
    
    if args.quick:
        print(f"Starting quick scan for {args.duration} seconds...")
        results = scanner.quick_scan(duration=args.duration)
    elif args.active:
        print(f"Starting active scan of {args.network or 'local network'}...")
        results = scanner.active_scan(network_range=args.network)
    elif args.discover:
        print("Discovering sources from logs...")
        results = scanner.discover_from_logs()
    else:
        print("Please specify --quick, --active, or --discover")
        return
        
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(f"\nFound {len(results)} sources:")
        for result in results:
            status = '✅' if result['in_database'] else '🆕'
            print(f"{status} {result['ip']} - {result['hostname'] or 'Unknown'} ({result['device_type']})")

if __name__ == "__main__":
    main()