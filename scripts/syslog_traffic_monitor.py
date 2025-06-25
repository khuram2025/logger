#!/usr/bin/env python3
"""
Syslog Traffic Monitor
Monitors UDP/TCP port 514 for incoming syslog traffic and automatically
detects new log sources.
"""

import socket
import threading
import time
import json
import os
import sys
import signal
from datetime import datetime, timedelta
from collections import defaultdict
import subprocess
import logging

# Add Django environment
sys.path.append('/home/net/analyzer')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'analyzer.settings')
import django
django.setup()

from dashboard.models import LogSource, LogSourceEvent

class SyslogTrafficMonitor:
    def __init__(self):
        self.running = False
        self.detected_sources = defaultdict(lambda: {
            'first_seen': datetime.now(),
            'last_seen': datetime.now(),
            'sample_logs': [],
            'packet_count': 0,
            'hostname': None,
            'detected_type': 'unknown'
        })
        self.lock = threading.Lock()
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/tmp/syslog_monitor.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def capture_udp_traffic(self):
        """Capture UDP traffic on port 514 using tcpdump"""
        try:
            # Use tcpdump to capture packets
            cmd = [
                'sudo', 'tcpdump', '-i', 'any', '-n', '-l',
                'udp', 'port', '514', '-A', '-c', '1000'
            ]
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            current_packet = {'src_ip': None, 'data': ''}
            
            for line in process.stdout:
                if self.running is False:
                    process.terminate()
                    break
                    
                # Parse tcpdump output
                if ' > ' in line and '.514:' in line:
                    # Extract source IP
                    parts = line.split()
                    for part in parts:
                        if '.' in part and not '.514' in part:
                            ip_part = part.split('.')[0:4]
                            if len(ip_part) == 4:
                                src_ip = '.'.join(ip_part)
                                if self._is_valid_ip(src_ip):
                                    current_packet['src_ip'] = src_ip
                                    break
                elif line.strip() and current_packet['src_ip']:
                    # This is packet data
                    current_packet['data'] += line.strip()
                    
                    # Check if we have a complete syslog message
                    if self._is_syslog_message(current_packet['data']):
                        self._process_packet(
                            current_packet['src_ip'],
                            current_packet['data']
                        )
                        current_packet = {'src_ip': None, 'data': ''}
                        
        except Exception as e:
            self.logger.error(f"Error capturing UDP traffic: {e}")
            
    def capture_tcp_traffic(self):
        """Capture TCP traffic on port 514"""
        try:
            # Create TCP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Try to bind to port 514 (may need permissions)
            try:
                sock.bind(('0.0.0.0', 514))
                sock.listen(5)
                self.logger.info("TCP listener started on port 514")
            except PermissionError:
                self.logger.warning("Cannot bind to port 514, using passive monitoring")
                return
                
            while self.running:
                try:
                    sock.settimeout(1.0)
                    conn, addr = sock.accept()
                    
                    # Handle connection in thread
                    thread = threading.Thread(
                        target=self._handle_tcp_connection,
                        args=(conn, addr)
                    )
                    thread.daemon = True
                    thread.start()
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    self.logger.error(f"TCP accept error: {e}")
                    
        except Exception as e:
            self.logger.error(f"TCP listener error: {e}")
        finally:
            sock.close()
            
    def _handle_tcp_connection(self, conn, addr):
        """Handle individual TCP connection"""
        src_ip = addr[0]
        try:
            data = conn.recv(4096).decode('utf-8', errors='ignore')
            if data:
                self._process_packet(src_ip, data)
        except Exception as e:
            self.logger.error(f"Error handling TCP connection from {src_ip}: {e}")
        finally:
            conn.close()
            
    def _is_valid_ip(self, ip):
        """Check if string is valid IP address"""
        try:
            parts = ip.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except:
            return False
            
    def _is_syslog_message(self, data):
        """Check if data looks like a syslog message"""
        # Basic syslog patterns
        syslog_indicators = [
            '<', '>', 'priority', 'facility',
            'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
            'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec',
            'devname=', 'logid=', 'type=', 'subtype=',
            'TRAFFIC', 'THREAT', 'SYSTEM'
        ]
        
        return any(indicator in data for indicator in syslog_indicators)
        
    def _process_packet(self, src_ip, data):
        """Process captured packet"""
        with self.lock:
            source = self.detected_sources[src_ip]
            source['last_seen'] = datetime.now()
            source['packet_count'] += 1
            
            # Keep only last 5 sample logs
            if len(source['sample_logs']) < 5:
                source['sample_logs'].append({
                    'timestamp': datetime.now().isoformat(),
                    'data': data[:500]  # First 500 chars
                })
                
            # Try to extract hostname
            if not source['hostname']:
                hostname = self._extract_hostname(data)
                if hostname:
                    source['hostname'] = hostname
                    
            # Detect device type
            if source['detected_type'] == 'unknown':
                device_type = LogSource.detect_device_type(data)
                if device_type != 'unknown':
                    source['detected_type'] = device_type
                    
        self.logger.info(f"Packet from {src_ip}: {source['packet_count']} packets, type: {source['detected_type']}")
        
    def _extract_hostname(self, data):
        """Try to extract hostname from log data"""
        # Common patterns for hostname
        import re
        
        patterns = [
            r'devname="([^"]+)"',  # FortiGate
            r'hostname=([^\s]+)',   # Generic
            r'host=([^\s]+)',      # Generic
            r'\s([a-zA-Z0-9\-\.]+)\s+\w+\[\d+\]:',  # Syslog format
        ]
        
        for pattern in patterns:
            match = re.search(pattern, data)
            if match:
                return match.group(1)
                
        return None
        
    def sync_to_database(self):
        """Sync detected sources to database"""
        while self.running:
            try:
                with self.lock:
                    sources_to_sync = list(self.detected_sources.items())
                    
                for src_ip, info in sources_to_sync:
                    try:
                        # Get or create log source
                        source, created = LogSource.objects.get_or_create(
                            ip_address=src_ip,
                            defaults={
                                'name': info['hostname'] or f"Device-{src_ip}",
                                'hostname': info['hostname'] or '',
                                'device_type': info['detected_type'],
                                'status': 'pending',
                                'first_seen': info['first_seen']
                            }
                        )
                        
                        # Update existing source
                        if not created:
                            source.last_seen = info['last_seen']
                            source.total_logs += info['packet_count']
                            
                            # Update device type if detected
                            if source.device_type == 'unknown' and info['detected_type'] != 'unknown':
                                source.device_type = info['detected_type']
                                
                            # Update hostname if found
                            if not source.hostname and info['hostname']:
                                source.hostname = info['hostname']
                                
                            source.save()
                        else:
                            # Log new detection event
                            LogSourceEvent.objects.create(
                                log_source=source,
                                event_type='detected',
                                description=f"New log source detected from {src_ip}",
                                metadata={
                                    'sample_logs': info['sample_logs'],
                                    'detected_type': info['detected_type']
                                }
                            )
                            self.logger.info(f"New log source detected: {src_ip} ({info['detected_type']})")
                            
                    except Exception as e:
                        self.logger.error(f"Error syncing source {src_ip}: {e}")
                        
                # Clear old entries from memory
                with self.lock:
                    cutoff_time = datetime.now() - timedelta(minutes=30)
                    self.detected_sources = {
                        ip: info for ip, info in self.detected_sources.items()
                        if info['last_seen'] > cutoff_time
                    }
                    
            except Exception as e:
                self.logger.error(f"Sync error: {e}")
                
            time.sleep(30)  # Sync every 30 seconds
            
    def start(self):
        """Start monitoring"""
        self.running = True
        
        # Start UDP capture thread
        udp_thread = threading.Thread(target=self.capture_udp_traffic)
        udp_thread.daemon = True
        udp_thread.start()
        
        # Start TCP listener thread
        tcp_thread = threading.Thread(target=self.capture_tcp_traffic)
        tcp_thread.daemon = True
        tcp_thread.start()
        
        # Start database sync thread
        sync_thread = threading.Thread(target=self.sync_to_database)
        sync_thread.daemon = True
        sync_thread.start()
        
        self.logger.info("Syslog traffic monitor started")
        
    def stop(self):
        """Stop monitoring"""
        self.running = False
        self.logger.info("Syslog traffic monitor stopped")
        
    def get_status(self):
        """Get current monitoring status"""
        with self.lock:
            status = {
                'running': self.running,
                'detected_sources': len(self.detected_sources),
                'sources': []
            }
            
            for ip, info in self.detected_sources.items():
                status['sources'].append({
                    'ip': ip,
                    'hostname': info['hostname'],
                    'type': info['detected_type'],
                    'packets': info['packet_count'],
                    'last_seen': info['last_seen'].isoformat()
                })
                
        return status

def main():
    monitor = SyslogTrafficMonitor()
    
    # Handle signals
    def signal_handler(sig, frame):
        print("\nShutting down...")
        monitor.stop()
        sys.exit(0)
        
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start monitoring
    monitor.start()
    
    # Keep running
    try:
        while True:
            time.sleep(60)
            status = monitor.get_status()
            print(f"\nStatus: {status['detected_sources']} sources detected")
            for source in status['sources']:
                print(f"  - {source['ip']} ({source['type']}): {source['packets']} packets")
    except KeyboardInterrupt:
        pass
        
    monitor.stop()

if __name__ == "__main__":
    main()