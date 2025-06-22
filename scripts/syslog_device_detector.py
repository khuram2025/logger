#!/usr/bin/env python3
"""
syslog_device_detector.py

Background daemon that monitors syslog traffic to automatically detect new devices
and create log source entries in the database for approval workflow.
"""

import os
import sys
import time
import logging
import socket
import threading
import signal
from datetime import datetime, timedelta
from collections import defaultdict, deque
import socketserver
import django

# Setup Django environment
sys.path.append('/home/net/analyzer')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dashboard.settings')
django.setup()

from dashboard.models import LogSource, LogSourceEvent

# Configuration
SYSLOG_PORT = 514
SYSLOG_HOST = '0.0.0.0'
DETECTION_WINDOW = 300  # 5 minutes window for detection
MIN_LOGS_FOR_DETECTION = 5  # Minimum logs required to detect a device
LOG_FILE = '/var/log/syslog-detector.log'

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s [SyslogDetector] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_FILE)
    ]
)

class DeviceDetector:
    """Detects new devices from syslog traffic patterns"""
    
    def __init__(self):
        self.device_cache = defaultdict(lambda: {
            'logs': deque(maxlen=100),  # Keep last 100 logs
            'first_seen': None,
            'last_seen': None,
            'log_count': 0,
            'sample_logs': deque(maxlen=10),  # Keep sample logs for analysis
            'hostname': None
        })
        self.lock = threading.RLock()
    
    def process_syslog_message(self, client_ip, message, hostname=None):
        """Process incoming syslog message and detect new devices"""
        current_time = datetime.now()
        
        with self.lock:
            device_info = self.device_cache[client_ip]
            
            # Update device information
            if device_info['first_seen'] is None:
                device_info['first_seen'] = current_time
            device_info['last_seen'] = current_time
            device_info['log_count'] += 1
            device_info['logs'].append({
                'timestamp': current_time,
                'message': message[:500]  # Limit message size
            })
            device_info['sample_logs'].append(message)
            
            # Update hostname if provided
            if hostname and not device_info['hostname']:
                device_info['hostname'] = hostname
            
            # Check if we should detect this device
            if self.should_detect_device(client_ip, device_info):
                self.detect_device(client_ip, device_info)
    
    def should_detect_device(self, client_ip, device_info):
        """Determine if device should be detected and added to database"""
        # Skip if we've already detected this device recently
        if hasattr(device_info, 'detected') and device_info.get('detected'):
            return False
        
        # Check if device already exists in database
        if LogSource.objects.filter(ip_address=client_ip).exists():
            device_info['detected'] = True
            return False
        
        # Must have minimum number of logs
        if device_info['log_count'] < MIN_LOGS_FOR_DETECTION:
            return False
        
        # Must be within detection window
        time_diff = datetime.now() - device_info['first_seen']
        if time_diff.total_seconds() > DETECTION_WINDOW:
            return True
        
        # Immediate detection for known device types
        for log_entry in device_info['sample_logs']:
            device_type = LogSource.detect_device_type(log_entry)
            if device_type != 'unknown':
                return True
        
        return False
    
    def detect_device(self, client_ip, device_info):
        """Detect and create log source entry for new device"""
        try:
            # Analyze sample logs to detect device type
            sample_log = '\n'.join(device_info['sample_logs'])
            
            # Create or update log source
            source, created = LogSource.detect_or_create(
                ip_address=client_ip,
                hostname=device_info.get('hostname'),
                sample_log=sample_log
            )
            
            if created:
                logging.info(f"New device detected: {client_ip} ({source.device_type})")
                
                # Create detection event
                LogSourceEvent.objects.create(
                    log_source=source,
                    event_type='detected',
                    description=f"Device automatically detected from syslog traffic. "
                               f"Received {device_info['log_count']} logs. "
                               f"Detected type: {source.device_type}",
                    metadata={
                        'log_count': device_info['log_count'],
                        'detection_window': DETECTION_WINDOW,
                        'sample_logs': list(device_info['sample_logs'])[:3]  # First 3 samples
                    }
                )
            else:
                # Update existing source statistics
                source.update_stats(device_info['log_count'])
                logging.debug(f"Updated existing device: {client_ip}")
            
            # Mark as detected to avoid re-detection
            device_info['detected'] = True
            
        except Exception as e:
            logging.error(f"Error detecting device {client_ip}: {e}")
    
    def cleanup_old_entries(self):
        """Clean up old entries from device cache"""
        cutoff_time = datetime.now() - timedelta(hours=1)
        with self.lock:
            expired_ips = []
            for ip, info in self.device_cache.items():
                if info['last_seen'] and info['last_seen'] < cutoff_time:
                    expired_ips.append(ip)
            
            for ip in expired_ips:
                del self.device_cache[ip]
            
            if expired_ips:
                logging.debug(f"Cleaned up {len(expired_ips)} expired device cache entries")


class SyslogHandler(socketserver.BaseRequestHandler):
    """Handle incoming syslog UDP packets"""
    
    def handle(self):
        try:
            data = self.request[0]
            client_ip = self.client_address[0]
            
            # Decode syslog message
            try:
                message = data.decode('utf-8', errors='ignore').strip()
            except Exception:
                message = str(data)
            
            # Skip empty messages
            if not message:
                return
            
            # Extract hostname from syslog message if available
            hostname = self.extract_hostname(message)
            
            # Skip localhost traffic
            if client_ip in ['127.0.0.1', '::1']:
                return
            
            # Process with device detector
            device_detector.process_syslog_message(client_ip, message, hostname)
            
            logging.debug(f"Processed syslog from {client_ip}: {message[:100]}...")
            
        except Exception as e:
            logging.error(f"Error handling syslog packet: {e}")
    
    def extract_hostname(self, message):
        """Extract hostname from syslog message"""
        try:
            # Standard syslog format: <priority>timestamp hostname program: message
            # Look for hostname after timestamp
            parts = message.split()
            if len(parts) >= 3:
                # Skip priority and timestamp, hostname should be next
                potential_hostname = parts[2]
                # Basic validation - hostnames shouldn't contain certain characters
                if not any(char in potential_hostname for char in [':', '/', '[', ']']):
                    return potential_hostname
        except Exception:
            pass
        return None


class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    """Threaded UDP server for handling multiple concurrent syslog messages"""
    allow_reuse_address = True
    daemon_threads = True


class SyslogDetectorDaemon:
    """Main daemon class for syslog device detection"""
    
    def __init__(self):
        self.server = None
        self.cleanup_thread = None
        self.running = False
    
    def start(self):
        """Start the syslog detector daemon"""
        global device_detector
        device_detector = DeviceDetector()
        
        logging.info(f"Starting Syslog Device Detector on {SYSLOG_HOST}:{SYSLOG_PORT}")
        
        try:
            # Create and start UDP server
            self.server = ThreadedUDPServer((SYSLOG_HOST, SYSLOG_PORT), SyslogHandler)
            self.running = True
            
            # Start cleanup thread
            self.cleanup_thread = threading.Thread(target=self._cleanup_worker, daemon=True)
            self.cleanup_thread.start()
            
            logging.info("Syslog Device Detector started successfully")
            
            # Start server
            self.server.serve_forever()
            
        except PermissionError:
            logging.error(f"Permission denied: Cannot bind to port {SYSLOG_PORT}. Run with sudo or use a port > 1024")
            return False
        except OSError as e:
            if e.errno == 98:  # Address already in use
                logging.error(f"Port {SYSLOG_PORT} is already in use. Stop rsyslog or use a different port")
            else:
                logging.error(f"Error starting server: {e}")
            return False
        except Exception as e:
            logging.error(f"Unexpected error starting daemon: {e}")
            return False
    
    def stop(self):
        """Stop the syslog detector daemon"""
        logging.info("Stopping Syslog Device Detector...")
        self.running = False
        
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        
        logging.info("Syslog Device Detector stopped")
    
    def _cleanup_worker(self):
        """Background worker for periodic cleanup"""
        while self.running:
            try:
                time.sleep(300)  # Clean up every 5 minutes
                if device_detector:
                    device_detector.cleanup_old_entries()
            except Exception as e:
                logging.error(f"Error in cleanup worker: {e}")


def signal_handler(signum, frame):
    """Handle shutdown signals"""
    logging.info(f"Received signal {signum}, shutting down...")
    if daemon:
        daemon.stop()
    sys.exit(0)


def main():
    """Main entry point"""
    global daemon
    
    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Create and start daemon
    daemon = SyslogDetectorDaemon()
    
    # Check if running as root for port 514
    if SYSLOG_PORT < 1024 and os.geteuid() != 0:
        logging.warning(f"Running on port {SYSLOG_PORT} requires root privileges")
        logging.info("Consider running with sudo or changing to a port > 1024")
    
    try:
        daemon.start()
    except KeyboardInterrupt:
        logging.info("Received keyboard interrupt")
    finally:
        daemon.stop()


if __name__ == '__main__':
    main()