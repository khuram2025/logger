#!/usr/bin/env python3
"""
real_time_device_monitor.py

Real-time monitoring of syslog traffic to detect new devices and update statistics
for existing log sources in the database.
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
import re
import socketserver

# Setup Django environment
sys.path.append('/home/net/analyzer')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'fwanalyzer.settings')
import django
django.setup()

from dashboard.models import LogSource, LogSourceEvent

# Configuration
MONITOR_PORT = 515  # Different port to avoid conflict with rsyslog
LOG_FILE = '/var/log/device-monitor.log'
UPDATE_INTERVAL = 60  # Update stats every 60 seconds

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s [DeviceMonitor] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_FILE)
    ]
)

class DeviceMonitor:
    """Monitor syslog traffic and update database statistics"""
    
    def __init__(self):
        self.device_stats = defaultdict(lambda: {
            'logs_count': 0,
            'last_seen': None,
            'hourly_logs': deque(maxlen=24),  # Last 24 hours
            'sample_logs': deque(maxlen=5)    # Keep 5 sample logs
        })
        self.lock = threading.RLock()
        self.running = True
    
    def process_syslog_message(self, client_ip, message):
        """Process incoming syslog message and update statistics"""
        current_time = datetime.now()
        
        with self.lock:
            stats = self.device_stats[client_ip]
            stats['logs_count'] += 1
            stats['last_seen'] = current_time
            stats['sample_logs'].append(message[:200])  # Store first 200 chars
            
            # Update hourly statistics
            current_hour = current_time.replace(minute=0, second=0, microsecond=0)
            if not stats['hourly_logs'] or stats['hourly_logs'][-1]['hour'] != current_hour:
                stats['hourly_logs'].append({
                    'hour': current_hour,
                    'count': 1
                })
            else:
                stats['hourly_logs'][-1]['count'] += 1
            
            logging.debug(f"Updated stats for {client_ip}: {stats['logs_count']} total logs")
    
    def update_database(self):
        """Update database with current statistics"""
        current_time = datetime.now()
        
        with self.lock:
            for ip_address, stats in self.device_stats.items():
                try:
                    # Try to find existing log source
                    try:
                        source = LogSource.objects.get(ip_address=ip_address)
                        
                        # Update statistics
                        source.total_logs += stats['logs_count']
                        
                        # Calculate logs today and last hour
                        today_start = current_time.replace(hour=0, minute=0, second=0, microsecond=0)
                        hour_start = current_time.replace(minute=0, second=0, microsecond=0)
                        
                        logs_today = sum(
                            hour_data['count'] 
                            for hour_data in stats['hourly_logs'] 
                            if hour_data['hour'] >= today_start
                        )
                        
                        logs_last_hour = sum(
                            hour_data['count']
                            for hour_data in stats['hourly_logs']
                            if hour_data['hour'] >= hour_start
                        )
                        
                        source.logs_today = logs_today
                        source.logs_last_hour = logs_last_hour
                        source.last_seen = stats['last_seen']
                        source.save()
                        
                        logging.debug(f"Updated {source.name}: +{stats['logs_count']} logs")
                        
                    except LogSource.DoesNotExist:
                        # New device detected - create pending entry
                        sample_content = '\n'.join(stats['sample_logs'])
                        device_type = LogSource.detect_device_type(sample_content)
                        
                        # Generate name based on detected type
                        if device_type == 'fortigate':
                            name = f"FortiGate-{ip_address.replace('.', '-')}"
                        elif device_type == 'paloalto':
                            name = f"PaloAlto-{ip_address.replace('.', '-')}"
                        else:
                            name = f"Unknown-{ip_address.replace('.', '-')}"
                        
                        source = LogSource.objects.create(
                            name=name,
                            description=f"Automatically detected device sending logs",
                            ip_address=ip_address,
                            device_type=device_type,
                            port=514,
                            status='pending',
                            save_logs=False,
                            total_logs=stats['logs_count'],
                            logs_today=stats['logs_count'],
                            logs_last_hour=stats['logs_count'],
                            last_seen=stats['last_seen']
                        )
                        
                        # Create detection event
                        LogSourceEvent.objects.create(
                            log_source=source,
                            event_type='detected',
                            description=f"New device detected sending {stats['logs_count']} logs. "
                                       f"Device type: {device_type}",
                            user='system',
                            metadata={
                                'detection_method': 'real_time_monitoring',
                                'logs_count': stats['logs_count'],
                                'sample_logs': list(stats['sample_logs'])
                            }
                        )
                        
                        logging.info(f"New device detected: {name} ({device_type}) - {stats['logs_count']} logs")
                    
                    # Clear processed stats
                    stats['logs_count'] = 0
                    
                except Exception as e:
                    logging.error(f"Error updating database for {ip_address}: {e}")
    
    def start_database_updater(self):
        """Start background thread to update database periodically"""
        def updater():
            while self.running:
                try:
                    time.sleep(UPDATE_INTERVAL)
                    if self.running:
                        self.update_database()
                except Exception as e:
                    logging.error(f"Error in database updater: {e}")
        
        thread = threading.Thread(target=updater, daemon=True)
        thread.start()
        return thread


class SyslogMonitorHandler(socketserver.BaseRequestHandler):
    """Handle incoming syslog UDP packets for monitoring"""
    
    def handle(self):
        try:
            data = self.request[0]
            client_ip = self.client_address[0]
            
            # Decode syslog message
            try:
                message = data.decode('utf-8', errors='ignore').strip()
            except Exception:
                message = str(data)
            
            # Skip empty messages or localhost
            if not message or client_ip in ['127.0.0.1', '::1']:
                return
            
            # Process with device monitor
            device_monitor.process_syslog_message(client_ip, message)
            
        except Exception as e:
            logging.error(f"Error handling syslog packet: {e}")


class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    """Threaded UDP server for handling concurrent syslog messages"""
    allow_reuse_address = True
    daemon_threads = True


class DeviceMonitorDaemon:
    """Main daemon for real-time device monitoring"""
    
    def __init__(self):
        self.server = None
        self.updater_thread = None
        self.running = False
    
    def start(self):
        """Start the device monitor daemon"""
        global device_monitor
        device_monitor = DeviceMonitor()
        
        logging.info(f"Starting Device Monitor on port {MONITOR_PORT}")
        
        try:
            # Start database updater
            self.updater_thread = device_monitor.start_database_updater()
            
            # Create and start UDP server
            self.server = ThreadedUDPServer(('0.0.0.0', MONITOR_PORT), SyslogMonitorHandler)
            self.running = True
            
            logging.info("Device Monitor started successfully")
            logging.info(f"Configure rsyslog to also send logs to port {MONITOR_PORT} for monitoring")
            
            # Start server
            self.server.serve_forever()
            
        except PermissionError:
            logging.error(f"Permission denied: Cannot bind to port {MONITOR_PORT}")
            return False
        except OSError as e:
            if e.errno == 98:  # Address already in use
                logging.error(f"Port {MONITOR_PORT} is already in use")
            else:
                logging.error(f"Error starting server: {e}")
            return False
        except Exception as e:
            logging.error(f"Unexpected error starting daemon: {e}")
            return False
    
    def stop(self):
        """Stop the device monitor daemon"""
        logging.info("Stopping Device Monitor...")
        self.running = False
        device_monitor.running = False
        
        # Final database update
        if device_monitor:
            device_monitor.update_database()
        
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        
        logging.info("Device Monitor stopped")


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
    daemon = DeviceMonitorDaemon()
    
    try:
        daemon.start()
    except KeyboardInterrupt:
        logging.info("Received keyboard interrupt")
    finally:
        daemon.stop()


if __name__ == '__main__':
    main()