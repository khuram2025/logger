#!/usr/bin/env python3
"""
Enhanced PaloAlto log processor - REAL-TIME version with robust file monitoring
Fixed for watchdog timeout and auto-processing issues
"""

import os
import time
import logging
import signal
import sys
import threading
from datetime import datetime
from clickhouse_driver import Client
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Configuration
CH_HOST = os.getenv('CH_HOST', 'localhost')
CH_PORT = int(os.getenv('CH_PORT', '9000'))
CH_USER = os.getenv('CH_USER', 'default')
CH_PASSWORD = os.getenv('CH_PASSWORD', 'Read@123')
CH_DB = os.getenv('CH_DB', 'network_logs')
LOG_FILE = '/var/log/paloalto-1004.log'

# Batch settings
BATCH_SIZE = 100
FLUSH_INTERVAL = 5  # Process batches every 5 seconds
FILE_CHECK_INTERVAL = 10  # Check file for new data every 10 seconds

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s [PaloAlto-RT] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/tmp/paloalto-realtime.log')
    ]
)

# ClickHouse client
try:
    CLIENT = Client(
        host=CH_HOST,
        port=CH_PORT,
        user=CH_USER,
        password=CH_PASSWORD,
        database=CH_DB
    )
    CLIENT.execute("SELECT 1")  # Test connection
    logging.info("ClickHouse connection established")
except Exception as e:
    logging.error(f"ClickHouse connection failed: {e}")
    sys.exit(1)

# URL Fields for ClickHouse
ALL_URL_FIELDS = [
    'timestamp', 'receive_time', 'generated_time', 'processing_timestamp', 'sequence_number',
    'session_id', 'device_name', 'serial_number', 'source_address', 'destination_address',
    'nat_source_ip', 'nat_destination_ip', 'source_port', 'destination_port',
    'source_zone', 'destination_zone', 'inbound_interface', 'outbound_interface',
    'ip_protocol', 'protocol', 'url', 'url_domain', 'url_path', 'url_query',
    'url_category', 'url_category_list', 'http_method', 'user_agent', 'referer',
    'content_type', 'response_code', 'response_size', 'rule_name', 'rule_uuid',
    'action', 'severity', 'direction', 'threat_id', 'threat_category',
    'log_action', 'source_user', 'destination_user', 'application',
    'application_category', 'source_country', 'destination_country',
    'raw_message', 'log_type', 'log_subtype', 'virtual_system'
]

# Global state
buffer = []
buffer_lock = threading.Lock()
last_position = 0
stats = {'processed': 0, 'errors': 0, 'last_update': time.time()}

def parse_url_log(fields, device_name, raw_message):
    """Parse URL log with robust error handling"""
    try:
        data = {}
        
        # Initialize all fields with defaults
        current_time = datetime.now()
        for field in ALL_URL_FIELDS:
            if field in ['sequence_number', 'session_id', 'source_port', 'destination_port', 
                        'ip_protocol', 'response_code', 'response_size']:
                data[field] = 0
            elif field in ['timestamp', 'receive_time', 'generated_time', 'processing_timestamp']:
                data[field] = current_time
            else:
                data[field] = ''
        
        data['raw_message'] = raw_message
        data['device_name'] = device_name
        data['log_type'] = 'THREAT'
        data['log_subtype'] = 'url'
        data['receive_time'] = current_time
        data['processing_timestamp'] = current_time
        
        # Parse timestamp
        if len(fields) > 6:
            try:
                timestamp_str = fields[6]
                parsed_time = datetime.strptime(timestamp_str, "%Y/%m/%d %H:%M:%S")
                data['timestamp'] = parsed_time
                data['generated_time'] = parsed_time
            except ValueError:
                pass
        
        # Extract key fields with bounds checking
        if len(fields) > 5 and fields[5].isdigit():
            data['sequence_number'] = int(fields[5])
        if len(fields) > 7:
            data['source_address'] = fields[7]
        if len(fields) > 8:
            data['destination_address'] = fields[8]
        if len(fields) > 24 and fields[24].isdigit():
            data['source_port'] = int(fields[24])
        if len(fields) > 25 and fields[25].isdigit():
            data['destination_port'] = int(fields[25])
        if len(fields) > 16:
            data['source_zone'] = fields[16]
        if len(fields) > 17:
            data['destination_zone'] = fields[17]
        if len(fields) > 18:
            data['inbound_interface'] = fields[18]
        if len(fields) > 19:
            data['outbound_interface'] = fields[19]
        if len(fields) > 29:
            data['protocol'] = fields[29]
        if len(fields) > 11:
            data['rule_name'] = fields[11]
        if len(fields) > 12:
            data['source_user'] = fields[12]
        if len(fields) > 14:
            data['application'] = fields[14]
        if len(fields) > 30:
            data['action'] = fields[30]
        if len(fields) > 34:
            data['severity'] = fields[34]
        if len(fields) > 35:
            data['direction'] = fields[35]
        if len(fields) > 15:
            data['virtual_system'] = fields[15]
        
        # Extract URL and clean it
        if len(fields) > 31:
            url = fields[31].strip('"')
            data['url'] = url
            
            # Parse domain and path
            if url:
                if url.startswith('http'):
                    try:
                        url_parts = url.split('//')[1]
                        domain = url_parts.split('/')[0]
                        path = '/' + '/'.join(url_parts.split('/')[1:]) if '/' in url_parts else '/'
                    except:
                        domain = url
                        path = '/'
                else:
                    url_parts = url.split('/', 1)
                    domain = url_parts[0]
                    path = '/' + url_parts[1] if len(url_parts) > 1 else '/'
                data['url_domain'] = domain
                data['url_path'] = path
        
        # Extract threat info
        if len(fields) > 32:
            threat_field = fields[32].strip('()')
            if threat_field.isdigit():
                data['threat_id'] = threat_field
            else:
                data['threat_category'] = threat_field
        
        # Extract category
        if len(fields) > 33:
            data['url_category'] = fields[33]
        
        # Set defaults
        data['http_method'] = 'GET'
        data['response_code'] = 0
        
        # Validate required fields
        if not data.get('url') or not data.get('source_address') or not data.get('destination_address'):
            return None
            
        return data
        
    except Exception as e:
        logging.error(f"Error parsing URL log: {e}")
        return None

def process_line(line):
    """Process a single log line"""
    try:
        if 'THREAT,url' not in line:
            return None
            
        # Parse syslog format
        parts = line.split(' ', 4)
        if len(parts) < 5:
            return None
            
        device_name = parts[3]
        log_data = parts[4]
        fields = log_data.split(',')
        
        if len(fields) > 4 and fields[3] == 'THREAT' and fields[4] == 'url':
            return parse_url_log(fields, device_name, line.rstrip('\n'))
            
    except Exception as e:
        logging.error(f"Error processing line: {e}")
        
    return None

def flush_buffer():
    """Flush buffer to ClickHouse"""
    global buffer, stats
    
    with buffer_lock:
        if not buffer:
            return 0
        
        batch = buffer[:]
        buffer.clear()
    
    try:
        if batch:
            rows = [[record.get(field, '') for field in ALL_URL_FIELDS] for record in batch]
            
            insert_query = f"INSERT INTO {CH_DB}.pa_urls_optimized ({', '.join(ALL_URL_FIELDS)}) VALUES"
            CLIENT.execute(insert_query, rows)
            
            stats['processed'] += len(batch)
            logging.info(f"✅ Inserted {len(batch)} URL records (total: {stats['processed']})")
            return len(batch)
            
    except Exception as e:
        logging.error(f"❌ Insert error: {e}")
        stats['errors'] += 1
        
    return 0

def read_new_data():
    """Read new data from log file"""
    global last_position
    
    try:
        with open(LOG_FILE, 'r') as f:
            f.seek(last_position)
            lines = f.readlines()
            last_position = f.tell()
            
            if lines:
                logging.info(f"Reading {len(lines)} new lines from position {last_position}")
                
                for line in lines:
                    parsed = process_line(line)
                    if parsed:
                        with buffer_lock:
                            buffer.append(parsed)
                            
                            # Auto-flush if buffer is full
                            if len(buffer) >= BATCH_SIZE:
                                threading.Thread(target=flush_buffer, daemon=True).start()
                                
    except Exception as e:
        logging.error(f"Error reading file: {e}")

class LogFileHandler(FileSystemEventHandler):
    """Handle file system events"""
    
    def on_modified(self, event):
        if event.src_path == LOG_FILE:
            logging.debug(f"File modified: {LOG_FILE}")
            read_new_data()

def init_file_position():
    """Initialize file reading position"""
    global last_position
    
    try:
        # Start from last 50MB to catch recent logs
        file_size = os.path.getsize(LOG_FILE)
        last_position = max(0, file_size - 50 * 1024 * 1024)
        
        logging.info(f"Starting from position {last_position} (file size: {file_size})")
        
        # Read initial batch
        read_new_data()
        
    except Exception as e:
        logging.error(f"Error initializing file position: {e}")
        last_position = 0

def main():
    """Main processing loop"""
    global stats
    
    logging.info("Starting Enhanced PaloAlto Real-time Processor")
    
    # Initialize file position
    init_file_position()
    
    # Setup file watcher
    event_handler = LogFileHandler()
    observer = Observer()
    observer.schedule(event_handler, path=os.path.dirname(LOG_FILE), recursive=False)
    observer.start()
    
    logging.info(f"Monitoring {LOG_FILE} for changes")
    
    def signal_handler(signum, frame):
        logging.info("Shutdown signal received, flushing buffers...")
        flush_buffer()
        observer.stop()
        observer.join()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        last_stats = time.time()
        
        while True:
            # Periodic file check (in case file watcher misses events)
            read_new_data()
            
            # Flush any pending data
            flush_buffer()
            
            # Print stats every minute
            if time.time() - last_stats > 60:
                logging.info(f"Stats: Processed={stats['processed']}, Errors={stats['errors']}")
                last_stats = time.time()
            
            # Sleep between checks
            time.sleep(FLUSH_INTERVAL)
            
    except Exception as e:
        logging.error(f"Main loop error: {e}")
    finally:
        observer.stop()
        observer.join()

if __name__ == '__main__':
    main()