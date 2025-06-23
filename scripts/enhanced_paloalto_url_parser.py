#!/usr/bin/env python3
"""
enhanced_paloalto_url_parser.py

Enhanced PaloAlto URL filtering log parser that processes THREAT,url logs
and inserts them into ClickHouse network_logs.pa_urls table.
Based on the working enhanced_paloalto_to_clickhouse.py pattern.
"""

import os
import time
import re
import logging
from datetime import datetime
from clickhouse_driver import Client
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading
import signal
import sys

# Import log manager for coordination
try:
    from log_manager import LogManager
except (ImportError, PermissionError) as e:
    logging.warning(f"LogManager not available, running in standalone mode: {e}")
    LogManager = None

# ── Configuration ─────────────────────────────────────────────────────────────
CH_HOST     = os.getenv('CH_HOST',     'localhost')
CH_PORT     = int(os.getenv('CH_PORT',     '9000'))
CH_USER     = os.getenv('CH_USER',     'default')
CH_PASSWORD = os.getenv('CH_PASSWORD', 'Read@123')
CH_DB       = os.getenv('CH_DB',       'network_logs')

LOG_FILE    = '/var/log/paloalto-1004.log'
STATUS_UPDATE_INTERVAL = 30

# ── Logging Setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s [PaloAlto-URL] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/var/log/paloalto-url-processor.log')
    ]
)

# ── ClickHouse Client ─────────────────────────────────────────────────────────
CLIENT = Client(
    host=CH_HOST,
    port=CH_PORT,
    user=CH_USER,
    password=CH_PASSWORD,
    database=CH_DB
)

# ── URL Log Parsing Logic ─────────────────────────────────────────────────────
ALL_URL_FIELDS = [
    'timestamp', 'url', 'url_domain', 'url_category', 'action', 
    'source_address', 'destination_address', 'device_name', 'http_method', 
    'response_code', 'user_agent', 'source_user', 'rule_name', 
    'application', 'bytes_sent', 'bytes_received', 'raw_message'
]

def parse_url_log(line: str) -> dict:
    """Parse a Palo Alto URL filtering log line"""
    data = {}
    try:
        # Set default values
        for field in ALL_URL_FIELDS:
            if field in ['response_code', 'bytes_sent', 'bytes_received']:
                data[field] = 0
            else:
                data[field] = ''
        
        data['raw_message'] = line.rstrip('\n')
        
        # Parse syslog format: timestamp hostname device_name message
        parts = line.split(' ', 4)
        if len(parts) < 5:
            return None
            
        # Extract device name
        data['device_name'] = parts[3]
        
        # Parse CSV fields
        csv_data = parts[4]
        fields = csv_data.split(',')
        
        # Check if this is a THREAT,url log
        if len(fields) < 5 or fields[3] != 'THREAT' or fields[4] != 'url':
            return None
        
        # Extract timestamp (field 6: generated_time)
        if len(fields) > 6:
            try:
                timestamp_str = fields[6]
                data['timestamp'] = datetime.strptime(timestamp_str, "%Y/%m/%d %H:%M:%S")
            except ValueError:
                data['timestamp'] = datetime.now()
        else:
            data['timestamp'] = datetime.now()
        
        # Extract URL (field 31) - remove quotes
        data['url'] = fields[31].strip('"') if len(fields) > 31 else ''
        
        # Extract URL domain
        if data['url']:
            if data['url'].startswith('http'):
                # Full URL
                try:
                    domain = data['url'].split('//')[1].split('/')[0]
                except:
                    domain = data['url']
            else:
                # Just domain/path
                domain = data['url'].split('/')[0]
            data['url_domain'] = domain
        else:
            data['url_domain'] = ''
        
        # Extract other fields based on Palo Alto URL filtering format
        data['url_category'] = fields[33] if len(fields) > 33 else ''
        data['action'] = fields[30] if len(fields) > 30 else ''
        data['source_address'] = fields[7] if len(fields) > 7 else ''
        data['destination_address'] = fields[8] if len(fields) > 8 else ''
        data['http_method'] = 'GET'  # Default since not explicitly in URL logs
        data['response_code'] = 0
        data['user_agent'] = ''  # Not typically in URL filtering logs
        data['source_user'] = fields[12] if len(fields) > 12 else ''
        data['rule_name'] = fields[11] if len(fields) > 11 else ''
        data['application'] = fields[14] if len(fields) > 14 else ''
        data['bytes_sent'] = 0
        data['bytes_received'] = 0
        
        # Validate required fields
        if not data.get('url') or not data.get('source_address') or not data.get('destination_address'):
            return None
            
        return data
        
    except Exception as e:
        logging.error(f"Error parsing URL log line: {e}")
        if 'timestamp' not in data:
            data['timestamp'] = datetime.now()
        if 'raw_message' not in data:
            data['raw_message'] = line.rstrip('\n')
        return None
    
    return data

# ── Enhanced Log Handler (same pattern as working parser) ─────────────────────
BATCH_SIZE = 100
BATCH_FLUSH_INTERVAL = 1
FILE_CHECK_INTERVAL = 1

class EnhancedURLLogHandler(FileSystemEventHandler):
    def __init__(self, filepath, buffer, buffer_lock, process_batch_func, log_manager=None):
        self.filepath = filepath
        self.buffer = buffer
        self.buffer_lock = buffer_lock
        self.process_batch_func = process_batch_func
        self.log_manager = log_manager
        
        self.total_lines_processed = 0
        self.total_urls_processed = 0
        self.total_bytes_processed = 0
        self.last_status_update = 0
        
        self._open_file()
        
    def _open_file(self):
        """Open or reopen the log file"""
        try:
            if hasattr(self, '_fp') and self._fp:
                self._fp.close()
            
            self._fp = open(self.filepath, 'r')
            
            # Resume from last processed position if log manager is available
            if self.log_manager and hasattr(self.log_manager, 'file_info'):
                file_info = self.log_manager.file_info.get(self.filepath)
                if file_info and file_info.last_processed_position > 0:
                    current_size = os.path.getsize(self.filepath)
                    if current_size < file_info.last_processed_position:
                        logging.info(f"File {self.filepath} was rotated, starting from beginning")
                        self._fp.seek(0)
                    else:
                        logging.info(f"Resuming from position {file_info.last_processed_position}")
                        self._fp.seek(file_info.last_processed_position)
                else:
                    self._fp.seek(0, os.SEEK_END)
            else:
                self._fp.seek(0, os.SEEK_END)
                
            current_pos = self._fp.tell()
            logging.info(f"Opened URL log file: {self.filepath} (position: {current_pos})")
            
        except Exception as e:
            logging.error(f"Error opening log file: {e}")
            
    def _check_file_rotation(self):
        """Enhanced file rotation check with log manager coordination"""
        try:
            if not os.path.exists(self.filepath) or os.stat(self.filepath).st_ino != os.fstat(self._fp.fileno()).st_ino:
                logging.info("Log rotation detected. Reopening log file.")
                self._update_processing_status()
                self._open_file()
                return True
                
            if self.log_manager and self.log_manager.check_file_rotation_needed(self.filepath):
                logging.warning(f"File {self.filepath} approaching size limit, requesting rotation")
                if self.log_manager.coordinate_rotation(self.filepath):
                    self._open_file()
                    return True
                    
        except Exception as e:
            logging.error(f"Error checking file rotation: {e}")
            self._open_file()
            return True
        return False

    def _update_processing_status(self):
        """Update processing status with log manager"""
        if self.log_manager and hasattr(self, '_fp'):
            try:
                current_position = self._fp.tell()
                self.log_manager.update_processing_status(
                    self.filepath, 
                    current_position, 
                    self.total_lines_processed
                )
                self.last_status_update = time.time()
                logging.debug(f"Updated processing status: position={current_position}, lines={self.total_lines_processed}")
            except Exception as e:
                logging.error(f"Error updating processing status: {e}")

    def on_modified(self, event):
        if event.src_path != self.filepath:
            return
            
        logging.debug(f"File modification detected for: {self.filepath}")
        self._check_file_rotation()
        
        lines_read = 0
        urls_found = 0
        
        while True:
            try:
                line = self._fp.readline()
                if not line:
                    break
                    
                lines_read += 1
                self.total_lines_processed += 1
                
                # Only process THREAT,url logs
                if 'THREAT,url,' in line:
                    parsed_data = parse_url_log(line)
                    if parsed_data:
                        urls_found += 1
                        self.total_urls_processed += 1
                        
                        with self.buffer_lock:
                            self.buffer.append(parsed_data)
                            if len(self.buffer) >= BATCH_SIZE:
                                self.process_batch_func()
                        
            except Exception as e:
                logging.error(f"Error reading log line: {e}")
                self._open_file()
                break
        
        if lines_read > 0:
            self.total_bytes_processed = self._fp.tell()
            logging.info(f"Read {lines_read} new lines from {self.filepath}, found {urls_found} URL logs (total: {self.total_urls_processed})")
            
            if time.time() - self.last_status_update > STATUS_UPDATE_INTERVAL:
                self._update_processing_status()

    def on_moved(self, event):
        if event.src_path == self.filepath or event.dest_path == self.filepath:
            logging.info(f"File move detected: {event.src_path} -> {event.dest_path}")
            self._update_processing_status()
            self._open_file()

# ── Main Enhanced Processing (same pattern as working parser) ─────────────────
def main():
    """Enhanced main function with log manager integration"""
    insert_query = f"""
        INSERT INTO {CH_DB}.pa_urls ({', '.join(ALL_URL_FIELDS)}) VALUES
    """
    
    # Initialize log manager if available
    log_manager = None
    if LogManager:
        try:
            log_manager = LogManager()
            logging.info("Log manager initialized successfully")
        except Exception as e:
            logging.warning(f"Could not initialize log manager: {e}")
    
    logging.info("Starting Enhanced PaloAlto URL → ClickHouse ingestion with batch size %d", BATCH_SIZE)

    buffer = []
    buffer_lock = threading.Lock()

    def process_batch():
        with buffer_lock:
            if not buffer:
                return
            batch = buffer[:]
            buffer.clear()
            
        if not batch:
            return
            
        logging.info(f"Processing batch of {len(batch)} URL records")
        
        rows = []
        for record in batch:
            try:
                row = [record[field] for field in ALL_URL_FIELDS]
                rows.append(row)
            except Exception as e:
                logging.error(f"Error preparing URL record: {e}")
                
        if rows:
            try:
                CLIENT.execute(insert_query, rows)
                logging.info(f"✅ Inserted {len(rows)} URL log records to ClickHouse")
            except Exception as e:
                logging.error(f"❌ Batch insert error: {e}")

    # Create enhanced file handler
    handler = EnhancedURLLogHandler(LOG_FILE, buffer, buffer_lock, process_batch, log_manager)
    observer = Observer()
    observer.schedule(handler, path=os.path.dirname(LOG_FILE) or '.', recursive=False)
    observer.start()
    
    logging.info(f"👀 Monitoring URL log file: {LOG_FILE}")
    logging.info(f"ClickHouse connection: {CH_HOST}:{CH_PORT}, DB: {CH_DB}")

    def flush_and_exit(signum, frame):
        logging.info("🛑 Shutting down. Flushing remaining URL logs...")
        handler._update_processing_status()
        process_batch()
        observer.stop()
        observer.join()
        sys.exit(0)

    signal.signal(signal.SIGINT, flush_and_exit)
    signal.signal(signal.SIGTERM, flush_and_exit)

    # Enhanced monitoring loop
    last_check_time = time.time()
    
    try:
        while True:
            current_time = time.time()
            should_check_file = (current_time - last_check_time) >= FILE_CHECK_INTERVAL
            
            if should_check_file:
                last_check_time = current_time
                handler._check_file_rotation()
                
                try:
                    file_size = os.path.getsize(LOG_FILE)
                    current_pos = handler._fp.tell()
                    
                    if log_manager:
                        status = log_manager.get_status()
                        file_status = status.get('file_info', {}).get(LOG_FILE, {})
                        processing_lag_mb = file_status.get('processing_lag_mb', 0)
                        
                        if processing_lag_mb > 100:
                            logging.warning(f"High processing lag detected: {processing_lag_mb:.1f} MB")
                    
                    if file_size > current_pos:
                        unread_bytes = file_size - current_pos
                        logging.info(f"Detected {unread_bytes} unread bytes, triggering read")
                        handler.on_modified(type('obj', (object,), {'src_path': LOG_FILE}))
                    
                except Exception as e:
                    logging.error(f"Error checking file: {e}")
            
            if current_time - handler.last_status_update > STATUS_UPDATE_INTERVAL:
                handler._update_processing_status()
            
            process_batch()
            time.sleep(BATCH_FLUSH_INTERVAL)
            
    except KeyboardInterrupt:
        flush_and_exit(None, None)

if __name__ == '__main__':
    main()