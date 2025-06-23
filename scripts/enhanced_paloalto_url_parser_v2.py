#!/usr/bin/env python3
"""
enhanced_paloalto_url_parser_v2.py

Comprehensive PaloAlto URL filtering log parser based on official PA documentation.
Captures all relevant fields from THREAT,url logs and stores them in ClickHouse.
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
    format='%(asctime)s %(levelname)s [PaloAlto-URL-v2] %(message)s',
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

# ── Comprehensive URL Log Field Mapping ──────────────────────────────────────
# Based on PaloAlto URL filtering log documentation and actual log analysis
PA_URL_FIELDS = {
    # Basic system fields
    'timestamp':                {'pos': 6,  'type': 'DateTime',   'default': 'now()'},
    'serial_number':           {'pos': 2,  'type': 'String',     'default': ''},
    'type':                    {'pos': 3,  'type': 'String',     'default': ''},
    'subtype':                 {'pos': 4,  'type': 'String',     'default': ''},
    'config_version':          {'pos': 5,  'type': 'String',     'default': ''},
    'generated_time':          {'pos': 6,  'type': 'DateTime',   'default': 'now()'},
    
    # Network fields
    'source_ip':               {'pos': 7,  'type': 'String',     'default': ''},
    'destination_ip':          {'pos': 8,  'type': 'String',     'default': ''},
    'nat_source_ip':           {'pos': 9,  'type': 'String',     'default': ''},
    'nat_destination_ip':      {'pos': 10, 'type': 'String',     'default': ''},
    
    # Policy and user info
    'rule_name':               {'pos': 11, 'type': 'String',     'default': ''},
    'source_user':             {'pos': 12, 'type': 'String',     'default': ''},
    'destination_user':        {'pos': 13, 'type': 'String',     'default': ''},
    'application':             {'pos': 14, 'type': 'String',     'default': ''},
    'virtual_system':          {'pos': 15, 'type': 'String',     'default': ''},
    'source_zone':             {'pos': 16, 'type': 'String',     'default': ''},
    'destination_zone':        {'pos': 17, 'type': 'String',     'default': ''},
    'inbound_interface':       {'pos': 18, 'type': 'String',     'default': ''},
    'outbound_interface':      {'pos': 19, 'type': 'String',     'default': ''},
    'log_action':              {'pos': 20, 'type': 'String',     'default': ''},
    
    # Session info
    'time_logged':             {'pos': 21, 'type': 'DateTime',   'default': 'now()'},
    'session_id':              {'pos': 22, 'type': 'UInt64',     'default': 0},
    'repeat_count':            {'pos': 23, 'type': 'UInt32',     'default': 0},
    'source_port':             {'pos': 24, 'type': 'UInt16',     'default': 0},
    'destination_port':        {'pos': 25, 'type': 'UInt16',     'default': 0},
    'nat_source_port':         {'pos': 26, 'type': 'UInt16',     'default': 0},
    'nat_destination_port':    {'pos': 27, 'type': 'UInt16',     'default': 0},
    'flags':                   {'pos': 28, 'type': 'String',     'default': ''},
    'protocol':                {'pos': 29, 'type': 'String',     'default': ''},
    
    # URL specific fields
    'action':                  {'pos': 30, 'type': 'String',     'default': ''},
    'url':                     {'pos': 31, 'type': 'String',     'default': ''},
    'url_category_list':       {'pos': 32, 'type': 'String',     'default': ''},
    'url_category':            {'pos': 33, 'type': 'String',     'default': ''},
    'severity':                {'pos': 34, 'type': 'String',     'default': ''},
    'direction':               {'pos': 35, 'type': 'String',     'default': ''},
    'sequence_number':         {'pos': 36, 'type': 'UInt64',     'default': 0},
    'action_flags':            {'pos': 37, 'type': 'String',     'default': ''},
    'source_location':         {'pos': 38, 'type': 'String',     'default': ''},
    'destination_location':    {'pos': 39, 'type': 'String',     'default': ''},
    
    # Content and threat info
    'content_type':            {'pos': 40, 'type': 'String',     'default': ''},
    'pcap_id':                 {'pos': 41, 'type': 'String',     'default': ''},
    'file_digest':             {'pos': 42, 'type': 'String',     'default': ''},
    'cloud':                   {'pos': 43, 'type': 'String',     'default': ''},
    'url_index':               {'pos': 44, 'type': 'UInt32',     'default': 0},
    'user_agent':              {'pos': 45, 'type': 'String',     'default': ''},
    'file_type':               {'pos': 46, 'type': 'String',     'default': ''},
    'xff':                     {'pos': 47, 'type': 'String',     'default': ''},
    'referer':                 {'pos': 48, 'type': 'String',     'default': ''},
    'sender':                  {'pos': 49, 'type': 'String',     'default': ''},
    'subject':                 {'pos': 50, 'type': 'String',     'default': ''},
    'recipient':               {'pos': 51, 'type': 'String',     'default': ''},
    'report_id':               {'pos': 52, 'type': 'String',     'default': ''},
    
    # Device and system info
    'device_group_hierarchy_l1': {'pos': 53, 'type': 'String',  'default': ''},
    'device_group_hierarchy_l2': {'pos': 54, 'type': 'String',  'default': ''},
    'device_group_hierarchy_l3': {'pos': 55, 'type': 'String',  'default': ''},
    'device_group_hierarchy_l4': {'pos': 56, 'type': 'String',  'default': ''},
    'virtual_system_name':     {'pos': 57, 'type': 'String',     'default': ''},
    'device_name':             {'pos': 58, 'type': 'String',     'default': ''},
    'virtual_system_id':       {'pos': 59, 'type': 'String',     'default': ''},
    
    # Additional threat fields
    'url_counter':             {'pos': 64, 'type': 'UInt32',     'default': 0},
    'uuid_for_rule':           {'pos': 65, 'type': 'String',     'default': ''},
    'http2_connection':        {'pos': 66, 'type': 'String',     'default': ''},
    'link_change_count':       {'pos': 67, 'type': 'UInt32',     'default': 0},
    'policy_id':               {'pos': 68, 'type': 'String',     'default': ''},
    'link_switches':           {'pos': 69, 'type': 'String',     'default': ''},
    'sdwan_cluster':           {'pos': 70, 'type': 'String',     'default': ''},
    'sdwan_device_type':       {'pos': 71, 'type': 'String',     'default': ''},
    'sdwan_cluster_type':      {'pos': 72, 'type': 'String',     'default': ''},
    'sdwan_site':              {'pos': 73, 'type': 'String',     'default': ''},
    'dynamic_user_group_name': {'pos': 74, 'type': 'String',     'default': ''},
    'x_forwarded_for_ip':      {'pos': 75, 'type': 'String',     'default': ''},
    'source_device_category':  {'pos': 76, 'type': 'String',     'default': ''},
    'source_device_profile':   {'pos': 77, 'type': 'String',     'default': ''},
    'source_device_model':     {'pos': 78, 'type': 'String',     'default': ''},
    'source_device_vendor':    {'pos': 79, 'type': 'String',     'default': ''},
    'source_device_os_family': {'pos': 80, 'type': 'String',     'default': ''},
    'source_device_os_version': {'pos': 81, 'type': 'String',    'default': ''},
    'source_hostname':         {'pos': 82, 'type': 'String',     'default': ''},
    'source_mac_address':      {'pos': 83, 'type': 'String',     'default': ''},
    'destination_device_category': {'pos': 84, 'type': 'String', 'default': ''},
    'destination_device_profile':  {'pos': 85, 'type': 'String', 'default': ''},
    'destination_device_model':    {'pos': 86, 'type': 'String', 'default': ''},
    'destination_device_vendor':   {'pos': 87, 'type': 'String', 'default': ''},
    'destination_device_os_family': {'pos': 88, 'type': 'String', 'default': ''},
    'destination_device_os_version': {'pos': 89, 'type': 'String', 'default': ''},
    'destination_hostname':    {'pos': 90, 'type': 'String',     'default': ''},
    'destination_mac_address': {'pos': 91, 'type': 'String',     'default': ''},
    'container_id':            {'pos': 92, 'type': 'String',     'default': ''},
    'pod_namespace':           {'pos': 93, 'type': 'String',     'default': ''},
    'pod_name':                {'pos': 94, 'type': 'String',     'default': ''},
    'source_external_dynamic_list': {'pos': 95, 'type': 'String', 'default': ''},
    'destination_external_dynamic_list': {'pos': 96, 'type': 'String', 'default': ''},
    'host_id':                 {'pos': 97, 'type': 'String',     'default': ''},
    'serial_number_2':         {'pos': 98, 'type': 'String',     'default': ''},
    'domain_edl':              {'pos': 99, 'type': 'String',     'default': ''},
    'source_dynamic_address_group': {'pos': 100, 'type': 'String', 'default': ''},
    'destination_dynamic_address_group': {'pos': 101, 'type': 'String', 'default': ''},
    'partial_hash':            {'pos': 102, 'type': 'String',     'default': ''},
    'high_res_timestamp':      {'pos': 103, 'type': 'DateTime',   'default': 'now()'},
    'reason':                  {'pos': 104, 'type': 'String',     'default': ''},
    'justification':           {'pos': 105, 'type': 'String',     'default': ''},
    'nssai_sst':               {'pos': 106, 'type': 'String',     'default': ''},
    'subcategory_of_app':      {'pos': 107, 'type': 'String',     'default': ''},
    'category_of_app':         {'pos': 108, 'type': 'String',     'default': ''},
    'technology_of_app':       {'pos': 109, 'type': 'String',     'default': ''},
    'risk_of_app':             {'pos': 110, 'type': 'String',     'default': ''},
    'characteristic_of_app':   {'pos': 111, 'type': 'String',     'default': ''},
    'container_of_app':        {'pos': 112, 'type': 'String',     'default': ''},
    'tunneled_app':            {'pos': 113, 'type': 'String',     'default': ''},
    'saas_of_app':             {'pos': 114, 'type': 'String',     'default': ''},
    'sanctioned_state_of_app': {'pos': 115, 'type': 'String',     'default': ''},
    
    # System fields
    'raw_message':             {'pos': -1,  'type': 'String',     'default': ''},
    'processing_timestamp':    {'pos': -1,  'type': 'DateTime',   'default': 'now()'},
}

# Create ordered field list for ClickHouse
ALL_URL_FIELDS = list(PA_URL_FIELDS.keys())

def parse_datetime(date_str: str) -> datetime:
    """Parse PaloAlto datetime format"""
    try:
        if '/' in date_str:
            return datetime.strptime(date_str, "%Y/%m/%d %H:%M:%S")
        elif 'T' in date_str:
            # Handle ISO format
            return datetime.fromisoformat(date_str.replace('T', ' ').split('+')[0].split('Z')[0])
        else:
            return datetime.now()
    except:
        return datetime.now()

def clean_field_value(value: str, field_type: str):
    """Clean and convert field values based on type"""
    if not value or value in ['', '""', "''", 'N/A', 'null']:
        if field_type.startswith('UInt'):
            return 0
        elif field_type == 'DateTime':
            return datetime.now()
        else:
            return ''
    
    # Remove quotes
    value = value.strip('"\'')
    
    if field_type.startswith('UInt'):
        try:
            # Handle hex values
            if value.startswith('0x'):
                return int(value, 16)
            return int(value)
        except:
            return 0
    elif field_type == 'DateTime':
        return parse_datetime(value)
    else:
        return value

def parse_url_log(line: str) -> dict:
    """Parse a comprehensive Palo Alto URL filtering log line"""
    data = {}
    try:
        # Initialize all fields with defaults
        for field, config in PA_URL_FIELDS.items():
            if config['type'].startswith('UInt'):
                data[field] = 0
            elif config['type'] == 'DateTime':
                data[field] = datetime.now()
            else:
                data[field] = ''
        
        data['raw_message'] = line.rstrip('\n')
        
        # Parse syslog format: timestamp hostname device_name message
        parts = line.split(' ', 4)
        if len(parts) < 5:
            return None
        
        # Extract device name from syslog
        syslog_device = parts[3]
        
        # Parse CSV fields
        csv_data = parts[4]
        fields = csv_data.split(',')
        
        # Check if this is a THREAT,url log
        if len(fields) < 5 or fields[3] != 'THREAT' or fields[4] != 'url':
            return None
        
        # Extract fields based on position mapping
        for field_name, config in PA_URL_FIELDS.items():
            pos = config['pos']
            field_type = config['type']
            
            if pos == -1:  # Special system fields
                if field_name == 'raw_message':
                    data[field_name] = line.rstrip('\n')
                elif field_name == 'processing_timestamp':
                    data[field_name] = datetime.now()
                continue
            
            if pos < len(fields):
                raw_value = fields[pos]
                data[field_name] = clean_field_value(raw_value, field_type)
        
        # Set device name from syslog if not in CSV
        if not data.get('device_name'):
            data['device_name'] = syslog_device
        
        # Extract URL domain for easier querying
        url = data.get('url', '')
        if url:
            try:
                if url.startswith('http'):
                    domain = url.split('//')[1].split('/')[0]
                else:
                    domain = url.split('/')[0]
                data['url_domain'] = domain
            except:
                data['url_domain'] = url
        else:
            data['url_domain'] = ''
        
        # Validate required fields
        if not data.get('url') or not data.get('source_ip'):
            return None
        
        return data
        
    except Exception as e:
        logging.error(f"Error parsing URL log line: {e}")
        return None

# Enhanced Log Handler (same pattern as working parser)
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

# Main Enhanced Processing
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
    
    logging.info("Starting Enhanced PaloAlto URL → ClickHouse ingestion v2 with batch size %d", BATCH_SIZE)
    logging.info(f"Capturing {len(ALL_URL_FIELDS)} fields per URL log")

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
                logging.info(f"✅ Inserted {len(rows)} comprehensive URL log records to ClickHouse")
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