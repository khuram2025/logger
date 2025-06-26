#!/usr/bin/env python3
"""
enhanced_paloalto_to_clickhouse.py

Enhanced PaloAlto log processor with integrated log management.
Coordinates with log_manager.py to ensure proper file rotation and cleanup.
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
except ImportError:
    logging.warning("LogManager not available, running in standalone mode")
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
    format='%(asctime)s %(levelname)s [PaloAlto] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/tmp/paloalto-processor.log')
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

# ── Parsing Logic (same as original) ─────────────────────────────────────────
NUMERIC_FIELDS = {
    'srcport', 'dstport', 'proto', 'sentbyte', 'rcvdbyte', 'sentpkt', 'rcvdpkt'
}

IP_FIELDS = {
    'srcip', 'dstip'
}

PROTO_MAP = {
    'tcp': 6, 'udp': 17, 'icmp': 1, 'ipsec': 50, 'gre': 47,
    'esp': 50, 'ah': 51, 'sctp': 132, 'ospf': 89, 'pim': 103, 'igmp': 2
}

ALL_FIELDS = [
    'timestamp', 'raw_message', 'devname', 'srcip', 'srcport',
    'srcintf', 'dstip', 'dstport', 'dstintf', 'action',
    'policyname', 'proto', 'appcat', 'dstcountry',
    'sentbyte', 'rcvdbyte', 'sentpkt', 'rcvdpkt', 'username'
]

# URL Log Fields (for pa_urls_optimized table)
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

def parse_traffic_log(fields, data, device_name):
    """Parse TRAFFIC log format"""
    try:
        # Set default values for traffic fields
        for field in ALL_FIELDS:
            if field in NUMERIC_FIELDS:
                data[field] = 0
            elif field in IP_FIELDS:
                data[field] = '0.0.0.0'
            else:
                data[field] = ''
        
        data['devname'] = device_name
        data['log_type'] = 'TRAFFIC'
        
        # Extract timestamp
        if len(fields) > 1:
            timestamp_str = fields[1]
            try:
                parsed_dt = datetime.strptime(timestamp_str, "%Y/%m/%d %H:%M:%S")
                data['timestamp'] = parsed_dt.replace(tzinfo=None) if hasattr(parsed_dt, 'tzinfo') and parsed_dt.tzinfo else parsed_dt
            except (ValueError, TypeError, AttributeError):
                data['timestamp'] = datetime.now()
        
        # Process fields based on traffic log format
        if len(fields) > 7:
            data['srcip'] = fields[7] if fields[7] else '0.0.0.0'
        if len(fields) > 8:
            data['dstip'] = fields[8] if fields[8] else '0.0.0.0'
        
        # Extract ports
        if len(fields) > 24:
            try:
                data['srcport'] = int(fields[24]) if fields[24] else 0
            except (ValueError, TypeError):
                data['srcport'] = 0
        if len(fields) > 25:
            try:
                data['dstport'] = int(fields[25]) if fields[25] else 0
            except (ValueError, TypeError):
                data['dstport'] = 0
        
        # Extract interfaces and other fields
        if len(fields) > 18:
            data['srcintf'] = fields[18] if fields[18] else ''
        if len(fields) > 19:
            data['dstintf'] = fields[19] if fields[19] else ''
        if len(fields) > 30:
            data['action'] = fields[30].lower() if fields[30] else ''
        if len(fields) > 11:
            data['policyname'] = fields[11] if fields[11] else ''
        if len(fields) > 12:
            data['username'] = fields[12] if fields[12] else ''
            
        # Protocol conversion
        if len(fields) > 29:
            proto_str = fields[29].lower() if fields[29] else ''
            if proto_str in PROTO_MAP:
                data['proto'] = PROTO_MAP[proto_str]
            elif proto_str.isdigit():
                data['proto'] = int(proto_str)
            else:
                data['proto'] = 0
                
        # Additional fields
        if len(fields) > 37:
            data['appcat'] = fields[37] if fields[37] else ''
        if len(fields) > 42:
            data['dstcountry'] = fields[42] if fields[42] else ''
            
        # Byte and packet counts
        if len(fields) > 32:
            try:
                data['sentbyte'] = int(fields[32]) if fields[32] else 0
            except (ValueError, TypeError):
                data['sentbyte'] = 0
        if len(fields) > 33:
            try:
                data['rcvdbyte'] = int(fields[33]) if fields[33] else 0
            except (ValueError, TypeError):
                data['rcvdbyte'] = 0
        if len(fields) > 44:
            try:
                data['sentpkt'] = int(fields[44]) if fields[44] else 0
            except (ValueError, TypeError):
                data['sentpkt'] = 0
        if len(fields) > 45:
            try:
                data['rcvdpkt'] = int(fields[45]) if fields[45] else 0
            except (ValueError, TypeError):
                data['rcvdpkt'] = 0
                
    except Exception as e:
        logging.error(f"Error parsing TRAFFIC log: {e}")
        if 'timestamp' not in data:
            data['timestamp'] = datetime.now()
    
    return data

def parse_url_log(fields, data, device_name):
    """Parse THREAT,url log format"""
    try:
        # Preserve raw_message if already set, then set default values for URL fields
        raw_message = data.get('raw_message', '')
        for field in ALL_URL_FIELDS:
            if field in ['sequence_number', 'session_id', 'source_port', 'destination_port', 
                        'ip_protocol', 'response_code', 'response_size']:
                data[field] = 0
            elif field in ['timestamp', 'receive_time', 'generated_time', 'processing_timestamp']:
                data[field] = datetime.now()
            else:
                data[field] = ''
        
        # Restore raw_message
        if raw_message:
            data['raw_message'] = raw_message
        
        data['device_name'] = device_name
        data['log_type'] = 'THREAT'
        data['log_subtype'] = 'url'
        
        # Extract timestamps
        current_time = datetime.now()
        data['receive_time'] = current_time
        data['processing_timestamp'] = current_time
        
        # Use actual log timestamp for main timestamp field
        if len(fields) > 6:
            try:
                timestamp_str = fields[6]
                parsed_time = datetime.strptime(timestamp_str, "%Y/%m/%d %H:%M:%S")
                data['timestamp'] = parsed_time  # Use actual log time
                data['generated_time'] = parsed_time
            except ValueError:
                data['timestamp'] = current_time
                data['generated_time'] = current_time
        else:
            data['timestamp'] = current_time
            data['generated_time'] = current_time
        
        # Extract key fields
        data['sequence_number'] = int(fields[5]) if len(fields) > 5 and fields[5].isdigit() else 0
        data['source_address'] = fields[7] if len(fields) > 7 else ''
        data['destination_address'] = fields[8] if len(fields) > 8 else ''
        data['source_port'] = int(fields[24]) if len(fields) > 24 and fields[24].isdigit() else 0
        data['destination_port'] = int(fields[25]) if len(fields) > 25 and fields[25].isdigit() else 0
        data['source_zone'] = fields[18] if len(fields) > 18 else ''
        data['destination_zone'] = fields[19] if len(fields) > 19 else ''
        data['inbound_interface'] = fields[20] if len(fields) > 20 else ''
        data['outbound_interface'] = fields[21] if len(fields) > 21 else ''
        data['protocol'] = fields[29] if len(fields) > 29 else ''
        data['rule_name'] = fields[11] if len(fields) > 11 else ''
        data['source_user'] = fields[12] if len(fields) > 12 else ''
        data['application'] = fields[14] if len(fields) > 14 else ''
        data['action'] = fields[30] if len(fields) > 30 else ''
        # For URL logs: field 32 is threat/content type (like 9999), field 34 is severity
        data['severity'] = fields[34] if len(fields) > 34 else ''
        data['direction'] = fields[35] if len(fields) > 35 else ''
        data['virtual_system'] = fields[16] if len(fields) > 16 else ''
        
        # Extract URL (field 31) - remove quotes
        data['url'] = fields[31].strip('"') if len(fields) > 31 else ''
        
        # Extract threat/content type (field 32) - often contains threat ID like (9999)
        threat_type_field = fields[32] if len(fields) > 32 else ''
        if threat_type_field:
            # Remove parentheses if present
            threat_type_clean = threat_type_field.strip('()')
            if threat_type_clean.isdigit():
                data['threat_id'] = threat_type_clean
            else:
                data['threat_category'] = threat_type_clean
        
        # Extract URL domain and path
        if data['url']:
            if data['url'].startswith('http'):
                try:
                    url_parts = data['url'].split('//')[1]
                    domain = url_parts.split('/')[0]
                    path = '/' + '/'.join(url_parts.split('/')[1:]) if '/' in url_parts else ''
                except:
                    domain = data['url']
                    path = ''
            else:
                url_parts = data['url'].split('/', 1)
                domain = url_parts[0]
                path = '/' + url_parts[1] if len(url_parts) > 1 else ''
            data['url_domain'] = domain
            data['url_path'] = path
        
        # Extract URL category
        data['url_category'] = fields[33] if len(fields) > 33 else ''
        
        # Default values for fields not typically in URL logs
        data['http_method'] = 'GET'
        data['response_code'] = 0
        
        # Validate required fields
        if not data.get('url') or not data.get('source_address') or not data.get('destination_address'):
            return None
            
    except Exception as e:
        logging.error(f"Error parsing URL log: {e}")
        if 'timestamp' not in data:
            data['timestamp'] = datetime.now()
    
    return data

def parse_line(line: str) -> dict:
    """Parse a PaloAlto firewall syslog line and route to appropriate parser"""
    try:
        data = {}
        data['raw_message'] = line.rstrip('\n')
        
        # Parse the log format
        parts = line.split(' ', 4)
        if len(parts) >= 4:
            device_name = parts[3]
            
            if len(parts) >= 5:
                log_data = parts[4]
                fields = log_data.split(',')
                
                # Handle both TRAFFIC and THREAT,url logs
                if len(fields) > 3:
                    log_type = fields[3]
                    if log_type == 'TRAFFIC':
                        return parse_traffic_log(fields, data, device_name)
                    elif log_type == 'THREAT' and len(fields) > 4 and fields[4] == 'url':
                        return parse_url_log(fields, data, device_name)
                    else:
                        return None  # Skip other log types
        
        return None
        
    except Exception as e:
        logging.error(f"Error parsing line: {e}\nLine: {line}")
        return None

# ── Enhanced Log Handler (same pattern as FortiGate) ─────────────────────────
BATCH_SIZE = 500
BATCH_FLUSH_INTERVAL = 1
FILE_CHECK_INTERVAL = 1

class EnhancedLogHandler(FileSystemEventHandler):
    def __init__(self, filepath, buffer, buffer_lock, process_batch_func, log_manager=None):
        self.filepath = filepath
        self.buffer = buffer
        self.buffer_lock = buffer_lock
        self.process_batch_func = process_batch_func
        self.log_manager = log_manager
        
        self.total_lines_processed = 0
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
                    logging.info(f"No saved position found, starting from beginning of file")
                    self._fp.seek(0)
            else:
                logging.info(f"Log manager not available, starting from near end of file")
                # Seek to last 10MB instead of beginning to avoid processing millions of old logs
                try:
                    file_size = os.path.getsize(self.filepath)
                    if file_size > 10 * 1024 * 1024:  # If file > 10MB
                        self._fp.seek(max(0, file_size - 10 * 1024 * 1024))
                        # Skip to next line boundary
                        self._fp.readline()
                        logging.info(f"Started from last 10MB of file (position: {self._fp.tell()})")
                    else:
                        self._fp.seek(0)
                        logging.info(f"File small enough, started from beginning")
                except Exception as e:
                    logging.error(f"Error positioning file: {e}, starting from end")
                    self._fp.seek(0, os.SEEK_END)
                
            current_pos = self._fp.tell()
            logging.info(f"Opened log file: {self.filepath} (position: {current_pos})")
            
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
        while True:
            try:
                line = self._fp.readline()
                if not line:
                    break
                    
                lines_read += 1
                self.total_lines_processed += 1
                
                # Parse the line to determine log type
                parsed_data = parse_line(line)
                if parsed_data:
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
            logging.info(f"Read {lines_read} new lines from {self.filepath}")
            
            if time.time() - self.last_status_update > STATUS_UPDATE_INTERVAL:
                self._update_processing_status()

    def on_moved(self, event):
        if event.src_path == self.filepath or event.dest_path == self.filepath:
            logging.info(f"File move detected: {event.src_path} -> {event.dest_path}")
            self._update_processing_status()
            self._open_file()

# ── Main Enhanced Processing (same pattern as FortiGate) ─────────────────────
def main():
    """Enhanced main function with log manager integration"""
    traffic_insert_query = f"""
        INSERT INTO {CH_DB}.paloalto_traffic ({', '.join(ALL_FIELDS)}) VALUES
    """
    url_insert_query = f"""
        INSERT INTO {CH_DB}.pa_urls_optimized ({', '.join(ALL_URL_FIELDS)}) VALUES
    """
    
    # Initialize log manager if available
    log_manager = None
    if LogManager:
        try:
            log_manager = LogManager()
            logging.info("Log manager initialized successfully")
        except Exception as e:
            logging.warning(f"Could not initialize log manager: {e}")
    
    logging.info("Starting Enhanced PaloAlto → ClickHouse ingestion with batch size %d (processing from file start)", BATCH_SIZE)

    buffer = []
    buffer_lock = threading.Lock()

    def process_batch():
        with buffer_lock:
            if not buffer:
                return
            batch = buffer[:]
            buffer.clear()
            
        traffic_rows = []
        url_rows = []
        
        for record in batch:
            try:
                if record.get('log_type') == 'TRAFFIC':
                    # Validate traffic record
                    srcip = record.get('srcip', '0.0.0.0')
                    dstip = record.get('dstip', '0.0.0.0')
                    
                    def is_valid_ip(ip):
                        try:
                            parts = str(ip).split('.')
                            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
                        except:
                            return False
                    
                    if is_valid_ip(srcip) and is_valid_ip(dstip):
                        row = [record[field] for field in ALL_FIELDS]
                        traffic_rows.append(row)
                    else:
                        logging.warning(f"Invalid IP addresses in traffic log - srcip='{srcip}', dstip='{dstip}' - skipping")
                        
                elif record.get('log_type') == 'THREAT' and record.get('log_subtype') == 'url':
                    # Validate URL record
                    if record.get('url') and record.get('source_address') and record.get('destination_address'):
                        row = [record[field] for field in ALL_URL_FIELDS]
                        url_rows.append(row)
                    else:
                        logging.warning(f"Missing required URL fields - skipping")
                        
            except Exception as e:
                logging.error(f"Error processing record: {e}")
                
        # Insert traffic logs
        if traffic_rows:
            try:
                CLIENT.execute(traffic_insert_query, traffic_rows)
                logging.info(f"✅ Inserted {len(traffic_rows)} TRAFFIC records to ClickHouse")
            except Exception as e:
                logging.error(f"❌ TRAFFIC batch insert error: {e}")
                
        # Insert URL logs  
        if url_rows:
            try:
                CLIENT.execute(url_insert_query, url_rows)
                logging.info(f"✅ Inserted {len(url_rows)} URL records to ClickHouse")
            except Exception as e:
                logging.error(f"❌ URL batch insert error: {e}")

    # Create enhanced file handler
    handler = EnhancedLogHandler(LOG_FILE, buffer, buffer_lock, process_batch, log_manager)
    observer = Observer()
    observer.schedule(handler, path=os.path.dirname(LOG_FILE) or '.', recursive=False)
    observer.start()
    
    logging.info(f"Monitoring log file: {LOG_FILE}")
    logging.info(f"ClickHouse connection: {CH_HOST}:{CH_PORT}, DB: {CH_DB}")

    def flush_and_exit(signum, frame):
        logging.info("Shutting down. Flushing remaining logs...")
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