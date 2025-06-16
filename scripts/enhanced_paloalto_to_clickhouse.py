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
        logging.FileHandler('/var/log/paloalto-processor.log')
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

def parse_line(line: str) -> dict:
    """Parse a PaloAlto firewall syslog line (same as original implementation)"""
    data = {}
    try:
        # Set default values
        for field in ALL_FIELDS:
            if field in NUMERIC_FIELDS:
                data[field] = 0
            elif field in IP_FIELDS:
                data[field] = '0.0.0.0'
            else:
                data[field] = ''
        
        data['raw_message'] = line.rstrip('\n')
        
        # Parse the log format
        parts = line.split(' ', 4)
        if len(parts) >= 4:
            data['devname'] = parts[3]
            
            if len(parts) >= 5:
                log_data = parts[4]
                fields = log_data.split(',')
                
                # Check if this is a TRAFFIC log entry
                if len(fields) > 3 and fields[3] != 'TRAFFIC':
                    return None
                
                # Extract timestamp
                if len(fields) > 1:
                    timestamp_str = fields[1]
                    try:
                        parsed_dt = datetime.strptime(timestamp_str, "%Y/%m/%d %H:%M:%S")
                        data['timestamp'] = parsed_dt.replace(tzinfo=None) if hasattr(parsed_dt, 'tzinfo') and parsed_dt.tzinfo else parsed_dt
                    except (ValueError, TypeError, AttributeError):
                        data['timestamp'] = datetime.now()
                
                # Process fields based on traffic log format
                if len(fields) > 6:
                    data['srcip'] = fields[7] if fields[7] else '0.0.0.0'
                if len(fields) > 8:
                    data['dstip'] = fields[8] if fields[8] else '0.0.0.0'
                
                # Extract ports
                if len(fields) > 25:
                    try:
                        data['srcport'] = int(fields[24]) if fields[24] else 0
                    except (ValueError, TypeError):
                        data['srcport'] = 0
                if len(fields) > 26:
                    try:
                        data['dstport'] = int(fields[25]) if fields[25] else 0
                    except (ValueError, TypeError):
                        data['dstport'] = 0
                
                # Extract interfaces and other fields
                if len(fields) > 14:
                    data['srcintf'] = fields[18] if fields[18] else ''
                if len(fields) > 15:
                    data['dstintf'] = fields[19] if fields[19] else ''
                if len(fields) > 31:
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
        
        if data.get('timestamp') is None:
            data['timestamp'] = datetime.now()
        
    except Exception as e:
        logging.error(f"Error parsing line: {e}\nLine: {line}")
        if 'timestamp' not in data:
            data['timestamp'] = datetime.now()
        if 'raw_message' not in data:
            data['raw_message'] = line.rstrip('\n')
        for field in ['srcip', 'dstip']:
            if field not in data:
                data[field] = '0.0.0.0'
        for field in NUMERIC_FIELDS:
            if field not in data:
                data[field] = 0
    
    return data

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
                    self._fp.seek(0, os.SEEK_END)
            else:
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
                
                with self.buffer_lock:
                    self.buffer.append(line)
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
    insert_query = f"""
        INSERT INTO {CH_DB}.fortigate_traffic ({', '.join(ALL_FIELDS)}) VALUES
    """
    
    # Initialize log manager if available
    log_manager = None
    if LogManager:
        try:
            log_manager = LogManager()
            logging.info("Log manager initialized successfully")
        except Exception as e:
            logging.warning(f"Could not initialize log manager: {e}")
    
    logging.info("Starting Enhanced PaloAlto → ClickHouse ingestion with batch size %d", BATCH_SIZE)

    buffer = []
    buffer_lock = threading.Lock()

    def process_batch():
        with buffer_lock:
            if not buffer:
                return
            batch = buffer[:]
            buffer.clear()
            
        rows = []
        for line in batch:
            try:
                rec = parse_line(line)
                if rec is None:  # Skip non-TRAFFIC logs
                    continue
                row = [rec[field] for field in ALL_FIELDS]
                rows.append(row)
            except Exception as e:
                logging.error(f"Parse error: {e} | line: {line.strip()}")
                
        if rows:
            valid_rows = []
            for i, row in enumerate(rows):
                try:
                    srcip_idx = ALL_FIELDS.index('srcip')
                    dstip_idx = ALL_FIELDS.index('dstip')
                    
                    srcip = row[srcip_idx]
                    dstip = row[dstip_idx]
                    
                    def is_valid_ip(ip):
                        try:
                            parts = str(ip).split('.')
                            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
                        except:
                            return False
                    
                    if is_valid_ip(srcip) and is_valid_ip(dstip):
                        valid_rows.append(row)
                    else:
                        logging.warning(f"Row {i}: Invalid IP addresses - srcip='{srcip}', dstip='{dstip}' - skipping")
                        
                except Exception as e:
                    logging.warning(f"Row {i}: Validation error {e} - skipping row")
            
            if valid_rows:
                try:
                    CLIENT.execute(insert_query, valid_rows)
                    logging.info(f"Inserted {len(valid_rows)} valid rows to ClickHouse (skipped {len(rows) - len(valid_rows)} invalid rows).")
                except Exception as e:
                    logging.error(f"Batch insert error: {e}")

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