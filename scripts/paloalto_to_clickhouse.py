#!/usr/bin/env python3
"""
paloalto_to_clickhouse.py

Continuously tails /var/log/paloalto-1004.log and inserts each entry into
the ClickHouse table `network_logs.fortigate_traffic`.

Requirements:
    pip3 install clickhouse-driver watchdog

Configurable via environment variables:
    CH_HOST        ClickHouse host        (default: localhost)
    CH_PORT        ClickHouse port        (default: 9000)
    CH_USER        ClickHouse user        (default: default)
    CH_PASSWORD    ClickHouse password    (default: empty)
    CH_DB          ClickHouse database    (default: network_logs)
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

# ── Configuration ─────────────────────────────────────────────────────────────
CH_HOST     = os.getenv('CH_HOST',     'localhost')
CH_PORT     = int(os.getenv('CH_PORT',     '9000'))
CH_USER     = os.getenv('CH_USER',     'default')
CH_PASSWORD = os.getenv('CH_PASSWORD', 'Read@123')
CH_DB       = os.getenv('CH_DB',       'network_logs')

LOG_FILE    = '/var/log/paloalto-1004.log'

# ── Logging Setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[logging.StreamHandler()]
)

# ── ClickHouse Client ─────────────────────────────────────────────────────────
CLIENT = Client(
    host=CH_HOST,
    port=CH_PORT,
    user=CH_USER,
    password=CH_PASSWORD,
    database=CH_DB
)

# ── Parsing Logic ─────────────────────────────────────────────────────────────
NUMERIC_FIELDS = {
    'srcport', 'dstport', 'proto', 'sentbyte', 'rcvdbyte', 'sentpkt', 'rcvdpkt'
}

IP_FIELDS = {
    'srcip', 'dstip'
}

# Protocol mapping (name -> number)
PROTO_MAP = {
    'tcp': 6,
    'udp': 17,
    'icmp': 1,
    'ipsec': 50,  # ESP
    'gre': 47,
    'esp': 50,
    'ah': 51,
    'sctp': 132,
    'ospf': 89,
    'pim': 103,
    'igmp': 2
}

# Define fields for PaloAlto logs
ALL_FIELDS = [
    'timestamp', 'raw_message', 'devname', 'srcip', 'srcport',
    'srcintf', 'dstip', 'dstport', 'dstintf', 'action',
    'policyname', 'proto', 'appcat', 'dstcountry',
    'sentbyte', 'rcvdbyte', 'sentpkt', 'rcvdpkt', 'username'
]

def parse_line(line: str) -> dict:
    """
    Parse a PaloAlto firewall syslog line into a dict of all expected fields.
    Missing numeric fields default to 0; others to empty string.
    
    Returns None if the log entry is not a TRAFFIC log.
    """
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
        
        # Store raw message
        data['raw_message'] = line.rstrip('\n')
        
        # Example format:
        # May 27 13:33:23 SMO-RUH-MU04-F09R14-INT-FW01.smo.sa 1,2025/05/27 13:33:23,024301003410,TRAFFIC,...
        
        # First split by the first space after the hostname
        parts = line.split(' ', 4)
        if len(parts) >= 4:  # We have at least month, day, time, hostname
            data['devname'] = parts[3]
            
            # If there's a 5th part, it contains the actual log data
            if len(parts) >= 5:
                log_data = parts[4]
                # Split the CSV fields
                fields = log_data.split(',')
                
                # Check if this is a TRAFFIC log entry (field index 3)
                if len(fields) > 3 and fields[3] != 'TRAFFIC':
                    return None  # Skip non-TRAFFIC logs
                
                # Extract timestamp (field 1)
                if len(fields) > 1:
                    timestamp_str = fields[1]
                    try:
                        # Parse timestamp and ensure it's timezone-naive for ClickHouse
                        parsed_dt = datetime.strptime(timestamp_str, "%Y/%m/%d %H:%M:%S")
                        # Ensure it's a naive datetime (no timezone info)
                        if hasattr(parsed_dt, 'tzinfo') and parsed_dt.tzinfo is not None:
                            data['timestamp'] = parsed_dt.replace(tzinfo=None)
                        else:
                            data['timestamp'] = parsed_dt
                    except (ValueError, TypeError, AttributeError):
                        data['timestamp'] = datetime.now()
                
                # Process fields based on traffic log format
                # The field positions are based on the Palo Alto traffic log format
                if len(fields) > 6:
                    # Source IP is at field index 7
                    data['srcip'] = fields[7] if fields[7] else '0.0.0.0'
                
                if len(fields) > 8:
                    # Destination IP is at field index 8
                    data['dstip'] = fields[8] if fields[8] else '0.0.0.0'
                
                # Extract port information
                if len(fields) > 25:
                    # Source port is at field index 24
                    try:
                        data['srcport'] = int(fields[24]) if fields[24] else 0
                    except (ValueError, TypeError):
                        data['srcport'] = 0
                
                if len(fields) > 26:
                    # Destination port is at field index 25
                    try:
                        data['dstport'] = int(fields[25]) if fields[25] else 0
                    except (ValueError, TypeError):
                        data['dstport'] = 0
                
                # Extract interfaces
                if len(fields) > 14:
                    # Source interface is at field index 13
                    data['srcintf'] = fields[18] if fields[18] else ''
                
                if len(fields) > 15:
                    # Destination interface is at field index 14
                    data['dstintf'] = fields[19] if fields[19] else ''
                
                # Extract action
                if len(fields) > 31:
                    # Action is at field index 30
                    data['action'] = fields[30].lower() if fields[30] else ''
                    
                # Extract additional fields based on the indices provided
                # Policy name (field 11)
                if len(fields) > 11:
                    data['policyname'] = fields[11] if fields[11] else ''
                
                # Username (field 12)
                if len(fields) > 12:
                    data['username'] = fields[12] if fields[12] else ''
                    
                # Protocol (field 29)
                if len(fields) > 29:
                    proto_str = fields[29].lower() if fields[29] else ''
                    # Convert protocol name to number
                    if proto_str in PROTO_MAP:
                        data['proto'] = PROTO_MAP[proto_str]
                    elif proto_str.isdigit():
                        data['proto'] = int(proto_str)
                    else:
                        data['proto'] = 0  # Default for unknown protocols
                    
                # Application category (field 37)
                if len(fields) > 37:
                    data['appcat'] = fields[37] if fields[37] else ''
                    
                # Destination country (field 42)
                if len(fields) > 42:
                    data['dstcountry'] = fields[42] if fields[42] else ''
                    
                # Extract byte and packet counts
                # Sent bytes (field 32)
                if len(fields) > 32:
                    try:
                        data['sentbyte'] = int(fields[32]) if fields[32] else 0
                    except (ValueError, TypeError):
                        data['sentbyte'] = 0
                        
                # Received bytes (field 33)
                if len(fields) > 33:
                    try:
                        data['rcvdbyte'] = int(fields[33]) if fields[33] else 0
                    except (ValueError, TypeError):
                        data['rcvdbyte'] = 0
                        
                # Sent packets (field 44)
                if len(fields) > 44:
                    try:
                        data['sentpkt'] = int(fields[44]) if fields[44] else 0
                    except (ValueError, TypeError):
                        data['sentpkt'] = 0
                        
                # Received packets (field 45)
                if len(fields) > 45:
                    try:
                        data['rcvdpkt'] = int(fields[45]) if fields[45] else 0
                    except (ValueError, TypeError):
                        data['rcvdpkt'] = 0
        
        # Ensure timestamp is always populated
        if data.get('timestamp') is None:
            data['timestamp'] = datetime.now()
        
    except Exception as e:
        logging.error(f"Error parsing line: {e}\nLine: {line}")
        # Provide fallback values for critical fields
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

# ── Log Handler for Watchdog ────────────────────────────────────────────────
BATCH_SIZE = 500
BATCH_FLUSH_INTERVAL = 1  # seconds
FILE_CHECK_INTERVAL = 1   # seconds

class LogHandler(FileSystemEventHandler):
    def __init__(self, filepath, buffer, buffer_lock, process_batch_func):
        self.filepath = filepath
        self.buffer = buffer
        self.buffer_lock = buffer_lock
        self.process_batch_func = process_batch_func
        self._open_file()
        
    def _open_file(self):
        """Open or reopen the log file and position at the end"""
        try:
            if hasattr(self, '_fp') and self._fp:
                self._fp.close()
            self._fp = open(self.filepath, 'r')
            self._fp.seek(0, os.SEEK_END)  # Only process new lines
            logging.info(f"Opened log file: {self.filepath} (position: {self._fp.tell()})")
        except Exception as e:
            logging.error(f"Error opening log file: {e}")
            
    def _check_file_rotation(self):
        """Check if the file has been rotated and reopen if needed"""
        try:
            # Check if file exists and has been rotated
            if not os.path.exists(self.filepath) or os.stat(self.filepath).st_ino != os.fstat(self._fp.fileno()).st_ino:
                logging.info("Log rotation detected. Reopening log file.")
                self._open_file()
                return True
        except Exception as e:
            logging.error(f"Error checking file rotation: {e}")
            self._open_file()
            return True
        return False

    def on_modified(self, event):
        if event.src_path != self.filepath:
            logging.debug(f"Ignoring event for different path: {event.src_path}")
            return
            
        logging.debug(f"File modification detected for: {self.filepath}")
        # Check for file rotation before reading
        self._check_file_rotation()
        
        lines_read = 0
        while True:
            try:
                line = self._fp.readline()
                if not line:
                    break
                lines_read += 1
                with self.buffer_lock:
                    self.buffer.append(line)
                    logging.debug(f"Buffer size now: {len(self.buffer)}")
                    if len(self.buffer) >= BATCH_SIZE:
                        logging.debug(f"Buffer reached batch size {BATCH_SIZE}, processing batch")
                        self.process_batch_func()
            except Exception as e:
                logging.error(f"Error reading log line: {e}")
                self._open_file()
                break
        
        if lines_read > 0:
            logging.info(f"Read {lines_read} new lines from {self.filepath}")
        else:
            logging.debug("No new lines read from file")

    def on_moved(self, event):
        if event.src_path == self.filepath or event.dest_path == self.filepath:
            logging.info(f"File move detected: {event.src_path} -> {event.dest_path}")
            self._open_file()


# ── Main Ingestion Loop ──────────────────────────────────────────────────────
def main():
    insert_query = f"""
        INSERT INTO {CH_DB}.fortigate_traffic ({', '.join(ALL_FIELDS)}) VALUES
    """
    logging.info("Starting PaloAlto → ClickHouse ingestion with batch size %d", BATCH_SIZE)

    buffer = []
    buffer_lock = threading.Lock()
    stop_event = threading.Event()

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
                # Skip if rec is None (not a TRAFFIC log)
                if rec is None:
                    continue
                row = [rec[field] for field in ALL_FIELDS]
                rows.append(row)
            except Exception as e:
                logging.error(f"Parse error: {e} | line: {line.strip()}")
        if rows:
            # Pre-validate all rows before insertion
            valid_rows = []
            for i, row in enumerate(rows):
                try:
                    # Validate critical fields
                    srcip_idx = ALL_FIELDS.index('srcip')
                    dstip_idx = ALL_FIELDS.index('dstip')
                    
                    srcip = row[srcip_idx]
                    dstip = row[dstip_idx]
                    
                    # Validate IP addresses
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
                    if valid_rows:
                        sample_row = valid_rows[0]
                        sample_dict = dict(zip(ALL_FIELDS, sample_row))
                        logging.error(f"Sample row that caused error: {sample_dict}")
            else:
                logging.warning(f"No valid rows found in batch of {len(rows)} rows")

    # Create file handler and observer
    handler = LogHandler(LOG_FILE, buffer, buffer_lock, process_batch)
    observer = Observer()
    observer.schedule(handler, path=os.path.dirname(LOG_FILE) or '.', recursive=False)
    observer.start()
    
    # Log initial status
    logging.info(f"Monitoring log file: {LOG_FILE}")
    logging.info(f"ClickHouse connection: {CH_HOST}:{CH_PORT}, DB: {CH_DB}")

    def flush_and_exit(signum, frame):
        logging.info("Shutting down. Flushing remaining logs...")
        process_batch()
        observer.stop()
        observer.join()
        sys.exit(0)

    signal.signal(signal.SIGINT, flush_and_exit)
    signal.signal(signal.SIGTERM, flush_and_exit)

    # Track last processed position and size
    last_check_time = time.time()
    last_size = os.path.getsize(LOG_FILE) if os.path.exists(LOG_FILE) else 0
    last_position = handler._fp.tell()
    
    # Periodically flush buffer and check file rotation
    try:
        while True:
            current_time = time.time()
            should_check_file = (current_time - last_check_time) >= FILE_CHECK_INTERVAL
            
            if should_check_file:
                last_check_time = current_time
                # Force check for file rotation periodically
                handler._check_file_rotation()
                
                # Check if the file has been modified recently
                try:
                    # Always check file size regardless of modification time
                    file_size = os.path.getsize(LOG_FILE)
                    current_pos = handler._fp.tell()
                    
                    # Log detailed information about file state
                    mtime = os.path.getmtime(LOG_FILE)
                    time_diff = current_time - mtime
                    size_diff = file_size - last_size
                    pos_diff = current_pos - last_position
                    
                    logging.debug(f"File check: last_modified={time_diff:.2f}s ago, size={file_size}, position={current_pos}")
                    logging.debug(f"Changes since last check: size_delta={size_diff}, position_delta={pos_diff}")
                    
                    # If there's unread data, force a read
                    if file_size > current_pos:
                        unread_bytes = file_size - current_pos
                        logging.info(f"Detected {unread_bytes} unread bytes in log file, triggering read")
                        # Simulate a file modification event
                        handler.on_modified(type('obj', (object,), {'src_path': LOG_FILE}))
                    elif size_diff > 0 and pos_diff == 0:
                        # File grew but our position didn't change - this indicates we missed some events
                        logging.warning(f"File grew by {size_diff} bytes but position unchanged. Forcing read.")
                        handler.on_modified(type('obj', (object,), {'src_path': LOG_FILE}))
                    
                    # Update tracking variables
                    last_size = file_size
                    last_position = current_pos
                    
                except Exception as e:
                    logging.error(f"Error checking file: {e}")
            
            # Process any buffered logs regardless of buffer size
            with buffer_lock:
                if buffer:
                    buffer_size = len(buffer)
                    if buffer_size > 0:
                        logging.debug(f"Flushing buffer with {buffer_size} entries due to interval timer")
            
            process_batch()
            time.sleep(BATCH_FLUSH_INTERVAL)
    except KeyboardInterrupt:
        flush_and_exit(None, None)

if __name__ == '__main__':
    main()
