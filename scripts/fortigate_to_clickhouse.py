#!/usr/bin/env python3
"""
fortigate_to_clickhouse.py

Continuously tails /var/log/fortigate.log and inserts each entry into
the ClickHouse table `network_logs.fortigate_traffic`.

Requirements:
    pip3 install clickhouse-driver

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

LOG_FILE    = '/var/log/fortigate.log'

# ── Logging Setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.DEBUG,  # Changed to DEBUG for more verbose logging
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
KV_PATTERN = re.compile(r'(\w+)=(".*?"|\S+)')

NUMERIC_FIELDS = {
    'eventtime', 'srcport', 'dstport', 'sessionid', 'proto', 'policyid',
    'duration', 'sentbyte', 'rcvdbyte', 'sentpkt', 'rcvdpkt',
    'sentdelta', 'rcvddelta', 'durationdelta', 'sentpktdelta', 'rcvdpktdelta'
}

IP_FIELDS = {
    'srcip', 'dstip', 'gateway', 'nexthop', 'dstserver', 'srcserver',
    'assignip', 'nat_ip', 'transip', 'unnip', 'locip', 'remip'
}

ALL_FIELDS = [
    'timestamp', 'raw_message', 'devname', 'devid', 'eventtime', 'tz',
    'logid', 'type', 'subtype', 'level', 'vd', 'srcip', 'srcport',
    'srcintf', 'srcintfrole', 'dstip', 'dstport', 'dstintf', 'dstintfrole',
    'srccountry', 'dstcountry', 'sessionid', 'proto', 'action', 'policyid',
    'policytype', 'poluuid', 'policyname', 'service', 'trandisp', 'appcat',
    'duration', 'sentbyte', 'rcvdbyte', 'sentpkt', 'rcvdpkt', 'sentdelta',
    'rcvddelta', 'durationdelta', 'sentpktdelta', 'rcvdpktdelta', 'vpntype'
]

def parse_line(line: str) -> dict:
    """
    Parse a FortiGate syslog line into a dict of all expected fields.
    Missing numeric fields default to 0; others to empty string.
    """
    data = {}
    try:
        for key, val in KV_PATTERN.findall(line):
            data[key] = val.strip('"')
    
        # Build timestamp & raw_message
        date = data.get('date', '')
        t    = data.get('time', '')
        timestamp_str = f"{date} {t}"
        try:
            data['timestamp'] = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S") if date and t else None
        except Exception:
            data['timestamp'] = None
        data['raw_message'] = line.rstrip('\n')
    
        # Ensure all numeric fields are integers
        for field in NUMERIC_FIELDS:
            val = data.get(field, 0)
            try:
                data[field] = int(val)
            except Exception:
                data[field] = 0
                
        # Critical IP fields must have valid values
        # Handle srcip and dstip fields which are IPv4 in ClickHouse schema
        for field in ['srcip', 'dstip']:
            if field not in data or not data[field] or data[field].strip() == '':
                data[field] = '0.0.0.0'
            # Ensure IP format is valid
            parts = data[field].split('.')
            if len(parts) != 4:
                data[field] = '0.0.0.0'
    
        # Handle all other IP-like fields that might exist in the data
        for field in IP_FIELDS:
            if field in data and (not data[field] or data[field].strip() == ''):
                data[field] = '0.0.0.0'
    
        # Assign defaults
        for field in ALL_FIELDS:
            if field not in data:
                data[field] = 0 if field in NUMERIC_FIELDS else ''
                if field in ['srcip', 'dstip']:
                    data[field] = '0.0.0.0'
    
        # Remove intermediate date/time keys
        data.pop('date', None)
        data.pop('time', None)
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
BATCH_FLUSH_INTERVAL = 1  # seconds - reduced for more frequent checks
FILE_CHECK_INTERVAL = 1   # seconds - explicit interval for file size checks

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
    logging.info("Starting FortiGate → ClickHouse ingestion with batch size %d", BATCH_SIZE)

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
                row = [rec[field] for field in ALL_FIELDS]
                rows.append(row)
            except Exception as e:
                logging.error(f"Parse error: {e} | line: {line.strip()}")
        if rows:
            try:
                CLIENT.execute(insert_query, rows)
                logging.info(f"Inserted {len(rows)} rows to ClickHouse.")
            except Exception as e:
                logging.error(f"Batch insert error: {e}")
                # Log a sample of the problematic data to help diagnose
                if rows:
                    sample_row = rows[0]
                    sample_dict = dict(zip(ALL_FIELDS, sample_row))
                    logging.error(f"Sample row that caused error: {sample_dict}")
                    
                    # Additional debugging - check the specific values of srcip and dstip
                    srcip_idx = ALL_FIELDS.index('srcip')
                    dstip_idx = ALL_FIELDS.index('dstip')
                    logging.error(f"srcip value: '{rows[0][srcip_idx]}', type: {type(rows[0][srcip_idx])}")
                    logging.error(f"dstip value: '{rows[0][dstip_idx]}', type: {type(rows[0][dstip_idx])}")
                    
                    # Try to insert valid records where possible by filtering out problematic rows
                    valid_rows = []
                    for r in rows:
                        try:
                            # Check if srcip and dstip are valid
                            srcip = r[ALL_FIELDS.index('srcip')]
                            dstip = r[ALL_FIELDS.index('dstip')]
                            if srcip and isinstance(srcip, str) and '.' in srcip and dstip and isinstance(dstip, str) and '.' in dstip:
                                valid_rows.append(r)
                        except Exception:
                            continue
                    
                    if valid_rows:
                        try:
                            CLIENT.execute(insert_query, valid_rows)
                            logging.info(f"Inserted {len(valid_rows)} filtered valid rows to ClickHouse.")
                        except Exception as e2:
                            logging.error(f"Failed to insert filtered rows: {e2}")
                    else:
                        logging.warning("No valid rows found after filtering")


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
