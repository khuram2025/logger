#!/usr/bin/env python3
"""
paloalto_to_clickhouse.py

Continuously tails /var/log/paloalto-1004.log and inserts each entry into
the ClickHouse table `network_logs.pa_traffic`.

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
    'src_port', 'dst_port', 'nat_src_port', 'nat_dst_port', 'protocol', 'app_risk',
    'bytes_sent', 'bytes_received', 'packets_sent', 'packets_received',
    'session_id', 'repeat_count', 'elapsed_time', 'sequence_number', 'tunnel_id',
    'parent_session_id'
}

IP_FIELDS = {
    'src_ip', 'dst_ip', 'nat_src_ip', 'nat_dst_ip'
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

# Define fields for PaloAlto traffic logs based on standard field positions
ALL_FIELDS = [
    'timestamp', 'raw_message', 'device_name', 'serial', 'log_type', 'log_subtype',
    'generated_time', 'received_time', 'session_id', 'repeat_count',
    'src_ip', 'src_port', 'src_zone', 'src_interface', 'src_user', 'src_mac',
    'dst_ip', 'dst_port', 'dst_zone', 'dst_interface', 'dst_user', 'dst_mac',
    'nat_src_ip', 'nat_src_port', 'nat_dst_ip', 'nat_dst_port',
    'rule_name', 'rule_uuid', 'application', 'app_category', 'app_subcategory',
    'app_technology', 'app_risk', 'protocol', 'ip_protocol', 'action',
    'bytes_sent', 'bytes_received', 'packets_sent', 'packets_received',
    'session_start_time', 'elapsed_time', 'src_country', 'dst_country',
    'src_location', 'dst_location', 'url_category', 'url_filename',
    'threat_id', 'threat_category', 'severity', 'direction',
    'device_group_hierarchy1', 'device_group_hierarchy2', 'device_group_hierarchy3', 'device_group_hierarchy4',
    'vsys', 'vsys_name', 'sequence_number', 'action_flags', 'tunnel_type', 'tunnel_id',
    'parent_session_id', 'parent_start_time'
]

# PaloAlto traffic log field positions (0-based index after splitting by comma)
FIELD_MAP = {
    # Field index: field_name
    1: 'generated_time',      # Time log was generated
    2: 'serial',              # Serial number
    3: 'log_type',            # Type (TRAFFIC)
    4: 'log_subtype',         # Subtype (start, end, drop, deny)
    6: 'received_time',       # Time log was received
    7: 'src_ip',              # Source IP
    8: 'dst_ip',              # Destination IP
    9: 'nat_src_ip',          # NAT source IP
    10: 'nat_dst_ip',         # NAT destination IP
    11: 'rule_name',          # Security rule name
    12: 'src_user',           # Source user
    13: 'dst_user',           # Destination user
    14: 'application',        # Application
    15: 'vsys',               # Virtual system
    16: 'src_zone',           # Source zone
    17: 'dst_zone',           # Destination zone
    18: 'src_interface',      # Ingress interface
    19: 'dst_interface',      # Egress interface
    20: 'log_forwarding_profile',  # Log forwarding profile
    22: 'session_id',         # Session ID
    23: 'repeat_count',       # Repeat count
    24: 'src_port',           # Source port
    25: 'dst_port',           # Destination port
    26: 'nat_src_port',       # NAT source port
    27: 'nat_dst_port',       # NAT destination port
    28: 'action_flags',       # Action flags
    29: 'ip_protocol',        # IP protocol (tcp, udp, icmp)
    30: 'action',             # Action (allow, deny, drop)
    31: 'bytes_sent',         # Bytes sent (src to dst)
    32: 'bytes_received',     # Bytes received (dst to src)
    33: 'packets_sent',       # Packets sent
    34: 'packets_received',   # Packets received
    35: 'session_start_time', # Session start time
    36: 'elapsed_time',       # Elapsed time (seconds)
    37: 'app_category',       # Application category
    38: 'app_subcategory',    # Application subcategory
    39: 'app_technology',     # Application technology
    40: 'app_risk',           # Application risk (1-5)
    41: 'url_category',       # URL category
    42: 'src_country',        # Source country
    43: 'dst_country',        # Destination country
    44: 'packets_sent',       # Packets sent (duplicate field in some versions)
    45: 'packets_received',   # Packets received (duplicate field in some versions)
    47: 'device_group_hierarchy1',  # Device group hierarchy level 1
    48: 'device_group_hierarchy2',  # Device group hierarchy level 2
    49: 'device_group_hierarchy3',  # Device group hierarchy level 3
    50: 'device_group_hierarchy4',  # Device group hierarchy level 4
    51: 'vsys_name',          # Virtual system name
    52: 'device_name',        # Device name
    55: 'src_mac',            # Source MAC address
    56: 'dst_mac',            # Destination MAC address
    58: 'tunnel_type',        # Tunnel type
    59: 'tunnel_id',          # Tunnel ID/PCAP ID
    61: 'parent_session_id',  # Parent session ID
    62: 'parent_start_time',  # Parent session start time
    63: 'tunnel_type',        # Tunnel type (for some versions)
    70: 'sequence_number',    # Sequence number
    77: 'src_location',       # Source location
    78: 'dst_location',       # Destination location
    80: 'rule_uuid'           # Rule UUID
}

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
            elif field in ['timestamp', 'generated_time', 'received_time', 'session_start_time', 'parent_start_time']:
                data[field] = datetime.now()
            else:
                data[field] = ''
        
        # Store raw message
        data['raw_message'] = line.rstrip('\n')
        
        # Example format:
        # May 27 13:33:23 hostname 1,2025/05/27 13:33:23,024301003410,TRAFFIC,...
        
        # First split by the first space after the hostname
        parts = line.split(' ', 4)
        if len(parts) >= 4:  # We have at least month, day, time, hostname
            # Use the syslog timestamp as our timestamp
            month, day, time_str = parts[0], parts[1], parts[2]
            year = datetime.now().year
            syslog_timestamp = f"{year} {month} {day} {time_str}"
            try:
                data['timestamp'] = datetime.strptime(syslog_timestamp, "%Y %b %d %H:%M:%S")
            except:
                data['timestamp'] = datetime.now()
            
            # If there's a 5th part, it contains the actual log data
            if len(parts) >= 5:
                log_data = parts[4]
                # Split the CSV fields
                fields = log_data.split(',')
                
                # Check if this is a TRAFFIC log entry (field index 3)
                if len(fields) > 3 and fields[3] != 'TRAFFIC':
                    return None  # Skip non-TRAFFIC logs
                
                # Parse fields based on FIELD_MAP
                for field_idx, field_name in FIELD_MAP.items():
                    if field_idx < len(fields) and fields[field_idx]:
                        value = fields[field_idx].strip()
                        
                        # Handle different field types
                        if field_name in NUMERIC_FIELDS:
                            try:
                                data[field_name] = int(value) if value else 0
                            except (ValueError, TypeError):
                                data[field_name] = 0
                        
                        elif field_name in IP_FIELDS:
                            # Validate and set IP address
                            if value and value != '0.0.0.0':
                                try:
                                    # Simple IP validation
                                    parts = value.split('.')
                                    if len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts):
                                        data[field_name] = value
                                    else:
                                        data[field_name] = '0.0.0.0'
                                except:
                                    data[field_name] = '0.0.0.0'
                            else:
                                data[field_name] = '0.0.0.0'
                        
                        elif field_name in ['generated_time', 'received_time', 'session_start_time', 'parent_start_time']:
                            # Parse datetime fields
                            try:
                                if '/' in value and ':' in value:
                                    data[field_name] = datetime.strptime(value, "%Y/%m/%d %H:%M:%S")
                                else:
                                    data[field_name] = data['timestamp']
                            except:
                                data[field_name] = data['timestamp']
                        
                        elif field_name == 'protocol':
                            # Convert protocol name to number
                            proto_str = value.lower()
                            if proto_str in PROTO_MAP:
                                data[field_name] = PROTO_MAP[proto_str]
                            elif proto_str.isdigit():
                                data[field_name] = int(proto_str)
                            else:
                                data[field_name] = 0
                        
                        else:
                            # String fields
                            data[field_name] = value
                
                # Extract device name from hostname (field 52 if available)
                if 52 < len(fields) and fields[52]:
                    data['device_name'] = fields[52]
                elif len(parts) >= 4:
                    data['device_name'] = parts[3]
        
    except Exception as e:
        logging.error(f"Error parsing line: {e}\nLine: {line}")
        # Ensure critical fields have valid values
        if 'timestamp' not in data or data['timestamp'] is None:
            data['timestamp'] = datetime.now()
        if 'raw_message' not in data:
            data['raw_message'] = line.rstrip('\n')
        for field in IP_FIELDS:
            if field not in data or not data[field]:
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
        INSERT INTO {CH_DB}.pa_traffic ({', '.join(ALL_FIELDS)}) VALUES
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
                    srcip_idx = ALL_FIELDS.index('src_ip')
                    dstip_idx = ALL_FIELDS.index('dst_ip')
                    
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
