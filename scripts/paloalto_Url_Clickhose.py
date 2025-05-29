#!/usr/bin/env python3
"""
paloalto_threat_clickhouse.py

Continuously tails /var/log/paloalto-1004.log and inserts THREAT,url entries into
the ClickHouse table `network_logs.threat_logs`.

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
    level=logging.DEBUG,  # Set to DEBUG for more verbose output
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

# ── Field Definitions ─────────────────────────────────────────────────────────
# Define all fields that match the threat_logs table structure
THREAT_FIELDS = [
    'timestamp', 'receive_time', 'serial_number', 'type', 'threat_content_type',
    'generated_time', 'source_address', 'destination_address', 'nat_source_ip',
    'nat_destination_ip', 'rule_name', 'source_user', 'destination_user',
    'application', 'virtual_system', 'source_zone', 'destination_zone',
    'inbound_interface', 'outbound_interface', 'log_action', 'session_id',
    'repeat_count', 'source_port', 'destination_port', 'nat_source_port',
    'nat_destination_port', 'flags', 'ip_protocol', 'action', 'url_filename',
    'threat_id', 'category', 'severity', 'direction', 'sequence_number',
    'action_flags', 'source_country', 'destination_country', 'content_type',
    'pcap_id', 'file_digest', 'cloud', 'url_index', 'user_agent', 'file_type',
    'x_forwarded_for', 'referer', 'sender', 'subject', 'recipient', 'report_id',
    'device_group_hierarchy_level_1', 'device_group_hierarchy_level_2',
    'device_group_hierarchy_level_3', 'device_group_hierarchy_level_4',
    'virtual_system_name', 'device_name', 'source_vm_uuid', 'destination_vm_uuid',
    'http_method', 'tunnel_id_imsi', 'monitor_tag_imei', 'parent_session_id',
    'parent_start_time', 'tunnel_type', 'threat_category', 'content_version',
    'sctp_association_id', 'payload_protocol_id', 'http_headers', 'url_category_list',
    'rule_uuid', 'http2_connection', 'dynamic_user_group_name', 'xff_address',
    'source_device_category', 'source_device_profile', 'source_device_model',
    'source_device_vendor', 'source_device_os_family', 'source_device_os_version',
    'source_hostname', 'source_mac_address', 'destination_device_category',
    'destination_device_profile', 'destination_device_model', 'destination_device_vendor',
    'destination_device_os_family', 'destination_device_os_version', 'destination_hostname',
    'destination_mac_address', 'container_id', 'pod_namespace', 'pod_name',
    'source_external_dynamic_list', 'destination_external_dynamic_list', 'host_id',
    'domain_edl', 'source_dynamic_address_group', 'destination_dynamic_address_group',
    'partial_hash', 'high_resolution_timestamp', 'reason', 'justification',
    'a_slice_service_type', 'application_subcategory', 'application_category',
    'application_technology', 'application_risk', 'application_characteristic',
    'application_container', 'tunneled_application', 'application_saas',
    'application_sanctioned_state', 'raw_message'
]

def parse_threat_line(line: str) -> dict:
    """
    Parse a PaloAlto THREAT,url log line into a dict for the threat_logs table.
    Returns None if the log entry is not a THREAT,url log.
    """
    data = {}
    
    try:
        # Initialize all fields with appropriate defaults
        # Integer fields need specific types
        int_fields = {
            'sequence_number': 0,      # UInt64
            'session_id': 0,           # UInt64
            'parent_session_id': 0,    # UInt64
            'repeat_count': 0,         # UInt32
            'source_port': 0,          # UInt16
            'destination_port': 0,     # UInt16
            'nat_source_port': 0,      # UInt16
            'nat_destination_port': 0, # UInt16
            'ip_protocol': 0,          # UInt8
            'payload_protocol_id': 0,  # General int
            'pcap_id': 0,             # General int
            'app_flap_count': 0,      # General int
            'bytes': 0,               # General int
            'bytes_sent': 0,          # General int
            'bytes_received': 0,      # General int
            'packets': 0,             # General int
            'packets_sent': 0,        # General int
            'packets_received': 0,    # General int
            'elapsed_time': 0,        # General int
            'sctp_chunks': 0,         # General int
            'sctp_chunks_sent': 0,    # General int
            'sctp_chunks_received': 0 # General int
        }
        
        for field in THREAT_FIELDS:
            if field in int_fields:
                data[field] = int_fields[field]
            elif field.endswith('_address') or field.endswith('_ip'):
                data[field] = ''  # String type for IPv4/IPv6 compatibility
            elif field in ['timestamp', 'receive_time', 'generated_time', 'parent_start_time']:
                data[field] = datetime.now()
            elif field == 'high_resolution_timestamp':
                data[field] = datetime.now()
            else:
                data[field] = ''
        
        # Store raw message
        data['raw_message'] = line.rstrip('\n')
        
        # Parse the syslog header
        # Format: May 29 17:40:15 SMO-RUH-MU04-F09R14-INT-FW01.smo.sa 1,2025/05/29 17:40:13,024301003410,THREAT,url,...
        parts = line.split(' ', 4)
        if len(parts) < 5:
            return None
            
        # Extract receive time from syslog header
        month = parts[0]
        day = parts[1]
        time_str = parts[2]
        current_year = datetime.now().year
        receive_time_str = f"{current_year} {month} {day} {time_str}"
        try:
            data['receive_time'] = datetime.strptime(receive_time_str, "%Y %b %d %H:%M:%S")
        except:
            data['receive_time'] = datetime.now()
        
        # Extract device name
        data['device_name'] = parts[3]
        
        # Parse the CSV fields
        csv_data = parts[4]
        fields = csv_data.split(',')
        
        # Check if this is a THREAT,url log (indices 3 and 4)
        if len(fields) < 5 or fields[3] != 'THREAT' or fields[4] != 'url':
            return None
        
        # Map field positions based on the Palo Alto THREAT log format
        field_mapping = {
            2: 'serial_number',          # Serial Number
            3: 'type',                   # Type (THREAT)
            4: 'threat_content_type',    # Threat/Content Type (url)
            6: 'generated_time',         # Generated Time
            7: 'source_address',         # Source Address
            8: 'destination_address',    # Destination Address
            9: 'nat_source_ip',          # NAT Source IP
            10: 'nat_destination_ip',    # NAT Destination IP
            11: 'rule_name',             # Rule Name
            12: 'source_user',           # Source User
            13: 'destination_user',      # Destination User
            14: 'application',           # Application
            15: 'virtual_system',        # Virtual System
            16: 'source_zone',           # Source Zone
            17: 'destination_zone',      # Destination Zone
            18: 'inbound_interface',     # Inbound Interface
            19: 'outbound_interface',    # Outbound Interface
            20: 'log_action',            # Log Action
            22: 'session_id',            # Session ID
            23: 'repeat_count',          # Repeat Count
            24: 'source_port',           # Source Port
            25: 'destination_port',      # Destination Port
            26: 'nat_source_port',       # NAT Source Port
            27: 'nat_destination_port',  # NAT Destination Port
            28: 'flags',                 # Flags
            29: 'ip_protocol',           # IP Protocol
            30: 'action',                # Action
            31: 'url_filename',          # URL/Filename
            32: 'threat_id',             # Threat ID
            33: 'category',              # Category
            34: 'severity',              # Severity
            35: 'direction',             # Direction
            36: 'sequence_number',       # Sequence Number
            37: 'action_flags',          # Action Flags
            38: 'source_country',        # Source Country
            39: 'destination_country',   # Destination Country
            41: 'content_type',          # Content Type
            42: 'pcap_id',               # PCAP_ID
            43: 'file_digest',           # File Digest
            44: 'cloud',                 # Cloud
            45: 'url_index',             # URL Index
            46: 'user_agent',            # User Agent
            47: 'file_type',             # File Type
            48: 'x_forwarded_for',       # X-Forwarded-For
            49: 'referer',               # Referer
            50: 'sender',                # Sender
            51: 'subject',               # Subject
            52: 'recipient',             # Recipient
            53: 'report_id',             # Report ID
            54: 'device_group_hierarchy_level_1',
            55: 'device_group_hierarchy_level_2',
            56: 'device_group_hierarchy_level_3',
            57: 'device_group_hierarchy_level_4',
            58: 'virtual_system_name',
            59: 'device_name',
            61: 'source_vm_uuid',
            62: 'destination_vm_uuid',
            63: 'http_method',
            64: 'tunnel_id_imsi',
            65: 'monitor_tag_imei',
            66: 'parent_session_id',
            67: 'parent_start_time',
            68: 'tunnel_type',
            69: 'threat_category',
            70: 'content_version',
            72: 'sctp_association_id',
            73: 'payload_protocol_id',
            74: 'http_headers',
            75: 'url_category_list',
            76: 'rule_uuid',
            77: 'http2_connection',
            78: 'dynamic_user_group_name',
            79: 'xff_address',
            80: 'source_device_category',
            81: 'source_device_profile',
            82: 'source_device_model',
            83: 'source_device_vendor',
            84: 'source_device_os_family',
            85: 'source_device_os_version',
            86: 'source_hostname',
            87: 'source_mac_address',
            88: 'destination_device_category',
            89: 'destination_device_profile',
            90: 'destination_device_model',
            91: 'destination_device_vendor',
            92: 'destination_device_os_family',
            93: 'destination_device_os_version',
            94: 'destination_hostname',
            95: 'destination_mac_address',
            96: 'container_id',
            97: 'pod_namespace',
            98: 'pod_name',
            99: 'source_external_dynamic_list',
            100: 'destination_external_dynamic_list',
            101: 'host_id',
            103: 'domain_edl',
            104: 'source_dynamic_address_group',
            105: 'destination_dynamic_address_group',
            106: 'partial_hash',
            107: 'high_resolution_timestamp',
            108: 'reason',
            109: 'justification',
            110: 'a_slice_service_type',
            111: 'application_subcategory',
            112: 'application_category',
            113: 'application_technology',
            114: 'application_risk',
            115: 'application_characteristic',
            116: 'application_container',
            117: 'tunneled_application',
            118: 'application_saas',
            119: 'application_sanctioned_state'
        }
        
        # Process each mapped field
        for idx, field_name in field_mapping.items():
            if idx < len(fields):
                value = fields[idx].strip()
                
                # Handle numeric fields
                if field_name in ['source_port', 'destination_port', 'nat_source_port', 
                                 'nat_destination_port', 'repeat_count', 'session_id', 
                                 'sequence_number', 'ip_protocol', 'payload_protocol_id',
                                 'parent_session_id', 'pcap_id', 'app_flap_count',
                                 'bytes', 'bytes_sent', 'bytes_received', 'packets',
                                 'packets_sent', 'packets_received', 'elapsed_time',
                                 'sctp_chunks', 'sctp_chunks_sent', 'sctp_chunks_received']:
                    try:
                        data[field_name] = int(value) if value else 0
                    except:
                        data[field_name] = 0
                        
                # Handle datetime fields
                elif field_name in ['generated_time', 'parent_start_time']:
                    try:
                        if value and '/' in value:
                            data[field_name] = datetime.strptime(value, "%Y/%m/%d %H:%M:%S")
                        else:
                            data[field_name] = datetime.now()
                    except:
                        data[field_name] = datetime.now()
                        
                # Handle high resolution timestamp
                elif field_name == 'high_resolution_timestamp':
                    try:
                        if value and 'T' in value:
                            # Parse ISO format with timezone
                            data[field_name] = datetime.fromisoformat(value.replace('+03:00', ''))
                        else:
                            data[field_name] = datetime.now()
                    except:
                        data[field_name] = datetime.now()
                        
                # Handle protocol mapping
                elif field_name == 'ip_protocol':
                    proto_map = {'tcp': 6, 'udp': 17, 'icmp': 1}
                    if value.lower() in proto_map:
                        data[field_name] = proto_map[value.lower()]
                    elif value.isdigit():
                        data[field_name] = int(value)
                    else:
                        data[field_name] = 0
                        
                # Handle string fields
                else:
                    # Remove quotes and parentheses from certain fields
                    if value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]
                    elif value.startswith('(') and value.endswith(')'):
                        value = value[1:-1]
                    data[field_name] = value
        
        # Use generated_time as timestamp if available
        if 'generated_time' in data and isinstance(data['generated_time'], datetime):
            data['timestamp'] = data['generated_time']
        
        return data
        
    except Exception as e:
        logging.error(f"Error parsing threat line: {e}\nLine: {line}")
        return None

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
            return
            
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
                    if len(self.buffer) >= BATCH_SIZE:
                        self.process_batch_func()
            except Exception as e:
                logging.error(f"Error reading log line: {e}")
                self._open_file()
                break
        
        if lines_read > 0:
            logging.info(f"Read {lines_read} new lines from {self.filepath}")

    def on_moved(self, event):
        if event.src_path == self.filepath or event.dest_path == self.filepath:
            logging.info(f"File move detected: {event.src_path} -> {event.dest_path}")
            self._open_file()

# ── Main Ingestion Loop ──────────────────────────────────────────────────────
def test_table_structure():
    """Check the structure of the threat_logs table and validate our field mapping"""
    try:
        # Test query to get field types
        fields_query = f"""DESCRIBE TABLE {CH_DB}.threat_logs"""
        logging.info("Checking threat_logs table structure...")
        result = CLIENT.execute(fields_query)
        
        field_types = {}
        for row in result:
            field_name, field_type = row[0], row[1]
            field_types[field_name] = field_type
            
        logging.info(f"Found {len(field_types)} fields in threat_logs table")
        
        # Check if our field list matches the table structure
        missing_fields = []
        for field in THREAT_FIELDS:
            if field not in field_types:
                missing_fields.append(field)
        
        if missing_fields:
            logging.error(f"Missing fields in THREAT_FIELDS: {missing_fields}")
        
        # Check for integer fields that might need special handling
        int_fields = []
        for field, type_info in field_types.items():
            if 'Int' in type_info or 'UInt' in type_info:
                int_fields.append(field)
        
        logging.info(f"Integer fields in threat_logs table: {int_fields}")
        return field_types
    
    except Exception as e:
        logging.error(f"Error checking table structure: {e}")
        return {}

def validate_record(record, field_types):
    """Validate that a record has the correct data types for insertion"""
    issues = []
    
    for field, value in record.items():
        if field not in field_types:
            issues.append(f"Field '{field}' not in table schema")
            continue
            
        field_type = field_types[field]
        value_type = type(value).__name__
        
        # Check integer fields
        if 'Int' in field_type and not isinstance(value, int):
            issues.append(f"Field '{field}' should be integer, got {value_type}")
        
        # Check datetime fields
        if field_type.startswith('DateTime') and not isinstance(value, datetime):
            issues.append(f"Field '{field}' should be datetime, got {value_type}")
    
    return issues

def main():
    # Prepare insert query for threat_logs table
    insert_query = f"""
        INSERT INTO {CH_DB}.threat_logs ({', '.join(THREAT_FIELDS)}) VALUES
    """
    
    logging.info("Starting PaloAlto THREAT,url → ClickHouse threat_logs ingestion")
    logging.info(f"Batch size: {BATCH_SIZE}, Flush interval: {BATCH_FLUSH_INTERVAL}s")
    
    # Run diagnostic checks
    field_types = test_table_structure()
    
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
        threat_count = 0
        valid_records = []
        
        for line in batch:
            try:
                rec = parse_threat_line(line)
                if rec is None:
                    continue
                    
                threat_count += 1
                
                # Validate the record before inserting
                if field_types:
                    issues = validate_record(rec, field_types)
                    if issues:
                        logging.warning(f"Record validation issues: {issues}")
                        logging.debug(f"Problematic record: {rec}")
                        continue
                
                # Fix any known problematic fields
                # Ensure all integer fields are proper integers
                for field in rec:
                    if field in field_types and ('Int' in field_types[field] or 'UInt' in field_types[field]):
                        try:
                            rec[field] = int(rec[field]) if rec[field] else 0
                        except:
                            rec[field] = 0
                
                valid_records.append(rec)
                row = [rec[field] for field in THREAT_FIELDS]
                rows.append(row)
                
            except Exception as e:
                logging.error(f"Parse error: {e} | line: {line.strip()}")
        
        if rows:
            try:
                # First log what we're trying to insert for debugging
                if rows and len(rows) > 0:
                    logging.debug(f"Attempting to insert {len(rows)} records")
                    sample = rows[0]
                    sample_dict = dict(zip(THREAT_FIELDS, sample))
                    logging.debug(f"Sample values: {sample_dict}")
                    
                # Execute the insert
                CLIENT.execute(insert_query, rows)
                logging.info(f"Inserted {len(rows)} THREAT,url records to threat_logs table")
                
            except Exception as e:
                logging.error(f"Batch insert error: {e}")
                
                # Log detailed error information
                if rows:
                    sample_row = rows[0]
                    sample_dict = dict(zip(THREAT_FIELDS, sample_row))
                    logging.error(f"Insert error with data types: {e}")
                    
                    # Identify problematic fields
                    for field_name, value in sample_dict.items():
                        if field_name in field_types:
                            expected_type = field_types[field_name]
                            actual_type = type(value).__name__
                            logging.debug(f"Field '{field_name}': expected {expected_type}, got {actual_type} ({value})")
                    
                    # Try with a more detailed query that shows type mismatches
                    try:
                        detailed_query = f"""INSERT INTO {CH_DB}.threat_logs ({', '.join(THREAT_FIELDS)}) VALUES"""
                        CLIENT.execute(detailed_query, rows, types_check=True)
                    except Exception as detailed_e:
                        logging.error(f"Detailed insert error: {detailed_e}")
                        
                    # Try inserting just one record to pinpoint issues
                    if len(rows) > 1:
                        try:
                            logging.debug("Attempting to insert just the first record...")
                            CLIENT.execute(insert_query, [rows[0]])
                            logging.info("Single record insert succeeded!")
                        except Exception as single_e:
                            logging.error(f"Single record insert failed: {single_e}")

    
    # Create file handler and observer
    handler = LogHandler(LOG_FILE, buffer, buffer_lock, process_batch)
    observer = Observer()
    observer.schedule(handler, path=os.path.dirname(LOG_FILE) or '.', recursive=False)
    observer.start()
    
    logging.info(f"Monitoring log file: {LOG_FILE}")
    logging.info(f"ClickHouse connection: {CH_HOST}:{CH_PORT}, DB: {CH_DB}, Table: threat_logs")
    
    def flush_and_exit(signum, frame):
        logging.info("Shutting down. Flushing remaining logs...")
        process_batch()
        observer.stop()
        observer.join()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, flush_and_exit)
    signal.signal(signal.SIGTERM, flush_and_exit)
    
    # Track file state
    last_check_time = time.time()
    last_size = os.path.getsize(LOG_FILE) if os.path.exists(LOG_FILE) else 0
    last_position = handler._fp.tell()
    
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
                    
                    if file_size > current_pos:
                        unread_bytes = file_size - current_pos
                        logging.info(f"Detected {unread_bytes} unread bytes, triggering read")
                        handler.on_modified(type('obj', (object,), {'src_path': LOG_FILE}))
                    
                    last_size = file_size
                    last_position = current_pos
                    
                except Exception as e:
                    logging.error(f"Error checking file: {e}")
            
            # Flush buffer periodically
            with buffer_lock:
                if buffer:
                    logging.debug(f"Flushing buffer with {len(buffer)} entries")
                    
            process_batch()
            time.sleep(BATCH_FLUSH_INTERVAL)
            
    except KeyboardInterrupt:
        flush_and_exit(None, None)

if __name__ == '__main__':
    main()