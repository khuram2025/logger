#!/usr/bin/env python3
"""
paloalto_url_clickhouse.py

Ultra-advanced PaloAlto Networks URL Filtering Log Parser
Continuously tails /var/log/paloalto-1004.log and extracts URL filtering entries,
parsing them with intelligent field mapping and inserting into ClickHouse table `network_logs.pa_urls`.

Features:
- Intelligent log type detection (URL filtering vs other types)
- Advanced field mapping with fallback strategies
- URL decomposition and analysis
- Performance optimization with batching and caching
- Comprehensive error handling and recovery
- Real-time monitoring and statistics
- Memory-efficient processing

Requirements:
    pip3 install clickhouse-driver watchdog urllib3

Configurable via environment variables:
    CH_HOST        ClickHouse host        (default: localhost)
    CH_PORT        ClickHouse port        (default: 9000)
    CH_USER        ClickHouse user        (default: default)
    CH_PASSWORD    ClickHouse password    (default: Read@123)
    CH_DB          ClickHouse database    (default: network_logs)
    LOG_LEVEL      Logging level          (default: INFO)
"""

import os
import time
import re
import logging
import signal
import sys
import threading
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict, deque
import json

# External dependencies
from clickhouse_driver import Client
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ═══════════════════════════════════════════════════════════════════════════════
# ⚙️  CONFIGURATION & CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

# Environment configuration
CH_HOST = os.getenv('CH_HOST', 'localhost')
CH_PORT = int(os.getenv('CH_PORT', '9000'))
CH_USER = os.getenv('CH_USER', 'default')
CH_PASSWORD = os.getenv('CH_PASSWORD', 'Read@123')
CH_DB = os.getenv('CH_DB', 'network_logs')
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()

# Processing configuration
LOG_FILE = '/var/log/paloalto-1004.log'
BATCH_SIZE = 1000  # Optimized batch size for URL logs
BATCH_FLUSH_INTERVAL = 2  # seconds
FILE_CHECK_INTERVAL = 1   # seconds
MAX_URL_LENGTH = 2048     # Maximum URL length to process
MAX_BUFFER_SIZE = 10000   # Maximum buffer size before forced flush

# Performance statistics
STATS = {
    'total_lines_processed': 0,
    'url_logs_parsed': 0,
    'non_url_logs_skipped': 0,
    'parse_errors': 0,
    'insert_success': 0,
    'insert_errors': 0,
    'start_time': None,
    'last_stats_time': None
}

# ═══════════════════════════════════════════════════════════════════════════════
# 🔧 LOGGING SETUP
# ═══════════════════════════════════════════════════════════════════════════════

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format='%(asctime)s [%(levelname)s] %(funcName)s:%(lineno)d - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/var/log/paloalto_url_parser.log', mode='a')
    ]
)

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
# 🔌 CLICKHOUSE CLIENT SETUP
# ═══════════════════════════════════════════════════════════════════════════════

CLIENT = Client(
    host=CH_HOST,
    port=CH_PORT,
    user=CH_USER,
    password=CH_PASSWORD,
    database=CH_DB,
    send_receive_timeout=30,
    connect_timeout=10
)

# ═══════════════════════════════════════════════════════════════════════════════
# 📊 FIELD DEFINITIONS & MAPPINGS
# ═══════════════════════════════════════════════════════════════════════════════

# Complete field list for pa_urls table (in insertion order)
PA_URL_FIELDS = [
    # Timestamp and Metadata
    'timestamp', 'receive_time', 'generated_time', 'start_time', 'high_resolution_timestamp',
    
    # Device and System Identification
    'serial_number', 'device_name', 'host_id', 'virtual_system', 'virtual_system_name',
    
    # Log Metadata
    'log_type', 'log_subtype', 'config_version', 'sequence_number',
    
    # Session Information
    'session_id', 'repeat_count', 'session_end_reason', 'start_time_utc', 'elapsed_time',
    
    # Network Connection Information
    'source_address', 'destination_address', 'nat_source_ip', 'nat_destination_ip',
    'source_port', 'destination_port', 'nat_source_port', 'nat_destination_port',
    'ip_protocol', 'protocol',
    
    # Zone and Interface Information
    'source_zone', 'destination_zone', 'inbound_interface', 'outbound_interface',
    
    # User and Authentication
    'source_user', 'destination_user', 'source_user_domain', 'destination_user_domain',
    
    # URL and Web-Specific Fields
    'url', 'url_domain', 'url_path', 'url_query', 'url_fragment',
    'url_category_list', 'url_category', 'url_index',
    
    # HTTP/HTTPS Specific Fields
    'http_method', 'http_version', 'user_agent', 'referer', 'content_type',
    'content_length', 'response_code', 'response_size', 'request_size',
    
    # SSL/TLS Information
    'ssl_version', 'ssl_cipher', 'ssl_certificate_subject', 'ssl_certificate_issuer',
    'ssl_certificate_serial', 'ssl_certificate_fingerprint',
    
    # Security and Policy
    'rule_name', 'rule_uuid', 'policy_id', 'policy_name', 'url_filtering_profile',
    'action', 'action_source', 'log_action',
    
    # Application Information
    'application', 'application_category', 'application_subcategory',
    'application_technology', 'application_risk', 'application_characteristic',
    'tunneled_application',
    
    # Geographic Information
    'source_country', 'destination_country', 'source_location', 'destination_location',
    
    # Device Identification (Source)
    'source_device_category', 'source_device_profile', 'source_device_model',
    'source_device_vendor', 'source_device_os_family', 'source_device_os_version',
    'source_hostname', 'source_mac_address',
    
    # Device Identification (Destination)
    'destination_device_category', 'destination_device_profile', 'destination_device_model',
    'destination_device_vendor', 'destination_device_os_family', 'destination_device_os_version',
    'destination_hostname', 'destination_mac_address',
    
    # Traffic Metrics
    'bytes_sent', 'bytes_received', 'packets_sent', 'packets_received',
    'total_bytes', 'total_packets',
    
    # Security Threat Information
    'threat_id', 'threat_category', 'severity', 'direction', 'file_digest',
    'file_type', 'wildfire_verdict',
    
    # Advanced Features
    'xff_address', 'dynamic_user_group_name', 'source_external_dynamic_list',
    'destination_external_dynamic_list', 'source_dynamic_address_group',
    'destination_dynamic_address_group',
    
    # Hierarchy and Organization
    'device_group_hierarchy_level_1', 'device_group_hierarchy_level_2',
    'device_group_hierarchy_level_3', 'device_group_hierarchy_level_4',
    
    # Container and Cloud Information
    'container_id', 'pod_namespace', 'pod_name', 'cloud_instance_id',
    'cloud_provider', 'cloud_region',
    
    # QoS and Performance
    'qos_class', 'qos_rule', 'response_time_ms', 'dns_resolution_time_ms',
    'tcp_handshake_time_ms', 'ssl_handshake_time_ms',
    
    # URL Override and Audit
    'override_user', 'override_reason', 'override_timestamp', 'audit_comment',
    
    # Machine Learning and Analytics
    'risk_score', 'anomaly_score', 'reputation_score',
    
    # Compliance and Legal
    'data_classification', 'compliance_tag', 'legal_hold_flag',
    
    # Custom and Future Fields
    'custom_field_1', 'custom_field_2', 'custom_field_3', 'tags',
    
    # System Fields
    'raw_message', 'processing_timestamp', 'log_date', 'log_hour'
]

# PaloAlto URL filtering log field positions (based on CSV structure)
# This mapping is based on PAN-OS 11.0 URL filtering log format
URL_FIELD_MAPPING = {
    # Core log structure
    2: 'serial_number',          # Serial Number
    3: 'log_type',               # Type (URL)
    4: 'log_subtype',            # Subtype (filtering)
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
    31: 'url',                   # URL/Filename
    32: 'threat_id',             # Threat ID
    33: 'url_category',          # URL Category
    34: 'severity',              # Severity
    35: 'direction',             # Direction
    36: 'sequence_number',       # Sequence Number
    37: 'action_flags',          # Action Flags
    38: 'source_country',        # Source Country
    39: 'destination_country',   # Destination Country
    40: 'content_type',          # Content Type
    41: 'pcap_id',               # PCAP ID
    42: 'file_digest',           # File Digest
    43: 'cloud',                 # Cloud
    44: 'url_index',             # URL Index
    45: 'user_agent',            # User Agent
    46: 'file_type',             # File Type
    47: 'xff_address',           # X-Forwarded-For
    48: 'referer',               # Referer
    49: 'sender',                # Sender
    50: 'subject',               # Subject
    51: 'recipient',             # Recipient
    52: 'report_id',             # Report ID
    53: 'device_group_hierarchy_level_1',
    54: 'device_group_hierarchy_level_2',
    55: 'device_group_hierarchy_level_3',
    56: 'device_group_hierarchy_level_4',
    57: 'virtual_system_name',
    58: 'device_name',
    59: 'action_source',
    60: 'source_vm_uuid',
    61: 'destination_vm_uuid',
    62: 'http_method',
    63: 'tunnel_id_imsi',
    64: 'monitor_tag_imei',
    65: 'parent_session_id',
    66: 'parent_start_time',
    67: 'tunnel_type',
    68: 'threat_category',
    69: 'content_version',
    70: 'sig_flags',
    71: 'sctp_association_id',
    72: 'payload_protocol_id',
    73: 'http_headers',
    74: 'url_category_list',
    75: 'rule_uuid',
    76: 'http2_connection',
    77: 'dynamic_user_group_name',
    78: 'xff_address',
    # Extended device profiling fields
    79: 'source_device_category',
    80: 'source_device_profile',
    81: 'source_device_model',
    82: 'source_device_vendor',
    83: 'source_device_os_family',
    84: 'source_device_os_version',
    85: 'source_hostname',
    86: 'source_mac_address',
    87: 'destination_device_category',
    88: 'destination_device_profile',
    89: 'destination_device_model',
    90: 'destination_device_vendor',
    91: 'destination_device_os_family',
    92: 'destination_device_os_version',
    93: 'destination_hostname',
    94: 'destination_mac_address',
    95: 'container_id',
    96: 'pod_namespace',
    97: 'pod_name',
    98: 'source_external_dynamic_list',
    99: 'destination_external_dynamic_list',
    100: 'host_id',
    101: 'domain_edl',
    102: 'source_dynamic_address_group',
    103: 'destination_dynamic_address_group',
    104: 'partial_hash',
    105: 'high_resolution_timestamp',
    106: 'reason',
    107: 'justification'
}

# Field type definitions for proper parsing
NUMERIC_FIELDS = {
    'sequence_number', 'session_id', 'repeat_count', 'source_port', 'destination_port',
    'nat_source_port', 'nat_destination_port', 'ip_protocol', 'url_index', 'content_length',
    'response_code', 'response_size', 'request_size', 'policy_id', 'application_risk',
    'bytes_sent', 'bytes_received', 'packets_sent', 'packets_received', 'total_bytes',
    'total_packets', 'elapsed_time', 'response_time_ms', 'dns_resolution_time_ms',
    'tcp_handshake_time_ms', 'ssl_handshake_time_ms', 'legal_hold_flag'
}

FLOAT_FIELDS = {
    'risk_score', 'anomaly_score', 'reputation_score'
}

DATETIME_FIELDS = {
    'timestamp', 'receive_time', 'generated_time', 'start_time', 'start_time_utc',
    'override_timestamp', 'processing_timestamp', 'high_resolution_timestamp'
}

DATE_FIELDS = {
    'log_date'
}

# ═══════════════════════════════════════════════════════════════════════════════
# 🧠 ADVANCED URL PARSING AND ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

class URLAnalyzer:
    """Advanced URL parsing and analysis class"""
    
    def __init__(self):
        self.url_cache = {}  # Cache for frequently accessed URLs
        self.category_mapping = self._load_category_mapping()
        
    def _load_category_mapping(self) -> Dict[str, str]:
        """Load URL category mapping for better categorization"""
        # This could be loaded from a configuration file or database
        return {
            'social-networking': 'social-media',
            'search-engines': 'web-search',
            'business-and-economy': 'business',
            'computer-and-internet-info': 'technology',
            'education': 'educational',
            'entertainment': 'entertainment',
            'health-and-medicine': 'health',
            'news': 'news-media',
            'sports': 'sports',
            'travel': 'travel'
        }
    
    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Comprehensive URL analysis and decomposition
        
        Args:
            url: The complete URL to analyze
            
        Returns:
            Dictionary containing parsed URL components and metadata
        """
        if not url or len(url) > MAX_URL_LENGTH:
            return self._get_empty_url_data()
            
        # Check cache first
        if url in self.url_cache:
            return self.url_cache[url]
            
        try:
            parsed = urlparse(url)
            
            # Extract components
            url_data = {
                'url': url,
                'url_domain': parsed.netloc.lower(),
                'url_path': parsed.path,
                'url_query': parsed.query,
                'url_fragment': parsed.fragment,
                'protocol': parsed.scheme.lower(),
                'port': parsed.port or self._get_default_port(parsed.scheme)
            }
            
            # Analyze domain
            url_data.update(self._analyze_domain(parsed.netloc))
            
            # Analyze path and query
            url_data.update(self._analyze_path_query(parsed.path, parsed.query))
            
            # Cache the result (limit cache size)
            if len(self.url_cache) > 1000:
                self.url_cache.clear()
            self.url_cache[url] = url_data
            
            return url_data
            
        except Exception as e:
            logger.warning(f"URL parsing error for '{url}': {e}")
            return self._get_empty_url_data()
    
    def _get_empty_url_data(self) -> Dict[str, Any]:
        """Return empty URL data structure"""
        return {
            'url': '', 'url_domain': '', 'url_path': '', 'url_query': '',
            'url_fragment': '', 'protocol': '', 'port': 0
        }
    
    def _get_default_port(self, scheme: str) -> int:
        """Get default port for protocol"""
        ports = {'http': 80, 'https': 443, 'ftp': 21, 'ftps': 990}
        return ports.get(scheme.lower(), 0)
    
    def _analyze_domain(self, domain: str) -> Dict[str, str]:
        """Analyze domain for additional insights"""
        # Simple domain analysis - could be enhanced with threat intelligence
        is_ip = self._is_ip_address(domain)
        is_suspicious = self._check_suspicious_domain(domain)
        
        return {
            'domain_type': 'ip' if is_ip else 'domain',
            'domain_suspicious': 'yes' if is_suspicious else 'no'
        }
    
    def _analyze_path_query(self, path: str, query: str) -> Dict[str, Any]:
        """Analyze URL path and query parameters"""
        path_depth = len([p for p in path.split('/') if p]) if path else 0
        query_params = len(parse_qs(query)) if query else 0
        
        return {
            'path_depth': path_depth,
            'query_param_count': query_params
        }
    
    def _is_ip_address(self, domain: str) -> bool:
        """Check if domain is an IP address"""
        try:
            import ipaddress
            ipaddress.ip_address(domain)
            return True
        except ValueError:
            return False
    
    def _check_suspicious_domain(self, domain: str) -> bool:
        """Basic suspicious domain detection"""
        suspicious_patterns = [
            r'\d+\.\d+\.\d+\.\d+',  # IP addresses
            r'[0-9a-f]{8,}',        # Long hex strings
            r'.+\.(tk|ml|ga|cf)$',  # Suspicious TLDs
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, domain, re.IGNORECASE):
                return True
        return False

# ═══════════════════════════════════════════════════════════════════════════════
# 🔍 ADVANCED LOG PARSING ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class PaloAltoURLParser:
    """Ultra-advanced PaloAlto URL filtering log parser"""
    
    def __init__(self):
        self.url_analyzer = URLAnalyzer()
        self.parse_stats = defaultdict(int)
        self.field_cache = {}
        self.protocol_map = {
            'tcp': 6, 'udp': 17, 'icmp': 1, 'ipsec': 50, 'esp': 50,
            'ah': 51, 'gre': 47, 'sctp': 132, 'ospf': 89, 'pim': 103,
            'igmp': 2, 'ipv6': 41, 'ipv6-icmp': 58
        }
        
    def parse_log_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Parse a single PaloAlto log line into structured data
        
        Args:
            line: Raw log line from PaloAlto firewall
            
        Returns:
            Parsed log data dictionary or None if not a URL log
        """
        STATS['total_lines_processed'] += 1
        
        try:
            # Initialize data structure with defaults
            data = self._initialize_data_structure()
            
            # Store raw message
            data['raw_message'] = line.rstrip('\n')
            
            # Parse syslog header
            syslog_parts = self._parse_syslog_header(line)
            if not syslog_parts:
                STATS['parse_errors'] += 1
                return None
                
            # Extract CSV data portion
            csv_data = syslog_parts.get('csv_data', '')
            fields = self._split_csv_safely(csv_data)
            
            # Validate this is a URL filtering log
            if not self._is_url_filtering_log(fields):
                STATS['non_url_logs_skipped'] += 1
                return None
                
            # Parse timestamps
            data.update(self._parse_timestamps(syslog_parts, fields))
            
            # Parse device information
            data.update(self._parse_device_info(syslog_parts, fields))
            
            # Parse network information
            data.update(self._parse_network_info(fields))
            
            # Parse URL and web-specific data
            data.update(self._parse_url_data(fields))
            
            # Parse user and authentication info
            data.update(self._parse_user_info(fields))
            
            # Parse policy and security info
            data.update(self._parse_security_info(fields))
            
            # Parse application info
            data.update(self._parse_application_info(fields))
            
            # Parse device profiling
            data.update(self._parse_device_profiling(fields))
            
            # Parse metrics and performance
            data.update(self._parse_metrics(fields))
            
            # Parse advanced features
            data.update(self._parse_advanced_features(fields))
            
            # Final validation and cleanup
            data = self._validate_and_cleanup(data)
            
            STATS['url_logs_parsed'] += 1
            logger.debug(f"Successfully parsed URL log: {data.get('url', 'N/A')}")
            
            return data
            
        except Exception as e:
            STATS['parse_errors'] += 1
            logger.error(f"Error parsing log line: {e}\nLine: {line[:200]}...")
            return None
    
    def _initialize_data_structure(self) -> Dict[str, Any]:
        """Initialize data structure with appropriate defaults"""
        data = {}
        
        # Set defaults based on field types
        for field in PA_URL_FIELDS:
            if field in NUMERIC_FIELDS:
                data[field] = 0
            elif field in FLOAT_FIELDS:
                data[field] = 0.0
            elif field in DATETIME_FIELDS:
                data[field] = datetime.now()
            elif field in DATE_FIELDS:
                data[field] = datetime.now().date()
            elif field == 'tags':
                data[field] = []
            else:
                data[field] = ''
                
        return data
    
    def _parse_syslog_header(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse syslog header portion of the log"""
        try:
            # Standard syslog format: timestamp hostname data
            # Example: Jun 18 13:45:21 SMO-RUH-MU04-F09R14-INT-FW01.smo.sa 1,2025/06/18...
            parts = line.split(' ', 4)
            
            if len(parts) < 5:
                return None
                
            month, day, time_str, hostname = parts[:4]
            csv_data = parts[4]
            
            # Parse receive time
            current_year = datetime.now().year
            receive_time_str = f"{current_year} {month} {day} {time_str}"
            
            try:
                receive_time = datetime.strptime(receive_time_str, "%Y %b %d %H:%M:%S")
            except ValueError:
                receive_time = datetime.now()
            
            return {
                'receive_time': receive_time,
                'hostname': hostname,
                'csv_data': csv_data
            }
            
        except Exception as e:
            logger.warning(f"Syslog header parsing error: {e}")
            return None
    
    def _split_csv_safely(self, csv_data: str) -> List[str]:
        """Safely split CSV data handling quoted fields"""
        try:
            # Simple CSV splitting with quote handling
            fields = []
            current_field = ''
            in_quotes = False
            
            i = 0
            while i < len(csv_data):
                char = csv_data[i]
                
                if char == '"' and (i == 0 or csv_data[i-1] == ','):
                    in_quotes = True
                elif char == '"' and in_quotes and (i == len(csv_data)-1 or csv_data[i+1] == ','):
                    in_quotes = False
                elif char == ',' and not in_quotes:
                    fields.append(current_field.strip())
                    current_field = ''
                    i += 1
                    continue
                else:
                    current_field += char
                    
                i += 1
            
            # Add the last field
            if current_field:
                fields.append(current_field.strip())
                
            return fields
            
        except Exception as e:
            logger.warning(f"CSV splitting error: {e}")
            return csv_data.split(',')
    
    def _is_url_filtering_log(self, fields: List[str]) -> bool:
        """Determine if this is a URL filtering log"""
        if len(fields) < 5:
            return False
            
        # Check log type (index 3) and subtype (index 4)
        log_type = fields[3].strip().upper() if len(fields) > 3 else ''
        log_subtype = fields[4].strip().lower() if len(fields) > 4 else ''
        
        # URL filtering logs typically have type "URL" and various subtypes
        return log_type == 'URL' or log_subtype in ['url', 'filtering', 'category']
    
    def _parse_timestamps(self, syslog_parts: Dict, fields: List[str]) -> Dict[str, Any]:
        """Parse all timestamp fields"""
        timestamps = {
            'receive_time': syslog_parts.get('receive_time', datetime.now()),
            'timestamp': syslog_parts.get('receive_time', datetime.now()),
            'processing_timestamp': datetime.now()
        }
        
        # Parse generated time from CSV
        if len(fields) > 6 and fields[6]:
            try:
                gen_time_str = fields[6].strip()
                if '/' in gen_time_str and ':' in gen_time_str:
                    timestamps['generated_time'] = datetime.strptime(gen_time_str, "%Y/%m/%d %H:%M:%S")
                    timestamps['timestamp'] = timestamps['generated_time']  # Use generated time as primary
            except ValueError:
                pass
        
        # Parse high resolution timestamp if available
        if len(fields) > 105 and fields[105]:
            try:
                hr_timestamp_str = fields[105].strip()
                if 'T' in hr_timestamp_str:
                    # ISO format timestamp
                    timestamps['high_resolution_timestamp'] = datetime.fromisoformat(
                        hr_timestamp_str.replace('+03:00', '').replace('Z', '')
                    )
            except (ValueError, IndexError):
                pass
        
        # Set computed date/hour fields
        base_time = timestamps['timestamp']
        timestamps['log_date'] = base_time.date()
        timestamps['log_hour'] = base_time.replace(minute=0, second=0, microsecond=0)
        
        return timestamps
    
    def _parse_device_info(self, syslog_parts: Dict, fields: List[str]) -> Dict[str, Any]:
        """Parse device and system information"""
        device_info = {
            'device_name': syslog_parts.get('hostname', ''),
            'host_id': syslog_parts.get('hostname', '')
        }
        
        # Map fields from CSV
        field_mapping = {
            2: 'serial_number',
            3: 'log_type',
            4: 'log_subtype',
            15: 'virtual_system',
            57: 'virtual_system_name',
            58: 'device_name'  # Override with CSV value if available
        }
        
        for idx, field_name in field_mapping.items():
            if idx < len(fields) and fields[idx]:
                device_info[field_name] = fields[idx].strip()
        
        return device_info
    
    def _parse_network_info(self, fields: List[str]) -> Dict[str, Any]:
        """Parse network connection information"""
        network_info = {}
        
        # Network field mapping
        field_mapping = {
            7: 'source_address',
            8: 'destination_address',
            9: 'nat_source_ip',
            10: 'nat_destination_ip',
            24: 'source_port',
            25: 'destination_port',
            26: 'nat_source_port',
            27: 'nat_destination_port',
            29: 'ip_protocol',
            16: 'source_zone',
            17: 'destination_zone',
            18: 'inbound_interface',
            19: 'outbound_interface'
        }
        
        for idx, field_name in field_mapping.items():
            if idx < len(fields) and fields[idx]:
                value = fields[idx].strip()
                
                # Handle port fields
                if field_name.endswith('_port'):
                    try:
                        network_info[field_name] = int(value) if value else 0
                    except ValueError:
                        network_info[field_name] = 0
                
                # Handle protocol field
                elif field_name == 'ip_protocol':
                    network_info[field_name] = self._parse_protocol(value)
                    network_info['protocol'] = value.lower()
                
                # Handle IP addresses
                else:
                    network_info[field_name] = value
        
        return network_info
    
    def _parse_url_data(self, fields: List[str]) -> Dict[str, Any]:
        """Parse URL and web-specific data"""
        url_data = {}
        
        # Extract URL from field 31
        if len(fields) > 31 and fields[31]:
            url = fields[31].strip()
            if url.startswith('"') and url.endswith('"'):
                url = url[1:-1]  # Remove quotes
            
            # Analyze URL components
            url_analysis = self.url_analyzer.analyze_url(url)
            url_data.update(url_analysis)
        
        # Extract URL category
        if len(fields) > 33 and fields[33]:
            url_data['url_category'] = fields[33].strip()
        
        # Extract URL category list
        if len(fields) > 74 and fields[74]:
            url_data['url_category_list'] = fields[74].strip()
        
        # Extract URL index
        if len(fields) > 44 and fields[44]:
            try:
                url_data['url_index'] = int(fields[44]) if fields[44] else 0
            except ValueError:
                url_data['url_index'] = 0
        
        # Extract HTTP method
        if len(fields) > 62 and fields[62]:
            url_data['http_method'] = fields[62].strip().upper()
        
        # Extract User Agent
        if len(fields) > 45 and fields[45]:
            user_agent = fields[45].strip()
            if user_agent.startswith('"') and user_agent.endswith('"'):
                user_agent = user_agent[1:-1]
            url_data['user_agent'] = user_agent
        
        # Extract Referer
        if len(fields) > 48 and fields[48]:
            referer = fields[48].strip()
            if referer.startswith('"') and referer.endswith('"'):
                referer = referer[1:-1]
            url_data['referer'] = referer
        
        # Extract Content Type
        if len(fields) > 40 and fields[40]:
            url_data['content_type'] = fields[40].strip()
        
        return url_data
    
    def _parse_user_info(self, fields: List[str]) -> Dict[str, Any]:
        """Parse user and authentication information"""
        user_info = {}
        
        # User field mapping
        field_mapping = {
            12: 'source_user',
            13: 'destination_user'
        }
        
        for idx, field_name in field_mapping.items():
            if idx < len(fields) and fields[idx]:
                user = fields[idx].strip()
                
                # Parse domain if present
                if '\\' in user:
                    domain, username = user.split('\\', 1)
                    user_info[field_name] = username
                    user_info[f"{field_name}_domain"] = domain
                elif '@' in user:
                    username, domain = user.split('@', 1)
                    user_info[field_name] = username
                    user_info[f"{field_name}_domain"] = domain
                else:
                    user_info[field_name] = user
        
        return user_info
    
    def _parse_security_info(self, fields: List[str]) -> Dict[str, Any]:
        """Parse security and policy information"""
        security_info = {}
        
        # Security field mapping
        field_mapping = {
            11: 'rule_name',
            30: 'action',
            32: 'threat_id',
            34: 'severity',
            35: 'direction',
            59: 'action_source',
            75: 'rule_uuid'
        }
        
        for idx, field_name in field_mapping.items():
            if idx < len(fields) and fields[idx]:
                security_info[field_name] = fields[idx].strip()
        
        # Parse sequence number
        if len(fields) > 36 and fields[36]:
            try:
                security_info['sequence_number'] = int(fields[36]) if fields[36] else 0
            except ValueError:
                security_info['sequence_number'] = 0
        
        return security_info
    
    def _parse_application_info(self, fields: List[str]) -> Dict[str, Any]:
        """Parse application information"""
        app_info = {}
        
        # Application field mapping
        field_mapping = {
            14: 'application'
        }
        
        for idx, field_name in field_mapping.items():
            if idx < len(fields) and fields[idx]:
                app_info[field_name] = fields[idx].strip()
        
        return app_info
    
    def _parse_device_profiling(self, fields: List[str]) -> Dict[str, Any]:
        """Parse device profiling information"""
        device_info = {}
        
        # Device profiling field mapping
        device_mapping = {
            79: 'source_device_category',
            80: 'source_device_profile',
            81: 'source_device_model',
            82: 'source_device_vendor',
            83: 'source_device_os_family',
            84: 'source_device_os_version',
            85: 'source_hostname',
            86: 'source_mac_address',
            87: 'destination_device_category',
            88: 'destination_device_profile',
            89: 'destination_device_model',
            90: 'destination_device_vendor',
            91: 'destination_device_os_family',
            92: 'destination_device_os_version',
            93: 'destination_hostname',
            94: 'destination_mac_address'
        }
        
        for idx, field_name in device_mapping.items():
            if idx < len(fields) and fields[idx]:
                device_info[field_name] = fields[idx].strip()
        
        return device_info
    
    def _parse_metrics(self, fields: List[str]) -> Dict[str, Any]:
        """Parse traffic metrics and performance data"""
        metrics = {}
        
        # Session information
        if len(fields) > 22 and fields[22]:
            try:
                metrics['session_id'] = int(fields[22]) if fields[22] else 0
            except ValueError:
                metrics['session_id'] = 0
        
        if len(fields) > 23 and fields[23]:
            try:
                metrics['repeat_count'] = int(fields[23]) if fields[23] else 0
            except ValueError:
                metrics['repeat_count'] = 0
        
        return metrics
    
    def _parse_advanced_features(self, fields: List[str]) -> Dict[str, Any]:
        """Parse advanced features and modern PAN-OS capabilities"""
        advanced = {}
        
        # Advanced field mapping
        field_mapping = {
            47: 'xff_address',
            53: 'device_group_hierarchy_level_1',
            54: 'device_group_hierarchy_level_2',
            55: 'device_group_hierarchy_level_3',
            56: 'device_group_hierarchy_level_4',
            77: 'dynamic_user_group_name',
            95: 'container_id',
            96: 'pod_namespace',
            97: 'pod_name',
            98: 'source_external_dynamic_list',
            99: 'destination_external_dynamic_list',
            100: 'host_id'
        }
        
        for idx, field_name in field_mapping.items():
            if idx < len(fields) and fields[idx]:
                advanced[field_name] = fields[idx].strip()
        
        return advanced
    
    def _parse_protocol(self, protocol_str: str) -> int:
        """Convert protocol string to numeric value"""
        if not protocol_str:
            return 0
            
        protocol_lower = protocol_str.lower().strip()
        
        # Check if it's already numeric
        if protocol_lower.isdigit():
            return int(protocol_lower)
        
        # Map from protocol name to number
        return self.protocol_map.get(protocol_lower, 0)
    
    def _validate_and_cleanup(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Final validation and cleanup of parsed data"""
        try:
            # Ensure all required fields are present
            for field in PA_URL_FIELDS:
                if field not in data:
                    if field in NUMERIC_FIELDS:
                        data[field] = 0
                    elif field in FLOAT_FIELDS:
                        data[field] = 0.0
                    elif field in DATETIME_FIELDS:
                        data[field] = datetime.now()
                    elif field == 'tags':
                        data[field] = []
                    else:
                        data[field] = ''
            
            # Validate numeric fields
            for field in NUMERIC_FIELDS:
                if field in data:
                    try:
                        data[field] = int(data[field]) if data[field] else 0
                    except (ValueError, TypeError):
                        data[field] = 0
            
            # Validate float fields
            for field in FLOAT_FIELDS:
                if field in data:
                    try:
                        data[field] = float(data[field]) if data[field] else 0.0
                    except (ValueError, TypeError):
                        data[field] = 0.0
            
            # Ensure datetime fields are datetime objects
            for field in DATETIME_FIELDS:
                if field in data and not isinstance(data[field], datetime):
                    data[field] = datetime.now()
            
            return data
            
        except Exception as e:
            logger.error(f"Validation error: {e}")
            return data

# ═══════════════════════════════════════════════════════════════════════════════
# 📁 FILE MONITORING AND PROCESSING
# ═══════════════════════════════════════════════════════════════════════════════

class LogHandler(FileSystemEventHandler):
    """Advanced file handler with intelligent monitoring and processing"""
    
    def __init__(self, filepath: str, buffer: deque, buffer_lock: threading.Lock, 
                 process_batch_func, parser: PaloAltoURLParser):
        self.filepath = filepath
        self.buffer = buffer
        self.buffer_lock = buffer_lock
        self.process_batch_func = process_batch_func
        self.parser = parser
        self.last_position = 0
        self.file_handle = None
        self._open_file()
        
    def _open_file(self):
        """Open or reopen the log file"""
        try:
            if self.file_handle:
                self.file_handle.close()
                
            self.file_handle = open(self.filepath, 'r', encoding='utf-8', errors='ignore')
            self.file_handle.seek(0, os.SEEK_END)  # Start from end for new logs only
            self.last_position = self.file_handle.tell()
            logger.info(f"Opened log file: {self.filepath} (position: {self.last_position})")
            
        except Exception as e:
            logger.error(f"Error opening log file: {e}")
            self.file_handle = None
    
    def _check_file_rotation(self) -> bool:
        """Check for file rotation and reopen if necessary"""
        try:
            if not os.path.exists(self.filepath):
                logger.warning(f"Log file {self.filepath} does not exist")
                return False
                
            if not self.file_handle:
                self._open_file()
                return True
                
            # Check if file was rotated
            current_inode = os.stat(self.filepath).st_ino
            file_inode = os.fstat(self.file_handle.fileno()).st_ino
            
            if current_inode != file_inode:
                logger.info("Log rotation detected, reopening file")
                self._open_file()
                return True
                
        except Exception as e:
            logger.error(f"Error checking file rotation: {e}")
            self._open_file()
            return True
            
        return False
    
    def on_modified(self, event):
        """Handle file modification events"""
        if event.src_path != self.filepath:
            return
            
        self._check_file_rotation()
        
        if not self.file_handle:
            return
        
        lines_read = 0
        try:
            while True:
                line = self.file_handle.readline()
                if not line:
                    break
                    
                lines_read += 1
                
                # Parse the line
                parsed_data = self.parser.parse_log_line(line)
                if parsed_data:
                    with self.buffer_lock:
                        self.buffer.append(parsed_data)
                        
                        # Trigger batch processing if buffer is full
                        if len(self.buffer) >= BATCH_SIZE:
                            logger.debug(f"Buffer full ({len(self.buffer)}), triggering batch process")
                            self.process_batch_func()
                        elif len(self.buffer) >= MAX_BUFFER_SIZE:
                            logger.warning(f"Buffer overflow ({len(self.buffer)}), forcing flush")
                            self.process_batch_func()
            
            if lines_read > 0:
                logger.info(f"Processed {lines_read} new lines from {self.filepath}")
                
        except Exception as e:
            logger.error(f"Error reading from file: {e}")
            self._open_file()
    
    def close(self):
        """Close file handle"""
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None

# ═══════════════════════════════════════════════════════════════════════════════
# 📊 STATISTICS AND MONITORING
# ═══════════════════════════════════════════════════════════════════════════════

def log_statistics():
    """Log processing statistics"""
    current_time = time.time()
    
    if STATS['start_time'] is None:
        STATS['start_time'] = current_time
        STATS['last_stats_time'] = current_time
        return
    
    elapsed_total = current_time - STATS['start_time']
    elapsed_interval = current_time - STATS['last_stats_time']
    
    if elapsed_interval >= 60:  # Log stats every minute
        logger.info(f"""
╭─────────────────────────────────────────────────────────────╮
│                   PALOALTO URL PARSER STATS                  │
├─────────────────────────────────────────────────────────────┤
│ Runtime: {elapsed_total/3600:.1f}h {(elapsed_total%3600)/60:.1f}m                                    │
│ Total Lines Processed: {STATS['total_lines_processed']:,}                          │
│ URL Logs Parsed: {STATS['url_logs_parsed']:,}                                │
│ Non-URL Logs Skipped: {STATS['non_url_logs_skipped']:,}                          │
│ Parse Errors: {STATS['parse_errors']:,}                                   │
│ Successful Inserts: {STATS['insert_success']:,}                            │
│ Insert Errors: {STATS['insert_errors']:,}                                 │
│ Parse Rate: {STATS['url_logs_parsed']/elapsed_total:.1f} logs/sec                        │
│ Success Rate: {(STATS['url_logs_parsed']/(STATS['url_logs_parsed']+STATS['parse_errors'])*100) if (STATS['url_logs_parsed']+STATS['parse_errors']) > 0 else 0:.1f}%                                  │
╰─────────────────────────────────────────────────────────────╯
        """)
        STATS['last_stats_time'] = current_time

# ═══════════════════════════════════════════════════════════════════════════════
# 🚀 MAIN PROCESSING ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    """Main processing loop with advanced error handling and monitoring"""
    
    logger.info("🚀 Starting PaloAlto URL Filtering Log Parser")
    logger.info(f"📁 Monitoring: {LOG_FILE}")
    logger.info(f"🔗 ClickHouse: {CH_HOST}:{CH_PORT}/{CH_DB}")
    logger.info(f"📊 Batch Size: {BATCH_SIZE}, Flush Interval: {BATCH_FLUSH_INTERVAL}s")
    
    # Test ClickHouse connection
    try:
        CLIENT.execute("SELECT 1")
        logger.info("✅ ClickHouse connection successful")
    except Exception as e:
        logger.error(f"❌ ClickHouse connection failed: {e}")
        sys.exit(1)
    
    # Verify table exists
    try:
        CLIENT.execute(f"DESCRIBE TABLE {CH_DB}.pa_urls")
        logger.info("✅ Table pa_urls found")
    except Exception as e:
        logger.error(f"❌ Table pa_urls not found: {e}")
        logger.error("Please create the table using the schema file first")
        sys.exit(1)
    
    # Initialize components
    parser = PaloAltoURLParser()
    buffer = deque()
    buffer_lock = threading.Lock()
    
    # Prepare insert query
    insert_query = f"""
        INSERT INTO {CH_DB}.pa_urls ({', '.join(PA_URL_FIELDS)}) VALUES
    """
    
    def process_batch():
        """Process accumulated batch of parsed logs"""
        with buffer_lock:
            if not buffer:
                return
            batch = list(buffer)
            buffer.clear()
        
        if not batch:
            return
        
        try:
            # Convert to rows for ClickHouse
            rows = []
            for data in batch:
                row = [data.get(field, None) for field in PA_URL_FIELDS]
                rows.append(row)
            
            # Insert to ClickHouse
            CLIENT.execute(insert_query, rows)
            
            STATS['insert_success'] += len(rows)
            logger.info(f"✅ Inserted {len(rows)} URL logs to pa_urls table")
            
        except Exception as e:
            STATS['insert_errors'] += len(batch)
            logger.error(f"❌ Batch insert error: {e}")
            
            # Log sample for debugging
            if batch:
                sample = batch[0]
                logger.debug(f"Sample record: {json.dumps(sample, default=str, indent=2)}")
    
    # Set up file monitoring
    handler = LogHandler(LOG_FILE, buffer, buffer_lock, process_batch, parser)
    observer = Observer()
    observer.schedule(handler, path=os.path.dirname(LOG_FILE) or '.', recursive=False)
    observer.start()
    
    logger.info(f"👀 Monitoring started for: {LOG_FILE}")
    
    # Signal handlers for graceful shutdown
    def shutdown_handler(signum, frame):
        logger.info("🛑 Shutdown signal received")
        process_batch()  # Final flush
        observer.stop()
        observer.join()
        handler.close()
        logger.info("👋 Shutdown complete")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)
    
    # Main monitoring loop
    last_check_time = time.time()
    
    try:
        while True:
            current_time = time.time()
            
            # Periodic file check
            if current_time - last_check_time >= FILE_CHECK_INTERVAL:
                last_check_time = current_time
                
                # Check for unread data
                try:
                    if handler.file_handle:
                        current_pos = handler.file_handle.tell()
                        file_size = os.path.getsize(LOG_FILE)
                        
                        if file_size > current_pos:
                            unread_bytes = file_size - current_pos
                            logger.debug(f"📈 {unread_bytes} unread bytes detected")
                            
                            # Trigger file processing
                            event = type('MockEvent', (), {'src_path': LOG_FILE})()
                            handler.on_modified(event)
                            
                except Exception as e:
                    logger.warning(f"File check error: {e}")
            
            # Periodic buffer flush
            with buffer_lock:
                if buffer and len(buffer) > 0:
                    logger.debug(f"🔄 Periodic flush: {len(buffer)} items in buffer")
                    process_batch()
            
            # Log statistics
            log_statistics()
            
            # Sleep
            time.sleep(BATCH_FLUSH_INTERVAL)
            
    except KeyboardInterrupt:
        shutdown_handler(None, None)

if __name__ == '__main__':
    main()