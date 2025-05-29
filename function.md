# Firewall Log Analyzer - Function Documentation

This document provides a comprehensive overview of all functions in the Firewall Log Analyzer project.

## Table of Contents

1. [Main Directory Files](#main-directory-files)
2. [Dashboard App](#dashboard-app)
3. [Scripts](#scripts)
4. [Template Tags](#template-tags)
5. [File Handlers](#file-handlers)

---

## Main Directory Files

### manage.py

#### `main()`
- **Location**: `manage.py:7-18`
- **Purpose**: Django's command-line utility entry point
- **Parameters**: None
- **Returns**: None
- **Description**: Sets up Django environment and executes management commands

---

## Dashboard App

### dashboard/views.py

#### `get_pagination_range(current_page, total_pages, neighbors=2)`
- **Location**: `dashboard/views.py:27-67`
- **Purpose**: Generates pagination range with ellipses for UI
- **Parameters**:
  - `current_page` (int): Current page number
  - `total_pages` (int): Total pages available
  - `neighbors` (int): Page links to show on each side
- **Returns**: List of integers and None values (None = ellipsis)
- **Example**: `[1, None, 5, 6, 7, None, 10]` for page 6 of 10

#### `dmu_view(request)`
- **Location**: `dashboard/views.py:69-71`
- **Purpose**: Renders static dashboard UI template
- **Parameters**: Django HTTP request
- **Returns**: HTTP response with rendered template

#### `top_summary_view(request)`
- **Location**: `dashboard/views.py:73-133`
- **Purpose**: Displays top traffic flows by total bytes
- **Features**:
  - Time range filtering (default: 24 hours)
  - Top 10 traffic flows from ClickHouse
  - Human-readable byte formatting
- **Parameters**: Django HTTP request
- **Returns**: HTTP response with top summary data

#### `format_bytes(num_bytes)`
- **Location**: `dashboard/views.py:142-150`
- **Purpose**: Converts bytes to human-readable format
- **Parameters**: `num_bytes` (int/float)
- **Returns**: Formatted string (e.g., "1.5 GB")
- **Units**: B, KB, MB, GB, TB, PB

#### `clickhouse_logs_view(request)`
- **Location**: `dashboard/views.py:152-424`
- **Purpose**: Main view for paginated firewall logs with advanced filtering
- **Features**:
  - Time range filtering
  - IP address filtering (source/destination)
  - Port filtering with range support (e.g., "80,443" or "8000-9000")
  - Action filtering (allow/deny)
  - Device name filtering
  - Pagination with customizable page size
- **Parameters**: Django HTTP request
- **Returns**: HTTP response with filtered logs

#### `grouped_logs_view(request)`
- **Location**: `dashboard/views.py:427-601`
- **Purpose**: Groups logs by /24 subnet with aggregated statistics
- **Features**:
  - Subnet-based grouping
  - Event count aggregation
  - Sent/received bytes totals
  - Protocol breakdown
  - Last seen timestamps
  - Sortable columns
  - Pagination
- **Parameters**: Django HTTP request
- **Returns**: HTTP response with grouped log data

---

## Scripts

### scripts/fortigate_loader.py (ElasticSearch Loader)

#### `bulk_index(docs)`
- **Location**: `scripts/fortigate_loader.py:27-36`
- **Purpose**: Bulk indexes documents to Elasticsearch
- **Parameters**: `docs` - List of documents
- **Features**: Retry logic on failures

#### `parser_worker()`
- **Location**: `scripts/fortigate_loader.py:37-69`
- **Purpose**: Worker thread for parsing log lines
- **Functionality**:
  - Processes lines from queue
  - Extracts key-value pairs
  - Buffers for bulk indexing

#### `main()`
- **Location**: `scripts/fortigate_loader.py:86-116`
- **Purpose**: Main entry point for FortiGate log loading
- **Features**:
  - Multi-threaded parsing
  - File monitoring
  - Graceful shutdown

### scripts/fortigate_to_clickhouse.py

#### `parse_line(line: str) -> dict`
- **Location**: `scripts/fortigate_to_clickhouse.py:80-151`
- **Purpose**: Parses FortiGate syslog lines
- **Parameters**: Raw log line string
- **Returns**: Dictionary with parsed fields
- **Features**:
  - Key-value pair extraction
  - Data type conversion
  - IP validation
  - Default value handling

#### `main()`
- **Location**: `scripts/fortigate_to_clickhouse.py:230-376`
- **Purpose**: Main ingestion loop for FortiGate logs
- **Features**:
  - Real-time log monitoring
  - Batch processing (500 logs/batch)
  - Automatic file rotation detection
  - Graceful shutdown handling

### scripts/paloalto_to_clickhouse.py

#### `parse_line(line: str) -> dict`
- **Location**: `scripts/paloalto_to_clickhouse.py:88-243`
- **Purpose**: Parses PaloAlto firewall syslog lines
- **Parameters**: Raw log line string
- **Returns**: Dictionary with parsed fields
- **Features**:
  - CSV format parsing
  - Protocol name to number mapping
  - Field validation
  - Error handling

#### `main()`
- **Location**: `scripts/paloalto_to_clickhouse.py:322-461`
- **Purpose**: Main ingestion loop for PaloAlto logs
- **Features**: Similar to FortiGate ingestion with PaloAlto-specific parsing

---

## Template Tags

### dashboard/templatetags/bytes_humanize.py

#### `bytes_humanize(value)`
- **Location**: `dashboard/templatetags/bytes_humanize.py:5-22`
- **Purpose**: Django filter for byte formatting in templates
- **Usage**: `{{ byte_value|bytes_humanize }}`
- **Returns**: Human-readable byte string

### dashboard/templatetags/dashboard_tags.py

#### `get_item(dictionary, key)`
- **Location**: `dashboard/templatetags/dashboard_tags.py:5-7`
- **Purpose**: Access dictionary items in Django templates
- **Usage**: `{{ my_dict|get_item:key_variable }}`
- **Returns**: Dictionary value or empty string

---

## File Handlers

### LogHandler Classes

All scripts implement similar LogHandler classes for file monitoring:

#### Common Methods:
- `__init__`: Initializes handler with file path and processing functions
- `on_modified`: Handles file modification events (new log lines)
- `on_moved`: Handles file rotation events
- `_open_file`: Opens/reopens log files
- `_check_file_rotation`: Detects log rotation

#### Implementations:
1. **FortiGate Loader**: `scripts/fortigate_loader.py:71-84`
2. **FortiGate ClickHouse**: `scripts/fortigate_to_clickhouse.py:158-227`
3. **PaloAlto ClickHouse**: `scripts/paloalto_to_clickhouse.py:250-318`

---

## Configuration Constants

### ClickHouse Settings
- `CH_HOST`: "localhost"
- `CH_PORT`: 9000
- `CH_USER`: "default"
- `CH_PASSWORD`: ""
- `CH_DB`: "firewall"

### Processing Settings
- `BATCH_SIZE`: 500 logs per batch
- `BATCH_FLUSH_INTERVAL`: 1 second
- `FILE_CHECK_INTERVAL`: 1 second
- `SUBNET_GROUP_PAGE_SIZE`: 50 entries

### Protocol Mappings
- TCP: 6
- UDP: 17
- ICMP: 1
- ESP: 50
- AH: 51
- GRE: 47

---

## Key Features Summary

1. **Real-time Log Ingestion**: Monitors syslog files and processes new entries
2. **Multi-Firewall Support**: Handles both FortiGate and PaloAlto formats
3. **Scalable Storage**: Uses ClickHouse for high-performance log storage
4. **Advanced Filtering**: IP, port, action, and time-based filtering
5. **Subnet Grouping**: Aggregates logs by /24 subnets for analysis
6. **Pagination**: Efficient handling of large datasets
7. **Graceful Shutdown**: Ensures no data loss on service stop
8. **File Rotation Support**: Automatically handles log file rotation

---

## Error Handling

All functions implement robust error handling:
- Invalid IP addresses are set to "0.0.0.0"
- Missing fields use appropriate defaults
- Database connection errors are logged
- Parsing errors skip individual lines without stopping processing