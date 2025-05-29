# Python Functions Documentation

## 1. Main Directory Files

### manage.py

#### `main()`
- **File**: `/home/net/analyzer/manage.py`
- **Line**: 7-18
- **Signature**: `def main():`
- **Purpose**: Django's command-line utility entry point for administrative tasks
- **Parameters**: None
- **Returns**: None
- **Description**: Sets Django settings module environment variable and executes command line arguments through Django's management system

---

## 2. Dashboard App Files

### dashboard/views.py

#### `get_pagination_range(current_page, total_pages, neighbors=2)`
- **File**: `/home/net/analyzer/dashboard/views.py`
- **Line**: 27-67
- **Signature**: `def get_pagination_range(current_page, total_pages, neighbors=2):`
- **Purpose**: Generates a list of page numbers for pagination display with ellipses
- **Parameters**:
  - `current_page`: Current page number (int)
  - `total_pages`: Total number of pages (int)
  - `neighbors`: Number of page links to show on each side of current page (int, default=2)
- **Returns**: List of integers and None values (None represents ellipsis)
- **Description**: Creates pagination range like [1, None, 5, 6, 7, None, 10] for better UI navigation

#### `dmu_view(request)`
- **File**: `/home/net/analyzer/dashboard/views.py`
- **Line**: 69-71
- **Signature**: `def dmu_view(request):`
- **Purpose**: Renders the static UI template for the dashboard
- **Parameters**:
  - `request`: Django HTTP request object
- **Returns**: Django HTTP response with rendered template
- **Description**: Simple view that renders the dashboard index template

#### `top_summary_view(request)`
- **File**: `/home/net/analyzer/dashboard/views.py`
- **Line**: 73-133
- **Signature**: `def top_summary_view(request):`
- **Purpose**: Displays top traffic summary from ClickHouse data
- **Parameters**:
  - `request`: Django HTTP request object
- **Returns**: Django HTTP response with rendered top summary template
- **Description**: Queries ClickHouse for top 10 traffic flows by total bytes within specified time range

#### `format_bytes(num_bytes)`
- **File**: `/home/net/analyzer/dashboard/views.py`
- **Line**: 142-150
- **Signature**: `def format_bytes(num_bytes):`
- **Purpose**: Converts byte values to human-readable format
- **Parameters**:
  - `num_bytes`: Number of bytes (int/float)
- **Returns**: Formatted string (e.g., "1.5 GB", "500 MB")
- **Description**: Formats bytes into appropriate units (B, KB, MB, GB, TB, PB)

#### `clickhouse_logs_view(request)`
- **File**: `/home/net/analyzer/dashboard/views.py`
- **Line**: 152-424
- **Signature**: `def clickhouse_logs_view(request):`
- **Purpose**: Main view for displaying paginated firewall logs with filtering
- **Parameters**:
  - `request`: Django HTTP request object
- **Returns**: Django HTTP response with rendered logs template
- **Description**: Retrieves and displays firewall logs from ClickHouse with support for:
  - Time range filtering
  - IP address filtering (source/destination)
  - Port filtering (source/destination with range support)
  - Action filtering
  - Device name filtering
  - Pagination

#### `grouped_logs_view(request)`
- **File**: `/home/net/analyzer/dashboard/views.py`
- **Line**: 427-601
- **Signature**: `def grouped_logs_view(request):`
- **Purpose**: Displays logs grouped by subnet with aggregated statistics
- **Parameters**:
  - `request`: Django HTTP request object
- **Returns**: Django HTTP response with rendered grouped logs template
- **Description**: Groups logs by /24 subnets and provides:
  - Event counts
  - Total sent/received bytes
  - Protocol information
  - Last seen timestamps
  - Sorting capabilities
  - Pagination

### dashboard/models.py
- **Note**: File is empty, no models defined

### dashboard/urls.py
- **Note**: Contains URL patterns only, no functions defined

### dashboard/apps.py
- **Note**: Contains only Django app configuration class, no functions

### dashboard/admin.py
- **Note**: File is empty, no admin configurations

---

## 3. Scripts Directory

### scripts/fortigate_loader.py

#### `bulk_index(docs)`
- **File**: `/home/net/analyzer/scripts/fortigate_loader.py`
- **Line**: 27-36
- **Signature**: `def bulk_index(docs):`
- **Purpose**: Bulk indexes documents to Elasticsearch
- **Parameters**:
  - `docs`: List of documents to index
- **Returns**: None
- **Description**: Uses Elasticsearch helpers to perform bulk indexing with retry logic

#### `parser_worker()`
- **File**: `/home/net/analyzer/scripts/fortigate_loader.py`
- **Line**: 37-69
- **Signature**: `def parser_worker():`
- **Purpose**: Worker thread function that parses log lines
- **Parameters**: None
- **Returns**: None
- **Description**: Continuously processes lines from queue, extracts key-value pairs, and adds to buffer for bulk indexing

#### `main()`
- **File**: `/home/net/analyzer/scripts/fortigate_loader.py`
- **Line**: 86-116
- **Signature**: `def main():`
- **Purpose**: Main entry point for FortiGate log loader
- **Parameters**: None
- **Returns**: None
- **Description**: Sets up parser threads, file monitoring, and coordinates log processing

### scripts/fortigate_to_clickhouse.py

#### `parse_line(line: str) -> dict`
- **File**: `/home/net/analyzer/scripts/fortigate_to_clickhouse.py`
- **Line**: 80-151
- **Signature**: `def parse_line(line: str) -> dict:`
- **Purpose**: Parses a FortiGate syslog line into structured data
- **Parameters**:
  - `line`: Raw log line string
- **Returns**: Dictionary with parsed fields
- **Description**: Extracts key-value pairs from log line, handles data type conversions, and ensures all required fields have valid values

#### `main()`
- **File**: `/home/net/analyzer/scripts/fortigate_to_clickhouse.py`
- **Line**: 230-376
- **Signature**: `def main():`
- **Purpose**: Main ingestion loop for FortiGate logs to ClickHouse
- **Parameters**: None
- **Returns**: None
- **Description**: Sets up log monitoring, batch processing, and handles graceful shutdown

#### `process_batch()` (nested function)
- **File**: `/home/net/analyzer/scripts/fortigate_to_clickhouse.py`
- **Line**: 240-292
- **Signature**: `def process_batch():`
- **Purpose**: Processes buffered log lines and inserts to ClickHouse
- **Parameters**: None (uses closure variables)
- **Returns**: None
- **Description**: Parses batch of lines, handles errors, and performs bulk insert to ClickHouse

#### `flush_and_exit(signum, frame)` (nested function)
- **File**: `/home/net/analyzer/scripts/fortigate_to_clickhouse.py`
- **Line**: 304-309
- **Signature**: `def flush_and_exit(signum, frame):`
- **Purpose**: Signal handler for graceful shutdown
- **Parameters**:
  - `signum`: Signal number
  - `frame`: Current stack frame
- **Returns**: None
- **Description**: Flushes remaining logs and stops observer on shutdown signals

### scripts/paloalto_to_clickhouse.py

#### `parse_line(line: str) -> dict`
- **File**: `/home/net/analyzer/scripts/paloalto_to_clickhouse.py`
- **Line**: 88-243
- **Signature**: `def parse_line(line: str) -> dict:`
- **Purpose**: Parses a PaloAlto firewall syslog line into structured data
- **Parameters**:
  - `line`: Raw log line string
- **Returns**: Dictionary with parsed fields
- **Description**: Extracts CSV fields from PaloAlto log format, maps protocol names to numbers, and ensures data integrity

#### `main()`
- **File**: `/home/net/analyzer/scripts/paloalto_to_clickhouse.py`
- **Line**: 322-461
- **Signature**: `def main():`
- **Purpose**: Main ingestion loop for PaloAlto logs to ClickHouse
- **Parameters**: None
- **Returns**: None
- **Description**: Similar to FortiGate ingestion but adapted for PaloAlto log format

#### `process_batch()` (nested function)
- **File**: `/home/net/analyzer/scripts/paloalto_to_clickhouse.py`
- **Line**: 332-377
- **Signature**: `def process_batch():`
- **Purpose**: Processes buffered PaloAlto log lines
- **Parameters**: None (uses closure variables)
- **Returns**: None
- **Description**: Batch processes and inserts PaloAlto logs to ClickHouse

#### `flush_and_exit(signum, frame)` (nested function)
- **File**: `/home/net/analyzer/scripts/paloalto_to_clickhouse.py`
- **Line**: 389-394
- **Signature**: `def flush_and_exit(signum, frame):`
- **Purpose**: Signal handler for graceful shutdown
- **Parameters**:
  - `signum`: Signal number
  - `frame`: Current stack frame
- **Returns**: None
- **Description**: Ensures remaining logs are processed before exit

---

## 4. Template Tags

### dashboard/templatetags/bytes_humanize.py

#### `bytes_humanize(value)`
- **File**: `/home/net/analyzer/dashboard/templatetags/bytes_humanize.py`
- **Line**: 5-22
- **Signature**: `@register.filter def bytes_humanize(value):`
- **Purpose**: Django template filter to convert bytes to human-readable format
- **Parameters**:
  - `value`: Byte value to format
- **Returns**: Formatted string (e.g., "2.50 GB")
- **Description**: Template filter for displaying byte values in templates

### dashboard/templatetags/dashboard_tags.py

#### `get_item(dictionary, key)`
- **File**: `/home/net/analyzer/dashboard/templatetags/dashboard_tags.py`
- **Line**: 5-7
- **Signature**: `@register.filter def get_item(dictionary, key):`
- **Purpose**: Django template filter to get dictionary item by key
- **Parameters**:
  - `dictionary`: Dictionary object
  - `key`: Key to retrieve
- **Returns**: Value from dictionary or empty string
- **Description**: Allows dictionary access in Django templates

---

## 5. Configuration Files

### fwanalyzer/settings.py
- **Note**: Contains Django settings configuration, no functions defined

### fwanalyzer/urls.py
- **Note**: Contains URL patterns only, no functions defined

---

## 6. File Handler Classes

### LogHandler (fortigate_loader.py)
- **File**: `/home/net/analyzer/scripts/fortigate_loader.py`
- **Lines**: 71-84
- **Methods**:
  - `__init__(self, path)`: Initializes handler with log file path
  - `on_modified(self, event)`: Handles file modification events
  - `on_moved(self, event)`: Handles file move/rotation events

### LogHandler (fortigate_to_clickhouse.py)
- **File**: `/home/net/analyzer/scripts/fortigate_to_clickhouse.py`
- **Lines**: 158-227
- **Methods**:
  - `__init__(self, filepath, buffer, buffer_lock, process_batch_func)`: Initializes handler
  - `_open_file(self)`: Opens or reopens log file
  - `_check_file_rotation(self)`: Checks for log rotation
  - `on_modified(self, event)`: Processes new log lines
  - `on_moved(self, event)`: Handles file moves

### LogHandler (paloalto_to_clickhouse.py)
- **File**: `/home/net/analyzer/scripts/paloalto_to_clickhouse.py`
- **Lines**: 250-318
- **Methods**: Same as FortiGate LogHandler but adapted for PaloAlto logs

---

## Global Constants and Configuration

### Common Constants:
- `CH_HOST`, `CH_PORT`, `CH_USER`, `CH_PASSWORD`, `CH_DB`: ClickHouse connection settings
- `BATCH_SIZE`: Number of logs to process in batch (500)
- `BATCH_FLUSH_INTERVAL`: Seconds between batch flushes (1)
- `FILE_CHECK_INTERVAL`: Seconds between file rotation checks (1)
- `SUBNET_GROUP_PAGE_SIZE`: Pagination size for subnet groups (50)
- `PROTO_MAP`: Protocol number to name mappings
- `NUMERIC_FIELDS`, `IP_FIELDS`, `ALL_FIELDS`: Field definitions for log parsing