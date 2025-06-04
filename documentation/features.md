# Firewall Log Analyzer - Feature Documentation

## Overview
The Firewall Log Analyzer is a comprehensive Django-based system for real-time ingestion, processing, and visualization of firewall logs from multiple vendors (FortiGate and PaloAlto) using ClickHouse as the analytical database backend.

## Core Features

### 1. Data Ingestion & Processing

#### 1.1 Multi-Firewall Support
- **FortiGate Firewall Integration**
  - Real-time log ingestion from `/var/log/fortigate.log`
  - Automatic parsing of FortiGate syslog format
  - Service: `fortigate_to_clickhouse.service`
  
- **PaloAlto Firewall Integration**
  - Real-time log ingestion from `/var/log/paloalto-1004.log`
  - Support for PaloAlto traffic logs
  - Support for PaloAlto URL/threat logs
  - Service: `paloalto_to_clickhouse.service`

#### 1.2 Data Storage
- **ClickHouse Database Backend**
  - High-performance columnar storage
  - Tables: `fortigate_traffic`, `paloalto_traffic`, `threat_logs`
  - Optimized for time-series log data
  - Support for billions of log entries
  - 90-day data retention with automatic cleanup

### 2. Log Viewing & Analysis

#### 2.1 Main Log Views
- **Individual Logs View** (`/logs/`)
  - Real-time log display with pagination
  - Expandable row details showing all 40+ log fields
  - Color-coded action badges (accept/deny/close/timeout)
  - Duration visualization with progress bars
  
- **Grouped Logs View** (`/grouped-logs/`)
  - Subnet-based aggregation of traffic (/24 grouping)
  - Expandable subnet groups showing individual IPs
  - Sortable by destination IP, last seen, and count
  - Aggregated traffic metrics (sent/received bytes)

- **Top Summary View** (`/top-summary/`)
  - Top 10 traffic flows by total bytes
  - Shows source IP, destination IP, port combinations
  - Human-readable byte formatting (KB, MB, GB)
  - Total sent/received/combined bytes

### 3. Filtering & Search Capabilities

#### 3.1 Time-Range Filtering
- Predefined ranges: Last hour, 24 hours, 7 days, 30 days
- Custom date/time range picker
- Persistent across all views

#### 3.2 Advanced Filtering Sidebar
- **IP Address Filters**
  - Source IP (exact match)
  - Destination IP (exact match)
  
- **Port Filters**
  - Source port (single or range e.g., 1000-2000)
  - Destination port (single or range e.g., 80,443)
  
- **Action Filter**
  - Dynamic dropdown populated from available actions
  - Options: accept, deny, close, timeout, server-rst, client-rst
  
- **Device Filter**
  - Filter by firewall device name
  - Dynamic dropdown showing available devices

### 4. User Interface Features

#### 4.1 Layout & Navigation
- **Responsive Design**
  - Mobile-friendly interface
  - Collapsible sidebars
  - Adaptive table layouts
  
- **Multi-Tab Navigation**
  - Dashboard, Firewalls, System Config, Reports, Settings tabs
  - Sub-navigation for Analytics, Logs, Health, etc.

#### 4.2 Interactive Elements
- **Expandable Log Details**
  - Click to expand full log information
  - Raw message display
  - Formatted field display
  - Network timing metrics
  
- **Collapsible Sidebars**
  - Log Analytics section
  - Client Analytics section
  - Load Balancer Analytics section
  - Filters section with toggle functionality

### 5. Data Export & Reporting

#### 5.1 Export Capabilities
- **CSV Export**
  - Export current view to CSV format
  - Includes all visible columns
  - Client-side generation
  
- **JSON Export**
  - Export logs with full details
  - Structured JSON format
  - Includes expanded log information

#### 5.2 Print Support
- Print-friendly view
- Optimized CSS for printing

### 6. Performance & Optimization

#### 6.1 Pagination
- Server-side pagination
- Configurable page size (default: 50)
- Smart page range display with ellipses
- URL parameter persistence

#### 6.2 Real-time Updates
- Watchdog-based file monitoring
- Automatic log ingestion on file changes
- Batch processing (500 logs per batch)
- 1-second flush intervals

### 7. Visualization & Analytics

#### 7.1 Traffic Metrics
- **Byte Counters**
  - Human-readable format (B, KB, MB, GB, TB)
  - Sent/Received byte tracking
  - Total traffic calculations
  
- **Duration Analysis**
  - Visual duration bars
  - Min/max duration tracking
  - Response time metrics

#### 7.2 Summary Statistics
- Total log count
- Unique source IPs
- Traffic volume summaries
- Connection duration stats

### 8. Security & Access Control

#### 8.1 User Management
- Django admin interface
- User authentication system
- Session management

#### 8.2 Network Security
- Support for multiple VLANs/interfaces
- Country-based traffic analysis
- Policy name tracking
- NAT translation tracking

### 9. System Administration

#### 9.1 Service Management
- Systemd service integration
- Automatic startup on boot
- Service health monitoring
- Graceful shutdown handling

#### 9.2 Configuration
- Environment-based configuration
- Customizable ClickHouse connection
- Flexible log file paths
- Rsyslog integration (UDP port 514)

### 10. Advanced Features

#### 10.1 Protocol Support
- TCP, UDP, ICMP protocol recognition
- Protocol number to name mapping
- Port service identification
- Application layer protocol tracking

#### 10.2 Geographic Analysis
- Source country tracking
- Destination country tracking
- Geographic traffic patterns

#### 10.3 Policy Analysis
- Policy ID and name tracking
- Policy type classification
- Policy UUID tracking
- Rule-based action tracking

### 11. Developer Features

#### 11.1 Template System
- Django template inheritance
- Reusable components (filters, headers, sidebars)
- Custom template tags for byte formatting
- Dictionary access filters

#### 11.2 API Integration
- RESTful URL structure
- JSON data serialization
- AJAX-ready endpoints

### 12. Monitoring & Alerts

#### 12.1 Visual Indicators
- Notification badge (100+ indicator)
- Color-coded status labels
- Action-based styling (green for accept, red for deny)

#### 12.2 Log Throttling
- Automatic detection of high log volumes
- Throttling indicators in UI
- Performance optimization for large datasets

## Technical Specifications

### Supported Log Fields
- **Network Information**: Source/Destination IPs, ports, interfaces, VLANs
- **Security Data**: Action, policy ID/name, threat level, categories
- **Performance Metrics**: Bytes sent/received, packets, duration, sessions
- **Metadata**: Timestamps, device names, log types, UUIDs
- **User Information**: Usernames, groups, authentication data
- **Geographic Data**: Source/destination countries

### Performance Capabilities
- Handles 12GB+ log files efficiently
- Processes thousands of logs per second
- Scales to billions of stored records
- Sub-second query response times

### Integration Points
- Rsyslog for log collection
- ClickHouse for analytical storage
- Django for web interface
- Systemd for service management
- Watchdog for file monitoring

This firewall log analyzer provides enterprise-grade capabilities for centralized log management, real-time monitoring, and advanced security analytics across multiple firewall platforms.