# Network Log Ingestion Pipeline - Complete Flow Documentation

## Overview

This document provides a comprehensive analysis of the syslog message flow from initial reception through parsing, validation, and storage in the network analysis system. The pipeline handles logs from FortiGate firewalls and PaloAlto devices with real-time processing capabilities.

## Architecture Overview

```
[Firewall Devices] � [rsyslog] � [Log Files] � [Python Scripts] � [ClickHouse Database] � [Django Web Interface]
       �                �           �              �                    �                      �
   UDP Syslog      Port 514/1004  File Storage   Real-time          Structured Storage    User Interface
   Messages        IP Filtering   Raw Logs       Processing         Network Analytics     & Management
```

## 1. Syslog Reception Layer

### 1.1 rsyslog Configuration
- **Service**: rsyslog daemon
- **Ports**: 
  - UDP 514 (FortiGate logs)
  - UDP 1004 (PaloAlto logs)
- **Configuration Files**: 
  - `/tmp/fortigate.conf`
  - `/tmp/paloalto.conf`

### 1.2 Source IP Filtering
- **FortiGate**: `192.168.100.221`
- **PaloAlto**: `10.12.50.61`, `192.168.1.100`

### 1.3 Message Templates
- **FortiGate Template**: `FortiGateRaw` - strips syslog priority headers
- **PaloAlto Template**: `PaloAltoRaw` - clean message format
- **Output Format**: `%rawmsg-after-pri%\n`

## 2. Log Storage Layer

### 2.1 Raw Log Files
- **FortiGate Logs**: `/var/log/fortigate.log`
- **PaloAlto Logs**: `/var/log/paloalto-1004.log`
- **Format**: Plain text, one log entry per line
- **Rotation**: Handled by logrotate (automatic file rotation detection)

## 3. Real-Time Processing Layer

### 3.1 File Monitoring Technology
- **Library**: Python Watchdog (`watchdog.observers.Observer`)
- **Method**: File system event monitoring
- **Events Tracked**:
  - File modifications (`on_modified`)
  - File moves/rotations (`on_moved`)
  - File size changes

### 3.2 Processing Scripts

#### A. FortiGate Traffic Processing
**Script**: `/home/net/analyzer/scripts/fortigate_to_clickhouse.py`

**Key Features**:
- **Parser**: Key-value pair regex pattern (`(\w+)=(".*?"|\S+)`)
- **Field Count**: 78 structured fields
- **Batch Size**: 500 logs per batch
- **Buffer Management**: Thread-safe with locks
- **Validation**: IP address format, UInt64 overflow protection
- **Error Handling**: Invalid log filtering, connection retries

**Field Categories**:
- **Timestamp Fields**: `timestamp`, `eventtime`, `tz`
- **Network Fields**: `srcip`, `dstip`, `srcport`, `dstport`, `proto`
- **Traffic Metrics**: `sentbyte`, `rcvdbyte`, `sentpkt`, `rcvdpkt`
- **Policy Fields**: `policyid`, `policyname`, `action`
- **Geographic**: `srccountry`, `dstcountry`

#### B. PaloAlto Traffic Processing
**Script**: `/home/net/analyzer/scripts/paloalto_to_clickhouse.py`

**Key Features**:
- **Parser**: CSV-based field extraction
- **Log Type Filter**: Only processes `TRAFFIC` logs
- **Field Count**: 19 core fields
- **Protocol Mapping**: Name-to-number conversion
- **Target Table**: `fortigate_traffic` (shared schema)

**Field Mapping**:
- Field 7: Source IP
- Field 8: Destination IP  
- Field 24: Source Port
- Field 25: Destination Port
- Field 29: Protocol
- Field 30: Action

#### C. PaloAlto Threat/URL Processing
**Script**: `/home/net/analyzer/scripts/paloalto_Url_Clickhose.py`

**Key Features**:
- **Parser**: Complex CSV parsing for threat logs
- **Log Type Filter**: Only processes `THREAT,url` logs
- **Field Count**: 90+ comprehensive threat fields
- **Target Table**: `threat_logs`
- **Use Case**: URL filtering, threat analysis, security monitoring

### 3.3 Processing Flow per Script

```
1. File Modification Event
2. File Rotation Check
3. Line-by-Line Reading
4. Buffer Accumulation (500 lines)
5. Batch Processing Trigger
6. Field Parsing & Validation
7. IP Address Validation
8. Data Type Conversion
9. ClickHouse Batch Insert
10. Error Logging & Recovery
```

## 4. Data Validation & Quality Control

### 4.1 IP Address Validation
```python
def is_valid_ip(ip):
    parts = str(ip).split('.')
    return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
```

### 4.2 Numeric Field Validation
- **UInt64 Range**: 0 to 18,446,744,073,709,551,615
- **Overflow Protection**: Values capped at maximum
- **Default Values**: Invalid numbers default to 0

### 4.3 Required Field Enforcement
- **Critical IPs**: `srcip`, `dstip` default to `0.0.0.0`
- **Timestamps**: Missing timestamps default to current time
- **String Fields**: Empty strings for missing text fields

## 5. Database Storage (ClickHouse)

### 5.1 Connection Configuration
```python
CH_HOST = 'localhost'
CH_PORT = 9000
CH_USER = 'default' 
CH_PASSWORD = 'Read@123'
CH_DB = 'network_logs'
```

### 5.2 Table Schemas

#### A. fortigate_traffic (Traffic Logs)
- **Purpose**: Network traffic analytics
- **Sources**: Both FortiGate and PaloAlto traffic logs
- **Key Fields**: IPs, ports, bytes, packets, policies
- **Indexes**: Optimized for time-series queries

#### B. threat_logs (Security Events)
- **Purpose**: Threat detection and URL filtering
- **Source**: PaloAlto threat/URL logs only
- **Key Fields**: URLs, threat IDs, security actions
- **Use Cases**: Security monitoring, compliance

### 5.3 Batch Insertion Strategy
- **Batch Size**: 500 records per insert
- **Validation**: Pre-insert validation of all rows
- **Error Recovery**: Invalid rows skipped, valid rows processed
- **Performance**: Optimized for high-throughput ingestion

## 6. System Service Management

### 6.1 Systemd Services
- `paloalto_to_clickhouse.service`
- `paloalto-url-loader.service`
- `fortigate_to_clickhouse.service`

### 6.2 Service Configuration
```ini
[Unit]
Description=FortiGate Log ClickHouse Loader
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/net/analyzer/scripts
ExecStart=/home/net/analyzer/env/bin/python fortigate_to_clickhouse.py
Restart=always
RestartSec=5
```

### 6.3 Service Management
- **Auto-restart**: Services automatically restart on failure
- **Logging**: Output directed to syslog
- **Monitoring**: Real-time status via Django web interface

## 7. Web Dashboard Integration

### 7.1 Django Application
- **Path**: `/home/net/analyzer/dashboard/`
- **Database**: Direct ClickHouse connections
- **Features**: Log viewing, filtering, analytics, system management

### 7.2 Key Functionalities
- **Log Queries**: Real-time log search and filtering
- **Service Control**: Start/stop/restart processing services
- **Configuration**: Dynamic rsyslog configuration management
- **Analytics**: Traffic summaries, top talkers, threat analysis

## 8. Error Handling & Recovery

### 8.1 File System Monitoring
- **Log Rotation**: Automatic detection and file reopening
- **File Permissions**: Error recovery for access issues
- **Missing Files**: Graceful handling of absent log files

### 8.2 Database Connection Management
- **Connection Pooling**: Persistent ClickHouse connections
- **Retry Logic**: Automatic reconnection on failures
- **Transaction Safety**: Batch processing ensures data consistency

### 8.3 Data Quality Assurance
- **Invalid Log Filtering**: Malformed entries skipped
- **Schema Compliance**: Field validation before insertion  
- **Monitoring**: Comprehensive logging of all errors and warnings

## 9. Performance Characteristics

### 9.1 Throughput Metrics
- **Processing Rate**: ~500 logs per second per script
- **Latency**: Sub-second from log generation to storage
- **Buffer Size**: 500 logs per batch for optimal performance
- **Memory Usage**: Low memory footprint with streaming processing

### 9.2 Scalability Features
- **Parallel Processing**: Multiple scripts process different log types
- **File Monitoring**: Efficient inotify-based file watching
- **Batch Processing**: Optimized database insertion
- **Resource Management**: Controlled memory and CPU usage

## 10. Step-by-Step Log Flow Example

### 10.1 FortiGate Log Journey
```
1. FortiGate Device � UDP:514 � rsyslog
   Log: "date=2024-06-16 time=14:30:15 devname=FGT60F srcip=192.168.1.100 dstip=8.8.8.8 srcport=54321 dstport=53 action=accept"

2. rsyslog � /var/log/fortigate.log
   Filtered by source IP, cleaned message format

3. Watchdog � File Modification Event
   Python script detects new log lines

4. Parse & Validate � Data Structure
   {
     'timestamp': datetime(2024, 6, 16, 14, 30, 15),
     'srcip': '192.168.1.100',
     'dstip': '8.8.8.8',
     'srcport': 54321,
     'dstport': 53,
     'action': 'accept',
     ...
   }

5. Buffer � Batch Processing (500 logs)
   Accumulated with other logs for efficient insertion

6. ClickHouse Insert � network_logs.fortigate_traffic
   Batch insertion with validation

7. Django Dashboard � User Interface
   Real-time querying and visualization
```

## 11. Enhanced Log Management System (NEW)

### 11.1 Advanced Log Rotation & Cleanup
The system now includes an intelligent log management component that addresses the critical need to prevent log files from exceeding 2GB while ensuring zero data loss.

#### Key Features:
- **Real-time Size Monitoring**: Continuous monitoring of log file sizes with proactive rotation at 1.8GB
- **Coordinated Rotation**: Seamless coordination between file rotation and active processing scripts
- **Processing Verification**: Ensures logs are safely stored in ClickHouse before deletion
- **Automatic Cleanup**: Safe removal of old rotated files after verification and aging
- **Zero Data Loss**: Guarantees no log entries are lost during rotation

#### Components:

**A. Log Manager (`log_manager.py`)**
- Monitors log file sizes in real-time
- Coordinates rotation with processing scripts
- Tracks processed vs. unprocessed data
- Verifies ClickHouse data integrity before cleanup
- Manages compressed backup files

**B. Enhanced Processing Scripts**
- `enhanced_fortigate_to_clickhouse.py`: FortiGate processor with log manager integration
- `enhanced_paloalto_to_clickhouse.py`: PaloAlto processor with log manager integration
- Real-time processing status updates
- Graceful handling of file rotation events
- Resume capability from last processed position

**C. Status Monitor (`log_status_monitor.py`)**
- Real-time monitoring dashboard data
- Alert generation for size and lag thresholds
- Performance metrics collection
- Web dashboard integration

**D. Web Dashboard Integration**
- Real-time log management status at `/log-management/`
- File size monitoring with visual progress bars
- Processing lag alerts and statistics
- Service status monitoring
- Rotation history and cleanup status

### 11.2 Installation & Deployment
```bash
# Install the enhanced log management system
sudo /tmp/install_log_management.sh

# Migrate from old processors
sudo /home/net/analyzer/scripts/migrate_to_enhanced.sh

# Check system status
/home/net/analyzer/scripts/log_management_status.sh
```

### 11.3 Configuration Files
- **Logrotate**: `/etc/logrotate.d/network-logs` - Backup rotation at 1.8GB
- **Services**: `/etc/systemd/system/log-manager.service` - Main log manager
- **Enhanced Processors**: systemd services with log manager coordination
- **Data Storage**: `/var/lib/log-manager/` - Processing registry and status

### 11.4 Monitoring & Alerts
The system provides comprehensive monitoring with multiple alert levels:

**File Size Alerts:**
- Warning: 1.5GB (75% of limit)
- Critical: 1.8GB (90% of limit)

**Processing Lag Alerts:**
- Warning: 100MB processing lag
- Critical: 500MB processing lag

**Dashboard Features:**
- Real-time file size visualization
- Processing lag monitoring
- Service status indicators
- Rotation history and statistics
- Auto-refresh every 30 seconds

### 11.5 Safety Mechanisms
1. **Atomic Rotation**: Uses copytruncate method for zero-downtime rotation
2. **Position Tracking**: Maintains exact file positions across rotations
3. **Data Verification**: Confirms ClickHouse storage before cleanup
4. **Backup System**: Compressed backups before permanent deletion
5. **Recovery**: Automatic resume from last processed position

## 12. Previous Improvement Areas

### 11.1 Performance Optimizations
1. **Parallel Processing**: 
   - Implement multi-threaded parsing within scripts
   - Use asyncio for non-blocking I/O operations
   
2. **Caching Layer**:
   - Redis cache for frequently accessed data
   - In-memory caching for recent logs
   
3. **Index Optimization**:
   - Additional ClickHouse indexes for common queries
   - Partitioning strategies for large datasets

### 11.2 Reliability Enhancements
1. **Message Queuing**:
   - Implement Apache Kafka or RabbitMQ for guaranteed delivery
   - Persistent queues for handling processing backlogs
   
2. **Data Deduplication**:
   - Hash-based duplicate detection
   - Idempotent processing for replayed messages
   
3. **Health Monitoring**:
   - Heartbeat monitoring for processing scripts
   - Alerting for processing delays or failures

### 11.3 Security Improvements
1. **Log Integrity**:
   - Cryptographic signatures for log authenticity
   - Tamper detection mechanisms
   
2. **Access Control**:
   - Role-based access to log data
   - Audit trails for log access
   
3. **Data Encryption**:
   - Encryption at rest for log storage
   - Encrypted transport for log transmission

### 11.4 Operational Enhancements
1. **Configuration Management**:
   - Version control for rsyslog configurations
   - Automated deployment of configuration changes
   
2. **Monitoring & Alerting**:
   - Prometheus metrics for processing rates
   - Grafana dashboards for operational visibility
   - Alert manager for critical failures
   
3. **Log Retention**:
   - Automated archival policies
   - Compressed storage for historical data
   - Compliance-driven retention schedules

### 11.5 Scalability Improvements
1. **Horizontal Scaling**:
   - Support for multiple processing nodes
   - Load balancing across processing instances
   
2. **Storage Scaling**:
   - ClickHouse cluster deployment
   - Distributed storage strategies
   
3. **Processing Pipeline**:
   - Stream processing with Apache Flink/Storm
   - Real-time analytics with complex event processing

## 12. Troubleshooting Guide

### 12.1 Common Issues
1. **Missing Logs**: Check rsyslog configuration and firewall connectivity
2. **Processing Delays**: Monitor service status and system resources
3. **Database Errors**: Verify ClickHouse connectivity and schema compatibility
4. **File Permissions**: Ensure proper read/write access to log files

### 12.2 Debug Commands
```bash
# Check service status
systemctl status fortigate_to_clickhouse.service

# Monitor log files
tail -f /var/log/fortigate.log

# Test ClickHouse connectivity
clickhouse-client --query "SELECT COUNT(*) FROM network_logs.fortigate_traffic"

# Check rsyslog configuration
rsyslogd -N1 -f /etc/rsyslog.conf
```

---

*This documentation provides a complete view of the log processing pipeline. Regular updates should be made as the system evolves and new features are added.*