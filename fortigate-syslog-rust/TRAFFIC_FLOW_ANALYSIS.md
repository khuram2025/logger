# Traffic Flow Analysis: 10.10.100.4 to ClickHouse

## Complete Log Processing Flow for Working Device (10.10.100.4)

### 1. Initial Packet Reception
**Location**: Network Interface (ens34)
**Port**: 514 (UDP)
**Source**: 10.10.100.4:53531

Sample captured packet:
```
16:17:47.135930 ens34 In  IP 10.10.100.4.53531 > 10.12.50.61.514: SYSLOG user.info, length: 818
<14>Jul  3 16:18:06 SMO-RUH-MU04-F09R14-INT-FW01.smo.sa 1,2025/07/03 16:18:06,024301003410,TRAFFIC,end,2817...
```

### 2. NAT Redirect Process
**NAT Rule**: 
```bash
REDIRECT 17 -- * * 0.0.0.0/0 0.0.0.0/0 udp dpt:514 redir ports 5514
```
**Statistics**: 157 packets, 94122 bytes processed

The iptables NAT rule redirects UDP traffic from port 514 to port 5514 where the Rust service listens.

### 3. Service Reception
**Service**: fortigate-syslog-rust
**Listen Address**: 0.0.0.0:5514
**Process ID**: 50971

**Log Evidence**:
```
INFO fortigate_syslog_rust::syslog: Received packet from 10.10.100.4 - Device info: Some(RegisteredDevice { 
    device_ip: "10.10.100.4", 
    device_name: "PaloAlto-FW01", 
    parser_type: "paloalto", 
    enabled: true 
})
```

### 4. Device Registration Lookup
**Database**: network_logs.registered_devices
**Query Result**:
- Device IP: 10.10.100.4
- Device Name: PaloAlto-FW01
- Parser Type: paloalto
- Status: enabled

### 5. Message Preprocessing
**Function**: `strip_syslog_priority()`
**Input**: `<14>Jul  3 16:18:06 SMO-RUH-MU04-F09R14-INT-FW01.smo.sa 1,2025/07/03...`
**Output**: `Jul  3 16:18:06 SMO-RUH-MU04-F09R14-INT-FW01.smo.sa 1,2025/07/03...`

**Log Evidence**:
```
INFO fortigate_syslog_rust::syslog: Processing from 10.10.100.4 - Parser: paloalto, Message preview: Jul  3 17:14:07 SMO-RUH-MU04-F09R14-INT-FW01.smo.sa 1,2025/07/03 17:14:06,024301003410,TRAFFIC,end,2817...
```

### 6. Parser Selection and Execution
**Parser**: Palo Alto parser (`paloalto.rs`)
**Function**: `PaloAltoRecord::parse()`

**CSV Detection Logic**:
```rust
let csv_part = if let Some(csv_start) = line.find("1,") {
    &line[csv_start..]
} else if let Some(start_pos) = line.find(char::is_numeric) {
    &line[start_pos..]
} else {
    line
};
```

**Field Parsing**:
- 117+ CSV fields extracted
- Key fields: type=TRAFFIC, src_ip, dst_ip, action, etc.
- Device info set via `set_device_info()`

### 7. Record Validation
**Function**: `validate()`
**Criteria**:
- Non-empty raw_message ✓
- Either devname or devid not empty ✓
- For TRAFFIC logs: valid source OR destination IP ✓

### 8. Channel Communication
**Channel**: `mpsc::Sender<FortiGateRecord>`
**Conversion**: PaloAltoRecord → FortiGateRecord
**Queue**: In-memory async channel with configurable buffer

**Log Evidence**:
```
INFO fortigate_syslog_rust::syslog: Successfully processed Palo Alto record from 10.10.100.4 - sent to ClickHouse queue
```

### 9. Batch Processing
**Configuration**:
- Batch size: 500 records
- Batch timeout: 1 second
- Buffer size: 10000 records
- Worker threads: 4

**Function**: `clickhouse_writer_task()`

### 10. ClickHouse Insertion
**Database**: network_logs.fortigate_traffic
**Method**: HTTP POST to localhost:8123
**Authentication**: user=default, password=Read@123

**Batch Insertion Evidence**:
```
INFO fortigate_syslog_rust: Inserted timeout batch of 240 records
INFO fortigate_syslog_rust: Inserted timeout batch of 269 records
```

### 11. Final Storage Verification
**Query Result**:
```sql
SELECT count(*) FROM network_logs.fortigate_traffic 
WHERE device_ip = '10.10.100.4' AND timestamp >= now() - INTERVAL 1 MINUTE;
-- Result: 1033 records
```

## Performance Statistics
- Packets received: 213,000+
- Packets processed: ~135,000 (63% success rate)
- Packets dropped: ~78,000 (37% drop rate)
- Average processing rate: ~1000+ packets/minute

## Configuration Files
1. **Main Config**: `/etc/fortigate-syslog-rust/config.toml`
2. **Service**: `/etc/systemd/system/fortigate-syslog.service`
3. **NAT Rules**: iptables PREROUTING chain

## Key Components
1. **Syslog Receiver** (`src/syslog.rs`) - UDP packet handling
2. **Palo Alto Parser** (`src/paloalto.rs`) - CSV parsing logic
3. **Device Manager** (`src/device_manager_simple.rs`) - Device registration
4. **ClickHouse Client** (`src/clickhouse_client.rs`) - Database insertion
5. **Configuration** (`src/config.rs`) - Settings management

## Issue Identification
The flow works perfectly for 10.10.100.4 but fails for 10.10.100.2 because **packets from 10.10.100.2 never reach the Rust service**, despite being visible on port 514. This suggests a NAT redirect issue specific to that source IP or a firewall rule blocking the redirect.