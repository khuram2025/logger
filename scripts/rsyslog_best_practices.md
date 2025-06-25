# Rsyslog Best Practices for Network Log Collection

## Current Setup
- FortiGate logs: `/var/log/fortigate.log` from IP 192.168.100.221
- PaloAlto logs: `/var/log/paloalto-1004.log`

## Recommended Improvements

### 1. Add Queue Management
To prevent log loss during high traffic or parser downtime:

```conf
# Add to /etc/rsyslog.d/fortigate.conf
if ($fromhost-ip == '192.168.100.221') then {
    action(
        type="omfile"
        file="/var/log/fortigate.log"
        template="FortiGateRaw"
        # Add queue management
        queue.type="LinkedList"
        queue.filename="fortigate"
        queue.maxdiskspace="1g"
        queue.saveonshutdown="on"
        queue.highwatermark="10000"
        queue.lowwatermark="2000"
    )
    stop
}
```

### 2. Add Rate Limiting
Prevent log flooding:

```conf
# Add to beginning of config files
$SystemLogRateLimitInterval 1
$SystemLogRateLimitBurst 5000
```

### 3. Optimize Performance
```conf
# Add to /etc/rsyslog.conf
$WorkDirectory /var/spool/rsyslog
$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat
$FileCreateMode 0644
$DirCreateMode 0755
$Umask 0022
```

### 4. Monitor Rsyslog Health
Create `/etc/rsyslog.d/00-stats.conf`:

```conf
module(load="impstats"
       interval="600"
       severity="6"
       log.syslog="on"
       log.file="/var/log/rsyslog-stats.log")
```

### 5. Prevent Duplicate Processing
Ensure configs don't overlap:

```bash
# Check for duplicate rules
grep -h "fromhost-ip\|:514" /etc/rsyslog.d/*.conf | sort | uniq -d
```

## Implementation Steps

1. **Backup current configs:**
   ```bash
   sudo cp -r /etc/rsyslog.d /etc/rsyslog.d.backup.$(date +%Y%m%d)
   ```

2. **Test configuration:**
   ```bash
   sudo rsyslogd -N1
   ```

3. **Apply changes:**
   ```bash
   sudo systemctl restart rsyslog
   ```

4. **Verify operation:**
   ```bash
   sudo journalctl -u rsyslog -f
   ```

## Monitoring Commands

```bash
# Check rsyslog status
sudo systemctl status rsyslog

# View recent errors
sudo journalctl -u rsyslog --since "1 hour ago" | grep -i error

# Check queue status (if impstats enabled)
tail -f /var/log/rsyslog-stats.log

# Monitor incoming logs
sudo tcpdump -i any -n port 514 -c 100
```