# ClickHouse Disk Usage Monitoring Setup

## Overview

The log management interface shows accurate ClickHouse storage usage by reading actual filesystem disk usage. Due to permission restrictions on `/var/lib/clickhouse/`, a separate monitoring process is needed.

## Current Status

- **Functional**: The interface currently shows accurate disk usage (28.0 GB actual vs 26.5 GB ClickHouse reported)
- **Data Source**: `/home/net/analyzer/config/clickhouse_disk_usage.json`
- **Update Method**: Manual (needs automation setup)

## Automatic Updates Setup

### Option 1: Root Cron Job (Recommended)

Add to root's crontab to update every 5 minutes:

```bash
sudo crontab -e
```

Add this line:
```
*/5 * * * * /home/net/analyzer/scripts/update_clickhouse_disk_usage.sh
```

### Option 2: ClickHouse User Cron Job

Add to clickhouse user's crontab:

```bash
sudo crontab -u clickhouse -e
```

Add this line:
```
*/5 * * * * /home/net/analyzer/scripts/update_clickhouse_disk_usage.sh
```

### Option 3: Systemd Timer (Advanced)

Create a systemd service and timer for more robust monitoring.

## Manual Update

To manually update the disk usage information:

```bash
# As root:
sudo /home/net/analyzer/scripts/update_clickhouse_disk_usage.sh

# As clickhouse user:
sudo -u clickhouse /home/net/analyzer/scripts/update_clickhouse_disk_usage.sh
```

## Files

- **Monitor Script**: `/home/net/analyzer/scripts/update_clickhouse_disk_usage.sh`
- **Data File**: `/home/net/analyzer/config/clickhouse_disk_usage.json`
- **Backup Script**: `/home/net/analyzer/scripts/clickhouse_disk_monitor.py`

## Current Data

The interface currently shows:
- **Actual Disk Usage**: 28.0 GB (accurate filesystem measurement)
- **ClickHouse Reported**: 26.5 GB (from system.parts table)
- **Difference**: 1.5 GB (metadata, logs, temp files, overhead)
- **Usage Percentage**: Based on actual disk usage for accurate monitoring

## Storage Configuration

The interface allows configuring:
- **Allocated Space**: Currently set to 200 GB
- **Warning Threshold**: 80% (160 GB)
- **Critical Threshold**: 90% (180 GB)
- **Status**: Currently showing "Normal" at 14.0% usage

## Troubleshooting

If disk usage shows "N/A":
1. Check if the data file exists: `ls -la /home/net/analyzer/config/clickhouse_disk_usage.json`
2. Verify file permissions: `chmod 644 /home/net/analyzer/config/clickhouse_disk_usage.json`
3. Check cron job status: `sudo tail -f /var/log/syslog | grep clickhouse_disk`
4. Manual run: `sudo /home/net/analyzer/scripts/update_clickhouse_disk_usage.sh`