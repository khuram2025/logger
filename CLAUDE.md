# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a comprehensive network log analysis platform that processes, stores, and visualizes firewall logs from FortiGate and Palo Alto devices. The system uses Django for the web interface, ClickHouse for high-performance log storage, and Rust parsers for efficient log processing.

## Architecture

### Core Components

1. **Django Web Application** (`dashboard/`, `fwanalyzer/`)
   - Main web interface for log visualization and management
   - Device registration and configuration
   - Real-time traffic analysis and URL filtering views
   - ClickHouse integration for querying log data

2. **Rust Syslog Receivers** (`fortigate-syslog-rust/`)
   - High-performance syslog listeners (UDP port 514)
   - Parse FortiGate and Palo Alto logs in real-time
   - Direct ClickHouse insertion for optimal performance
   - Device authentication via both database and config file

3. **ClickHouse Database**
   - Primary storage for all log data
   - Tables: `fortigate_traffic`, `paloalto_traffic`, `pa_url_logs`
   - Optimized for time-series queries and aggregations

4. **Background Services**
   - Multiple systemd services for log processing
   - Monitoring and auto-restart scripts in `scripts/`
   - Log rotation and cleanup processes

## Development Commands

### Django Application

```bash
# Activate virtual environment
source env/bin/activate

# Run development server
python manage.py runserver 0.0.0.0:8001

# Run Django checks
python manage.py check

# Database migrations
python manage.py makemigrations
python manage.py migrate

# Collect static files
python manage.py collectstatic --noinput

# Django shell
python manage.py shell
```

### Rust Parsers

```bash
# Build Rust parser
cd fortigate-syslog-rust
cargo build --release

# Run with debug logging
RUST_LOG=debug ./target/release/fortigate-syslog-rust --config /etc/fortigate-syslog-rust/config.toml

# Check compilation
cargo check

# Run tests
cargo test
```

### Service Management

```bash
# Check service status
sudo systemctl status fortigate-syslog.service
sudo systemctl status paloalto-processor.service
sudo systemctl status gunicorn.service

# Restart services
sudo systemctl restart fortigate-syslog.service
sudo systemctl daemon-reload

# View service logs
sudo journalctl -u fortigate-syslog.service -f

# Start enhanced processors
./start_enhanced_processors.sh
```

### ClickHouse Operations

```bash
# Connect to ClickHouse
clickhouse-client

# Common queries
USE network_logs;
SELECT * FROM fortigate_traffic ORDER BY timestamp DESC LIMIT 10;
SELECT * FROM paloalto_traffic ORDER BY timestamp DESC LIMIT 10;
SELECT * FROM pa_url_logs ORDER BY timestamp DESC LIMIT 10;
```

### Monitoring & Debugging

```bash
# Monitor syslog traffic
sudo tcpdump -i any -A -n 'port 514' -c 5
sudo tcpdump -i any host 10.10.100.2 and port 514 -A

# Check log files
tail -f /var/log/fortigate.log
tail -f logs/gunicorn_error.log

# Run parser monitor
python scripts/parser_monitor.py

# Manual URL processing
python scripts/manual_url_processor.py
```

## Key Configuration Files

- **Django settings**: `fwanalyzer/settings.py`
- **Rust parser config**: `/etc/fortigate-syslog-rust/config.toml`
- **Nginx config**: `nginx_analyzer.conf`
- **Gunicorn config**: `gunicorn.conf.py`
- **Service definitions**: `*.service` files in root directory

## Database Schema

### ClickHouse Tables

- `fortigate_traffic`: FortiGate firewall traffic logs
- `paloalto_traffic`: Palo Alto firewall traffic logs  
- `pa_url_logs`: Palo Alto URL filtering logs
- `registered_devices`: Device registration and authentication

### Django Models

- Located in `dashboard/models.py`
- Device management: zones, subnets, interfaces
- Log source configuration

## Important Notes

1. **Device Authorization**: Devices require dual authorization:
   - Database registration via web interface
   - Config file allowlist in `/etc/fortigate-syslog-rust/config.toml`

2. **Performance Optimization**:
   - Use Rust parsers for high-volume log ingestion
   - ClickHouse for efficient time-series queries
   - Implement proper log rotation to prevent disk issues

3. **Debugging Tips**:
   - Check both application logs and system journals
   - Verify network connectivity with tcpdump
   - Monitor ClickHouse disk usage and query performance

4. **Testing**:
   - Test parsers: `python test_paloalto_log.py`, `python test_fortigate_format.py`
   - Test URL parsing: `python scripts/test_url_parsing.py`
   - Monitor real-time processing: `python scripts/test_realtime_processing.py`

## Common Development Tasks

### Adding New Log Fields

1. Update Rust parser structs in `fortigate-syslog-rust/src/`
2. Modify ClickHouse table schema with ALTER TABLE
3. Update Django views and templates to display new fields
4. Rebuild and deploy Rust parser

### Implementing New Features

1. For UI changes: Modify templates in `dashboard/templates/`
2. For new views: Add to `dashboard/views/` and update `dashboard/urls.py`
3. For API endpoints: Implement in views and add URL patterns
4. Static files: Place in `dashboard/static/` and run collectstatic

### Troubleshooting Log Ingestion

1. Verify device is sending logs: `tcpdump -i any port 514`
2. Check parser is running: `systemctl status fortigate-syslog.service`
3. Verify device registration in database and config file
4. Check ClickHouse insertion: monitor table row counts
5. Review parser logs for errors: `journalctl -u fortigate-syslog.service`