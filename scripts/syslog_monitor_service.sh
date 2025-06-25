#!/bin/bash
# Syslog Monitor Service Script
# This script manages the syslog traffic monitor as a background service

SCRIPT_DIR="/home/net/analyzer/scripts"
ENV_DIR="/home/net/analyzer/env"
PID_FILE="/var/run/syslog_monitor.pid"
LOG_FILE="/var/log/syslog_monitor.log"

# Ensure we're running with appropriate permissions
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root or with sudo for network monitoring capabilities"
    exit 1
fi

start() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if ps -p $PID > /dev/null 2>&1; then
            echo "Syslog monitor is already running (PID: $PID)"
            return 1
        fi
    fi
    
    echo "Starting syslog monitor..."
    
    # Activate virtual environment and start monitor
    source "$ENV_DIR/bin/activate"
    nohup python "$SCRIPT_DIR/syslog_traffic_monitor.py" > "$LOG_FILE" 2>&1 &
    PID=$!
    
    echo $PID > "$PID_FILE"
    echo "Syslog monitor started (PID: $PID)"
    echo "Logs: $LOG_FILE"
}

stop() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if ps -p $PID > /dev/null 2>&1; then
            echo "Stopping syslog monitor (PID: $PID)..."
            kill $PID
            sleep 2
            
            # Force kill if still running
            if ps -p $PID > /dev/null 2>&1; then
                kill -9 $PID
            fi
            
            rm -f "$PID_FILE"
            echo "Syslog monitor stopped"
        else
            echo "Syslog monitor is not running"
            rm -f "$PID_FILE"
        fi
    else
        echo "Syslog monitor is not running"
    fi
}

status() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if ps -p $PID > /dev/null 2>&1; then
            echo "Syslog monitor is running (PID: $PID)"
            
            # Show recent log entries
            echo -e "\nRecent activity:"
            tail -5 "$LOG_FILE" 2>/dev/null
            
            # Show current detections
            echo -e "\nChecking for detected sources..."
            source "$ENV_DIR/bin/activate"
            python -c "
import sys
sys.path.append('$SCRIPT_DIR')
from network_scanner import NetworkScanner
scanner = NetworkScanner()
results = scanner.discover_from_logs(hours=1)
print(f'Sources detected in last hour: {len(results)}')
for r in results[:5]:
    print(f\"  - {r['ip']} ({r.get('hostname', 'Unknown')})\")
"
        else
            echo "Syslog monitor is not running (stale PID file)"
            rm -f "$PID_FILE"
        fi
    else
        echo "Syslog monitor is not running"
    fi
}

case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        stop
        sleep 2
        start
        ;;
    status)
        status
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac