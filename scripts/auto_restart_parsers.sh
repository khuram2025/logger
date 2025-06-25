#!/bin/bash
# Auto-restart parsers if they're not running or have issues

SCRIPT_DIR="/home/net/analyzer/scripts"
ENV_DIR="/home/net/analyzer/env"
LOG_DIR="/tmp"

# Function to check if parser is running
is_parser_running() {
    local parser_name=$1
    pgrep -f "$parser_name" > /dev/null
    return $?
}

# Function to start parser
start_parser() {
    local parser_script=$1
    local log_file=$2
    
    echo "Starting $parser_script..."
    source "$ENV_DIR/bin/activate"
    nohup python "$SCRIPT_DIR/$parser_script" > "$LOG_DIR/$log_file" 2>&1 &
    sleep 2
    
    if is_parser_running "$parser_script"; then
        echo "✅ $parser_script started successfully"
        return 0
    else
        echo "❌ Failed to start $parser_script"
        return 1
    fi
}

# Check and restart FortiGate parser
if ! is_parser_running "enhanced_fortigate_to_clickhouse"; then
    echo "⚠️  FortiGate parser not running, attempting restart..."
    start_parser "enhanced_fortigate_to_clickhouse.py" "fortigate_enhanced.log"
else
    echo "✅ FortiGate parser is running"
fi

# Check and restart PaloAlto parser
if ! is_parser_running "enhanced_paloalto_to_clickhouse"; then
    echo "⚠️  PaloAlto parser not running, attempting restart..."
    start_parser "enhanced_paloalto_to_clickhouse.py" "paloalto_enhanced.log"
else
    echo "✅ PaloAlto parser is running"
fi

# Run health check
echo -e "\nRunning health check..."
python "$SCRIPT_DIR/parser_monitor.py"

# Setup cron job for automatic monitoring
CRON_JOB="*/5 * * * * $SCRIPT_DIR/auto_restart_parsers.sh > /tmp/parser_restart.log 2>&1"
(crontab -l 2>/dev/null | grep -v "auto_restart_parsers.sh"; echo "$CRON_JOB") | crontab -

echo -e "\n✅ Cron job installed for automatic monitoring every 5 minutes"