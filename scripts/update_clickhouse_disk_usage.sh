#!/bin/bash
# Update ClickHouse disk usage information
# This script should be run by root or clickhouse user via cron

CLICKHOUSE_PATH="/var/lib/clickhouse/"
OUTPUT_FILE="/home/net/analyzer/config/clickhouse_disk_usage.json"
PYTHON_SCRIPT="/home/net/analyzer/scripts/clickhouse_disk_monitor.py"

# Ensure output directory exists
mkdir -p "$(dirname "$OUTPUT_FILE")"

# Get disk usage in bytes
USAGE_BYTES=$(du -sb "$CLICKHOUSE_PATH" 2>/dev/null | awk '{print $1}')

if [ -n "$USAGE_BYTES" ] && [ "$USAGE_BYTES" -gt 0 ]; then
    # Calculate GB for display
    USAGE_GB=$(echo "scale=2; $USAGE_BYTES / 1024 / 1024 / 1024" | bc)
    
    # Create JSON output
    cat > "$OUTPUT_FILE" << EOF
{
  "path": "$CLICKHOUSE_PATH",
  "usage_bytes": $USAGE_BYTES,
  "usage_formatted": "${USAGE_GB} GB",
  "timestamp": "$(date -Iseconds)",
  "status": "success",
  "updated_by": "cron_script"
}
EOF
    
    echo "Disk usage updated: ${USAGE_GB} GB"
else
    # Create error output
    cat > "$OUTPUT_FILE" << EOF
{
  "path": "$CLICKHOUSE_PATH",
  "usage_bytes": null,
  "usage_formatted": "N/A",
  "timestamp": "$(date -Iseconds)",
  "status": "error",
  "error": "Permission denied or path not accessible",
  "updated_by": "cron_script"
}
EOF
    
    echo "Error: Could not access ClickHouse directory"
fi

# Set permissions so web app can read it
chmod 644 "$OUTPUT_FILE" 2>/dev/null || true