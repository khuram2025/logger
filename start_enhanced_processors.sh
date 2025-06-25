#!/bin/bash
cd /home/net/analyzer
source env/bin/activate

echo "Starting enhanced log processors..."

# Kill any existing processors
pkill -f enhanced_fortigate_to_clickhouse
pkill -f enhanced_paloalto_to_clickhouse
sleep 2

# Start enhanced processors
nohup python scripts/enhanced_fortigate_to_clickhouse.py > /tmp/fortigate-enhanced.log 2>&1 &
nohup python scripts/enhanced_paloalto_to_clickhouse.py > /tmp/paloalto-enhanced.log 2>&1 &

echo "Enhanced processors started"
sleep 2

# Show status
ps aux | grep enhanced | grep -v grep