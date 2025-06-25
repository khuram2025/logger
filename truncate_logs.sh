#!/bin/bash
# Script to truncate log files and restart enhanced processors

echo "Stopping all log processors..."
pkill -f enhanced_fortigate_to_clickhouse
pkill -f enhanced_paloalto_to_clickhouse
pkill -f fortigate_to_clickhouse
pkill -f paloalto_to_clickhouse
sleep 3

echo "Truncating log files..."
sudo truncate -s 0 /var/log/fortigate.log
sudo truncate -s 0 /var/log/paloalto-1004.log

echo "Log files truncated:"
ls -la /var/log/fortigate.log /var/log/paloalto-1004.log

echo "Starting enhanced processors..."
cd /home/net/analyzer
source env/bin/activate
nohup python scripts/enhanced_fortigate_to_clickhouse.py > /tmp/fortigate-enhanced.log 2>&1 &
nohup python scripts/enhanced_paloalto_to_clickhouse.py > /tmp/paloalto-enhanced.log 2>&1 &

echo "Enhanced processors started"
sleep 2
ps aux | grep enhanced | grep -v grep