#!/bin/bash
# Script to update systemd service configuration

SERVICE_FILE="/etc/systemd/system/paloalto-processor.service"

cat > paloalto-processor.service << 'EOF'
[Unit]
Description=Enhanced PaloAlto Log Processor (Traffic + URL)
After=network.target clickhouse-server.service
Wants=clickhouse-server.service

[Service]
Type=simple
User=net
Group=net
WorkingDirectory=/home/net/analyzer
Environment="PATH=/home/net/analyzer/env/bin:/usr/local/bin:/usr/bin:/bin"
Environment="CH_HOST=localhost"
Environment="CH_PORT=9000"
Environment="CH_USER=default"
Environment="CH_PASSWORD=Read@123"
Environment="CH_DB=network_logs"
ExecStart=/home/net/analyzer/env/bin/python /home/net/analyzer/scripts/enhanced_paloalto_to_clickhouse.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=paloalto-processor

# Resource limits
LimitNOFILE=65536
MemoryLimit=1G

# Watchdog
WatchdogSec=300
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF

echo "Service file created: paloalto-processor.service"
echo ""
echo "To install and start the service, run:"
echo "sudo cp paloalto-processor.service /etc/systemd/system/"
echo "sudo systemctl daemon-reload"
echo "sudo systemctl stop paloalto-url-loader.service"
echo "sudo systemctl disable paloalto-url-loader.service"
echo "sudo systemctl enable paloalto-processor.service"
echo "sudo systemctl start paloalto-processor.service"