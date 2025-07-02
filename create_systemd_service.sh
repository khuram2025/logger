#!/bin/bash

echo "Creating systemd service for Django Analyzer..."

# Create the systemd service file
sudo tee /etc/systemd/system/analyzer.service > /dev/null << 'EOF'
[Unit]
Description=Django Analyzer Application
After=network.target

[Service]
Type=simple
User=net
Group=net
WorkingDirectory=/home/net/analyzer
ExecStart=/home/net/analyzer/start_analyzer.sh
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and enable the service
sudo systemctl daemon-reload
sudo systemctl enable analyzer.service

echo "Systemd service created and enabled!"
echo "To start: sudo systemctl start analyzer"
echo "To check status: sudo systemctl status analyzer"
echo "To view logs: sudo journalctl -u analyzer -f"