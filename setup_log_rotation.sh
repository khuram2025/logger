#!/bin/bash

# Setup Log Rotation Service
# This script configures and starts the log-manager service

echo "Setting up log rotation service..."

# Create required directories
echo "Creating required directories..."
echo "Read@123" | sudo -S mkdir -p /var/lib/log-manager/backups
sudo chmod 755 /var/lib/log-manager
sudo chown -R root:root /var/lib/log-manager

# Copy service file to systemd directory
echo "Installing log-manager service..."
sudo cp /home/net/analyzer/log-manager.service /etc/systemd/system/

# Reload systemd daemon
echo "Reloading systemd daemon..."
sudo systemctl daemon-reload

# Enable and start the service
echo "Enabling and starting log-manager service..."
sudo systemctl enable log-manager.service
sudo systemctl start log-manager.service

# Check service status
echo "Checking service status..."
sudo systemctl status log-manager.service --no-pager

# Manually rotate oversized files first
echo ""
echo "Current log file sizes:"
ls -lh /var/log/fortigate.log /var/log/paloalto-1004.log 2>/dev/null || echo "Log files not found"

echo ""
echo "Rotating oversized log files..."

# Rotate FortiGate log if it exists and is over 2GB
if [ -f "/var/log/fortigate.log" ]; then
    SIZE=$(stat -c%s "/var/log/fortigate.log")
    if [ $SIZE -gt 2147483648 ]; then
        echo "Rotating /var/log/fortigate.log ($(numfmt --to=iec $SIZE))..."
        TIMESTAMP=$(date +%Y%m%d_%H%M%S)
        sudo cp /var/log/fortigate.log "/var/lib/log-manager/backups/fortigate.log.$TIMESTAMP"
        sudo truncate -s 0 /var/log/fortigate.log
        echo "FortiGate log rotated successfully"
    fi
fi

# Rotate PaloAlto log if it exists and is over 2GB
if [ -f "/var/log/paloalto-1004.log" ]; then
    SIZE=$(stat -c%s "/var/log/paloalto-1004.log")
    if [ $SIZE -gt 2147483648 ]; then
        echo "Rotating /var/log/paloalto-1004.log ($(numfmt --to=iec $SIZE))..."
        TIMESTAMP=$(date +%Y%m%d_%H%M%S)
        sudo cp /var/log/paloalto-1004.log "/var/lib/log-manager/backups/paloalto-1004.log.$TIMESTAMP"
        sudo truncate -s 0 /var/log/paloalto-1004.log
        echo "PaloAlto log rotated successfully"
    fi
fi

echo ""
echo "Log file sizes after rotation:"
ls -lh /var/log/fortigate.log /var/log/paloalto-1004.log 2>/dev/null

echo ""
echo "Log rotation setup complete!"
echo ""
echo "To check log-manager service status: sudo systemctl status log-manager"
echo "To view logs: sudo journalctl -u log-manager -f"
echo "To restart service: sudo systemctl restart log-manager"