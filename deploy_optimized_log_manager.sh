#!/bin/bash

# Deploy Optimized Log Manager
echo "Deploying optimized log manager..."

# Install pigz for faster parallel compression
echo "Installing pigz for faster compression..."
echo "Read@123" | sudo -S apt update
sudo apt install -y pigz

# Stop the current service
echo "Stopping current log-manager service..."
sudo systemctl stop log-manager.service

# Copy updated service file
echo "Updating service file..."
sudo cp /home/net/analyzer/log-manager.service /etc/systemd/system/

# Reload systemd daemon
echo "Reloading systemd daemon..."
sudo systemctl daemon-reload

# Start the optimized service
echo "Starting optimized log-manager service..."
sudo systemctl start log-manager.service

# Check service status
echo "Checking service status..."
sudo systemctl status log-manager.service --no-pager

# Show recent logs
echo ""
echo "Recent logs:"
tail -10 /var/log/log-manager.log

echo ""
echo "Optimized log manager deployed successfully!"
echo ""
echo "Key improvements:"
echo "- Asynchronous compression using background threads"
echo "- Parallel compression with pigz (faster than gzip)"
echo "- Better monitoring and status reporting"
echo "- Non-blocking file rotation"
echo ""
echo "To monitor: tail -f /var/log/log-manager.log"