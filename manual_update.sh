#!/bin/bash

echo "🔄 Manually updating the binary..."

# Stop service
echo "Stopping service..."
echo "Read@123" | sudo -S systemctl stop fortigate-syslog

# Wait for process to stop
sleep 3

# Kill any remaining processes
echo "Killing remaining processes..."
echo "Read@123" | sudo -S pkill -f fortigate-syslog-rust
sleep 2

# Copy the new binary
echo "Copying new binary..."
echo "Read@123" | sudo -S cp /home/net/analyzer/fortigate-syslog-rust/target/release/fortigate-syslog-rust /opt/fortigate-syslog-rust/

# Set permissions
echo "Setting permissions..."
echo "Read@123" | sudo -S chown syslog:syslog /opt/fortigate-syslog-rust/fortigate-syslog-rust
echo "Read@123" | sudo -S chmod +x /opt/fortigate-syslog-rust/fortigate-syslog-rust
echo "Read@123" | sudo -S setcap 'cap_net_bind_service=+ep' /opt/fortigate-syslog-rust/fortigate-syslog-rust

# Start service
echo "Starting service..."
echo "Read@123" | sudo -S systemctl start fortigate-syslog

# Check status
sleep 2
systemctl is-active fortigate-syslog && echo "✅ Service started successfully!" || echo "❌ Service failed to start"

# Verify Palo Alto support
echo "Checking for Palo Alto support..."
if strings /opt/fortigate-syslog-rust/fortigate-syslog-rust | grep -q "paloalto"; then
    echo "✅ Palo Alto parser detected!"
else
    echo "❌ Palo Alto parser not found"
fi