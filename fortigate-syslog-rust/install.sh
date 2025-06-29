#!/bin/bash

# FortiGate Syslog Rust - Installation Script
# This script installs the FortiGate syslog receiver and replaces rsyslog

set -e

echo "🚀 Installing FortiGate Syslog Rust Receiver..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}" 
   exit 1
fi

# Build the application
echo -e "${YELLOW}Building Rust application...${NC}"
if ! cargo build --release; then
    echo -e "${RED}Failed to build Rust application${NC}"
    exit 1
fi

# Create directories
echo -e "${YELLOW}Creating directories...${NC}"
mkdir -p /opt/fortigate-syslog-rust
mkdir -p /etc/fortigate-syslog-rust
mkdir -p /var/log/fortigate-syslog-rust

# Copy binary
echo -e "${YELLOW}Installing binary...${NC}"
cp target/release/fortigate-syslog-rust /opt/fortigate-syslog-rust/
chmod +x /opt/fortigate-syslog-rust/fortigate-syslog-rust

# Copy configuration
echo -e "${YELLOW}Installing configuration...${NC}"
cp config.toml /etc/fortigate-syslog-rust/
chmod 644 /etc/fortigate-syslog-rust/config.toml

# Create syslog user
echo -e "${YELLOW}Creating syslog user...${NC}"
if ! id -u syslog >/dev/null 2>&1; then
    useradd -r -s /bin/false -d /nonexistent syslog
    echo -e "${GREEN}Created syslog user${NC}"
else
    echo -e "${GREEN}syslog user already exists${NC}"
fi

# Set permissions
chown -R syslog:syslog /var/log/fortigate-syslog-rust
chown syslog:syslog /opt/fortigate-syslog-rust/fortigate-syslog-rust

# Grant capability to bind to port 514
echo -e "${YELLOW}Granting network binding capability...${NC}"
setcap 'cap_net_bind_service=+ep' /opt/fortigate-syslog-rust/fortigate-syslog-rust

# Install systemd service
echo -e "${YELLOW}Installing systemd service...${NC}"
cp fortigate-syslog.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable fortigate-syslog

# Stop and disable rsyslog fortigate processing
echo -e "${YELLOW}Configuring rsyslog...${NC}"
if systemctl is-active --quiet rsyslog; then
    echo -e "${YELLOW}Stopping rsyslog to prevent conflicts...${NC}"
    systemctl stop rsyslog
    
    # Backup and disable fortigate.conf
    if [ -f /etc/rsyslog.d/fortigate.conf ]; then
        cp /etc/rsyslog.d/fortigate.conf /etc/rsyslog.d/fortigate.conf.backup
        echo -e "${GREEN}Backed up /etc/rsyslog.d/fortigate.conf${NC}"
        
        # Comment out the fortigate configuration
        sed -i 's/^/# DISABLED BY RUST SERVICE: /' /etc/rsyslog.d/fortigate.conf
        echo -e "${GREEN}Disabled FortiGate rsyslog configuration${NC}"
    fi
    
    # Restart rsyslog with disabled fortigate config
    systemctl start rsyslog
else
    echo -e "${GREEN}rsyslog is not running${NC}"
fi

# Test ClickHouse connection
echo -e "${YELLOW}Testing ClickHouse connection...${NC}"
if clickhouse-client -q "SELECT 1" >/dev/null 2>&1; then
    echo -e "${GREEN}ClickHouse connection successful${NC}"
else
    echo -e "${RED}⚠️  ClickHouse connection failed - please check ClickHouse is running and credentials are correct${NC}"
fi

# Start the service
echo -e "${YELLOW}Starting FortiGate Syslog Rust service...${NC}"
systemctl start fortigate-syslog

# Check status
if systemctl is-active --quiet fortigate-syslog; then
    echo -e "${GREEN}✅ FortiGate Syslog Rust service started successfully!${NC}"
    echo ""
    echo "📊 Service Status:"
    systemctl status fortigate-syslog --no-pager -l
    echo ""
    echo "📝 View logs: sudo journalctl -u fortigate-syslog -f"
    echo "🔧 Edit config: sudo nano /etc/fortigate-syslog-rust/config.toml"
    echo "🔄 Restart service: sudo systemctl restart fortigate-syslog"
    echo ""
    echo -e "${GREEN}Installation completed successfully!${NC}"
    echo -e "${YELLOW}The service is now listening on UDP port 514 for FortiGate logs${NC}"
else
    echo -e "${RED}❌ Failed to start FortiGate Syslog Rust service${NC}"
    echo "Check logs: sudo journalctl -u fortigate-syslog -n 50"
    exit 1
fi