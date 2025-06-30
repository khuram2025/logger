#!/bin/bash

# Update FortiGate Syslog Rust Receiver with Palo Alto support
echo "🔄 Updating FortiGate Syslog Rust Receiver with Palo Alto support..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root or with sudo
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}This script must be run with sudo${NC}"
    exit 1
fi

echo -e "${YELLOW}Stopping FortiGate Syslog Rust service...${NC}"
systemctl stop fortigate-syslog-rust

echo -e "${YELLOW}Backing up current binary...${NC}"
cp /opt/fortigate-syslog-rust/fortigate-syslog-rust /opt/fortigate-syslog-rust/fortigate-syslog-rust.backup

echo -e "${YELLOW}Installing updated binary with Palo Alto parser...${NC}"
cp /home/net/analyzer/fortigate-syslog-rust/target/release/fortigate-syslog-rust /opt/fortigate-syslog-rust/

echo -e "${YELLOW}Setting proper permissions...${NC}"
chown syslog:syslog /opt/fortigate-syslog-rust/fortigate-syslog-rust
chmod +x /opt/fortigate-syslog-rust/fortigate-syslog-rust
setcap 'cap_net_bind_service=+ep' /opt/fortigate-syslog-rust/fortigate-syslog-rust

echo -e "${YELLOW}Starting FortiGate Syslog Rust service...${NC}"
systemctl start fortigate-syslog-rust

echo -e "${YELLOW}Checking service status...${NC}"
sleep 2

if systemctl is-active --quiet fortigate-syslog-rust; then
    echo -e "${GREEN}✅ Service updated and started successfully!${NC}"
    echo ""
    echo "📊 Service Status:"
    systemctl status fortigate-syslog-rust --no-pager -l
    echo ""
    echo -e "${GREEN}The updated receiver now supports both FortiGate and Palo Alto logs${NC}"
    echo -e "${YELLOW}Palo Alto logs should now start appearing in ClickHouse${NC}"
else
    echo -e "${RED}❌ Failed to start the updated service${NC}"
    echo "Restoring backup..."
    cp /opt/fortigate-syslog-rust/fortigate-syslog-rust.backup /opt/fortigate-syslog-rust/fortigate-syslog-rust
    systemctl start fortigate-syslog-rust
    echo "Check logs: journalctl -u fortigate-syslog-rust -n 50"
    exit 1
fi

echo ""
echo "🔍 To verify Palo Alto logs are being processed:"
echo "clickhouse-client --host=localhost --port=9000 --user=default --password='Read@123' --database=network_logs --query=\"SELECT COUNT(*) FROM fortigate_traffic WHERE device_ip = '10.10.100.4' AND timestamp > now() - INTERVAL 5 MINUTE\""
echo ""
echo "🌐 View logs in web interface:"
echo "http://10.12.50.61:8001/logs/?devname=PaloAlto-FW01&time_range=last_hour"