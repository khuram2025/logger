#!/bin/bash
# Fix log rotation issues for FortiGate and PaloAlto parsers

# Create logrotate configuration for fortigate and paloalto logs
cat > /tmp/network-logs-rotation << 'EOF'
/var/log/fortigate.log
/var/log/paloalto-1004.log
{
    size 500M
    rotate 5
    compress
    delaycompress
    missingok
    notifempty
    create 0644 syslog adm
    sharedscripts
    postrotate
        # Send HUP signal to rsyslog to reopen log files
        /usr/bin/systemctl reload rsyslog >/dev/null 2>&1 || true
        
        # Notify parsers to reopen files (if they have PID files)
        if [ -f /var/run/fortigate-parser.pid ]; then
            kill -HUP $(cat /var/run/fortigate-parser.pid) 2>/dev/null || true
        fi
        if [ -f /var/run/paloalto-parser.pid ]; then
            kill -HUP $(cat /var/run/paloalto-parser.pid) 2>/dev/null || true
        fi
    endscript
}
EOF

echo "Logrotate configuration created at /tmp/network-logs-rotation"
echo "To install (requires sudo):"
echo "  sudo cp /tmp/network-logs-rotation /etc/logrotate.d/network-logs"
echo "  sudo chown root:root /etc/logrotate.d/network-logs"
echo "  sudo chmod 644 /etc/logrotate.d/network-logs"
echo ""
echo "To test rotation:"
echo "  sudo logrotate -d /etc/logrotate.d/network-logs  # Dry run"
echo "  sudo logrotate -f /etc/logrotate.d/network-logs  # Force rotation"