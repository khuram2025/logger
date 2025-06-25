#!/bin/bash
# Setup Script for Automated Log Source Monitoring
# This script sets up the complete log source monitoring system

SCRIPT_DIR="/home/net/analyzer/scripts"
ANALYZER_DIR="/home/net/analyzer"
ENV_DIR="/home/net/analyzer/env"

echo "🚀 Setting up Automated Log Source Monitoring System"
echo "================================================="

# Check if running as appropriate user
if [ "$EUID" -eq 0 ]; then
    echo "⚠️  Warning: Running as root. Some operations will be adjusted for permissions."
    SUDO_CMD=""
else
    echo "ℹ️  Running as user. Will use sudo for system operations."
    SUDO_CMD="sudo"
fi

echo ""
echo "1️⃣  Installing system dependencies..."

# Install required packages
if command -v apt-get &> /dev/null; then
    $SUDO_CMD apt-get update
    $SUDO_CMD apt-get install -y tcpdump nmap net-tools
elif command -v yum &> /dev/null; then
    $SUDO_CMD yum install -y tcpdump nmap net-tools
else
    echo "⚠️  Could not detect package manager. Please install tcpdump and nmap manually."
fi

echo ""
echo "2️⃣  Setting up Python dependencies..."

# Activate virtual environment and install any missing packages
source "$ENV_DIR/bin/activate"
pip install psutil django-extensions

echo ""
echo "3️⃣  Creating directory structure..."

# Create necessary directories
mkdir -p /tmp/rsyslog.d/backups
$SUDO_CMD mkdir -p /var/log/network_analyzer
$SUDO_CMD chown -R $USER:$USER /var/log/network_analyzer 2>/dev/null || true

echo ""
echo "4️⃣  Setting up database migrations..."

# Run Django migrations
cd "$ANALYZER_DIR"
python manage.py makemigrations dashboard
python manage.py migrate

echo ""
echo "5️⃣  Testing network scanner..."

# Test the network scanner
python "$SCRIPT_DIR/network_scanner.py" --discover --json > /tmp/scanner_test.json
if [ $? -eq 0 ]; then
    echo "✅ Network scanner test successful"
    DISCOVERED=$(cat /tmp/scanner_test.json | grep -o '"ip"' | wc -l)
    echo "   Found $DISCOVERED potential sources in logs"
else
    echo "❌ Network scanner test failed"
fi

echo ""
echo "6️⃣  Testing rsyslog configuration manager..."

# Test rsyslog config manager
python "$SCRIPT_DIR/rsyslog_config_manager.py" --validate
if [ $? -eq 0 ]; then
    echo "✅ Rsyslog configuration manager working"
else
    echo "❌ Rsyslog configuration manager test failed"
fi

echo ""
echo "7️⃣  Setting up Django management commands..."

# Test Django management command
python manage.py manage_log_sources --list
if [ $? -eq 0 ]; then
    echo "✅ Django management commands working"
else
    echo "❌ Django management commands failed"
fi

echo ""
echo "8️⃣  Setting up systemd service (optional)..."

# Create systemd service file
cat > /tmp/syslog-monitor.service << 'EOF'
[Unit]
Description=Syslog Traffic Monitor
After=network.target

[Service]
Type=forking
User=root
Group=root
WorkingDirectory=/home/net/analyzer
ExecStart=/home/net/analyzer/scripts/syslog_monitor_service.sh start
ExecStop=/home/net/analyzer/scripts/syslog_monitor_service.sh stop
ExecReload=/home/net/analyzer/scripts/syslog_monitor_service.sh restart
PIDFile=/var/run/syslog_monitor.pid
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

echo "📄 Systemd service file created at /tmp/syslog-monitor.service"
echo "   To install: sudo cp /tmp/syslog-monitor.service /etc/systemd/system/"
echo "   To enable:  sudo systemctl enable syslog-monitor"
echo "   To start:   sudo systemctl start syslog-monitor"

echo ""
echo "9️⃣  Setting up cron job for periodic scanning..."

# Create cron job
CRON_JOB="0 */6 * * * cd $ANALYZER_DIR && python manage.py manage_log_sources --scan --scan-type discover --auto-approve > /tmp/log_source_scan.log 2>&1"

# Add to cron if not already present
(crontab -l 2>/dev/null | grep -v "manage_log_sources"; echo "$CRON_JOB") | crontab -

echo "⏰ Cron job installed for automatic scanning every 6 hours"

echo ""
echo "🔟 Creating quick start scripts..."

# Create quick start script
cat > "$SCRIPT_DIR/quick_scan.sh" << 'EOF'
#!/bin/bash
# Quick scan for new log sources
cd /home/net/analyzer
source env/bin/activate
echo "🔍 Scanning for new log sources..."
python manage.py manage_log_sources --scan --scan-type quick
echo ""
echo "📋 Current pending sources:"
python manage.py manage_log_sources --list --status pending
EOF

chmod +x "$SCRIPT_DIR/quick_scan.sh"

# Create approve all script
cat > "$SCRIPT_DIR/approve_all.sh" << 'EOF'
#!/bin/bash
# Approve all pending sources
cd /home/net/analyzer
source env/bin/activate
echo "✅ Auto-approving known device types..."
python manage.py manage_log_sources --auto-approve
echo ""
echo "📋 All sources status:"
python manage.py manage_log_sources --list
EOF

chmod +x "$SCRIPT_DIR/approve_all.sh"

echo "✅ Quick start scripts created:"
echo "   - $SCRIPT_DIR/quick_scan.sh (scan for new sources)"
echo "   - $SCRIPT_DIR/approve_all.sh (approve pending sources)"

echo ""
echo "✨ Setup Complete! ✨"
echo "===================="
echo ""
echo "🌐 Web Interface:"
echo "   - Log Sources: http://10.12.50.61:8001/log-sources/"
echo "   - Logs View:   http://10.12.50.61:8001/logs/"
echo ""
echo "🔧 Command Line Tools:"
echo "   - Scan:        python manage.py manage_log_sources --scan"
echo "   - List:        python manage.py manage_log_sources --list"
echo "   - Approve:     python manage.py manage_log_sources --approve <ID>"
echo "   - Configure:   python manage.py manage_log_sources --configure <ID>"
echo ""
echo "🚀 Quick Actions:"
echo "   - Quick scan:  $SCRIPT_DIR/quick_scan.sh"
echo "   - Approve all: $SCRIPT_DIR/approve_all.sh"
echo "   - Monitor:     $SCRIPT_DIR/syslog_monitor_service.sh start"
echo ""
echo "📚 Documentation:"
echo "   - Network Scanner:     $SCRIPT_DIR/network_scanner.py --help"
echo "   - Traffic Monitor:     $SCRIPT_DIR/syslog_traffic_monitor.py"
echo "   - Config Manager:      $SCRIPT_DIR/rsyslog_config_manager.py --help"
echo ""
echo "🎯 Next Steps:"
echo "1. Start the traffic monitor: sudo $SCRIPT_DIR/syslog_monitor_service.sh start"
echo "2. Run a quick scan: $SCRIPT_DIR/quick_scan.sh"
echo "3. Visit the web interface to approve sources"
echo "4. Configure rsyslog for approved sources"
echo ""
echo "Happy monitoring! 🎉"