#!/usr/bin/env python3
"""
Detect New Log Sources
Monitor for devices attempting to send logs that aren't configured yet.
"""

import subprocess
import re
import time
from datetime import datetime, timedelta

def monitor_syslog_traffic(duration=30):
    """
    Monitor network traffic to port 514 to detect new log sources
    """
    print(f"Monitoring UDP port 514 for {duration} seconds...")
    
    try:
        # Use tcpdump to monitor port 514 traffic
        cmd = [
            'timeout', str(duration),
            'tcpdump', '-i', 'any', '-n', '-q',
            'udp', 'port', '514',
            '-c', '100'  # Limit to 100 packets
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        detected_sources = set()
        
        for line in result.stdout.split('\n'):
            if 'UDP' in line and '.514:' in line:
                # Extract source IP from tcpdump output
                # Format: 16:21:28.123456 IP 192.168.100.221.12345 > 10.12.50.61.514: UDP, length 120
                match = re.search(r'IP ([0-9.]+)\.\d+ > [0-9.]+\.514:', line)
                if match:
                    source_ip = match.group(1)
                    if source_ip not in detected_sources:
                        detected_sources.add(source_ip)
                        print(f"📡 Detected log traffic from: {source_ip}")
        
        return list(detected_sources)
        
    except Exception as e:
        print(f"Error monitoring traffic: {e}")
        return []

def check_rsyslog_errors():
    """
    Check rsyslog logs for rejected/unknown sources
    """
    print("Checking rsyslog for unknown sources...")
    
    try:
        # Check recent rsyslog logs
        cmd = ['journalctl', '-u', 'rsyslog', '--since', '1 hour ago', '-q']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        unknown_sources = set()
        
        for line in result.stdout.split('\n'):
            # Look for messages about unknown sources or denied connections
            if any(keyword in line.lower() for keyword in ['unknown', 'denied', 'rejected', 'not configured']):
                # Extract IP addresses
                ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                for ip in ips:
                    if not ip.startswith('127.') and not ip.startswith('0.'):
                        unknown_sources.add(ip)
                        print(f"⚠️  Potential unconfigured source: {ip}")
        
        return list(unknown_sources)
        
    except Exception as e:
        print(f"Error checking rsyslog logs: {e}")
        return []

def main():
    print("🔍 Detecting new log sources...")
    print()
    
    # Method 1: Monitor live traffic
    traffic_sources = monitor_syslog_traffic(15)
    
    # Method 2: Check rsyslog errors
    error_sources = check_rsyslog_errors()
    
    all_sources = set(traffic_sources + error_sources)
    
    print()
    print(f"Summary: Found {len(all_sources)} potential log sources")
    
    if all_sources:
        print("\nTo configure these sources:")
        for ip in all_sources:
            print(f"  1. Add to /etc/rsyslog.d/: if ($fromhost-ip == '{ip}') then {{ ... }}")
            print(f"  2. Create log file: /var/log/device-{ip.replace('.', '-')}.log")
            print(f"  3. Restart rsyslog: sudo systemctl restart rsyslog")
            print()
    else:
        print("No new sources detected. All traffic appears to be from configured sources.")

if __name__ == "__main__":
    main()