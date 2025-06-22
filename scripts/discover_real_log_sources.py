#!/usr/bin/env python3
"""
discover_real_log_sources.py

Analyzes actual rsyslog configuration and log files to discover and populate 
real log sources in the database.
"""

import os
import sys
import re
import glob
from datetime import datetime, timedelta
import subprocess

# Setup Django environment
sys.path.append('/home/net/analyzer')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'fwanalyzer.settings')
import django
django.setup()

from dashboard.models import LogSource, LogSourceEvent

def parse_rsyslog_config(config_file):
    """Parse rsyslog config file to extract IP addresses and file paths"""
    sources = []
    
    try:
        with open(config_file, 'r') as f:
            content = f.read()
        
        # Find IP addresses and corresponding log files
        ip_pattern = r'\$fromhost-ip\s*==\s*[\'"]([0-9.]+)[\'"]'
        file_pattern = r'file="([^"]+)"'
        
        ip_matches = re.findall(ip_pattern, content)
        file_matches = re.findall(file_pattern, content)
        
        # Try to match IPs with files based on proximity in the config
        lines = content.split('\n')
        current_ip = None
        
        for line in lines:
            line = line.strip()
            
            # Look for IP address
            ip_match = re.search(ip_pattern, line)
            if ip_match:
                current_ip = ip_match.group(1)
            
            # Look for file path
            file_match = re.search(file_pattern, line)
            if file_match and current_ip:
                log_file = file_match.group(1)
                sources.append({
                    'ip_address': current_ip,
                    'log_file': log_file,
                    'config_file': config_file
                })
                
    except Exception as e:
        print(f"Error parsing {config_file}: {e}")
    
    return sources

def analyze_log_file(log_file_path):
    """Analyze log file to determine device type and get statistics"""
    if not os.path.exists(log_file_path):
        return None
    
    try:
        # Get file stats
        stat_info = os.stat(log_file_path)
        file_size = stat_info.st_size
        last_modified = datetime.fromtimestamp(stat_info.st_mtime)
        
        # Read a sample of the log file to detect device type
        sample_lines = []
        try:
            with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f):
                    if i >= 10:  # Read first 10 lines
                        break
                    sample_lines.append(line.strip())
        except Exception as e:
            print(f"Error reading {log_file_path}: {e}")
            return None
        
        # Detect device type from log content
        sample_content = '\n'.join(sample_lines)
        device_type = LogSource.detect_device_type(sample_content)
        
        # Count approximate number of lines
        try:
            result = subprocess.run(['wc', '-l', log_file_path], 
                                  capture_output=True, text=True)
            total_lines = int(result.stdout.split()[0]) if result.returncode == 0 else 0
        except:
            total_lines = 0
        
        return {
            'file_size': file_size,
            'last_modified': last_modified,
            'device_type': device_type,
            'total_lines': total_lines,
            'sample_content': sample_content
        }
        
    except Exception as e:
        print(f"Error analyzing {log_file_path}: {e}")
        return None

def get_device_name(ip_address, device_type, log_file):
    """Generate a device name based on available information"""
    if device_type == 'fortigate':
        return f"FortiGate-{ip_address.replace('.', '-')}"
    elif device_type == 'paloalto':
        # Extract model from filename if possible
        if '1004' in log_file:
            return f"PaloAlto-1004"
        elif '1002' in log_file:
            return f"PaloAlto-1002"
        else:
            return f"PaloAlto-{ip_address.replace('.', '-')}"
    else:
        return f"Device-{ip_address.replace('.', '-')}"

def discover_and_populate():
    """Main function to discover and populate real log sources"""
    print("Discovering real log sources from rsyslog configuration...")
    
    # Clear existing sample data
    print("Clearing existing sample data...")
    LogSource.objects.all().delete()
    
    # Find all rsyslog config files
    config_files = glob.glob('/etc/rsyslog.d/*.conf')
    
    discovered_sources = []
    
    for config_file in config_files:
        print(f"Analyzing {config_file}...")
        sources = parse_rsyslog_config(config_file)
        discovered_sources.extend(sources)
    
    print(f"Found {len(discovered_sources)} configured log sources")
    
    # Analyze each discovered source
    for source_info in discovered_sources:
        ip_address = source_info['ip_address']
        log_file = source_info['log_file']
        config_file = source_info['config_file']
        
        print(f"Analyzing source: {ip_address} -> {log_file}")
        
        # Analyze the log file
        log_analysis = analyze_log_file(log_file)
        
        if log_analysis is None:
            print(f"  Could not analyze {log_file}, skipping...")
            continue
        
        # Determine device type and generate name
        device_type = log_analysis['device_type']
        device_name = get_device_name(ip_address, device_type, log_file)
        
        # Calculate statistics
        file_size_mb = log_analysis['file_size'] / (1024 * 1024)
        
        # Estimate logs per day based on file size and modification time
        time_diff = datetime.now() - log_analysis['last_modified']
        if time_diff.total_seconds() > 0:
            logs_per_second = log_analysis['total_lines'] / time_diff.total_seconds()
            logs_today = int(logs_per_second * 86400)  # 24 hours
            logs_last_hour = int(logs_per_second * 3600)  # 1 hour
        else:
            logs_today = log_analysis['total_lines']
            logs_last_hour = 0
        
        # Create log source
        log_source = LogSource.objects.create(
            name=device_name,
            description=f"Discovered from {config_file}",
            ip_address=ip_address,
            device_type=device_type,
            port=514,  # Default syslog port
            status='active',  # Real sources are active
            save_logs=True,
            log_file_path=log_file,
            log_template='fortigate_default' if device_type == 'fortigate' else 'paloalto_default' if device_type == 'paloalto' else 'raw',
            parse_to_database=True if device_type in ['fortigate', 'paloalto'] else False,
            total_logs=log_analysis['total_lines'],
            logs_today=logs_today,
            logs_last_hour=logs_last_hour,
            approved_by='system',
            approved_at=datetime.now()
        )
        
        # Create discovery event
        LogSourceEvent.objects.create(
            log_source=log_source,
            event_type='detected',
            description=f"Real log source discovered from rsyslog configuration. "
                       f"File size: {file_size_mb:.1f}MB, "
                       f"Total logs: {log_analysis['total_lines']:,}",
            user='system',
            metadata={
                'discovery_method': 'rsyslog_config_analysis',
                'config_file': config_file,
                'file_size_bytes': log_analysis['file_size'],
                'device_type_detected': device_type,
                'sample_log': log_analysis['sample_content'][:200] + '...' if len(log_analysis['sample_content']) > 200 else log_analysis['sample_content']
            }
        )
        
        print(f"  Created: {device_name} ({device_type}) - {file_size_mb:.1f}MB, {log_analysis['total_lines']:,} logs")
    
    # Also check for any other log files that might not be in rsyslog config
    print("\nChecking for additional log files...")
    log_pattern = '/var/log/*.log'
    all_log_files = glob.glob(log_pattern)
    
    for log_file in all_log_files:
        # Skip if already discovered
        if LogSource.objects.filter(log_file_path=log_file).exists():
            continue
        
        # Skip system log files
        if any(skip in log_file for skip in ['auth.log', 'syslog', 'kern.log', 'boot.log']):
            continue
        
        print(f"Analyzing unmanaged log file: {log_file}")
        log_analysis = analyze_log_file(log_file)
        
        if log_analysis and log_analysis['file_size'] > 1024:  # Only files > 1KB
            device_type = log_analysis['device_type']
            
            # Create as pending since we don't know the source IP
            log_source = LogSource.objects.create(
                name=f"Unknown-{os.path.basename(log_file)}",
                description=f"Unmanaged log file found: {log_file}",
                ip_address='0.0.0.0',  # Unknown IP
                device_type=device_type,
                port=514,
                status='pending',  # Needs investigation
                save_logs=True,
                log_file_path=log_file,
                log_template='raw',
                parse_to_database=False,
                total_logs=log_analysis['total_lines'],
                logs_today=0,  # Unknown
                logs_last_hour=0
            )
            
            LogSourceEvent.objects.create(
                log_source=log_source,
                event_type='detected',
                description=f"Unmanaged log file discovered. Requires configuration.",
                user='system',
                metadata={
                    'discovery_method': 'filesystem_scan',
                    'file_size_bytes': log_analysis['file_size'],
                    'device_type_detected': device_type
                }
            )
            
            print(f"  Created pending: {log_source.name} ({device_type})")
    
    print(f"\nDiscovery complete! Total sources: {LogSource.objects.count()}")
    print(f"Active sources: {LogSource.objects.filter(status='active').count()}")
    print(f"Pending sources: {LogSource.objects.filter(status='pending').count()}")

if __name__ == '__main__':
    discover_and_populate()