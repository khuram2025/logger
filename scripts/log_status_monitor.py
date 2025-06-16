#!/usr/bin/env python3
"""
log_status_monitor.py

Monitoring script for log file management system.
Provides real-time status and alerts for log file sizes and processing.
"""

import os
import time
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List

# Configuration
LOG_FILES = {
    '/var/log/fortigate.log': 'FortiGate Traffic',
    '/var/log/paloalto-1004.log': 'PaloAlto Traffic'
}

ALERT_THRESHOLDS = {
    'file_size_warning': 1.5 * 1024 * 1024 * 1024,  # 1.5GB
    'file_size_critical': 1.8 * 1024 * 1024 * 1024,  # 1.8GB
    'processing_lag_warning': 100 * 1024 * 1024,     # 100MB
    'processing_lag_critical': 500 * 1024 * 1024      # 500MB
}

REGISTRY_FILE = '/var/lib/log-manager/processed_logs.json'
STATUS_FILE = '/var/lib/log-manager/status.json'

def format_bytes(bytes_val):
    """Format bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.1f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.1f} PB"

def get_file_status(filepath: str) -> Dict:
    """Get detailed status for a log file"""
    try:
        if not os.path.exists(filepath):
            return {
                'exists': False,
                'size': 0,
                'size_formatted': '0 B',
                'last_modified': 0,
                'alert_level': 'info'
            }
        
        stat = os.stat(filepath)
        size = stat.st_size
        
        # Determine alert level
        alert_level = 'ok'
        if size >= ALERT_THRESHOLDS['file_size_critical']:
            alert_level = 'critical'
        elif size >= ALERT_THRESHOLDS['file_size_warning']:
            alert_level = 'warning'
        
        return {
            'exists': True,
            'size': size,
            'size_formatted': format_bytes(size),
            'last_modified': stat.st_mtime,
            'last_modified_formatted': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            'alert_level': alert_level,
            'percentage_of_limit': (size / (2 * 1024 * 1024 * 1024)) * 100  # Percentage of 2GB
        }
    except Exception as e:
        return {
            'exists': False,
            'error': str(e),
            'alert_level': 'error'
        }

def load_log_manager_status() -> Dict:
    """Load status from log manager registry"""
    try:
        if os.path.exists(REGISTRY_FILE):
            with open(REGISTRY_FILE, 'r') as f:
                data = json.load(f)
                return data
        return {}
    except Exception as e:
        logging.error(f"Error loading log manager status: {e}")
        return {}

def calculate_processing_lag(filepath: str, registry_data: Dict) -> Dict:
    """Calculate processing lag for a file"""
    try:
        file_info = registry_data.get('file_info', {}).get(filepath, {})
        
        if not file_info:
            return {'lag_bytes': 0, 'lag_formatted': '0 B', 'alert_level': 'info'}
        
        current_size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
        last_processed_position = file_info.get('last_processed_position', 0)
        
        lag_bytes = max(0, current_size - last_processed_position)
        
        # Determine alert level for processing lag
        alert_level = 'ok'
        if lag_bytes >= ALERT_THRESHOLDS['processing_lag_critical']:
            alert_level = 'critical'
        elif lag_bytes >= ALERT_THRESHOLDS['processing_lag_warning']:
            alert_level = 'warning'
        
        return {
            'lag_bytes': lag_bytes,
            'lag_formatted': format_bytes(lag_bytes),
            'alert_level': alert_level,
            'last_processed_position': last_processed_position,
            'current_size': current_size,
            'total_lines_processed': file_info.get('total_lines_processed', 0),
            'last_processed_time': file_info.get('last_processed_time', 0),
            'last_processed_time_formatted': datetime.fromtimestamp(file_info.get('last_processed_time', 0)).strftime('%Y-%m-%d %H:%M:%S') if file_info.get('last_processed_time', 0) > 0 else 'Never'
        }
    except Exception as e:
        logging.error(f"Error calculating processing lag for {filepath}: {e}")
        return {'lag_bytes': 0, 'lag_formatted': '0 B', 'alert_level': 'error', 'error': str(e)}

def get_rotation_status(registry_data: Dict) -> Dict:
    """Get rotation and cleanup status"""
    try:
        processed_records = registry_data.get('processed_records', [])
        
        total_rotated_files = len(processed_records)
        verified_files = len([r for r in processed_records if r.get('safe_to_delete', False)])
        pending_verification = total_rotated_files - verified_files
        
        # Calculate total size of rotated files
        total_rotated_size = 0
        for record in processed_records:
            rotated_file = record.get('rotated_file', '')
            if rotated_file and os.path.exists(rotated_file):
                total_rotated_size += os.path.getsize(rotated_file)
        
        return {
            'total_rotated_files': total_rotated_files,
            'verified_files': verified_files,
            'pending_verification': pending_verification,
            'total_rotated_size': total_rotated_size,
            'total_rotated_size_formatted': format_bytes(total_rotated_size),
            'last_rotation_time': max([r.get('processing_start_time', 0) for r in processed_records] + [0]),
            'last_rotation_time_formatted': datetime.fromtimestamp(max([r.get('processing_start_time', 0) for r in processed_records] + [0])).strftime('%Y-%m-%d %H:%M:%S') if processed_records else 'Never'
        }
    except Exception as e:
        logging.error(f"Error getting rotation status: {e}")
        return {'error': str(e)}

def generate_alerts(status_data: Dict) -> List[Dict]:
    """Generate alerts based on current status"""
    alerts = []
    
    for filepath, file_status in status_data.get('files', {}).items():
        filename = os.path.basename(filepath)
        
        # File size alerts
        if file_status.get('alert_level') == 'critical':
            alerts.append({
                'type': 'critical',
                'message': f"{filename} has reached critical size: {file_status.get('size_formatted', 'Unknown')}",
                'details': f"File is at {file_status.get('percentage_of_limit', 0):.1f}% of 2GB limit",
                'timestamp': time.time()
            })
        elif file_status.get('alert_level') == 'warning':
            alerts.append({
                'type': 'warning',
                'message': f"{filename} approaching size limit: {file_status.get('size_formatted', 'Unknown')}",
                'details': f"File is at {file_status.get('percentage_of_limit', 0):.1f}% of 2GB limit",
                'timestamp': time.time()
            })
        
        # Processing lag alerts
        processing_lag = status_data.get('processing_lag', {}).get(filepath, {})
        if processing_lag.get('alert_level') == 'critical':
            alerts.append({
                'type': 'critical',
                'message': f"{filename} has critical processing lag: {processing_lag.get('lag_formatted', 'Unknown')}",
                'details': f"Processing is behind by {processing_lag.get('lag_formatted', 'Unknown')}",
                'timestamp': time.time()
            })
        elif processing_lag.get('alert_level') == 'warning':
            alerts.append({
                'type': 'warning',
                'message': f"{filename} has processing lag: {processing_lag.get('lag_formatted', 'Unknown')}",
                'details': f"Processing is behind by {processing_lag.get('lag_formatted', 'Unknown')}",
                'timestamp': time.time()
            })
    
    return alerts

def collect_status() -> Dict:
    """Collect comprehensive status information"""
    logging.info("Collecting log management status...")
    
    # Load log manager registry
    registry_data = load_log_manager_status()
    
    # Collect file status
    files_status = {}
    processing_lag = {}
    
    for filepath, description in LOG_FILES.items():
        files_status[filepath] = get_file_status(filepath)
        files_status[filepath]['description'] = description
        processing_lag[filepath] = calculate_processing_lag(filepath, registry_data)
    
    # Get rotation status
    rotation_status = get_rotation_status(registry_data)
    
    # Calculate overall system status
    total_size = sum(f.get('size', 0) for f in files_status.values())
    max_alert_level = 'ok'
    
    for file_status in files_status.values():
        if file_status.get('alert_level') == 'critical':
            max_alert_level = 'critical'
            break
        elif file_status.get('alert_level') == 'warning':
            max_alert_level = 'warning'
    
    for lag_status in processing_lag.values():
        if lag_status.get('alert_level') == 'critical':
            max_alert_level = 'critical'
            break
        elif lag_status.get('alert_level') == 'warning' and max_alert_level == 'ok':
            max_alert_level = 'warning'
    
    status = {
        'timestamp': time.time(),
        'timestamp_formatted': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'overall_status': max_alert_level,
        'files': files_status,
        'processing_lag': processing_lag,
        'rotation': rotation_status,
        'summary': {
            'total_files': len(LOG_FILES),
            'total_size': total_size,
            'total_size_formatted': format_bytes(total_size),
            'registry_last_updated': registry_data.get('last_updated', 0)
        }
    }
    
    # Generate alerts
    status['alerts'] = generate_alerts(status)
    
    return status

def save_status(status_data: Dict):
    """Save status to file for web interface consumption"""
    try:
        os.makedirs(os.path.dirname(STATUS_FILE), exist_ok=True)
        
        # Atomic write
        temp_file = STATUS_FILE + '.tmp'
        with open(temp_file, 'w') as f:
            json.dump(status_data, f, indent=2)
        
        os.rename(temp_file, STATUS_FILE)
        logging.debug("Status saved successfully")
        
    except Exception as e:
        logging.error(f"Error saving status: {e}")

def monitor_loop():
    """Main monitoring loop"""
    logging.info("Starting log status monitoring...")
    
    while True:
        try:
            status = collect_status()
            save_status(status)
            
            # Log summary
            overall_status = status['overall_status']
            total_size = status['summary']['total_size_formatted']
            alert_count = len(status['alerts'])
            
            log_level = logging.INFO
            if overall_status == 'critical':
                log_level = logging.ERROR
            elif overall_status == 'warning':
                log_level = logging.WARNING
            
            logging.log(log_level, f"Status: {overall_status.upper()} | Total Size: {total_size} | Alerts: {alert_count}")
            
            # Log critical alerts immediately
            for alert in status['alerts']:
                if alert['type'] == 'critical':
                    logging.error(f"CRITICAL ALERT: {alert['message']} - {alert['details']}")
            
        except Exception as e:
            logging.error(f"Error in monitoring loop: {e}")
        
        time.sleep(60)  # Check every minute

def main():
    """Main entry point"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s [LogMonitor] %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('/var/log/log-monitor.log')
        ]
    )
    
    import signal
    import sys
    
    def signal_handler(signum, frame):
        logging.info("Received shutdown signal")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start monitoring
    monitor_loop()

if __name__ == '__main__':
    main()