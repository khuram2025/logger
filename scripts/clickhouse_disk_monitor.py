#!/usr/bin/env python3
"""
ClickHouse Disk Usage Monitor

This script monitors the actual disk usage of ClickHouse data directory
and stores the result in a JSON file that the web interface can read.
"""

import os
import json
import subprocess
import time
from datetime import datetime


def get_disk_usage(path):
    """Get disk usage for a given path using du command"""
    try:
        result = subprocess.run(
            ['du', '-sb', path],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            return int(result.stdout.split()[0])
    except Exception as e:
        print(f"Error getting disk usage: {e}")
    return None


def get_clickhouse_path():
    """Get ClickHouse data path"""
    # Default path
    return '/var/lib/clickhouse/'


def main():
    output_file = '/home/net/analyzer/config/clickhouse_disk_usage.json'
    data_path = get_clickhouse_path()
    
    # Get disk usage
    usage_bytes = get_disk_usage(data_path)
    
    # Prepare data
    data = {
        'path': data_path,
        'usage_bytes': usage_bytes,
        'usage_formatted': f"{usage_bytes / (1024**3):.2f} GB" if usage_bytes else "N/A",
        'timestamp': datetime.now().isoformat(),
        'status': 'success' if usage_bytes is not None else 'error'
    }
    
    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    # Write to file
    try:
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"Disk usage updated: {data['usage_formatted']}")
    except Exception as e:
        print(f"Error writing to file: {e}")


if __name__ == '__main__':
    main()