#!/usr/bin/env python3
"""
Test real-time log processing by monitoring the current enhanced script
"""

import os
import time
import subprocess
from datetime import datetime
from clickhouse_driver import Client

# Configuration
CH_HOST = 'localhost'
CH_PORT = 9000
CH_USER = 'default'
CH_PASSWORD = 'Read@123'
CH_DB = 'network_logs'

def check_recent_processing():
    """Check if new URL logs have been processed in the last few minutes"""
    try:
        client = Client(
            host=CH_HOST,
            port=CH_PORT,
            user=CH_USER,
            password=CH_PASSWORD,
            database=CH_DB
        )
        
        # Check for records in last 5 minutes
        result = client.execute("""
            SELECT count(*) FROM pa_urls_optimized 
            WHERE timestamp >= now() - interval 5 minute
        """)[0][0]
        
        print(f"URL records in last 5 minutes: {result}")
        return result
        
    except Exception as e:
        print(f"Error checking processing: {e}")
        return 0

def get_log_file_stats():
    """Get current log file statistics"""
    try:
        stat = os.stat('/var/log/paloalto-1004.log')
        size_mb = stat.st_size / (1024 * 1024)
        mtime = datetime.fromtimestamp(stat.st_mtime)
        print(f"Log file size: {size_mb:.1f} MB")
        print(f"Last modified: {mtime}")
        return stat.st_size, mtime
    except Exception as e:
        print(f"Error getting file stats: {e}")
        return 0, None

def check_service_activity():
    """Check if the systemd service is showing any activity"""
    try:
        result = subprocess.run([
            'journalctl', '-u', 'paloalto-processor.service', 
            '--since', '2 minutes ago', '--no-pager'
        ], capture_output=True, text=True)
        
        lines = result.stdout.strip().split('\n')
        print(f"Service log entries in last 2 minutes: {len(lines)}")
        
        # Show recent entries
        for line in lines[-5:]:
            if line.strip():
                print(f"  {line}")
                
    except Exception as e:
        print(f"Error checking service activity: {e}")

def main():
    """Test real-time processing"""
    print("=== Testing Real-time PaloAlto URL Processing ===")
    print(f"Test started at: {datetime.now()}")
    print()
    
    # Initial state
    print("1. Initial state:")
    initial_count = check_recent_processing()
    initial_size, initial_mtime = get_log_file_stats()
    check_service_activity()
    print()
    
    # Wait and check again
    print("2. Waiting 30 seconds for new activity...")
    time.sleep(30)
    print()
    
    # Check after waiting
    print("3. After 30 seconds:")
    final_count = check_recent_processing()
    final_size, final_mtime = get_log_file_stats()
    check_service_activity()
    print()
    
    # Summary
    print("4. Analysis:")
    if final_count > initial_count:
        print(f"✅ Processing is working! {final_count - initial_count} new records processed")
    else:
        print("❌ No new records processed")
        
    if final_size > initial_size:
        print(f"✅ Log file is growing: {(final_size - initial_size) / 1024:.1f} KB added")
    else:
        print("⚠️ Log file size unchanged")
        
    if final_mtime > initial_mtime:
        print("✅ Log file was modified")
    else:
        print("⚠️ Log file not modified")

if __name__ == '__main__':
    main()