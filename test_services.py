#!/usr/bin/env python3
"""
Test script to verify service status detection
"""
import subprocess

services = [
    'paloalto_to_clickhouse.service',
    'paloalto-url-loader.service', 
    'fortigate_to_clickhouse.service'
]

print("Testing service status detection:")
print("=" * 50)

for service_name in services:
    try:
        # Test is-active command
        result = subprocess.run(
            ['systemctl', 'is-active', service_name],
            capture_output=True,
            text=True,
            timeout=5
        )
        status_output = result.stdout.strip()
        is_active = status_output == 'active'
        
        print(f"Service: {service_name}")
        print(f"  Raw output: '{status_output}'")
        print(f"  Is active: {is_active}")
        print(f"  Return code: {result.returncode}")
        
        # Test detailed status
        status_result = subprocess.run(
            ['systemctl', 'status', service_name],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        # Parse status info
        status_lines = status_result.stdout.split('\n')
        main_pid = None
        memory_usage = None
        
        for line in status_lines:
            if 'Main PID:' in line:
                main_pid = line.split('Main PID:')[1].strip().split(' ')[0]
            elif 'Memory:' in line:
                memory_usage = line.split('Memory:')[1].strip().split(' ')[0]
        
        print(f"  Main PID: {main_pid}")
        print(f"  Memory: {memory_usage}")
        print()
        
    except Exception as e:
        print(f"Error checking {service_name}: {e}")
        print()