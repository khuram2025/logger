#!/usr/bin/env python3
"""
Test recent URL logs parsing
"""

import os
from datetime import datetime
from clickhouse_driver import Client

# Configuration
CH_HOST = 'localhost'
CH_PORT = 9000
CH_USER = 'default'
CH_PASSWORD = 'Read@123'
CH_DB = 'network_logs'
LOG_FILE = '/var/log/paloalto-1004.log'

# Connect to ClickHouse
CLIENT = Client(
    host=CH_HOST,
    port=CH_PORT,
    user=CH_USER,
    password=CH_PASSWORD,
    database=CH_DB
)

print("Testing recent URL log processing...")

# Get last 100 lines from log file and check for URL logs
print(f"Reading last 100 lines from {LOG_FILE}")
with open(LOG_FILE, 'r') as f:
    f.seek(0, os.SEEK_END)
    file_size = f.tell()
    
    # Go back 1MB
    seek_pos = max(0, file_size - 1024 * 1024)
    f.seek(seek_pos)
    if seek_pos > 0:
        f.readline()  # Skip partial line
    
    lines = f.readlines()
    print(f"Read {len(lines)} lines from last 1MB")

# Find URL logs
url_lines = []
for line in lines:
    if 'THREAT,url' in line:
        url_lines.append(line)

print(f"Found {len(url_lines)} URL log lines")

if url_lines:
    print("Sample URL logs:")
    for i, line in enumerate(url_lines[-3:]):  # Show last 3
        print(f"{i+1}: {line[:150]}...")
        
    # Parse one sample
    sample_line = url_lines[-1]
    parts = sample_line.split(' ', 4)
    if len(parts) >= 5:
        log_data = parts[4]
        fields = log_data.split(',')
        print(f"\nSample parsing - Total fields: {len(fields)}")
        print(f"Log type: {fields[3] if len(fields) > 3 else 'N/A'}")
        print(f"Log subtype: {fields[4] if len(fields) > 4 else 'N/A'}")
        print(f"URL: {fields[31] if len(fields) > 31 else 'N/A'}")
        print(f"Source: {fields[7] if len(fields) > 7 else 'N/A'}")
        print(f"Dest: {fields[8] if len(fields) > 8 else 'N/A'}")

# Check recent URL records in ClickHouse
print("\nChecking ClickHouse for recent URL records...")
result = CLIENT.execute("""
    SELECT count(*) as cnt, max(timestamp) as latest 
    FROM pa_urls_optimized 
    WHERE timestamp >= now() - interval 2 hour
""")
print(f"URL records in last 2 hours: {result[0][0]}")
if result[0][1]:
    print(f"Latest URL record timestamp: {result[0][1]}")

# Check if new records are being inserted
print("\nChecking last 10 URL records...")
recent_urls = CLIENT.execute("""
    SELECT timestamp, url, source_address, destination_address 
    FROM pa_urls_optimized 
    ORDER BY timestamp DESC 
    LIMIT 10
""")

for i, (ts, url, src, dst) in enumerate(recent_urls):
    print(f"{i+1}: {ts} | {url} | {src} -> {dst}")