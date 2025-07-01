#!/usr/bin/env python3
"""
Manual URL log processor - Simple version to fix the current issue
"""

import os
import sys
from datetime import datetime
from clickhouse_driver import Client

# Configuration
CH_HOST = 'localhost'
CH_PORT = 9000
CH_USER = 'default'
CH_PASSWORD = 'Read@123'
CH_DB = 'network_logs'
LOG_FILE = '/var/log/paloalto-1004.log'

def get_client():
    """Create a fresh ClickHouse client for each operation"""
    return Client(
        host=CH_HOST,
        port=CH_PORT,
        user=CH_USER,
        password=CH_PASSWORD,
        database=CH_DB
    )

def parse_url_log(fields, device_name, raw_message):
    """Parse URL log fields"""
    data = {}
    current_time = datetime.now()
    
    # Initialize with defaults
    data['timestamp'] = current_time
    data['receive_time'] = current_time
    data['generated_time'] = current_time
    data['processing_timestamp'] = current_time
    data['sequence_number'] = 0
    data['session_id'] = 0
    data['device_name'] = device_name
    data['serial_number'] = fields[2] if len(fields) > 2 else ''
    data['source_address'] = fields[7] if len(fields) > 7 else ''
    data['destination_address'] = fields[8] if len(fields) > 8 else ''
    data['nat_source_ip'] = fields[9] if len(fields) > 9 else ''
    data['nat_destination_ip'] = fields[10] if len(fields) > 10 else ''
    data['source_port'] = int(fields[24]) if len(fields) > 24 and fields[24].isdigit() else 0
    data['destination_port'] = int(fields[25]) if len(fields) > 25 and fields[25].isdigit() else 0
    data['source_zone'] = fields[16] if len(fields) > 16 else ''
    data['destination_zone'] = fields[17] if len(fields) > 17 else ''
    data['inbound_interface'] = fields[18] if len(fields) > 18 else ''
    data['outbound_interface'] = fields[19] if len(fields) > 19 else ''
    data['ip_protocol'] = 6  # TCP default
    data['protocol'] = 'tcp'
    data['url'] = fields[31] if len(fields) > 31 else ''
    data['url_domain'] = ''
    data['url_path'] = ''
    data['url_query'] = ''
    data['url_category'] = fields[33] if len(fields) > 33 else ''
    data['url_category_list'] = ''
    data['http_method'] = ''
    data['user_agent'] = fields[46] if len(fields) > 46 else ''
    data['referer'] = ''
    data['content_type'] = ''
    data['response_code'] = 0
    data['response_size'] = 0
    data['rule_name'] = fields[11] if len(fields) > 11 else ''
    data['rule_uuid'] = ''
    data['action'] = fields[30] if len(fields) > 30 else ''
    data['severity'] = fields[34] if len(fields) > 34 else ''
    data['direction'] = fields[35] if len(fields) > 35 else ''
    data['threat_id'] = fields[32] if len(fields) > 32 else ''
    data['threat_category'] = ''
    data['log_action'] = fields[20] if len(fields) > 20 else ''
    data['source_user'] = fields[12] if len(fields) > 12 else ''
    data['destination_user'] = fields[13] if len(fields) > 13 else ''
    data['application'] = fields[14] if len(fields) > 14 else ''
    data['application_category'] = ''
    data['source_country'] = fields[38] if len(fields) > 38 else ''
    data['destination_country'] = fields[39] if len(fields) > 39 else ''
    data['raw_message'] = raw_message
    data['log_type'] = 'THREAT'
    data['log_subtype'] = 'url'
    data['virtual_system'] = fields[15] if len(fields) > 15 else ''
    
    # Parse URL parts
    if data['url']:
        url = data['url']
        if '://' in url:
            parts = url.split('://', 1)[1].split('/', 1)
            data['url_domain'] = parts[0]
            if len(parts) > 1:
                path_parts = parts[1].split('?', 1)
                data['url_path'] = '/' + path_parts[0]
                if len(path_parts) > 1:
                    data['url_query'] = path_parts[1]
        else:
            parts = url.split('/', 1)
            data['url_domain'] = parts[0]
            if len(parts) > 1:
                path_parts = parts[1].split('?', 1)
                data['url_path'] = '/' + path_parts[0]
                if len(path_parts) > 1:
                    data['url_query'] = path_parts[1]
    
    return data

def process_recent_logs():
    """Process recent logs to catch up"""
    print("Processing recent URL logs...")
    
    try:
        # Read last 1000 lines
        with open(LOG_FILE, 'r') as f:
            lines = f.readlines()
            recent_lines = lines[-1000:]  # Last 1000 lines
        
        url_records = []
        processed = 0
        
        for line in recent_lines:
            line = line.strip()
            if not line:
                continue
                
            try:
                # Parse syslog format
                parts = line.split(' ', 4)
                if len(parts) < 5:
                    continue
                    
                device_name = parts[3]
                log_data = parts[4]
                fields = log_data.split(',')
                
                # Check if it's a THREAT,url log
                if len(fields) > 4 and fields[3] == 'THREAT' and fields[4] == 'url':
                    record = parse_url_log(fields, device_name, line)
                    url_records.append(record)
                    processed += 1
                    
            except Exception as e:
                print(f"Error processing line: {e}")
                continue
        
        if url_records:
            print(f"Found {len(url_records)} URL records to insert")
            
            # Prepare data for ClickHouse
            fields = [
                'timestamp', 'receive_time', 'generated_time', 'processing_timestamp', 'sequence_number',
                'session_id', 'device_name', 'serial_number', 'source_address', 'destination_address',
                'nat_source_ip', 'nat_destination_ip', 'source_port', 'destination_port',
                'source_zone', 'destination_zone', 'inbound_interface', 'outbound_interface',
                'ip_protocol', 'protocol', 'url', 'url_domain', 'url_path', 'url_query',
                'url_category', 'url_category_list', 'http_method', 'user_agent', 'referer',
                'content_type', 'response_code', 'response_size', 'rule_name', 'rule_uuid',
                'action', 'severity', 'direction', 'threat_id', 'threat_category',
                'log_action', 'source_user', 'destination_user', 'application',
                'application_category', 'source_country', 'destination_country',
                'raw_message', 'log_type', 'log_subtype', 'virtual_system'
            ]
            
            rows = []
            for record in url_records:
                row = [record.get(field, '') for field in fields]
                rows.append(row)
            
            # Insert to ClickHouse
            client = get_client()
            insert_query = f"INSERT INTO {CH_DB}.pa_urls_optimized ({', '.join(fields)}) VALUES"
            client.execute(insert_query, rows)
            client.disconnect()
            
            print(f"✅ Successfully inserted {len(rows)} URL records")
        else:
            print("No URL records found in recent logs")
            
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    process_recent_logs()