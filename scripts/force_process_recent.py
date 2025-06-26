#!/usr/bin/env python3
"""
Force process recent URL logs from PaloAlto
"""

import os
import re
import logging
from datetime import datetime
from clickhouse_driver import Client

# Configuration
CH_HOST = 'localhost'
CH_PORT = 9000
CH_USER = 'default'
CH_PASSWORD = 'Read@123'
CH_DB = 'network_logs'
LOG_FILE = '/var/log/paloalto-1004.log'

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s [FORCE-PROCESS] %(message)s'
)

# Connect to ClickHouse
CLIENT = Client(
    host=CH_HOST,
    port=CH_PORT,
    user=CH_USER,
    password=CH_PASSWORD,
    database=CH_DB
)

# URL Log Fields (same as enhanced script)
ALL_URL_FIELDS = [
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

def parse_url_log(fields, device_name, raw_message):
    """Parse THREAT,url log format"""
    try:
        data = {}
        
        # Set default values for URL fields
        for field in ALL_URL_FIELDS:
            if field in ['sequence_number', 'session_id', 'source_port', 'destination_port', 
                        'ip_protocol', 'response_code', 'response_size']:
                data[field] = 0
            elif field in ['timestamp', 'receive_time', 'generated_time', 'processing_timestamp']:
                data[field] = datetime.now()
            else:
                data[field] = ''
        
        data['raw_message'] = raw_message
        data['device_name'] = device_name
        data['log_type'] = 'THREAT'
        data['log_subtype'] = 'url'
        
        # Extract timestamps
        current_time = datetime.now()
        data['receive_time'] = current_time
        data['processing_timestamp'] = current_time
        
        # Use actual log timestamp for main timestamp field
        if len(fields) > 6:
            try:
                timestamp_str = fields[6]
                parsed_time = datetime.strptime(timestamp_str, "%Y/%m/%d %H:%M:%S")
                data['timestamp'] = parsed_time
                data['generated_time'] = parsed_time
            except ValueError:
                data['timestamp'] = current_time
                data['generated_time'] = current_time
        else:
            data['timestamp'] = current_time
            data['generated_time'] = current_time
        
        # Extract key fields
        data['sequence_number'] = int(fields[5]) if len(fields) > 5 and fields[5].isdigit() else 0
        data['source_address'] = fields[7] if len(fields) > 7 else ''
        data['destination_address'] = fields[8] if len(fields) > 8 else ''
        data['source_port'] = int(fields[24]) if len(fields) > 24 and fields[24].isdigit() else 0
        data['destination_port'] = int(fields[25]) if len(fields) > 25 and fields[25].isdigit() else 0
        data['source_zone'] = fields[16] if len(fields) > 16 else ''
        data['destination_zone'] = fields[17] if len(fields) > 17 else ''
        data['inbound_interface'] = fields[18] if len(fields) > 18 else ''
        data['outbound_interface'] = fields[19] if len(fields) > 19 else ''
        data['protocol'] = fields[29] if len(fields) > 29 else ''
        data['rule_name'] = fields[11] if len(fields) > 11 else ''
        data['source_user'] = fields[12] if len(fields) > 12 else ''
        data['application'] = fields[14] if len(fields) > 14 else ''
        data['action'] = fields[30] if len(fields) > 30 else ''
        data['severity'] = fields[34] if len(fields) > 34 else ''
        data['direction'] = fields[35] if len(fields) > 35 else ''
        data['virtual_system'] = fields[15] if len(fields) > 15 else ''
        
        # Extract URL (field 31) - remove quotes
        data['url'] = fields[31].strip('"') if len(fields) > 31 else ''
        
        # Extract threat/content type (field 32)
        threat_type_field = fields[32] if len(fields) > 32 else ''
        if threat_type_field:
            threat_type_clean = threat_type_field.strip('()')
            if threat_type_clean.isdigit():
                data['threat_id'] = threat_type_clean
            else:
                data['threat_category'] = threat_type_clean
        
        # Extract URL domain and path
        if data['url']:
            if data['url'].startswith('http'):
                try:
                    url_parts = data['url'].split('//')[1]
                    domain = url_parts.split('/')[0]
                    path = '/' + '/'.join(url_parts.split('/')[1:]) if '/' in url_parts else '/'
                except:
                    domain = data['url']
                    path = '/'
            else:
                url_parts = data['url'].split('/', 1)
                domain = url_parts[0]
                path = '/' + url_parts[1] if len(url_parts) > 1 else '/'
            data['url_domain'] = domain
            data['url_path'] = path
        
        # Extract URL category
        data['url_category'] = fields[33] if len(fields) > 33 else ''
        
        # Default values
        data['http_method'] = 'GET'
        data['response_code'] = 0
        
        # Validate required fields
        if not data.get('url') or not data.get('source_address') or not data.get('destination_address'):
            return None
            
        return data
            
    except Exception as e:
        logging.error(f"Error parsing URL log: {e}")
        return None

def main():
    """Force process recent URL logs"""
    url_insert_query = f"""
        INSERT INTO {CH_DB}.pa_urls_optimized ({', '.join(ALL_URL_FIELDS)}) VALUES
    """
    
    logging.info("Force processing recent URL logs from PaloAlto")
    
    # Read last 10MB of log file
    with open(LOG_FILE, 'r') as f:
        f.seek(0, os.SEEK_END)
        file_size = f.tell()
        
        # Go back 10MB
        seek_pos = max(0, file_size - 10 * 1024 * 1024)
        f.seek(seek_pos)
        if seek_pos > 0:
            f.readline()  # Skip partial line
        
        lines = f.readlines()
        logging.info(f"Read {len(lines)} lines from last 10MB")

    # Find and process URL logs
    url_records = []
    processed = 0
    errors = 0
    
    for line in lines:
        if 'THREAT,url' in line:
            try:
                # Parse the line
                parts = line.split(' ', 4)
                if len(parts) >= 4:
                    device_name = parts[3]
                    
                    if len(parts) >= 5:
                        log_data = parts[4]
                        fields = log_data.split(',')
                        
                        if len(fields) > 4 and fields[3] == 'THREAT' and fields[4] == 'url':
                            parsed_data = parse_url_log(fields, device_name, line.rstrip('\n'))
                            if parsed_data:
                                url_records.append(parsed_data)
                                processed += 1
                                
                                # Process in batches of 500
                                if len(url_records) >= 500:
                                    try:
                                        rows = [[record.get(field, '') for field in ALL_URL_FIELDS] for record in url_records]
                                        CLIENT.execute(url_insert_query, rows)
                                        logging.info(f"✅ Inserted {len(url_records)} URL records")
                                        url_records.clear()
                                    except Exception as e:
                                        logging.error(f"❌ Batch insert error: {e}")
                                        errors += 1
                                        url_records.clear()
                            
            except Exception as e:
                logging.error(f"Error processing line: {e}")
                errors += 1
    
    # Insert remaining records
    if url_records:
        try:
            rows = [[record.get(field, '') for field in ALL_URL_FIELDS] for record in url_records]
            CLIENT.execute(url_insert_query, rows)
            logging.info(f"✅ Inserted final {len(url_records)} URL records")
        except Exception as e:
            logging.error(f"❌ Final batch insert error: {e}")
            errors += 1
    
    logging.info(f"Processing complete - Processed: {processed}, Errors: {errors}")

if __name__ == '__main__':
    main()