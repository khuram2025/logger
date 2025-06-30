from django.shortcuts import render
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.http import JsonResponse, Http404
from django.utils.html import escape
from django.db.models import Sum, Count
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from .models import LogSource, LogSourceEvent, ParserTemplate

import re
import math
import logging
from clickhouse_driver import Client
import os
import json
import subprocess
from datetime import datetime, timedelta, timezone
import os
from collections import defaultdict
import ipaddress
import json # For serializing log data for JS if needed

# ClickHouse connection settings
CH_HOST = os.getenv('CH_HOST', 'localhost')
CH_PORT = int(os.getenv('CH_PORT', '9000'))
CH_USER = os.getenv('CH_USER', 'default')
CH_PASSWORD = os.getenv('CH_PASSWORD', 'Read@123')
CH_DB = os.getenv('CH_DB', 'network_logs')
SUBNET_GROUP_PAGE_SIZE = 50

def create_rsyslog_config(log_source):
    """
    Create rsyslog configuration for a log source device
    Adds device to appropriate config file based on device type
    """
    device_type = log_source.device_type
    ip_address = log_source.ip_address
    
    try:
        # Determine target config file based on device type
        if device_type == 'fortigate':
            config_file = '/etc/rsyslog.d/fortigate.conf'
            template_name = "FortiGateRaw"  # Use existing template
        elif device_type == 'paloalto':
            config_file = '/etc/rsyslog.d/02-paloalto.conf'
            template_name = "PaloAltoRaw"  # Use existing template
        else:
            # For other device types, create a generic config file
            config_file = f'/etc/rsyslog.d/99-device-{ip_address.replace(".", "-")}.conf'
            template_name = f"DeviceRaw_{ip_address.replace('.', '_')}"
        
        # Generate log file path (use existing patterns)
        if device_type == 'fortigate':
            log_file = '/var/log/fortigate.log'  # All FortiGate devices use same file
        elif device_type == 'paloalto':
            # PaloAlto uses format like paloalto-1002.log, paloalto-1004.log
            ip_suffix = ip_address.split('.')[-1]  # Get last octet
            log_file = f'/var/log/paloalto-{ip_suffix}.log'
        else:
            log_file = f'/var/log/device-{ip_address.replace(".", "-")}.log'
        
        # Update log source with log file path
        log_source.log_file_path = log_file
        log_source.save()
        
        # Check if device already exists in config
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                content = f.read()
                if ip_address in content:
                    return {
                        'success': True,
                        'message': f'Device {ip_address} already configured in {config_file}'
                    }
        
        # Generate new config entry
        if device_type in ['fortigate', 'paloalto']:
            # Add to existing config file
            new_config_entry = f"""
if ($fromhost-ip == '{ip_address}') then {{
    action(
        type="omfile"
        file="{log_file}"
        template="{template_name}"
    )
    stop
}}
"""
            
            # Read existing config
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    existing_content = f.read()
                
                # Find insertion point (before the last #### end comment)
                if device_type == 'fortigate':
                    insertion_point = existing_content.rfind('#### end fortigate.conf ####')
                elif device_type == 'paloalto':
                    insertion_point = existing_content.rfind('#### end paloalto.conf ####')
                
                if insertion_point != -1:
                    # Insert new config before the end comment
                    new_content = (existing_content[:insertion_point] + 
                                 new_config_entry + 
                                 existing_content[insertion_point:])
                else:
                    # Append to end if no end comment found
                    new_content = existing_content + new_config_entry
            else:
                return {
                    'success': False,
                    'error': f'Config file {config_file} does not exist'
                }
        else:
            # Create new config file for other device types
            new_content = f"""#### start device-{ip_address.replace('.', '-')}.conf ####

template(name="{template_name}" type="string" string="%rawmsg-after-pri%\\n")

if ($fromhost-ip == '{ip_address}') then {{
    action(
        type="omfile"
        file="{log_file}"
        template="{template_name}"
    )
    stop
}}

#### end device-{ip_address.replace('.', '-')}.conf ####
"""
        
        # Write config file using subprocess to handle permissions
        try:
            # Write to temp file first
            temp_file = f'/tmp/rsyslog_config_{ip_address.replace(".", "_")}.conf'
            with open(temp_file, 'w') as f:
                f.write(new_content)
            
            # Try to copy to target location
            try:
                subprocess.run(['sudo', 'cp', temp_file, config_file], check=True, input=b'\n', timeout=5)
                subprocess.run(['rm', temp_file], check=True)
                
                # Restart rsyslog to apply changes
                subprocess.run(['sudo', 'systemctl', 'restart', 'rsyslog'], check=True, input=b'\n', timeout=10)
                
                return {
                    'success': True,
                    'message': f'Added {ip_address} to {config_file} and restarted rsyslog'
                }
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                # If sudo fails, provide manual instructions
                return {
                    'success': False,
                    'error': f'Config created at {temp_file}. Please run: sudo cp {temp_file} {config_file} && sudo systemctl restart rsyslog',
                    'temp_file': temp_file,
                    'config_content': new_content
                }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to create rsyslog config: {str(e)}'
            }
            
    except Exception as e:
        return {
            'success': False,
            'error': f'Error creating rsyslog config: {str(e)}'
        }

# Helper function to generate pagination range
def get_pagination_range(current_page, total_pages, neighbors=2):
    """
    Generates a list of page numbers for pagination, including ellipses.
    e.g., [1, None, 5, 6, 7, None, 10] for current_page=6, total_pages=10
    None represents an ellipsis.
    """
    if total_pages <= (2 * neighbors + 1) + 2: # Show all if not many (e.g., 1 ... 3 4 5 ... 7)
        return list(range(1, total_pages + 1))

    page_range = []
    # Ensure first page is always added
    page_range.append(1)

    # Ellipsis after first page?
    if current_page > neighbors + 2:
        page_range.append(None) # Represents '...'

    # Pages around current_page
    start_range = max(2, current_page - neighbors)
    end_range = min(total_pages - 1, current_page + neighbors)

    for i in range(start_range, end_range + 1):
        if i not in page_range:
            page_range.append(i)

    # Ellipsis before last page?
    if current_page < total_pages - neighbors - 1:
        # Avoid double ellipsis if last page is close or already None
        if not page_range or page_range[-1] is not None:
             if total_pages -1 not in page_range : # ensure no ellipsis if next is last page
                page_range.append(None) # Represents '...'

    # Ensure last page is always added (if not already)
    if total_pages not in page_range:
        page_range.append(total_pages)
        
    # Remove potential leading None if page_range starts with [1, None, 2 ...]
    if len(page_range) > 1 and page_range[0] == 1 and page_range[1] is None and (len(page_range) == 2 or page_range[2] == 2):
        page_range.pop(1)
        
    return page_range


def top_summary_view(request):
    client = Client(
        host=CH_HOST,
        port=CH_PORT,
        user=CH_USER,
        password=CH_PASSWORD,
        database=CH_DB
    )
    # Get time_range from GET params
    time_range = request.GET.get('time_range', '1h')
    now = datetime.now()
    
    if time_range == '1h':
        since = now - timedelta(hours=1)
        selected_time_range = '1h'
    elif time_range == '1d':
        since = now - timedelta(days=1)
        selected_time_range = '1d'
    elif time_range == '7d':
        since = now - timedelta(days=7)
        selected_time_range = '7d'
    elif time_range == '1m':
        since = now - timedelta(days=30)
        selected_time_range = '1m'
    elif time_range == 'custom':
        # Handle custom date range
        start_date_str = request.GET.get('start_date')
        end_date_str = request.GET.get('end_date')
        
        if start_date_str and end_date_str:
            try:
                # Parse datetime-local format (YYYY-MM-DDTHH:MM)
                since = datetime.fromisoformat(start_date_str.replace('T', ' '))
                until = datetime.fromisoformat(end_date_str.replace('T', ' '))
                selected_time_range = 'custom'
            except ValueError:
                # Fallback to last hour if parsing fails
                since = now - timedelta(hours=1)
                until = now
                selected_time_range = '1h'
        else:
            # Fallback to last hour if dates not provided
            since = now - timedelta(hours=1)
            until = now
            selected_time_range = '1h'
    else:
        # Default to last hour
        since = now - timedelta(hours=1)
        selected_time_range = '1h'
    
    # For non-custom ranges, set until to now
    if time_range != 'custom':
        until = now

    # ClickHouse expects ISO format
    since_str = since.strftime('%Y-%m-%d %H:%M:%S')
    until_str = until.strftime('%Y-%m-%d %H:%M:%S')

    # Query 1: Top Traffic (existing)
    traffic_query = f'''
        SELECT
            srcip,
            dstip,
            dstport,
            sum(sentbyte) AS total_sent,
            sum(rcvdbyte) AS total_rcvd,
            sum(sentbyte) + sum(rcvdbyte) AS total_bytes
        FROM fortigate_traffic
        WHERE timestamp >= now() - INTERVAL {since_interval}
        GROUP BY srcip, dstip, dstport
        ORDER BY total_bytes DESC
        LIMIT 10
    '''
    
    # Query 2: Top Categories
    categories_query = f'''
        SELECT
            appcategory,
            count(*) AS count,
            sum(sentbyte) + sum(rcvdbyte) AS total_bytes
        FROM fortigate_traffic
        WHERE timestamp >= now() - INTERVAL {since_interval}
          AND appcategory != '' AND appcategory IS NOT NULL
        GROUP BY appcategory
        ORDER BY count DESC
        LIMIT 10
    '''
    
    # Query 3: Top URLs (from threat_logs table if exists, otherwise from fortigate_traffic)
    urls_query = f'''
        SELECT
            hostname,
            count(*) AS count,
            sum(sentbyte) + sum(rcvdbyte) AS total_bytes
        FROM fortigate_traffic
        WHERE timestamp >= now() - INTERVAL {since_interval}
          AND hostname != '' AND hostname IS NOT NULL
        GROUP BY hostname
        ORDER BY count DESC
        LIMIT 10
    '''
    
    # Query 4: Top Users
    users_query = f'''
        SELECT
            username,
            count(*) AS count,
            sum(sentbyte) + sum(rcvdbyte) AS total_bytes
        FROM fortigate_traffic
        WHERE timestamp >= now() - INTERVAL {since_interval}
          AND username != '' AND username IS NOT NULL
        GROUP BY username
        ORDER BY count DESC
        LIMIT 10
    '''
    
    # Query 5: Top Destination Countries
    countries_query = f'''
        SELECT
            dstcountry,
            count(*) AS count,
            sum(sentbyte) + sum(rcvdbyte) AS total_bytes
        FROM fortigate_traffic
        WHERE timestamp >= now() - INTERVAL {since_interval}
          AND dstcountry != '' AND dstcountry IS NOT NULL
        GROUP BY dstcountry
        ORDER BY count DESC
        LIMIT 10
    '''
    
    # Execute all queries
    try:
        traffic_rows = client.execute(traffic_query)
    except Exception:
        traffic_rows = []
        
    try:
        categories_rows = client.execute(categories_query)
    except Exception:
        categories_rows = []
        
    try:
        urls_rows = client.execute(urls_query)
    except Exception:
        urls_rows = []
        
    try:
        users_rows = client.execute(users_query)
    except Exception:
        users_rows = []
        
    try:
        countries_rows = client.execute(countries_query)
    except Exception:
        countries_rows = []
    
    # Format results
    top_traffic = [
        {
            'srcip': row[0],
            'dstip': row[1],
            'dstport': row[2],
            'total_sent': row[3],
            'total_rcvd': row[4],
            'total_bytes': row[5],
        }
        for row in traffic_rows
    ]
    
    top_categories = [
        {
            'category': row[0],
            'count': row[1],
            'total_bytes': row[2],
        }
        for row in categories_rows
    ]
    
    top_urls = [
        {
            'url': row[0],
            'count': row[1],
            'total_bytes': row[2],
        }
        for row in urls_rows
    ]
    
    top_users = [
        {
            'username': row[0],
            'count': row[1],
            'total_bytes': row[2],
        }
        for row in users_rows
    ]
    
    top_countries = [
        {
            'country': row[0],
            'count': row[1],
            'total_bytes': row[2],
        }
        for row in countries_rows
    ]
    
    # Calculate summary statistics
    total_connections = 0
    total_bytes = 0
    active_ips = 0
    
    try:
        # Get total connection count
        conn_query = f"""
        SELECT COUNT(*) 
        FROM fortigate_traffic 
        WHERE timestamp >= now() - INTERVAL {since_interval}
        """
        # Custom time range until clause not needed for standard intervals
            
        conn_result = client.execute(conn_query)
        total_connections = conn_result[0][0] if conn_result else 0
        
        # Get total bytes transferred
        bytes_query = f"""
        SELECT SUM(sentbyte + rcvdbyte) 
        FROM fortigate_traffic 
        WHERE timestamp >= now() - INTERVAL {since_interval}
        """
        # Custom time range until clause not needed for standard intervals
            
        bytes_result = client.execute(bytes_query)
        total_bytes = bytes_result[0][0] if bytes_result and bytes_result[0][0] else 0
        
        # Get active unique source IPs
        ips_query = f"""
        SELECT COUNT(DISTINCT srcip) 
        FROM fortigate_traffic 
        WHERE timestamp >= now() - INTERVAL {since_interval}
        """
        # Custom time range until clause not needed for standard intervals
            
        ips_result = client.execute(ips_query)
        active_ips = ips_result[0][0] if ips_result else 0
        
    except Exception as e:
        print(f"Error calculating summary statistics: {e}")
        # Keep default values of 0
    
    return render(request, 'dashboard/top_summary.html', {
        'top_traffic': top_traffic,
        'top_categories': top_categories,
        'top_urls': top_urls,
        'top_users': top_users,
        'top_countries': top_countries,
        'selected_time_range': selected_time_range,
        'total_connections': total_connections,
        'total_bytes': total_bytes,
        'active_ips': active_ips,
    })


PROTO_MAP = {
    1: 'ICMP', 6: 'TCP', 17: 'UDP', 47: 'GRE',
    50: 'ESP', 51: 'AH', 58: 'ICMPv6',
    # Add more if needed
}

def format_bytes(num_bytes):
    if num_bytes is None:
        return "0 B"
    num = float(num_bytes)
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(num) < 1024.0:
            return f"{num:.0f} {unit}" if unit == 'B' else f"{num:.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} PB"

def clickhouse_logs_view(request):
    client = Client(
        host=CH_HOST,
        port=CH_PORT,
        user=CH_USER,
        password=CH_PASSWORD,
        database=CH_DB
    )
    
    # Check which tables exist
    try:
        tables_result = client.execute("SHOW TABLES FROM network_logs")
        available_tables = [row[0] for row in tables_result]
        has_pa_traffic = 'pa_traffic' in available_tables
        has_threat_logs = 'threat_logs' in available_tables
        has_fortigate_traffic = 'fortigate_traffic' in available_tables
    except Exception:
        has_pa_traffic = False
        has_threat_logs = False
        has_fortigate_traffic = True  # Fallback to original table
    

    # Get client's real IP (for display or other purposes)
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        viewer_ip = x_forwarded_for.split(',')[0]
    else:
        viewer_ip = request.META.get('REMOTE_ADDR')

    # --- Time Filter ---
    time_range = request.GET.get('time_range', 'last_hour')
    # Use ClickHouse native time functions instead of Django UTC time to avoid timezone issues
    use_clickhouse_time = True
    until = None
    
    if time_range == 'last_6_hours':
        since_interval = '6 HOUR'
    elif time_range == 'last_24_hours':
        since_interval = '1 DAY'
    elif time_range == 'last_7_days':
        since_interval = '7 DAY'
    elif time_range == 'last_30_days':
        since_interval = '30 DAY'
    elif time_range == 'custom':
        # Handle custom time range - still use Django time for custom ranges
        use_clickhouse_time = False
        time_from = request.GET.get('time_from', '')
        time_to = request.GET.get('time_to', '')
        
        # Get ClickHouse current time for proper timezone handling
        ch_now = client.execute('SELECT now()')[0][0]
        
        if time_from:
            try:
                since = datetime.strptime(time_from, '%Y-%m-%dT%H:%M')
            except ValueError:
                since = ch_now - timedelta(hours=1)
        else:
            since = ch_now - timedelta(hours=1)
            
        if time_to:
            try:
                until = datetime.strptime(time_to, '%Y-%m-%dT%H:%M')
            except ValueError:
                until = None
        
        since_str = since.strftime('%Y-%m-%d %H:%M:%S')
    else:  # default to last_hour
        since_interval = '1 HOUR'
    
    # Create user-friendly time range display
    time_range_display = {
        'last_hour': 'Last Hour',
        'last_6_hours': 'Last 6 Hours', 
        'last_24_hours': 'Last 24 Hours',
        'last_7_days': 'Last 7 Days',
        'last_30_days': 'Last 30 Days',
        'custom': 'Custom Range'
    }.get(time_range, 'Last Hour')
    
    # --- Get filter values from request ---
    srcip_filter = request.GET.get('srcip', '').strip()
    dstip_filter = request.GET.get('dstip', '').strip()
    srcport_filter = request.GET.get('srcport', '').strip()
    dstport_filter = request.GET.get('dstport', '').strip()
    action_filter = request.GET.get('action', '').strip()
    devname_filter = request.GET.get('devname', '').strip()
    appcategory_filter = request.GET.get('appcategory', '').strip()
    hostname_filter = request.GET.get('hostname', '').strip()
    username_filter = request.GET.get('username', '').strip()
    dstcountry_filter = request.GET.get('dstcountry', '').strip()
    log_source_filter = request.GET.get('log_source', '').strip()
    
    # By default, exclude threat_logs unless specifically requested
    if not log_source_filter or log_source_filter not in ['threat_logs']:
        has_threat_logs = False
    
    # New filter parameters
    protocol_filter = request.GET.get('protocol', '').strip()
    search_filter = request.GET.get('search', '').strip()
    min_bytes_filter = request.GET.get('min_bytes', '').strip()
    max_bytes_filter = request.GET.get('max_bytes', '').strip()
    min_duration_filter = request.GET.get('min_duration', '').strip()
    max_duration_filter = request.GET.get('max_duration', '').strip()
    
    # Build WHERE clauses based on filter inputs
    if use_clickhouse_time:
        where_clauses = [f"timestamp >= now() - INTERVAL {since_interval}"]
    else:
        where_clauses = [f"timestamp >= parseDateTimeBestEffort('{since_str}')"]
        # Add until clause if custom time range with end date
        if until:
            until_str = until.strftime('%Y-%m-%d %H:%M:%S')
            where_clauses.append(f"timestamp <= parseDateTimeBestEffort('{until_str}')") 
    
    if srcip_filter:
        if srcip_filter == 'external_only':
            # Filter for external IPs (not private networks)
            where_clauses.append("""
                NOT (
                    srcip LIKE '10.%' OR 
                    srcip LIKE '192.168.%' OR 
                    srcip LIKE '172.16.%' OR srcip LIKE '172.17.%' OR srcip LIKE '172.18.%' OR srcip LIKE '172.19.%' OR
                    srcip LIKE '172.20.%' OR srcip LIKE '172.21.%' OR srcip LIKE '172.22.%' OR srcip LIKE '172.23.%' OR
                    srcip LIKE '172.24.%' OR srcip LIKE '172.25.%' OR srcip LIKE '172.26.%' OR srcip LIKE '172.27.%' OR
                    srcip LIKE '172.28.%' OR srcip LIKE '172.29.%' OR srcip LIKE '172.30.%' OR srcip LIKE '172.31.%' OR
                    srcip = '127.0.0.1' OR srcip LIKE '169.254.%'
                )
            """.strip())
        else:
            where_clauses.append(f"srcip = '{srcip_filter}'")
    if dstip_filter:
        where_clauses.append(f"dstip = '{dstip_filter}'")
    if srcport_filter:
        # Handle range if provided (e.g., 1000-2000)
        if '-' in srcport_filter:
            start, end = srcport_filter.split('-')
            where_clauses.append(f"srcport >= {start.strip()} AND srcport <= {end.strip()}")
        else:
            where_clauses.append(f"srcport = {srcport_filter}")
    if dstport_filter:
        # Handle range if provided (e.g., 3000-4000)
        if '-' in dstport_filter:
            start, end = dstport_filter.split('-')
            where_clauses.append(f"dstport >= {start.strip()} AND dstport <= {end.strip()}")
        else:
            where_clauses.append(f"dstport = {dstport_filter}")
    if action_filter:
        where_clauses.append(f"action = '{action_filter}'")
    if devname_filter:
        where_clauses.append(f"device_name = '{devname_filter}'")
    if appcategory_filter:
        where_clauses.append(f"appcategory = '{appcategory_filter}'")
    if hostname_filter:
        where_clauses.append(f"hostname = '{hostname_filter}'")
    if username_filter:
        where_clauses.append(f"username = '{username_filter}'")
    if dstcountry_filter:
        where_clauses.append(f"dstcountry = '{dstcountry_filter}'")
    
    # New filter clauses
    if protocol_filter:
        # Map protocol names to numbers
        protocol_map = {'TCP': 6, 'UDP': 17, 'ICMP': 1, 'GRE': 47}
        if protocol_filter.upper() in protocol_map:
            where_clauses.append(f"proto = {protocol_map[protocol_filter.upper()]}")
        elif protocol_filter.isdigit():
            where_clauses.append(f"proto = {protocol_filter}")
    
    if search_filter:
        # Search across multiple fields (simple text search)
        search_conditions = [
            f"srcip LIKE '%{search_filter}%'",
            f"dstip LIKE '%{search_filter}%'",
            f"hostname LIKE '%{search_filter}%'",
            f"username LIKE '%{search_filter}%'",
            f"appcategory LIKE '%{search_filter}%'"
        ]
        where_clauses.append(f"({' OR '.join(search_conditions)})")
    
    if min_bytes_filter and min_bytes_filter.isdigit():
        where_clauses.append(f"(sentbyte + rcvdbyte) >= {min_bytes_filter}")
    
    if max_bytes_filter and max_bytes_filter.isdigit():
        where_clauses.append(f"(sentbyte + rcvdbyte) <= {max_bytes_filter}")
    
    if min_duration_filter and min_duration_filter.isdigit():
        where_clauses.append(f"duration >= {min_duration_filter}")
    
    if max_duration_filter and max_duration_filter.isdigit():
        where_clauses.append(f"duration <= {max_duration_filter}")
    
    # Combine all WHERE clauses
    where_clause = ' AND '.join(where_clauses)
    
    # --- Fetch available action values for dropdown from all tables ---
    action_queries = []
    if has_fortigate_traffic:
        action_queries.append(f"SELECT DISTINCT action FROM fortigate_traffic WHERE {where_clause}")
    if has_pa_traffic:
        pa_where_clause = where_clause.replace('srcip', 'src_ip').replace('dstip', 'dst_ip').replace('srcport', 'src_port').replace('dstport', 'dst_port').replace('appcategory', 'app_category').replace('hostname', 'application').replace('username', 'src_user').replace('dstcountry', 'dst_country').replace('proto', 'protocol').replace('sentbyte', 'bytes_sent').replace('rcvdbyte', 'bytes_received')
        action_queries.append(f"SELECT DISTINCT action FROM pa_traffic WHERE {pa_where_clause}")
    
    if action_queries:
        action_query = f"SELECT DISTINCT action FROM ({' UNION ALL '.join(action_queries)}) AS combined_actions ORDER BY action"
    else:
        action_query = "SELECT 'allow' as action"
    
    try:
        available_actions = [row[0] for row in client.execute(action_query)]
    except Exception as e:
        available_actions = ['allow', 'deny', 'drop', 'accept']  # Default fallback

    # --- Fetch available device names from registered_devices table ---
    try:
        # First, check if registered_devices table exists
        tables_result = client.execute("SHOW TABLES LIKE 'registered_devices'")
        has_registered_devices = len(tables_result) > 0
        
        if has_registered_devices:
            # Get device names from registered_devices table (only enabled devices)
            device_query = "SELECT DISTINCT device_name FROM registered_devices WHERE enabled = 1 AND device_name IS NOT NULL AND device_name <> '' ORDER BY device_name"
            available_devices = [row[0] for row in client.execute(device_query)]
        else:
            # Fallback to old method if registered_devices table doesn't exist
            device_queries = []
            if has_fortigate_traffic:
                device_queries.append("SELECT DISTINCT devname as device_name FROM fortigate_traffic WHERE devname IS NOT NULL AND devname <> '' AND length(devname) >= 3 AND devname NOT LIKE '%:%' AND devname NOT LIKE '%=' AND (devname NOT LIKE '%.%' OR devname LIKE '%.%.%.%') AND devname NOT LIKE 'FGT-' AND devname NOT LIKE 'FGT-F' AND devname NOT LIKE 'FGT-FW' AND devname NOT LIKE 'FGT-FW0'")
            if has_pa_traffic:
                device_queries.append("SELECT DISTINCT device_name FROM pa_traffic WHERE device_name IS NOT NULL AND device_name <> '' AND length(device_name) > 8 AND NOT match(device_name, '^[0-9]+$') AND (device_name LIKE '%FW%' OR device_name LIKE '%PA%' OR device_name LIKE '%PALO%')")
            
            if device_queries:
                device_query = f"SELECT DISTINCT device_name FROM ({' UNION ALL '.join(device_queries)}) AS combined_devices ORDER BY device_name"
                available_devices = [row[0] for row in client.execute(device_query)]
            else:
                available_devices = []
                
    except Exception as e:
        logging.error(f"Error fetching device names: {e}")
        available_devices = []

    # --- Pagination ---
    page = int(request.GET.get('page', 1))
    
    # Update count query to include all tables
    count_queries = []
    if has_fortigate_traffic:
        count_queries.append(f"SELECT count() FROM fortigate_traffic WHERE {where_clause}")
    if has_pa_traffic:
        pa_where_clause = where_clause.replace('srcip', 'src_ip').replace('dstip', 'dst_ip').replace('srcport', 'src_port').replace('dstport', 'dst_port').replace('appcategory', 'app_category').replace('hostname', 'application').replace('username', 'src_user').replace('dstcountry', 'dst_country').replace('proto', 'protocol').replace('sentbyte', 'bytes_sent').replace('rcvdbyte', 'bytes_received')
        count_queries.append(f"SELECT count() FROM pa_traffic WHERE {pa_where_clause}")
    if has_threat_logs:
        threat_where_clause = where_clause.replace('srcip', 'source_address').replace('dstip', 'destination_address').replace('srcport', 'source_port').replace('dstport', 'destination_port').replace('appcategory', 'application_category').replace('hostname', 'application').replace('username', 'source_user').replace('dstcountry', 'destination_country').replace('proto', 'protocol').replace('sentbyte', 'bytes_sent').replace('rcvdbyte', 'bytes_received')
        count_queries.append(f"SELECT count() FROM threat_logs WHERE {threat_where_clause}")
    
    if count_queries:
        count_query = f"SELECT {' + '.join([f'({q})' for q in count_queries])}"
    else:
        count_query = "SELECT 0"
    
    try:
        total_logs_count_result = client.execute(count_query)
        total_logs_count = total_logs_count_result[0][0] if total_logs_count_result else 0
    except Exception:
        total_logs_count = 0  # Fallback on error

    total_pages = (total_logs_count + SUBNET_GROUP_PAGE_SIZE - 1) // SUBNET_GROUP_PAGE_SIZE if SUBNET_GROUP_PAGE_SIZE > 0 else 1
    offset = (page - 1) * SUBNET_GROUP_PAGE_SIZE

    # Get total count of fine-grained groups with filters
    total_grouped_logs_count_query = f"""
        SELECT count()
        FROM (
            SELECT srcip, dstip, dstport, action
            FROM fortigate_traffic
            WHERE {where_clause}
            GROUP BY srcip, dstip, dstport, action
        )
    """
    
    try:
        total_grouped_logs_count_result = client.execute(total_grouped_logs_count_query)
        total_grouped_logs_count = total_grouped_logs_count_result[0][0] if total_grouped_logs_count_result else 0
    except Exception as e:
        total_grouped_logs_count = 0 # Fallback on error

    # --- Build union query to fetch logs from multiple tables ---
    union_queries = []
    
    # Apply log source filter - skip tables not matching the filter
    if log_source_filter:
        if log_source_filter == 'fortigate_traffic':
            has_pa_traffic = False
            has_threat_logs = False
        elif log_source_filter == 'pa_traffic':
            has_fortigate_traffic = False
            has_threat_logs = False
        elif log_source_filter == 'threat_logs':
            has_fortigate_traffic = False
            has_pa_traffic = False
    
    # FortiGate traffic logs
    if has_fortigate_traffic:
        fortigate_query = f"""
            SELECT
                timestamp,
                raw_message,
                toString(srcip) as src_ip,
                srcport as src_port,
                toString(dstip) as dst_ip,
                dstport as dst_port,
                action,
                proto as protocol,
                rcvdbyte as bytes_received,
                sentbyte as bytes_sent,
                sentpkt as packets_sent,
                rcvdpkt as packets_received,
                duration as elapsed_time,
                srcintf as src_interface,
                dstintf as dst_interface,
                policyname as rule_name,
                username as src_user,
                srccountry as src_country,
                dstcountry as dst_country,
                'fortigate_traffic' as log_source,
                device_name,
                '' as application,
                '' as threat_id,
                '' as severity
            FROM fortigate_traffic
            WHERE {where_clause}
        """
        union_queries.append(fortigate_query)
    
    # PaloAlto traffic logs
    if has_pa_traffic:
        # Adjust where clause for pa_traffic table field names
        pa_where_clause = where_clause
        pa_where_clause = pa_where_clause.replace('srcip', 'src_ip')
        pa_where_clause = pa_where_clause.replace('dstip', 'dst_ip')
        pa_where_clause = pa_where_clause.replace('srcport', 'src_port')
        pa_where_clause = pa_where_clause.replace('dstport', 'dst_port')
        pa_where_clause = pa_where_clause.replace('devname', 'device_name')
        pa_where_clause = pa_where_clause.replace('appcategory', 'app_category')
        pa_where_clause = pa_where_clause.replace('hostname', 'application')
        pa_where_clause = pa_where_clause.replace('username', 'src_user')
        pa_where_clause = pa_where_clause.replace('dstcountry', 'dst_country')
        pa_where_clause = pa_where_clause.replace('proto', 'protocol')
        pa_where_clause = pa_where_clause.replace('sentbyte', 'bytes_sent')
        pa_where_clause = pa_where_clause.replace('rcvdbyte', 'bytes_received')
        
        paloalto_query = f"""
            SELECT
                timestamp,
                raw_message,
                toString(src_ip) as src_ip,
                src_port,
                toString(dst_ip) as dst_ip,
                dst_port,
                action,
                protocol,
                bytes_received,
                bytes_sent,
                packets_sent,
                packets_received,
                elapsed_time,
                src_interface,
                dst_interface,
                rule_name,
                src_user,
                src_country,
                dst_country,
                'pa_traffic' as log_source,
                device_name,
                application,
                '' as threat_id,
                '' as severity
            FROM pa_traffic
            WHERE {pa_where_clause}
        """
        union_queries.append(paloalto_query)
    
    # Threat logs
    if has_threat_logs:
        # Adjust where clause for threat_logs table field names
        threat_where_clause = where_clause
        threat_where_clause = threat_where_clause.replace('srcip', 'source_address')
        threat_where_clause = threat_where_clause.replace('dstip', 'destination_address')
        threat_where_clause = threat_where_clause.replace('srcport', 'source_port')
        threat_where_clause = threat_where_clause.replace('dstport', 'destination_port')
        threat_where_clause = threat_where_clause.replace('devname', 'device_name')
        threat_where_clause = threat_where_clause.replace('appcategory', 'application_category')
        threat_where_clause = threat_where_clause.replace('hostname', 'application')
        threat_where_clause = threat_where_clause.replace('username', 'source_user')
        threat_where_clause = threat_where_clause.replace('dstcountry', 'destination_country')
        threat_where_clause = threat_where_clause.replace('proto', 'protocol')
        threat_where_clause = threat_where_clause.replace('sentbyte', 'bytes_sent')
        threat_where_clause = threat_where_clause.replace('rcvdbyte', 'bytes_received')
        
        threat_query = f"""
            SELECT
                timestamp,
                raw_message,
                source_address as src_ip,
                source_port as src_port,
                destination_address as dst_ip,
                destination_port as dst_port,
                action,
                protocol,
                bytes_received,
                bytes_sent,
                packets_sent,
                packets_received,
                elapsed_time,
                inbound_interface as src_interface,
                outbound_interface as dst_interface,
                rule_name,
                source_user as src_user,
                source_country as src_country,
                destination_country as dst_country,
                'threat_logs' as log_source,
                device_name,
                application,
                type as threat_id,
                log_action as severity
            FROM threat_logs
            WHERE {threat_where_clause}
        """
        union_queries.append(threat_query)
    
    # Combine all queries with UNION ALL
    if union_queries:
        query = f"""
            SELECT * FROM (
                {' UNION ALL '.join(union_queries)}
            ) AS combined_logs
            ORDER BY timestamp DESC
            LIMIT {SUBNET_GROUP_PAGE_SIZE} OFFSET {offset}
        """
    else:
        # Fallback to empty result if no tables available
        query = "SELECT timestamp, '', '', 0, '', 0, '', 0, 0, 0, 0, 0, 0, '', '', '', '', '', '', '', '', '', '', '' LIMIT 0"
    
    try:
        db_rows = client.execute(query)
    except Exception:
        db_rows = []  # Fallback on error

    processed_logs_for_template = []
    for db_row in db_rows:
        # Unpack fields from unified query result
        ts_obj = db_row[0]
        raw_message_val = db_row[1]
        srcip_val = db_row[2]
        srcport_val = db_row[3]
        dstip_val = db_row[4]
        dstport_val = db_row[5]
        action_val = db_row[6]
        proto_num = db_row[7]
        rcvdbyte_val = db_row[8]
        sentbyte_val = db_row[9]
        sentpkt_val = db_row[10]
        rcvdpkt_val = db_row[11]
        duration_val = db_row[12] if db_row[12] is not None else 0
        srcintf_val = db_row[13]
        dstintf_val = db_row[14]
        policyname_val = db_row[15]
        username_val = db_row[16] if len(db_row) > 16 and db_row[16] is not None else 'N/A'
        srccountry_val = db_row[17] if len(db_row) > 17 and db_row[17] is not None else 'N/A'
        dstcountry_val = db_row[18] if len(db_row) > 18 and db_row[18] is not None else 'N/A'
        log_source_val = db_row[19] if len(db_row) > 19 and db_row[19] is not None else 'unknown'
        device_name_val = db_row[20] if len(db_row) > 20 and db_row[20] is not None else 'N/A'
        application_val = db_row[21] if len(db_row) > 21 and db_row[21] is not None else 'N/A'
        threat_id_val = db_row[22] if len(db_row) > 22 and db_row[22] is not None else ''
        severity_val = db_row[23] if len(db_row) > 23 and db_row[23] is not None else ''

        # DEBUG: Print the raw_message value for each row

        # --- Format and Prepare Log Entry ---
        ts_display_str = ts_obj.strftime('%Y-%m-%d %H:%M:%S') if hasattr(ts_obj, 'strftime') else str(ts_obj)
        proto_str = PROTO_MAP.get(proto_num, str(proto_num))
        rcvdbyte_display_str = format_bytes(rcvdbyte_val)
        sentbyte_display_str = format_bytes(sentbyte_val)
        duration_display_str = f"{duration_val}ms"

        # --- Create a comprehensive dictionary for each log ---
        # This dictionary's keys should align with what your JavaScript expansion template expects.
        log_entry = {
            # Fields for main table display (also available for expansion)
            'ts_display': ts_display_str,
            'action': action_val,  # Corresponds to `log.waf` in JS example (FLAGGED/PASSED)
            'srcip': srcip_val,
            'username': username_val, # Add username to log_entry
            'dstip': dstip_val,
            'dstport_val': dstport_val, # For display in table as Dst Port
            'proto_str': proto_str,
            'rcvdbyte_display': rcvdbyte_display_str,
            'sentbyte_display': sentbyte_display_str,
            'duration_ms': duration_val,       # For `log.dur` in JS for bar width
            'duration_display': duration_display_str, # For text like "67ms"
            'responseCode': 'N/A', # No response_code in DB
            'responseLengthDisplay': rcvdbyte_display_str, # Example: Use received bytes for response length
                                                           # Or use a dedicated response length field if available.
                                                           # Corresponds to `log.len` in JS table and `log.responseLength` in expansion
            'raw_message': raw_message_val,    # Pass raw_message to frontend
            'srcintf': srcintf_val,
            'dstintf': dstintf_val,
            'policyname': policyname_val,
            'sentpkt': sentpkt_val,
            'rcvdpkt': rcvdpkt_val,
            'srccountry': srccountry_val,
            'dstcountry': dstcountry_val,
            'log_source': log_source_val,      # New field to identify source table
            'device_name': device_name_val,    # Device name from all tables
            'application': application_val,    # Application info
            'threat_id': threat_id_val,        # Threat ID for threat logs
            'severity': severity_val,          # Severity for threat logs

            # Detailed fields for JavaScript expansion (Populate these from your data)
            'clientRTT': "N/A",                 # TODO: Fetch or derive
            'serverRTTLB': "N/A",               # TODO: Fetch or derive
            'appResponse': "N/A",               # TODO: Fetch or derive
            'dataTransfer': "N/A",              # TODO: Fetch or derive
            'totalTime': duration_display_str,  # Or a more specific total time if available

            'srcport': srcport_val,             # Use 'srcport' to match template, assign fetched value
            'location': "Internal",             # Fallback for `log.srcport` if `srcport_val` is "N/A" # This fallback might need review if srcport is now always present
            
            # Example: Parsing User Agent for OS and Browser
            'sourceInterfaceOS': "N/A",         # Not available in DB
            'browser': "N/A",                   # Not available in DB
            'device': "N/A",                    # Not available in DB

            'startTime': ts_obj.strftime("%Y-%m-%d, %H:%M:%S") if hasattr(ts_obj, 'strftime') else "N/A", # Format for `log.startTime`

            'requestID': "N/A",                 # For `log.requestID` (Destination Interface) - TODO: Fetch or derive
            'endTime': "N/A",                   # TODO: Calculate or fetch for `log.endTime`
            'serviceEngine': "N/A",             # TODO: Fetch or derive for `log.serviceEngine`
            'persistenceSessionID': "N/A",      # TODO: Fetch or derive for `log.persistenceSessionID`
            'significance': "N/A",              # Not available in DB
            'serverIPDetail': "N/A",            # TODO: Fetch or derive for `log.serverIPDetail`
            'resContentType': "N/A",            # TODO: Fetch or derive for `log.resContentType`
            'resOtherDetails': "N/A",           # TODO: Fetch or derive for `log.resOther`
            'tl': "|||", # If this is still needed for the table
        }
        processed_logs_for_template.append(log_entry)

    # Pagination range logic for up to 5 pages
    if total_pages <= 5:
        page_range = range(1, total_pages + 1)
    else:
        start = max(page - 2, 1)
        end = min(start + 4, total_pages)
        if end - start < 4:
            start = max(end - 4, 1)
        page_range = range(start, end + 1)

    # Pagination range logic for up to 5 pages
    if total_pages <= 5:
        page_range = range(1, total_pages + 1)
    else:
        start = max(page - 2, 1)
        end = min(start + 4, total_pages)
        if end - start < 4:
            start = max(end - 4, 1)
        page_range = range(start, end + 1)

    context = {
        'logs_for_display': processed_logs_for_template, # For Django template to render table rows
        'logs_json_for_expansion': json.dumps(processed_logs_for_template, default=str), # For JS `logData`
        'viewer_ip': viewer_ip, # The IP of the person viewing the page
        'current_page': page,
        'total_pages': total_pages,
        'total_logs_count': total_logs_count,
        'page_range': page_range,
        'selected_time_range': time_range, # Pass to template for dropdown selection
        
        # Filter-related context variables
        'available_actions': available_actions, # For Action dropdown
        'srcip_filter': srcip_filter,  # Current filter values to prepopulate inputs
        'dstip_filter': dstip_filter,
        'srcport_filter': srcport_filter,
        'dstport_filter': dstport_filter,
        'action_filter': action_filter,
        'devname_filter': devname_filter,
        'available_devices': available_devices,
        'appcategory_filter': appcategory_filter,
        'hostname_filter': hostname_filter,
        'username_filter': username_filter,
        'dstcountry_filter': dstcountry_filter,
        'protocol_filter': protocol_filter,
        'search_filter': search_filter,
        'min_bytes_filter': min_bytes_filter,
        'max_bytes_filter': max_bytes_filter,
        'min_duration_filter': min_duration_filter,
        'max_duration_filter': max_duration_filter,
        'time_range': time_range,
        'time_range_display': time_range_display,
        'time_from': request.GET.get('time_from', ''),
        'time_to': request.GET.get('time_to', ''),
        'log_source_filter': log_source_filter,
    }
    return render(request, 'dashboard/logs2.html', context)



def system_config_view(request):
    """System Configuration view with service status dashboard"""
    import subprocess
    import json
    
    # Define the services we want to monitor
    services = [
        {
            'name': 'paloalto_to_clickhouse.service',
            'display_name': 'PaloAlto Traffic Logs',
            'description': 'Ingests PaloAlto firewall traffic logs to ClickHouse',
            'category': 'PaloAlto'
        },
        {
            'name': 'paloalto-url-loader.service',
            'display_name': 'PaloAlto URL Threat Logs',
            'description': 'Ingests PaloAlto URL threat logs to ClickHouse',
            'category': 'PaloAlto'
        },
        {
            'name': 'fortigate_to_clickhouse.service',
            'display_name': 'FortiGate Log Ingestion',
            'description': 'Ingests FortiGate firewall logs to ClickHouse',
            'category': 'FortiGate'
        }
    ]
    
    # Get status for each service
    service_statuses = []
    for service in services:
        try:
            # Get service status
            result = subprocess.run(
                ['systemctl', 'is-active', service['name']],
                capture_output=True,
                text=True,
                timeout=5
            )
            status_output = result.stdout.strip()
            is_active = status_output == 'active'
            
            # Debug logging
            print(f"DEBUG: Service {service['name']} status output: '{status_output}', is_active: {is_active}")
            
            # Get detailed status
            status_result = subprocess.run(
                ['systemctl', 'status', service['name']],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            # Parse status info
            status_lines = status_result.stdout.split('\n')
            main_pid = None
            memory_usage = None
            cpu_time = None
            uptime = None
            
            for line in status_lines:
                if 'Main PID:' in line:
                    main_pid = line.split('Main PID:')[1].strip().split(' ')[0]
                elif 'Memory:' in line:
                    memory_usage = line.split('Memory:')[1].strip().split(' ')[0]
                elif 'CPU:' in line:
                    cpu_time = line.split('CPU:')[1].strip().split(' ')[0]
                elif 'Active:' in line and 'since' in line:
                    try:
                        uptime_part = line.split('since ')[1].split(';')[0].strip()
                        uptime = uptime_part
                    except:
                        uptime = 'Unknown'
            
            service_statuses.append({
                'name': service['name'],
                'display_name': service['display_name'],
                'description': service['description'],
                'category': service['category'],
                'status': 'running' if is_active else 'stopped',
                'main_pid': main_pid or 'N/A',
                'memory_usage': memory_usage or 'N/A',
                'cpu_time': cpu_time or 'N/A',
                'uptime': uptime or 'N/A',
                'enabled': True  # We'll assume enabled for now
            })
            
        except Exception as e:
            service_statuses.append({
                'name': service['name'],
                'display_name': service['display_name'],
                'description': service['description'],
                'category': service['category'],
                'status': 'error',
                'main_pid': 'N/A',
                'memory_usage': 'N/A',
                'cpu_time': 'N/A',
                'uptime': 'N/A',
                'enabled': False,
                'error': str(e)
            })
    
    # Group services by category
    services_by_category = {}
    for service in service_statuses:
        category = service['category']
        if category not in services_by_category:
            services_by_category[category] = []
        services_by_category[category].append(service)
    
    context = {
        'services_by_category': services_by_category,
        'total_services': len(service_statuses),
        'running_services': len([s for s in service_statuses if s['status'] == 'running']),
        'stopped_services': len([s for s in service_statuses if s['status'] == 'stopped']),
        'error_services': len([s for s in service_statuses if s['status'] == 'error']),
    }
    
    return render(request, 'dashboard/system_config.html', context)

def service_action_view(request):
    """Handle service start/stop/restart actions via AJAX"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Method not allowed'})
    
    import subprocess
    import json
    
    try:
        data = json.loads(request.body)
        service_name = data.get('service_name')
        action = data.get('action')
        
        if not service_name or not action:
            return JsonResponse({'success': False, 'error': 'Missing service_name or action'})
        
        if action not in ['start', 'stop', 'restart']:
            return JsonResponse({'success': False, 'error': 'Invalid action'})
        
        # Execute the systemctl command
        cmd = ['sudo', 'systemctl', action, service_name]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            return JsonResponse({'success': True, 'message': f'Service {action} successful'})
        else:
            return JsonResponse({
                'success': False, 
                'error': f'Command failed: {result.stderr or result.stdout}'
            })
            
    except subprocess.TimeoutExpired:
        return JsonResponse({'success': False, 'error': 'Command timed out'})
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON data'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': f'Unexpected error: {str(e)}'})

def logs_config_view(request):
    """Logs Configuration view for managing firewall log settings"""
    import subprocess
    import json
    import os
    import glob
    
    # Define current log configurations
    log_configs = {
        'fortigate': {
            'name': 'FortiGate',
            'ip_addresses': ['192.168.100.221'],
            'log_file': '/var/log/fortigate.log',
            'rsyslog_config': '/etc/rsyslog.d/fortigate.conf',
            'service': 'fortigate_to_clickhouse.service',
            'port': 514,
            'protocol': 'UDP',
            'description': 'FortiGate firewall logs via syslog'
        },
        'paloalto': {
            'name': 'PaloAlto',
            'ip_addresses': ['10.12.50.61', '192.168.1.100'],
            'log_file': '/var/log/paloalto-1004.log',
            'rsyslog_config': '/etc/rsyslog.d/paloalto.conf',
            'service': 'paloalto_to_clickhouse.service',
            'port': 1004,
            'protocol': 'UDP',
            'description': 'PaloAlto firewall logs via syslog'
        }
    }
    
    # Get current log file statistics
    log_stats = {}
    for vendor, config in log_configs.items():
        try:
            log_file = config['log_file']
            if os.path.exists(log_file):
                stat = os.stat(log_file)
                size_mb = stat.st_size / (1024 * 1024)
                
                # Get rotated files
                rotated_files = glob.glob(f"{log_file}*")
                rotated_count = len(rotated_files) - 1  # Exclude the main file
                
                # Get last modification time
                from datetime import datetime
                last_modified = datetime.fromtimestamp(stat.st_mtime)
                
                # Check if service is actively writing (recent modification)
                import time
                is_active = (time.time() - stat.st_mtime) < 300  # Within 5 minutes
                
                log_stats[vendor] = {
                    'exists': True,
                    'size_mb': round(size_mb, 2),
                    'rotated_files': rotated_count,
                    'last_modified': last_modified.strftime('%Y-%m-%d %H:%M:%S'),
                    'is_active': is_active,
                    'path': log_file
                }
            else:
                log_stats[vendor] = {
                    'exists': False,
                    'size_mb': 0,
                    'rotated_files': 0,
                    'last_modified': 'N/A',
                    'is_active': False,
                    'path': log_file
                }
                
        except Exception as e:
            log_stats[vendor] = {
                'exists': False,
                'size_mb': 0,
                'rotated_files': 0,
                'last_modified': 'Error',
                'is_active': False,
                'error': str(e),
                'path': config.get('log_file', 'Unknown')
            }
    
    # Get rsyslog configuration status
    rsyslog_status = {}
    for vendor, config in log_configs.items():
        try:
            rsyslog_file = config['rsyslog_config']
            if os.path.exists(rsyslog_file):
                with open(rsyslog_file, 'r') as f:
                    content = f.read()
                    rsyslog_status[vendor] = {
                        'exists': True,
                        'content_preview': content[:200] + '...' if len(content) > 200 else content,
                        'size': len(content)
                    }
            else:
                rsyslog_status[vendor] = {
                    'exists': False,
                    'content_preview': '',
                    'size': 0
                }
        except Exception as e:
            rsyslog_status[vendor] = {
                'exists': False,
                'content_preview': f'Error: {str(e)}',
                'size': 0
            }
    
    # Get disk usage for log directory
    try:
        result = subprocess.run(['df', '-h', '/var/log'], capture_output=True, text=True)
        disk_usage = result.stdout.split('\n')[1].split() if result.returncode == 0 else None
    except:
        disk_usage = None
    
    # Get total log sizes
    total_log_size = sum(stats.get('size_mb', 0) for stats in log_stats.values())
    
    context = {
        'log_configs': log_configs,
        'log_stats': log_stats,
        'rsyslog_status': rsyslog_status,
        'disk_usage': disk_usage,
        'total_log_size_mb': round(total_log_size, 2),
        'total_devices': sum(len(config['ip_addresses']) for config in log_configs.values()),
    }
    
    return render(request, 'dashboard/logs_config.html', context)

def logs_config_save_view(request):
    """Save logs configuration changes"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Method not allowed'})
    
    import json
    import os
    import subprocess
    
    try:
        data = json.loads(request.body)
        config_type = data.get('config_type')  # 'fortigate' or 'paloalto'
        settings = data.get('settings', {})
        
        if config_type == 'fortigate':
            # Update FortiGate rsyslog configuration
            ip_address = settings.get('ip_address', '192.168.100.221')
            log_file = settings.get('log_file', '/var/log/fortigate.log')
            port = settings.get('port', 514)
            
            rsyslog_content = f"""#### start fortigate.conf ####

# Load UDP syslog listener only once
module(load="imudp")

# Listen on port {port}
input(type="imudp" port="{port}")

# Template for clean FortiGate messages (without PRI)
template(name="FortiGateRaw" type="string" string="%rawmsg-after-pri%\\n")

# Log all messages coming from {ip_address} only
if ($fromhost-ip == '{ip_address}') then {{
    action(
        type="omfile"
        file="{log_file}"
        template="FortiGateRaw"
    )
    stop
}}

#### end fortigate.conf ####
"""
            
            # Write configuration file
            with open('/tmp/fortigate.conf', 'w') as f:
                f.write(rsyslog_content)
                
            return JsonResponse({
                'success': True, 
                'message': 'FortiGate configuration updated. Restart rsyslog to apply changes.',
                'config_preview': rsyslog_content
            })
            
        elif config_type == 'paloalto':
            # Update PaloAlto rsyslog configuration
            ip_addresses = settings.get('ip_addresses', ['10.12.50.61'])
            log_file = settings.get('log_file', '/var/log/paloalto-1004.log')
            port = settings.get('port', 1004)
            
            # Create condition for multiple IPs
            if len(ip_addresses) == 1:
                ip_condition = f"$fromhost-ip == '{ip_addresses[0]}'"
            else:
                ip_conditions = [f"$fromhost-ip == '{ip}'" for ip in ip_addresses]
                ip_condition = " or ".join(ip_conditions)
                ip_condition = f"({ip_condition})"
            
            rsyslog_content = f"""#### start paloalto.conf ####

# Load UDP syslog listener
module(load="imudp")

# Listen on port {port}
input(type="imudp" port="{port}")

# Template for clean PaloAlto messages
template(name="PaloAltoRaw" type="string" string="%rawmsg-after-pri%\\n")

# Log messages from PaloAlto devices: {', '.join(ip_addresses)}
if ({ip_condition}) then {{
    action(
        type="omfile"
        file="{log_file}"
        template="PaloAltoRaw"
    )
    stop
}}

#### end paloalto.conf ####
"""
            
            # Write configuration file
            with open('/tmp/paloalto.conf', 'w') as f:
                f.write(rsyslog_content)
                
            return JsonResponse({
                'success': True, 
                'message': 'PaloAlto configuration updated. Restart rsyslog to apply changes.',
                'config_preview': rsyslog_content
            })
            
        else:
            return JsonResponse({'success': False, 'error': 'Invalid configuration type'})
            
    except Exception as e:
        return JsonResponse({'success': False, 'error': f'Configuration save failed: {str(e)}'})

def logs_config_test_view(request):
    """Test log configuration and connectivity"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Method not allowed'})
    
    import json
    import subprocess
    import socket
    import os
    
    try:
        data = json.loads(request.body)
        test_type = data.get('test_type')
        config = data.get('config', {})
        
        results = {'success': True, 'tests': []}
        
        if test_type == 'connectivity':
            # Test network connectivity to firewall devices
            ip_address = config.get('ip_address')
            port = config.get('port', 514)
            
            try:
                # Test UDP port connectivity
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(5)
                sock.sendto(b'test', (ip_address, port))
                sock.close()
                
                results['tests'].append({
                    'name': f'UDP Connectivity to {ip_address}:{port}',
                    'status': 'success',
                    'message': 'Connection successful'
                })
            except Exception as e:
                results['tests'].append({
                    'name': f'UDP Connectivity to {ip_address}:{port}',
                    'status': 'error',
                    'message': f'Connection failed: {str(e)}'
                })
                
        elif test_type == 'log_file':
            # Test log file permissions and accessibility
            log_file = config.get('log_file')
            
            # Check if file exists
            if os.path.exists(log_file):
                results['tests'].append({
                    'name': f'Log file exists: {log_file}',
                    'status': 'success',
                    'message': 'File found'
                })
                
                # Check write permissions
                if os.access(log_file, os.W_OK):
                    results['tests'].append({
                        'name': 'Write permissions',
                        'status': 'success',
                        'message': 'File is writable'
                    })
                else:
                    results['tests'].append({
                        'name': 'Write permissions',
                        'status': 'error',
                        'message': 'File is not writable'
                    })
            else:
                # Check if directory exists and is writable
                log_dir = os.path.dirname(log_file)
                if os.path.exists(log_dir) and os.access(log_dir, os.W_OK):
                    results['tests'].append({
                        'name': f'Log file: {log_file}',
                        'status': 'warning',
                        'message': 'File does not exist but directory is writable'
                    })
                else:
                    results['tests'].append({
                        'name': f'Log file: {log_file}',
                        'status': 'error',
                        'message': 'File and directory not accessible'
                    })
                    
        elif test_type == 'rsyslog':
            # Test rsyslog configuration
            try:
                result = subprocess.run(['rsyslogd', '-N1'], capture_output=True, text=True)
                if result.returncode == 0:
                    results['tests'].append({
                        'name': 'Rsyslog configuration syntax',
                        'status': 'success',
                        'message': 'Configuration is valid'
                    })
                else:
                    results['tests'].append({
                        'name': 'Rsyslog configuration syntax',
                        'status': 'error',
                        'message': f'Configuration error: {result.stderr}'
                    })
            except Exception as e:
                results['tests'].append({
                    'name': 'Rsyslog configuration test',
                    'status': 'error',
                    'message': f'Test failed: {str(e)}'
                })
                
        return JsonResponse(results)
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': f'Test failed: {str(e)}'})


# Log Sources Management Views

def log_sources_view(request):
    """Main log sources management view"""
    from datetime import datetime, timedelta
    from dashboard.models import LogSource
    
    # Get registered devices from ClickHouse instead of Django LogSource
    from clickhouse_driver import Client
    
    try:
        client = Client(
            host=CH_HOST,
            port=CH_PORT,
            user=CH_USER,
            password=CH_PASSWORD,
            database=CH_DB
        )
        
        # Get all registered devices from ClickHouse
        devices_query = """
            SELECT device_ip, device_name, parser_type, enabled, created_at 
            FROM registered_devices 
            ORDER BY created_at DESC
        """
        devices = client.execute(devices_query)
        
        # Convert to format expected by template
        log_sources_data = []
        for device in devices:
            device_ip, device_name, parser_type, enabled, created_at = device
            
            # Map parser_type to device_type and determine status
            device_type = parser_type  # fortigate, paloalto, etc.
            status = 'approved' if enabled else 'inactive'
            
            # Map parser_type to log_template
            if parser_type == 'fortigate':
                log_template = 'fortigate_default'
            elif parser_type == 'paloalto':
                log_template = 'paloalto_default'
            else:
                log_template = 'generic'
            
            log_sources_data.append({
                'id': f"ch_{device_ip.replace('.', '_')}",  # Create unique ID for ClickHouse devices
                'name': device_name,
                'description': f'Registered via ClickHouse integration - {parser_type.title()} parser',
                'ip_address': device_ip,
                'hostname': '',
                'port': 514,
                'status': status,
                'device_type': device_type,
                'device_model': '',
                'save_logs': enabled,
                'logs_today': 0,  # Not tracking these stats for ClickHouse devices
                'logs_last_hour': 0,
                'total_logs': 0,
                'log_file_path': '',
                'log_template': log_template,
                'parse_to_database': enabled,
                'first_seen': created_at,
                'last_seen': created_at,
                'approved_by': 'system',
                'approved_at': created_at if enabled else None,
                'rejected_reason': '' if enabled else 'Device disabled',
                'created_at': created_at
            })
        
        # Calculate overview statistics from ClickHouse data
        total_sources = len(log_sources_data)
        active_sources = sum(1 for d in log_sources_data if d['status'] == 'approved')
        inactive_sources = sum(1 for d in log_sources_data if d['status'] == 'inactive')
        pending_sources = sum(1 for d in log_sources_data if d['status'] == 'pending')
        approved_sources = active_sources
        rejected_sources = 0
        
    except Exception as e:
        logging.error(f"Error fetching devices from ClickHouse: {e}")
        # Fallback to empty data if ClickHouse is unavailable
        log_sources_data = []
        total_sources = active_sources = inactive_sources = pending_sources = approved_sources = rejected_sources = 0
    
    # Get recent events for activity feed
    from dashboard.models import LogSourceEvent
    recent_events = LogSourceEvent.objects.select_related('log_source').order_by('-timestamp')[:10]
    
    context = {
        'log_sources': log_sources_data,
        'total_sources': total_sources,
        'active_sources': active_sources,
        'inactive_sources': inactive_sources,
        'pending_sources': pending_sources,
        'approved_sources': approved_sources,
        'rejected_sources': rejected_sources,
        'recent_events': recent_events,
        'last_updated': datetime.now(),
        'device_type_choices': LogSource.DEVICE_TYPE_CHOICES,
        'template_choices': LogSource.TEMPLATE_CHOICES,
    }
    
    return render(request, 'dashboard/log_sources.html', context)

def toggle_save_logs_view(request):
    """Toggle log saving for a specific source"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Method not allowed'})
    
    try:
        import json
        data = json.loads(request.body)
        source_id = data.get('source_id')
        save_logs = data.get('save_logs', False)
        
        # In production, update the database record
        # For now, we'll simulate success
        
        # Update rsyslog configuration based on the source
        # This would involve modifying rsyslog rules to include/exclude the source
        
        return JsonResponse({
            'success': True,
            'message': f'Log saving {"enabled" if save_logs else "disabled"} for source {source_id}'
        })
        
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON data'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': f'Error: {str(e)}'})

def log_source_action_view(request):
    """Perform actions on log sources (approve, reject, enable, disable)"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Method not allowed'})
    
    try:
        import json
        import subprocess
        from dashboard.models import LogSource, LogSourceEvent
        
        data = json.loads(request.body)
        source_id = data.get('source_id')
        action = data.get('action')
        reason = data.get('reason', '')
        device_type = data.get('device_type', '')
        template = data.get('template', '')
        
        if action not in ['approve', 'reject', 'enable', 'disable', 'activate', 'deactivate']:
            return JsonResponse({'success': False, 'error': 'Invalid action'})
        
        try:
            source = LogSource.objects.get(id=source_id)
        except LogSource.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Log source not found'})
        
        # Perform the requested action
        if action == 'approve':
            # Update device type if provided
            if device_type:
                source.device_type = device_type
                source.save()
            
            # Update template if provided
            if template:
                source.log_template = template
                source.save()
            
            # Approve the source
            success = source.approve(approved_by_user='admin')
            if success:
                # Generate rsyslog configuration
                rsyslog_config = source.get_rsyslog_config()
                
                # Write rsyslog configuration file
                config_file_path = f"/etc/rsyslog.d/{source.name.lower().replace(' ', '-')}-{source.ip_address.replace('.', '-')}.conf"
                try:
                    with open(config_file_path, 'w') as f:
                        f.write(rsyslog_config)
                    
                    # Reload rsyslog
                    subprocess.run(['sudo', '-S', 'systemctl', 'reload', 'rsyslog'], 
                                 input='Read@123\n', text=True, capture_output=True, check=True)
                    
                    # Activate the source
                    source.activate()
                    
                    message = f'Source {source.name} approved, configured, and activated'
                    
                except Exception as e:
                    message = f'Source approved but configuration failed: {str(e)}'
            else:
                message = f'Failed to approve source {source.name}'
                
        elif action == 'reject':
            success = source.reject(reason=reason)
            if success:
                message = f'Source {source.name} rejected'
                if reason:
                    message += f': {reason}'
            else:
                message = f'Failed to reject source {source.name}'
                
        elif action == 'enable' or action == 'activate':
            success = source.activate()
            if success:
                message = f'Source {source.name} activated'
            else:
                message = f'Failed to activate source {source.name}'
                
        elif action == 'disable' or action == 'deactivate':
            success = source.deactivate()
            if success:
                message = f'Source {source.name} deactivated'
            else:
                message = f'Failed to deactivate source {source.name}'
        
        # Create event log
        LogSourceEvent.objects.create(
            log_source=source,
            event_type=action,
            description=message,
            user='admin',
            metadata={
                'reason': reason,
                'device_type': device_type,
                'template': template
            }
        )
        
        return JsonResponse({'success': True, 'message': message})
        
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON data'})
    except Exception as e:
        logging.error(f"Error in log_source_action_view: {e}")
        return JsonResponse({'success': False, 'error': f'Error: {str(e)}'})

def test_log_source_view(request):
    """Test connection to a log source"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Method not allowed'})
    
    try:
        import json
        import subprocess
        import socket
        data = json.loads(request.body)
        source_id = data.get('source_id')
        
        # In production, get source details from database
        # For demonstration, use mock data
        mock_sources = {
            '1': {'ip': '192.168.100.221', 'port': 514},
            '2': {'ip': '10.12.50.61', 'port': 1004},
            '3': {'ip': '192.168.1.100', 'port': 514},
            '4': {'ip': '10.10.10.50', 'port': 514}
        }
        
        source = mock_sources.get(str(source_id))
        if not source:
            return JsonResponse({'success': False, 'error': 'Source not found'})
        
        # Test network connectivity
        try:
            # Test if we can reach the IP (ping test)
            ping_result = subprocess.run(['ping', '-c', '1', '-W', '3', source['ip']], 
                                       capture_output=True, text=True, timeout=5)
            
            if ping_result.returncode == 0:
                # Test port connectivity
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3)
                try:
                    # For UDP, we'll try to connect (though UDP is connectionless)
                    sock.connect((source['ip'], source['port']))
                    sock.close()
                    return JsonResponse({
                        'success': True, 
                        'message': f'Successfully connected to {source["ip"]}:{source["port"]}'
                    })
                except socket.error as e:
                    return JsonResponse({
                        'success': False, 
                        'error': f'Port {source["port"]} not reachable: {str(e)}'
                    })
            else:
                return JsonResponse({
                    'success': False, 
                    'error': f'Host {source["ip"]} not reachable'
                })
                
        except subprocess.TimeoutExpired:
            return JsonResponse({
                'success': False, 
                'error': 'Connection test timed out'
            })
        
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON data'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': f'Test failed: {str(e)}'})

@csrf_exempt
def scan_log_sources_view(request):
    """Scan network for potential log sources"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Method not allowed'})
    
    try:
        import sys
        sys.path.append('/home/net/analyzer/scripts')
        from proper_log_source_scanner import ProperLogSourceScanner
        
        scanner = ProperLogSourceScanner()
        
        # Get scan type from request (handle both POST form data and JSON)
        if request.content_type == 'application/json':
            import json
            try:
                data = json.loads(request.body)
                scan_type = data.get('scan_type', 'quick')
                network_range = data.get('network_range', None)
            except:
                scan_type = 'quick'
                network_range = None
        else:
            scan_type = request.POST.get('scan_type', 'quick')
            network_range = request.POST.get('network_range', None)
        
        # Discover actual log source devices
        results = scanner.discover_log_sources()
        
        # Process results and create/update log sources
        discovered_sources = []
        new_sources = 0
        updated_sources = 0
        
        for result in results:
            if result['in_database']:
                # Update existing source
                try:
                    source = LogSource.objects.get(ip_address=result['ip'])
                    source.last_seen = timezone.now()
                    if result['hostname'] and not source.hostname:
                        source.hostname = result['hostname']
                    source.save()
                    updated_sources += 1
                except:
                    pass
            else:
                # Create new pending source
                try:
                    source, created = LogSource.objects.get_or_create(
                        ip_address=result['ip'],
                        defaults={
                            'name': result['hostname'] or f"Device-{result['ip']}",
                            'hostname': result['hostname'] or '',
                            'device_type': result['device_type'],
                            'status': 'pending',
                            'port': 514,
                            'protocol': 'udp'
                        }
                    )
                    if created:
                        new_sources += 1
                        # Log detection event
                        LogSourceEvent.objects.create(
                            log_source=source,
                            event_type='detected',
                            description=f"Detected via network scan ({scan_type})",
                            user=request.user.username if request.user.is_authenticated else 'system'
                        )
                except:
                    pass
            
            discovered_sources.append({
                'ip': result['ip'],
                'hostname': result.get('hostname', ''),
                'device_type': result.get('device_type', 'unknown'),
                'status': result.get('current_status', 'pending'),
                'in_database': result['in_database']
            })
        
        return JsonResponse({
            'success': True,
            'scan_type': scan_type,
            'discovered_count': len(discovered_sources),
            'new_sources': new_sources,
            'updated_sources': updated_sources,
            'sources': discovered_sources
        })
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': f'Scan failed: {str(e)}'})

def log_sources_status_view(request):
    """Get current status of all log sources (for auto-refresh)"""
    # Mock data - in production this would query the database
    status_data = {
        'total_sources': 4,
        'active_sources': 2,
        'inactive_sources': 1,
        'pending_sources': 1,
        'last_updated': datetime.now().isoformat()
    }
    
    return JsonResponse(status_data)

def add_log_source_view(request):
    """Add a new log source manually"""
    if request.method == 'GET':
        # Return form data for GET request
        return JsonResponse({
            'device_types': [{'value': k, 'label': v} for k, v in LogSource.DEVICE_TYPE_CHOICES],
            'protocols': [{'value': k, 'label': v} for k, v in LogSource.PROTOCOL_CHOICES],
            'templates': [{'value': k, 'label': v} for k, v in LogSource.TEMPLATE_CHOICES]
        })
    
    elif request.method == 'POST':
        try:
            # Validate required fields
            ip_address = request.POST.get('ip_address', '').strip()
            name = request.POST.get('name', '').strip()
            device_type = request.POST.get('device_type', 'unknown')
            
            if not ip_address:
                return JsonResponse({'success': False, 'error': 'IP address is required'})
            
            if not name:
                name = f"Device-{ip_address}"
            
            # Check if IP already exists
            if LogSource.objects.filter(ip_address=ip_address).exists():
                return JsonResponse({'success': False, 'error': f'Log source with IP {ip_address} already exists'})
            
            # Create new log source
            source = LogSource.objects.create(
                ip_address=ip_address,
                name=name,
                device_type=device_type,
                hostname=request.POST.get('hostname', ''),
                port=int(request.POST.get('port', 514)),
                protocol=request.POST.get('protocol', 'udp'),
                status='pending',
                description=request.POST.get('description', ''),
                save_logs=request.POST.get('save_logs', 'true').lower() == 'true'
            )
            
            # Generate default log file path
            source.generate_log_file_path()
            
            # Auto-configure parser if device type is known
            if device_type in ['fortigate', 'paloalto']:
                source.auto_configure_parser()
            
            # Create rsyslog configuration automatically
            try:
                create_rsyslog_config_result = create_rsyslog_config(source)
                if create_rsyslog_config_result['success']:
                    source.status = 'active'  # Set to active since config is created
                    source.save()
                    config_message = create_rsyslog_config_result['message']
                else:
                    config_message = f"Warning: {create_rsyslog_config_result['error']}"
            except Exception as e:
                config_message = f"Warning: Failed to create rsyslog config: {str(e)}"
            
            # Log creation event
            LogSourceEvent.objects.create(
                log_source=source,
                event_type='detected',
                description='Manually added via web interface',
                user=request.user.username if request.user.is_authenticated else 'admin'
            )
            
            return JsonResponse({
                'success': True,
                'message': f'Log source {name} added successfully. {config_message}',
                'source_id': source.id,
                'config_created': create_rsyslog_config_result.get('success', False) if 'create_rsyslog_config_result' in locals() else False
            })
            
        except Exception as e:
            return JsonResponse({'success': False, 'error': f'Failed to add log source: {str(e)}'})
    
    return JsonResponse({'success': False, 'error': 'Method not allowed'})

def device_registration_view(request):
    """Device registration view with ClickHouse integration"""
    if request.method == 'GET':
        # Return form data for GET request or render the form template
        if request.headers.get('Accept') == 'application/json':
            return JsonResponse({
                'device_types': [
                    {'value': 'fortigate', 'label': 'FortiGate Firewall'},
                    {'value': 'paloalto', 'label': 'Palo Alto Firewall'},
                    {'value': 'cisco', 'label': 'Cisco Device'},
                    {'value': 'checkpoint', 'label': 'Check Point Firewall'},
                    {'value': 'sophos', 'label': 'Sophos Firewall'},
                    {'value': 'juniper', 'label': 'Juniper Device'},
                    {'value': 'generic', 'label': 'Generic Syslog Device'},
                ],
                'parser_types': [
                    {'value': 'fortigate', 'label': 'FortiGate Parser'},
                    {'value': 'paloalto', 'label': 'Palo Alto Parser'},
                    {'value': 'generic', 'label': 'Generic Parser'},
                ]
            })
        else:
            # Render the HTML template
            context = {
                'device_types': [
                    {'value': 'fortigate', 'label': 'FortiGate Firewall'},
                    {'value': 'paloalto', 'label': 'Palo Alto Firewall'},
                    {'value': 'cisco', 'label': 'Cisco Device'},
                    {'value': 'checkpoint', 'label': 'Check Point Firewall'},
                    {'value': 'sophos', 'label': 'Sophos Firewall'},
                    {'value': 'juniper', 'label': 'Juniper Device'},
                    {'value': 'generic', 'label': 'Generic Syslog Device'},
                ],
                'parser_types': [
                    {'value': 'fortigate', 'label': 'FortiGate Parser'},
                    {'value': 'paloalto', 'label': 'Palo Alto Parser'},
                    {'value': 'generic', 'label': 'Generic Parser'},
                ]
            }
            return render(request, 'dashboard/device_registration.html', context)
    
    elif request.method == 'POST':
        try:
            # Validate required fields
            device_ip = request.POST.get('device_ip', '').strip()
            device_name = request.POST.get('device_name', '').strip()
            parser_type = request.POST.get('parser_type', 'fortigate')
            
            if not device_ip:
                return JsonResponse({'success': False, 'error': 'Device IP address is required'})
            
            if not device_name:
                device_name = f"Device-{device_ip}"
            
            # Connect to ClickHouse
            try:
                client = Client(
                    host=CH_HOST,
                    port=CH_PORT,
                    user=CH_USER,
                    password=CH_PASSWORD,
                    database=CH_DB
                )
                
                # Check if device already exists
                existing_device = client.execute(
                    "SELECT COUNT(*) FROM registered_devices WHERE device_ip = %(device_ip)s",
                    {'device_ip': device_ip}
                )
                
                if existing_device[0][0] > 0:
                    return JsonResponse({'success': False, 'error': f'Device with IP {device_ip} already registered'})
                
                # Create the registered_devices table if it doesn't exist
                client.execute("""
                    CREATE TABLE IF NOT EXISTS registered_devices (
                        device_ip String,
                        device_name String,
                        parser_type String,
                        enabled UInt8,
                        created_at DateTime DEFAULT now()
                    ) ENGINE = MergeTree()
                    ORDER BY device_ip
                """)
                
                # Insert the new device
                client.execute(
                    """INSERT INTO registered_devices (device_ip, device_name, parser_type, enabled) 
                       VALUES (%(device_ip)s, %(device_name)s, %(parser_type)s, 1)""",
                    {
                        'device_ip': device_ip,
                        'device_name': device_name,
                        'parser_type': parser_type
                    }
                )
                
                # Also create a LogSource entry for compatibility
                source = LogSource.objects.create(
                    ip_address=device_ip,
                    name=device_name,
                    device_type=parser_type,
                    port=514,
                    protocol='udp',
                    status='approved',
                    description=f'Device registered via ClickHouse integration',
                    save_logs=True
                )
                
                # Auto-configure parser
                source.auto_configure_parser()
                
                # Log creation event
                LogSourceEvent.objects.create(
                    log_source=source,
                    event_type='detected',
                    description='Registered via device registration interface',
                    user=request.user.username if request.user.is_authenticated else 'admin'
                )
                
                return JsonResponse({
                    'success': True,
                    'message': f'Device {device_name} ({device_ip}) registered successfully with {parser_type} parser',
                    'device_id': device_ip,
                    'source_id': source.id
                })
                
            except Exception as e:
                return JsonResponse({'success': False, 'error': f'ClickHouse error: {str(e)}'})
            
        except Exception as e:
            return JsonResponse({'success': False, 'error': f'Failed to register device: {str(e)}'})
    
    return JsonResponse({'success': False, 'error': 'Method not allowed'})

def device_list_view(request):
    """List registered devices from ClickHouse"""
    try:
        client = Client(
            host=CH_HOST,
            port=CH_PORT,
            user=CH_USER,
            password=CH_PASSWORD,
            database=CH_DB
        )
        
        # Get all registered devices
        devices = client.execute("""
            SELECT device_ip, device_name, parser_type, enabled, created_at 
            FROM registered_devices 
            ORDER BY created_at DESC
        """)
        
        device_list = []
        for device in devices:
            device_list.append({
                'device_ip': device[0],
                'device_name': device[1],
                'parser_type': device[2],
                'enabled': bool(device[3]),
                'created_at': device[4].strftime('%Y-%m-%d %H:%M:%S') if device[4] else 'Unknown'
            })
        
        return JsonResponse({
            'success': True,
            'devices': device_list,
            'count': len(device_list)
        })
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': f'Failed to fetch devices: {str(e)}'})

def configure_log_source_view(request, source_id):
    """Configure a specific log source"""
    try:
        source = LogSource.objects.get(id=source_id)
    except LogSource.DoesNotExist:
        raise Http404("Log source not found")
    
    context = {
        'source': source,
    }
    
    return render(request, 'dashboard/configure_log_source.html', context)

def save_log_source_config_view(request, source_id):
    """Save log source configuration"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Method not allowed'})
    
    try:
        # Get the log source from database
        try:
            source = LogSource.objects.get(id=source_id)
        except LogSource.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Log source not found'})
        
        data = json.loads(request.body)
        
        # Validate required fields
        required_fields = ['name', 'ip_address', 'port', 'device_type']
        for field in required_fields:
            if not data.get(field):
                return JsonResponse({'success': False, 'error': f'Missing required field: {field}'})
        
        # Validate IP address format
        try:
            ipaddress.ip_address(data['ip_address'])
        except ValueError:
            return JsonResponse({'success': False, 'error': 'Invalid IP address format'})
        
        # Validate port range
        port = data.get('port')
        if not isinstance(port, int) or port < 1 or port > 65535:
            return JsonResponse({'success': False, 'error': 'Port must be between 1 and 65535'})
        
        # Update the log source in database
        source.name = data['name']
        source.description = data.get('description', source.description)
        source.ip_address = data['ip_address']
        source.port = port
        source.device_type = data['device_type']
        source.save_logs = data.get('save_logs', False)
        source.log_file_path = data.get('log_file_path', f'/var/log/{data["device_type"]}.log') if source.save_logs else None
        source.parse_to_database = data.get('parse_to_database', False)
        source.save()
        
        # Create event for configuration update
        LogSourceEvent.objects.create(
            log_source=source,
            event_type='configured',
            description=f'Configuration updated for {source.name}',
            user=request.user.username if request.user.is_authenticated else 'system',
            metadata={
                'updated_fields': list(data.keys()),
                'save_logs_enabled': source.save_logs,
                'parse_to_database': source.parse_to_database
            }
        )
        
        # Generate rsyslog configuration
        device_type = data['device_type']
        ip_address = data['ip_address']
        save_logs = data.get('save_logs', False)
        log_file_path = data.get('log_file_path', f'/var/log/{device_type}.log')
        log_template = data.get('log_template', 'raw')
        custom_template = data.get('custom_template', '%rawmsg-after-pri%\\n')
        
        # Determine template string
        template_string = ''
        if log_template == 'raw':
            template_string = '%rawmsg-after-pri%\\n'
        elif log_template == 'timestamp':
            template_string = '%timegenerated% %rawmsg-after-pri%\\n'
        elif log_template == 'detailed':
            template_string = '%timegenerated% %hostname% %rawmsg-after-pri%\\n'
        elif log_template == 'custom':
            template_string = custom_template
        
        # Generate rsyslog configuration content
        config_content = f"""#### start {device_type}.conf ####

# Load UDP syslog listener
module(load="imudp")
input(type="imudp" port="{port}")

# Template for {device_type} messages
template(name="{device_type.capitalize()}Template" type="string" string="{template_string}")

# Process messages from {ip_address}
if ($fromhost-ip == '{ip_address}') then {{
"""
        
        if save_logs:
            config_content += f"""    action(
        type="omfile"
        file="{log_file_path}"
        template="{device_type.capitalize()}Template"
    )
"""
        else:
            config_content += "    # Log saving disabled\n"
        
        config_content += f"""    stop
}}

#### end {device_type}.conf ####"""
        
        # Write configuration file to /etc/rsyslog.d/
        config_filename = f"/etc/rsyslog.d/{device_type}-{ip_address.replace('.', '-')}.conf"
        
        try:
            with open(config_filename, 'w') as f:
                f.write(config_content)
            
            # Reload rsyslog service
            subprocess.run(['sudo', 'systemctl', 'reload', 'rsyslog'], check=True)
            
            return JsonResponse({
                'success': True,
                'message': f'Configuration saved successfully for {source.name}',
                'config_file': config_filename,
                'config_content': config_content
            })
            
        except (IOError, subprocess.CalledProcessError) as e:
            return JsonResponse({
                'success': False,
                'error': f'Failed to write configuration file or reload rsyslog: {str(e)}'
            })
        
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON data'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': f'Configuration save failed: {str(e)}'})


def format_bytes(bytes_val):
    """Format bytes to human readable format"""
    if bytes_val == 0:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.1f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.1f} PB"

def log_management_status_view(request):
    """View for displaying log management and rotation status"""
    import json
    import os
    import time
    import subprocess
    from datetime import datetime
    
    STATUS_FILE = '/var/lib/log-manager/status.json'
    
    try:
        # Load status from log monitor
        status_data = {}
        if os.path.exists(STATUS_FILE):
            with open(STATUS_FILE, 'r') as f:
                status_data = json.load(f)
        
        # If no status file exists, create basic status
        if not status_data:
            status_data = {
                'timestamp': time.time(),
                'timestamp_formatted': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'overall_status': 'unknown',
                'files': {},
                'processing_lag': {},
                'rotation': {},
                'summary': {
                    'total_files': 0,
                    'total_size': 0,
                    'total_size_formatted': '0 B'
                },
                'alerts': []
            }
            
            # Get basic file info
            log_files = {
                '/var/log/fortigate.log': 'FortiGate Traffic',
                '/var/log/paloalto-1004.log': 'PaloAlto Traffic'
            }
            
            for filepath, description in log_files.items():
                if os.path.exists(filepath):
                    stat = os.stat(filepath)
                    size = stat.st_size
                    
                    status_data['files'][filepath] = {
                        'exists': True,
                        'size': size,
                        'size_formatted': format_bytes(size),
                        'description': description,
                        'last_modified': stat.st_mtime,
                        'last_modified_formatted': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                        'alert_level': 'warning' if size > 1.5 * 1024 * 1024 * 1024 else 'ok',
                        'percentage_of_limit': (size / (2 * 1024 * 1024 * 1024)) * 100
                    }
                    
                    status_data['processing_lag'][filepath] = {
                        'lag_bytes': 0,
                        'lag_formatted': '0 B',
                        'alert_level': 'unknown',
                        'last_processed_time_formatted': 'Unknown'
                    }
                else:
                    status_data['files'][filepath] = {
                        'exists': False,
                        'description': description,
                        'alert_level': 'error'
                    }
            
            # Update summary
            total_size = sum(f.get('size', 0) for f in status_data['files'].values())
            status_data['summary'].update({
                'total_files': len([f for f in status_data['files'].values() if f.get('exists')]),
                'total_size': total_size,
                'total_size_formatted': format_bytes(total_size)
            })
        
        # Add service status information
        service_status = {}
        services = [
            'log-manager.service',
            'fortigate_to_clickhouse.service', 
            'paloalto_to_clickhouse.service',
            'paloalto-url-loader.service'
        ]
        
        for service_name in services:
            try:
                result = subprocess.run(
                    ['systemctl', 'is-active', service_name],
                    capture_output=True, text=True, timeout=5
                )
                is_active = result.stdout.strip() == 'active'
                
                # Get detailed status
                status_result = subprocess.run(
                    ['systemctl', 'status', service_name],
                    capture_output=True, text=True, timeout=5
                )
                
                # Parse memory usage and PID
                main_pid = None
                memory_usage = None
                for line in status_result.stdout.split('\n'):
                    if 'Main PID:' in line:
                        main_pid = line.split('Main PID:')[1].strip().split(' ')[0]
                    elif 'Memory:' in line:
                        memory_usage = line.split('Memory:')[1].strip().split(' ')[0]
                
                service_status[service_name] = {
                    'active': is_active,
                    'status': result.stdout.strip(),
                    'main_pid': main_pid,
                    'memory_usage': memory_usage
                }
                
            except Exception as e:
                service_status[service_name] = {
                    'active': False,
                    'status': 'error',
                    'error': str(e)
                }
        
        status_data['services'] = service_status
        
        return render(request, 'dashboard/log_management.html', {
            'status': status_data,
            'refresh_interval': 30  # Auto-refresh every 30 seconds
        })
        
    except Exception as e:
        logging.error(f"Error loading log management status: {e}")
        return render(request, 'dashboard/log_management.html', {
            'status': {
                'error': str(e),
                'overall_status': 'error'
            },
            'refresh_interval': 30
        })


def clickhouse_storage_view(request):
    """Get ClickHouse storage usage information"""
    import json
    import os
    import subprocess
    from django.http import JsonResponse
    from clickhouse_driver import Client
    
    try:
        # Connect to ClickHouse
        client = Client(
            host='localhost',
            port=9000,
            user='default',
            password='Read@123'
        )
        
        # Get database sizes
        db_sizes_query = """
        SELECT 
            database,
            formatReadableSize(sum(bytes_on_disk)) AS size,
            sum(bytes_on_disk) AS bytes,
            count() AS tables,
            formatReadableSize(sum(data_compressed_bytes)) AS compressed_size,
            sum(data_compressed_bytes) AS compressed_bytes,
            formatReadableSize(sum(data_uncompressed_bytes)) AS uncompressed_size,
            sum(data_uncompressed_bytes) AS uncompressed_bytes
        FROM system.parts
        WHERE active
        GROUP BY database
        ORDER BY sum(bytes_on_disk) DESC
        """
        
        db_sizes = client.execute(db_sizes_query)
        
        # Get table sizes for network_logs database
        table_sizes_query = """
        SELECT 
            table,
            formatReadableSize(sum(bytes_on_disk)) AS size,
            sum(bytes_on_disk) AS bytes,
            formatReadableSize(sum(data_compressed_bytes)) AS compressed_size,
            sum(data_compressed_bytes) AS compressed_bytes,
            formatReadableSize(sum(data_uncompressed_bytes)) AS uncompressed_size,
            sum(data_uncompressed_bytes) AS uncompressed_bytes,
            sum(rows) AS row_count,
            count() AS parts
        FROM system.parts
        WHERE active AND database = 'network_logs'
        GROUP BY table
        ORDER BY sum(bytes_on_disk) DESC
        """
        
        table_sizes = client.execute(table_sizes_query)
        
        # Get data path from ClickHouse
        data_path_query = "SELECT path FROM system.disks WHERE name = 'default'"
        try:
            data_path_result = client.execute(data_path_query)
            data_path = data_path_result[0][0] if data_path_result else '/var/lib/clickhouse/'
        except:
            data_path = '/var/lib/clickhouse/'
        
        # Get actual filesystem information
        def get_filesystem_info(path):
            """Get filesystem space information for the given path"""
            import shutil
            try:
                total, used, free = shutil.disk_usage(path)
                return {
                    'total_bytes': total,
                    'used_bytes': used,
                    'free_bytes': free,
                    'total_formatted': format_bytes(total),
                    'used_formatted': format_bytes(used),
                    'free_formatted': format_bytes(free),
                    'used_percentage': round((used / total) * 100, 1)
                }
            except Exception as e:
                logging.warning(f"Failed to get filesystem info for {path}: {e}")
                return None
        
        filesystem_info = get_filesystem_info(data_path)
        
        # Get actual disk usage using Python os.walk
        def get_directory_size(path):
            total_size = 0
            try:
                for dirpath, dirnames, filenames in os.walk(path):
                    for filename in filenames:
                        try:
                            filepath = os.path.join(dirpath, filename)
                            if os.path.exists(filepath):
                                total_size += os.path.getsize(filepath)
                        except (OSError, IOError):
                            continue
            except (OSError, IOError, PermissionError):
                return None
            return total_size
        
        # Try to read disk usage from monitoring file
        def read_disk_usage_from_file():
            try:
                with open('/home/net/analyzer/config/clickhouse_disk_usage.json', 'r') as f:
                    data = json.load(f)
                    if data.get('status') == 'success' and data.get('usage_bytes'):
                        return data['usage_bytes']
            except:
                pass
            return None
        
        actual_usage_bytes = read_disk_usage_from_file()
        
        # If file method failed, try the directory size method as fallback
        if actual_usage_bytes is None:
            actual_usage_bytes = get_directory_size(data_path)
        
        # Skip disk space information for now due to ClickHouse type issues
        disk_info = []
        
        # Get allocated space from configuration with filesystem validation
        CONFIG_FILE = '/home/net/analyzer/config/clickhouse_storage.json'
        
        # Calculate reasonable default based on filesystem
        if filesystem_info:
            # Suggest 70% of available space as reasonable allocation
            suggested_allocation_gb = round((filesystem_info['free_bytes'] * 0.7) / (1024**3))
            max_possible_gb = round(filesystem_info['free_bytes'] / (1024**3))
        else:
            suggested_allocation_gb = 20  # Conservative fallback
            max_possible_gb = 50
        
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    allocated_space_gb = config.get('allocated_space_gb', suggested_allocation_gb)
                    warning_threshold = config.get('warning_threshold_percentage', 80)
                    critical_threshold = config.get('critical_threshold_percentage', 90)
            else:
                allocated_space_gb = suggested_allocation_gb
                warning_threshold = 80
                critical_threshold = 90
        except:
            allocated_space_gb = suggested_allocation_gb
            warning_threshold = 80
            critical_threshold = 90
        
        allocated_space_bytes = allocated_space_gb * 1024 * 1024 * 1024
        
        # Calculate total usage from ClickHouse parts
        clickhouse_reported_bytes = sum(row[2] for row in db_sizes)
        
        # Use actual disk usage if available, otherwise fall back to ClickHouse reported
        if actual_usage_bytes is not None and actual_usage_bytes > 0:
            total_usage_bytes = actual_usage_bytes
            usage_source = "filesystem"
        else:
            total_usage_bytes = clickhouse_reported_bytes
            usage_source = "clickhouse"
        
        usage_percentage = round((total_usage_bytes / allocated_space_bytes) * 100, 2)
        
        response_data = {
            'success': True,
            'databases': [
                {
                    'name': row[0],
                    'size': row[1],
                    'bytes': row[2],
                    'tables': row[3],
                    'compressed_size': row[4],
                    'compressed_bytes': row[5],
                    'uncompressed_size': row[6],
                    'uncompressed_bytes': row[7]
                } for row in db_sizes
            ],
            'tables': [
                {
                    'name': row[0],
                    'size': row[1],
                    'bytes': row[2],
                    'compressed_size': row[3],
                    'compressed_bytes': row[4],
                    'uncompressed_size': row[5],
                    'uncompressed_bytes': row[6],
                    'rows': row[7],
                    'parts': row[8]
                } for row in table_sizes
            ],
            'disks': [
                {
                    'name': row[0],
                    'path': row[1],
                    'free_space': row[2],
                    'free_bytes': row[3],
                    'total_space': row[4],
                    'total_bytes': row[5],
                    'used_space': row[6],
                    'used_bytes': row[7],
                    'used_percentage': row[8]
                } for row in disk_info
            ],
            'summary': {
                'total_usage': format_bytes(total_usage_bytes),
                'total_usage_bytes': total_usage_bytes,
                'clickhouse_reported': format_bytes(clickhouse_reported_bytes),
                'clickhouse_reported_bytes': clickhouse_reported_bytes,
                'actual_disk_usage': format_bytes(actual_usage_bytes) if actual_usage_bytes else 'N/A',
                'actual_disk_usage_bytes': actual_usage_bytes,
                'usage_source': usage_source,
                'allocated_space': format_bytes(allocated_space_bytes),
                'allocated_space_bytes': allocated_space_bytes,
                'usage_percentage': usage_percentage,
                'remaining_space': format_bytes(allocated_space_bytes - total_usage_bytes),
                'remaining_bytes': allocated_space_bytes - total_usage_bytes,
                'warning_threshold': warning_threshold,
                'critical_threshold': critical_threshold,
                'storage_path': data_path,
                'status': 'critical' if usage_percentage >= critical_threshold else 'warning' if usage_percentage >= warning_threshold else 'ok',
                'suggested_allocation_gb': suggested_allocation_gb,
                'max_possible_gb': max_possible_gb
            },
            'filesystem': filesystem_info
        }
        
        return JsonResponse(response_data)
        
    except Exception as e:
        logging.error(f"Error getting ClickHouse storage info: {e}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@csrf_exempt
def storage_allocation_view(request):
    """Get or update ClickHouse storage allocation settings"""
    import json
    import os
    from django.http import JsonResponse
    from datetime import datetime
    
    CONFIG_FILE = '/home/net/analyzer/config/clickhouse_storage.json'
    
    # Ensure config directory exists
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    
    # Load current settings
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                settings = json.load(f)
        except:
            settings = {
                "allocated_space_gb": 100,
                "storage_path": "/var/lib/clickhouse",
                "warning_threshold_percentage": 80,
                "critical_threshold_percentage": 90,
                "data_retention_days": 90,
                "enable_auto_cleanup": True
            }
    else:
        settings = {
            "allocated_space_gb": 100,
            "storage_path": "/var/lib/clickhouse",
            "warning_threshold_percentage": 80,
            "critical_threshold_percentage": 90,
            "data_retention_days": 90,
            "enable_auto_cleanup": True
        }
    
    if request.method == 'POST':
        try:
            # Parse request data
            data = json.loads(request.body)
            
            # Get filesystem info for validation
            import shutil
            try:
                total, used, free = shutil.disk_usage('/var/lib/clickhouse/')
                max_available_gb = round(free / (1024**3))
                recommended_max_gb = round((free * 0.8) / (1024**3))  # 80% of free space
            except:
                max_available_gb = 50  # Fallback
                recommended_max_gb = 40
            
            # Update settings
            if 'allocated_space_gb' in data:
                allocated_gb = int(data['allocated_space_gb'])
                if allocated_gb < 5:
                    return JsonResponse({
                        'success': False,
                        'error': 'Allocated space must be at least 5 GB'
                    }, status=400)
                if allocated_gb > max_available_gb:
                    return JsonResponse({
                        'success': False,
                        'error': f'Allocated space cannot exceed available filesystem space ({max_available_gb} GB available)'
                    }, status=400)
                if allocated_gb > recommended_max_gb:
                    # Warning but allow it
                    logging.warning(f"Allocation {allocated_gb}GB exceeds recommended maximum {recommended_max_gb}GB")
                
                settings['allocated_space_gb'] = allocated_gb
            
            if 'storage_path' in data:
                settings['storage_path'] = data['storage_path']
            
            if 'warning_threshold_percentage' in data:
                warning_threshold = int(data['warning_threshold_percentage'])
                if not 50 <= warning_threshold <= 95:
                    return JsonResponse({
                        'success': False,
                        'error': 'Warning threshold must be between 50% and 95%'
                    }, status=400)
                settings['warning_threshold_percentage'] = warning_threshold
            
            if 'critical_threshold_percentage' in data:
                critical_threshold = int(data['critical_threshold_percentage'])
                if not 60 <= critical_threshold <= 99:
                    return JsonResponse({
                        'success': False,
                        'error': 'Critical threshold must be between 60% and 99%'
                    }, status=400)
                settings['critical_threshold_percentage'] = critical_threshold
            
            if 'data_retention_days' in data:
                retention_days = int(data['data_retention_days'])
                if not 30 <= retention_days <= 365:
                    return JsonResponse({
                        'success': False,
                        'error': 'Data retention must be between 30 and 365 days'
                    }, status=400)
                settings['data_retention_days'] = retention_days
            
            if 'enable_auto_cleanup' in data:
                settings['enable_auto_cleanup'] = bool(data['enable_auto_cleanup'])
            
            # Add metadata
            settings['last_updated'] = datetime.now().isoformat()
            settings['updated_by'] = request.user.username if request.user.is_authenticated else 'anonymous'
            
            # Save settings
            with open(CONFIG_FILE, 'w') as f:
                json.dump(settings, f, indent=4)
            
            return JsonResponse({
                'success': True,
                'message': 'Storage allocation settings updated successfully',
                'settings': settings
            })
            
        except Exception as e:
            logging.error(f"Error updating storage allocation: {e}")
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=500)
    
    else:  # GET request
        # Get actual ClickHouse data path and filesystem info
        try:
            from clickhouse_driver import Client
            client = Client(
                host='localhost',
                port=9000,
                user='default',
                password='Read@123'
            )
            
            data_path_result = client.execute("SELECT path FROM system.disks WHERE name = 'default'")
            if data_path_result:
                settings['actual_storage_path'] = data_path_result[0][0]
        except:
            settings['actual_storage_path'] = settings.get('storage_path', '/var/lib/clickhouse')
        
        # Add filesystem information
        import shutil
        try:
            total, used, free = shutil.disk_usage(settings['actual_storage_path'])
            settings['filesystem'] = {
                'total_space': f"{total / (1024**3):.1f} GB",
                'used_space': f"{used / (1024**3):.1f} GB", 
                'free_space': f"{free / (1024**3):.1f} GB",
                'used_percentage': round((used / total) * 100, 1),
                'max_allocation_gb': round(free / (1024**3)),
                'recommended_max_gb': round((free * 0.8) / (1024**3))
            }
        except:
            settings['filesystem'] = None
        
        return JsonResponse({
            'success': True,
            'settings': settings
        })


@require_http_methods(["POST"])
def service_control_view(request):
    """Handle service control actions (start, stop, restart)"""
    import json
    import subprocess
    from django.http import JsonResponse
    from django.views.decorators.csrf import csrf_exempt
    
    try:
        # Parse JSON request body
        data = json.loads(request.body)
        service_name = data.get('service')
        action = data.get('action')
        
        # Validate inputs
        allowed_services = [
            'log-manager.service',
            'fortigate_to_clickhouse.service', 
            'paloalto_to_clickhouse.service',
            'paloalto-url-loader.service'
        ]
        
        allowed_actions = ['start', 'stop', 'restart']
        
        if service_name not in allowed_services:
            return JsonResponse({
                'success': False,
                'message': f'Service "{service_name}" is not allowed to be controlled'
            }, status=400)
            
        if action not in allowed_actions:
            return JsonResponse({
                'success': False,
                'message': f'Action "{action}" is not allowed'
            }, status=400)
        
        # Execute systemctl command with sudo
        try:
            cmd = ['sudo', '-S', 'systemctl', action, service_name]
            result = subprocess.run(
                cmd,
                input='Read@123\n',
                text=True,
                capture_output=True,
                timeout=30
            )
            
            if result.returncode == 0:
                return JsonResponse({
                    'success': True,
                    'message': f'Successfully {action}ed {service_name}'
                })
            else:
                error_msg = result.stderr.strip() if result.stderr else 'Unknown error'
                return JsonResponse({
                    'success': False,
                    'message': f'Failed to {action} {service_name}: {error_msg}'
                }, status=500)
                
        except subprocess.TimeoutExpired:
            return JsonResponse({
                'success': False,
                'message': f'Timeout while trying to {action} {service_name}'
            }, status=500)
        except Exception as e:
            return JsonResponse({
                'success': False,
                'message': f'Error executing {action} on {service_name}: {str(e)}'
            }, status=500)
            
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'message': 'Invalid JSON in request body'
        }, status=400)
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': f'Unexpected error: {str(e)}'
        }, status=500)

def pa_url_logs_view(request):
    """Palo Alto URL filtering logs view"""
    client = Client(
        host=CH_HOST,
        port=CH_PORT,
        user=CH_USER,
        password=CH_PASSWORD,
        database=CH_DB
    )
    
    # Time filter - use ClickHouse native time to avoid timezone issues
    time_range = request.GET.get('time_range', 'last_hour')
    
    if time_range == 'last_6_hours':
        since_interval = '6 HOUR'
    elif time_range == 'last_24_hours':
        since_interval = '1 DAY'
    elif time_range == 'last_7_days':
        since_interval = '7 DAY'
    elif time_range == 'custom':
        # Handle custom time range with explicit timestamps  
        use_custom_time = True
        time_from = request.GET.get('time_from', '')
        
        # Get ClickHouse current time for proper timezone handling
        ch_now = client.execute('SELECT now()')[0][0]
        
        if time_from:
            try:
                since = datetime.strptime(time_from, '%Y-%m-%dT%H:%M')
            except ValueError:
                since = ch_now - timedelta(hours=1)
        else:
            since = ch_now - timedelta(hours=1)
            
        since_str = since.strftime('%Y-%m-%d %H:%M:%S')
    else:  # default to last_hour
        since_interval = '1 HOUR'
        use_custom_time = False
    
    # Create user-friendly time range display
    time_range_display = {
        'last_hour': 'Last Hour',
        'last_6_hours': 'Last 6 Hours', 
        'last_24_hours': 'Last 24 Hours',
        'last_7_days': 'Last 7 Days',
        'custom': 'Custom Range'
    }.get(time_range, 'Last Hour')
    
    # Get filter values
    url_filter = request.GET.get('url', '').strip()
    src_ip_filter = request.GET.get('src_ip', '').strip()
    dst_ip_filter = request.GET.get('dst_ip', '').strip()
    category_filter = request.GET.get('category', '').strip()
    action_filter = request.GET.get('action', '').strip()
    severity_filter = request.GET.get('severity', '').strip()
    device_filter = request.GET.get('device', '').strip()
    user_filter = request.GET.get('user', '').strip()
    
    # Build WHERE clause
    if use_custom_time:
        where_conditions = [f"timestamp >= parseDateTimeBestEffort('{since_str}')"]
    else:
        where_conditions = [f"timestamp >= now() - INTERVAL {since_interval}"]
    
    if url_filter:
        where_conditions.append(f"url ILIKE '%{url_filter}%'")
    if src_ip_filter:
        where_conditions.append(f"source_address ILIKE '%{src_ip_filter}%'")
    if dst_ip_filter:
        where_conditions.append(f"destination_address ILIKE '%{dst_ip_filter}%'")
    if category_filter:
        where_conditions.append(f"url_category ILIKE '%{category_filter}%'")
    if action_filter:
        where_conditions.append(f"action ILIKE '%{action_filter}%'")
    if severity_filter:
        where_conditions.append(f"severity = '{severity_filter}'")
    if device_filter:
        where_conditions.append(f"device_name ILIKE '%{device_filter}%'")
    if user_filter:
        where_conditions.append(f"source_user ILIKE '%{user_filter}%'")
    
    where_clause = " AND ".join(where_conditions)
    
    # Pagination
    page = request.GET.get('page', '1')
    try:
        page = int(page)
    except ValueError:
        page = 1
    
    page_size = 50
    offset = (page - 1) * page_size
    
    # Main query
    query = f"""
        SELECT 
            timestamp,
            device_name,
            source_address,
            destination_address,
            url,
            url_category,
            action,
            source_user,
            application,
            rule_name,
            http_method,
            response_code,
            user_agent,
            raw_message,
            severity
        FROM pa_urls_optimized 
        WHERE {where_clause}
        ORDER BY timestamp DESC 
        LIMIT {page_size} OFFSET {offset}
    """
    
    # Count query
    count_query = f"""
        SELECT COUNT(*) FROM pa_urls_optimized WHERE {where_clause}
    """
    
    try:
        logs = client.execute(query)
        total_count = client.execute(count_query)[0][0]
        
        # Format logs for template
        formatted_logs = []
        for log in logs:
            # Pass datetime object directly to Django template for proper date filtering
            timestamp_obj = log[0] if log[0] else None
            
            formatted_logs.append({
                'generated_time': timestamp_obj,  # Pass datetime object directly
                'device_name': str(log[1]) if log[1] else '',     # device_name
                'src_ip': str(log[2]) if log[2] else '',          # source_address
                'dst_ip': str(log[3]) if log[3] else '',          # destination_address
                'url': str(log[4]) if log[4] else '',             # url
                'category': str(log[5]) if log[5] else '',        # url_category
                'action': str(log[6]) if log[6] else '',          # action
                'src_user': str(log[7]) if log[7] else '',        # source_user
                'application': str(log[8]) if log[8] else '',     # application
                'rule_name': str(log[9]) if log[9] else '',       # rule_name
                'http_method': str(log[10]) if log[10] else '',   # http_method
                'response_code': int(log[11]) if log[11] else 0,  # response_code
                'user_agent': str(log[12]) if log[12] else '',    # user_agent
                'raw_message': str(log[13]) if log[13] else '',   # raw_message
                'src_port': '',            # No port data in this table
                'dst_port': '',            # No port data in this table
                'severity': str(log[14]) if log[14] else ''       # severity field (index 14)
            })
        
        # Pagination info
        total_pages = math.ceil(total_count / page_size)
        has_next = page < total_pages
        has_prev = page > 1
        
        # Get unique values for filters
        categories = client.execute("SELECT DISTINCT url_category FROM pa_urls_optimized WHERE url_category != '' ORDER BY url_category")
        actions = client.execute("SELECT DISTINCT action FROM pa_urls_optimized WHERE action != '' ORDER BY action")
        severities = client.execute("SELECT DISTINCT severity FROM pa_urls_optimized WHERE severity != '' ORDER BY severity")
        devices = client.execute("SELECT DISTINCT device_name FROM pa_urls_optimized WHERE device_name != '' ORDER BY device_name")
        
    except Exception as e:
        formatted_logs = []
        total_count = 0
        total_pages = 0
        has_next = False
        has_prev = False
        categories = []
        actions = []
        severities = []
        devices = []
        print(f"Database error: {e}")
    
    # Create JSON-safe version of logs for JavaScript
    logs_json_safe = []
    for log in formatted_logs:
        log_copy = log.copy()
        # Convert datetime to string for JSON
        if log_copy.get('generated_time') and hasattr(log_copy['generated_time'], 'strftime'):
            log_copy['generated_time'] = log_copy['generated_time'].strftime('%Y-%m-%d %H:%M:%S')
        logs_json_safe.append(log_copy)
    
    context = {
        'logs': formatted_logs,
        'logs_json': json.dumps(logs_json_safe),
        'total_count': total_count,
        'page': page,
        'total_pages': total_pages,
        'has_next': has_next,
        'has_prev': has_prev,
        'time_range': time_range,
        'time_range_display': time_range_display,
        'url_filter': url_filter,
        'src_ip_filter': src_ip_filter,
        'dst_ip_filter': dst_ip_filter,
        'category_filter': category_filter,
        'action_filter': action_filter,
        'severity_filter': severity_filter,
        'device_filter': device_filter,
        'user_filter': user_filter,
        'categories': [row[0] for row in categories],
        'actions': [row[0] for row in actions],
        'severities': [row[0] for row in severities],
        'devices': [row[0] for row in devices],
    }
    
    return render(request, 'dashboard/pa_url_logs.html', context)


def url_summary_view(request):
    """URL Analytics Summary Dashboard - Similar to top_summary_view but for URL logs"""
    client = Client(
        host=CH_HOST,
        port=CH_PORT,
        user=CH_USER,
        password=CH_PASSWORD,
        database=CH_DB
    )
    
    # Get time_range from GET params (same pattern as top_summary_view)
    time_range = request.GET.get('time_range', '1h')
    selected_time_range = time_range
    
    # Define time filter conditions using ClickHouse native time functions
    # This avoids timezone issues between Python and ClickHouse
    # Server is already in Asia/Riyadh timezone, so use now() directly
    if time_range == '1h':
        time_condition = "timestamp >= now() - INTERVAL 1 HOUR AND timestamp <= now()"
        selected_time_range = '1h'
    elif time_range == '6h':
        time_condition = "timestamp >= now() - INTERVAL 6 HOUR AND timestamp <= now()"
        selected_time_range = '6h'
    elif time_range == '1d':
        time_condition = "timestamp >= now() - INTERVAL 1 DAY AND timestamp <= now()"
        selected_time_range = '1d'
    elif time_range == '7d':
        time_condition = "timestamp >= now() - INTERVAL 7 DAY AND timestamp <= now()"
        selected_time_range = '7d'
    elif time_range == '1m':
        time_condition = "timestamp >= now() - INTERVAL 30 DAY AND timestamp <= now()"
        selected_time_range = '1m'
    elif time_range == 'custom':
        # Handle custom date range
        start_date_str = request.GET.get('start_date')
        end_date_str = request.GET.get('end_date')
        
        if start_date_str and end_date_str:
            try:
                # Parse datetime-local format (YYYY-MM-DDTHH:MM)
                since = datetime.fromisoformat(start_date_str.replace('T', ' '))
                until = datetime.fromisoformat(end_date_str.replace('T', ' '))
                since_str = since.strftime('%Y-%m-%d %H:%M:%S')
                until_str = until.strftime('%Y-%m-%d %H:%M:%S')
                time_condition = f"timestamp >= parseDateTimeBestEffort('{since_str}') AND timestamp <= parseDateTimeBestEffort('{until_str}')"
                selected_time_range = 'custom'
            except ValueError:
                # Fallback to last hour if parsing fails
                time_condition = "timestamp >= now() - INTERVAL 1 HOUR AND timestamp <= now()"
                since_str = "N/A"
                until_str = "N/A"
                selected_time_range = '1h'
        else:
            # Fallback to last hour if dates not provided
            time_condition = "timestamp >= now() - INTERVAL 1 HOUR AND timestamp <= now()"
            since_str = "N/A"
            until_str = "N/A"
            selected_time_range = '1h'
    else:
        # Default to last hour
        time_condition = "timestamp >= now() - INTERVAL 1 HOUR AND timestamp <= now()"
        since_str = "N/A"
        until_str = "N/A"
        selected_time_range = '1h'
    
    # For non-custom ranges, set display values for template
    if time_range != 'custom':
        # Get current time (server is already in correct timezone)
        now_display = datetime.now()
        if time_range == '1h':
            since_display = now_display - timedelta(hours=1)
        elif time_range == '6h':
            since_display = now_display - timedelta(hours=6)
        elif time_range == '1d':
            since_display = now_display - timedelta(days=1)
        elif time_range == '7d':
            since_display = now_display - timedelta(days=7)
        elif time_range == '1m':
            since_display = now_display - timedelta(days=30)
        else:
            since_display = now_display - timedelta(hours=1)
        
        since_str = since_display.strftime('%Y-%m-%d %H:%M:%S')
        until_str = now_display.strftime('%Y-%m-%d %H:%M:%S')

    # Query 1: Top URLs by Request Count
    top_urls_query = f'''
        SELECT
            url_domain,
            url,
            count(*) AS request_count,
            uniq(source_address) AS unique_users,
            url_category,
            action
        FROM pa_urls_optimized
        WHERE {time_condition}
          AND url <> ''
        GROUP BY url_domain, url, url_category, action
        ORDER BY request_count DESC
        LIMIT 15
    '''
    
    # Query 2: Top URL Categories
    categories_query = f'''
        SELECT
            url_category,
            count(*) AS request_count,
            uniq(source_address) AS unique_users,
            countIf(action = 'block-url') AS blocked_count,
            countIf(action = 'alert') AS alert_count
        FROM pa_urls_optimized
        WHERE {time_condition}
          AND url_category <> ''
        GROUP BY url_category
        ORDER BY request_count DESC
        LIMIT 10
    '''
    
    # Query 3: Top Blocked URLs
    blocked_urls_query = f'''
        SELECT
            url_domain,
            url,
            count(*) AS block_count,
            uniq(source_address) AS unique_users,
            url_category
        FROM pa_urls_optimized
        WHERE {time_condition}
          AND action = 'block-url'
          AND url <> ''
        GROUP BY url_domain, url, url_category
        ORDER BY block_count DESC
        LIMIT 15
    '''
    
    # Query 4: Top Users by URL Activity
    top_users_query = f'''
        SELECT
            source_user,
            source_address,
            count(*) AS request_count,
            uniq(url_domain) AS unique_domains,
            countIf(action = 'block-url') AS blocked_requests
        FROM pa_urls_optimized
        WHERE {time_condition}
          AND source_address <> ''
        GROUP BY source_user, source_address
        ORDER BY request_count DESC
        LIMIT 15
    '''
    
    # Query 5: Security Activity (Threats and Blocks)
    security_activity_query = f'''
        SELECT
            action,
            url_category,
            count(*) AS count,
            uniq(source_address) AS unique_sources
        FROM pa_urls_optimized
        WHERE {time_condition}
          AND action IN ('block-url', 'alert')
        GROUP BY action, url_category
        ORDER BY count DESC
        LIMIT 15
    '''
    
    # Query 6: Applications and URL Usage with Severity
    applications_query = f'''
        SELECT
            application,
            count(*) AS request_count,
            uniq(url_domain) AS unique_domains,
            uniq(source_address) AS unique_users,
            countIf(severity = 'informational') AS informational_count,
            countIf(severity = 'low') AS low_count,
            countIf(severity = 'medium') AS medium_count,
            countIf(severity = 'high') AS high_count,
            countIf(severity = 'critical') AS critical_count,
            countIf(action = 'block-url') AS blocked_count,
            countIf(action = 'alert') AS alert_count
        FROM pa_urls_optimized
        WHERE {time_condition}
          AND application <> ''
        GROUP BY application
        ORDER BY request_count DESC
        LIMIT 10
    '''
    
    # Query 7: Summary Statistics
    summary_stats_query = f'''
        SELECT
            count(*) AS total_requests,
            uniq(url_domain) AS unique_domains,
            uniq(source_address) AS unique_users,
            countIf(action = 'block-url') AS blocked_requests,
            countIf(action = 'alert') AS threat_alerts
        FROM pa_urls_optimized
        WHERE {time_condition}
    '''
    
    # Query 8: Previous Period Statistics for Trend Calculation
    # Calculate previous period condition based on time range
    if time_range == '1h':
        prev_time_condition = "timestamp >= now() - INTERVAL 2 HOUR AND timestamp < now() - INTERVAL 1 HOUR"
    elif time_range == '6h':
        prev_time_condition = "timestamp >= now() - INTERVAL 12 HOUR AND timestamp < now() - INTERVAL 6 HOUR"
    elif time_range == '1d':
        prev_time_condition = "timestamp >= now() - INTERVAL 2 DAY AND timestamp < now() - INTERVAL 1 DAY"
    elif time_range == '7d':
        prev_time_condition = "timestamp >= now() - INTERVAL 14 DAY AND timestamp < now() - INTERVAL 7 DAY"
    elif time_range == '1m':
        prev_time_condition = "timestamp >= now() - INTERVAL 60 DAY AND timestamp < now() - INTERVAL 30 DAY"
    else:
        # Default to 1h comparison
        prev_time_condition = "timestamp >= now() - INTERVAL 2 HOUR AND timestamp < now() - INTERVAL 1 HOUR"
    
    prev_summary_stats_query = f'''
        SELECT
            count(*) AS total_requests,
            uniq(url_domain) AS unique_domains,
            uniq(source_address) AS unique_users,
            countIf(action = 'block-url') AS blocked_requests,
            countIf(action = 'alert') AS threat_alerts
        FROM pa_urls_optimized
        WHERE {prev_time_condition}
    '''

    # Execute all queries with error handling
    try:
        top_urls_rows = client.execute(top_urls_query)
    except Exception as e:
        print(f"Error executing top_urls_query: {e}")
        top_urls_rows = []
        
    try:
        categories_rows = client.execute(categories_query)
    except Exception as e:
        print(f"Error executing categories_query: {e}")
        categories_rows = []
        
    try:
        blocked_urls_rows = client.execute(blocked_urls_query)
    except Exception as e:
        print(f"Error executing blocked_urls_query: {e}")
        blocked_urls_rows = []
        
    try:
        top_users_rows = client.execute(top_users_query)
    except Exception as e:
        print(f"Error executing top_users_query: {e}")
        top_users_rows = []
        
    try:
        security_activity_rows = client.execute(security_activity_query)
    except Exception as e:
        print(f"Error executing security_activity_query: {e}")
        security_activity_rows = []
        
    try:
        applications_rows = client.execute(applications_query)
    except Exception as e:
        print(f"Error executing applications_query: {e}")
        applications_rows = []
    
    try:
        summary_stats = client.execute(summary_stats_query)
        if summary_stats:
            total_requests, unique_domains, unique_users, blocked_requests, threat_alerts = summary_stats[0]
        else:
            total_requests = unique_domains = unique_users = blocked_requests = threat_alerts = 0
    except Exception as e:
        print(f"Error executing summary_stats_query: {e}")
        total_requests = unique_domains = unique_users = blocked_requests = threat_alerts = 0
    
    # Execute previous period query for trend calculation
    try:
        prev_summary_stats = client.execute(prev_summary_stats_query)
        if prev_summary_stats:
            prev_total_requests, prev_unique_domains, prev_unique_users, prev_blocked_requests, prev_threat_alerts = prev_summary_stats[0]
        else:
            prev_total_requests = prev_unique_domains = prev_unique_users = prev_blocked_requests = prev_threat_alerts = 0
    except Exception as e:
        print(f"Error executing prev_summary_stats_query: {e}")
        prev_total_requests = prev_unique_domains = prev_unique_users = prev_blocked_requests = prev_threat_alerts = 0
    
    # Calculate trend percentages
    def calculate_trend(current, previous):
        if previous == 0:
            return {"percentage": 0, "direction": "neutral", "sign": ""}
        
        change = ((current - previous) / previous) * 100
        direction = "up" if change > 0 else "down" if change < 0 else "neutral"
        sign = "+" if change > 0 else ""
        
        return {
            "percentage": abs(round(change, 1)),
            "direction": direction,
            "sign": sign
        }
    
    # Calculate trends for each metric
    total_requests_trend = calculate_trend(total_requests, prev_total_requests)
    threat_alerts_trend = calculate_trend(threat_alerts, prev_threat_alerts)

    # Prepare data for template
    context = {
        'selected_time_range': selected_time_range,
        'time_range_start': since_str,
        'time_range_end': until_str,
        
        # Summary statistics
        'total_requests': total_requests,
        'unique_domains': unique_domains,
        'unique_users': unique_users,
        'blocked_requests': blocked_requests,
        'threat_alerts': threat_alerts,
        
        # Trend data
        'total_requests_trend': total_requests_trend,
        'threat_alerts_trend': threat_alerts_trend,
        
        # Top data sets
        'top_urls': [
            {
                'domain': row[0],
                'url': row[1],
                'request_count': row[2],
                'unique_users': row[3],
                'category': row[4],
                'action': row[5]
            }
            for row in top_urls_rows
        ],
        
        'categories': [
            {
                'category': row[0],
                'request_count': row[1],
                'unique_users': row[2],
                'blocked_count': row[3],
                'alert_count': row[4]
            }
            for row in categories_rows
        ],
        
        'blocked_urls': [
            {
                'domain': row[0],
                'url': row[1],
                'block_count': row[2],
                'unique_users': row[3],
                'category': row[4]
            }
            for row in blocked_urls_rows
        ],
        
        'top_users': [
            {
                'username': row[0] or 'Unknown',
                'ip_address': row[1],
                'request_count': row[2],
                'unique_domains': row[3],
                'blocked_requests': row[4]
            }
            for row in top_users_rows
        ],
        
        'security_activity': [
            {
                'action': row[0],
                'category': row[1],
                'count': row[2],
                'unique_sources': row[3]
            }
            for row in security_activity_rows
        ],
        
        'applications': [
            {
                'application': row[0],
                'request_count': row[1],
                'unique_domains': row[2],
                'unique_users': row[3],
                'informational_count': row[4],
                'low_count': row[5],
                'medium_count': row[6],
                'high_count': row[7],
                'critical_count': row[8],
                'blocked_count': row[9],
                'alert_count': row[10],
                # Calculate percentages for severity bars
                'critical_percentage': round((row[8] * 100 / row[1]), 1) if row[1] > 0 else 0,
                'high_percentage': round((row[7] * 100 / row[1]), 1) if row[1] > 0 else 0,
                'medium_percentage': round((row[6] * 100 / row[1]), 1) if row[1] > 0 else 0,
                'low_percentage': round((row[5] * 100 / row[1]), 1) if row[1] > 0 else 0,
                'informational_percentage': round((row[4] * 100 / row[1]), 1) if row[1] > 0 else 0
            }
            for row in applications_rows
        ],
    }
    
    # Add template filter support for mathematical operations
    context['allowed_requests'] = total_requests - blocked_requests if total_requests > 0 else 0
    context['allowed_percentage'] = round((total_requests - blocked_requests) * 100 / total_requests, 1) if total_requests > 0 else 0
    context['blocked_percentage'] = round(blocked_requests * 100 / total_requests, 1) if total_requests > 0 else 0
    
    # Query for Security Timeline Chart - Get hourly data for the selected time range
    try:
        if time_range == '1h':
            # For 1 hour, get data every 10 minutes
            timeline_interval = "10 MINUTE"
            timeline_query = f'''
                SELECT 
                    toStartOfInterval(timestamp, INTERVAL {timeline_interval}) as time_bucket,
                    countIf(action = 'alert') as alerts,
                    countIf(action = 'block-url') as blocked,
                    countIf(action NOT IN ('alert', 'block-url')) as allowed
                FROM pa_urls_optimized
                WHERE {time_condition}
                GROUP BY time_bucket
                ORDER BY time_bucket
            '''
        elif time_range == '6h':
            # For 6 hours, get data every 30 minutes
            timeline_interval = "30 MINUTE"
            timeline_query = f'''
                SELECT 
                    toStartOfInterval(timestamp, INTERVAL {timeline_interval}) as time_bucket,
                    countIf(action = 'alert') as alerts,
                    countIf(action = 'block-url') as blocked,
                    countIf(action NOT IN ('alert', 'block-url')) as allowed
                FROM pa_urls_optimized
                WHERE {time_condition}
                GROUP BY time_bucket
                ORDER BY time_bucket
            '''
        elif time_range == '1d':
            # For 1 day, get data every hour
            timeline_interval = "1 HOUR"
            timeline_query = f'''
                SELECT 
                    toStartOfInterval(timestamp, INTERVAL {timeline_interval}) as time_bucket,
                    countIf(action = 'alert') as alerts,
                    countIf(action = 'block-url') as blocked,
                    countIf(action NOT IN ('alert', 'block-url')) as allowed
                FROM pa_urls_optimized
                WHERE {time_condition}
                GROUP BY time_bucket
                ORDER BY time_bucket
            '''
        else:
            # For longer periods, get data every 4 hours
            timeline_interval = "4 HOUR"
            timeline_query = f'''
                SELECT 
                    toStartOfInterval(timestamp, INTERVAL {timeline_interval}) as time_bucket,
                    countIf(action = 'alert') as alerts,
                    countIf(action = 'block-url') as blocked,
                    countIf(action NOT IN ('alert', 'block-url')) as allowed
                FROM pa_urls_optimized
                WHERE {time_condition}
                GROUP BY time_bucket
                ORDER BY time_bucket
            '''
        
        timeline_data = client.execute(timeline_query)
        
        # Format timeline data for chart
        timeline_labels = []
        allowed_data = []
        blocked_data = []
        alerts_data = []
        
        for row in timeline_data:
            # Format timestamp for display
            time_bucket = row[0]
            if isinstance(time_bucket, datetime):
                timeline_labels.append(time_bucket.strftime('%H:%M'))
            else:
                timeline_labels.append(str(time_bucket))
            
            alerts_data.append(row[1])
            blocked_data.append(row[2]) 
            allowed_data.append(row[3])
        
        # If no data, create dummy data points
        if not timeline_data:
            timeline_labels = ['Current']
            allowed_data = [context['allowed_requests']]
            blocked_data = [blocked_requests]
            alerts_data = [threat_alerts]
        
        context['timeline_labels'] = timeline_labels
        context['timeline_allowed'] = allowed_data
        context['timeline_blocked'] = blocked_data
        context['timeline_alerts'] = alerts_data
        
    except Exception as e:
        logging.error(f"Error fetching timeline data: {e}")
        # Fallback to single data point
        context['timeline_labels'] = ['Current']
        context['timeline_allowed'] = [context['allowed_requests']]
        context['timeline_blocked'] = [blocked_requests]
        context['timeline_alerts'] = [threat_alerts]
    
    return render(request, 'dashboard/url_summary.html', context)


def edit_device_view(request, device_ip):
    """Edit a registered device in ClickHouse"""
    if request.method == 'GET':
        try:
            # Connect to ClickHouse
            client = Client(
                host=CH_HOST,
                port=CH_PORT,
                user=CH_USER,
                password=CH_PASSWORD,
                database=CH_DB
            )
            
            # Get device details
            device = client.execute(
                "SELECT device_ip, device_name, parser_type, enabled FROM registered_devices WHERE device_ip = %(device_ip)s",
                {'device_ip': device_ip}
            )
            
            if not device:
                return JsonResponse({'success': False, 'error': 'Device not found'})
            
            device_data = {
                'device_ip': device[0][0],
                'device_name': device[0][1],
                'parser_type': device[0][2],
                'enabled': bool(device[0][3])
            }
            
            return JsonResponse({'success': True, 'device': device_data})
            
        except Exception as e:
            return JsonResponse({'success': False, 'error': f'Failed to fetch device: {str(e)}'})
    
    elif request.method == 'POST':
        try:
            # Parse request data
            import json
            data = json.loads(request.body)
            
            device_name = data.get('device_name', '').strip()
            parser_type = data.get('parser_type', 'fortigate')
            enabled = data.get('enabled', True)
            
            if not device_name:
                return JsonResponse({'success': False, 'error': 'Device name is required'})
            
            # Connect to ClickHouse
            client = Client(
                host=CH_HOST,
                port=CH_PORT,
                user=CH_USER,
                password=CH_PASSWORD,
                database=CH_DB
            )
            
            # Since ClickHouse doesn't support UPDATE easily, we'll delete and re-insert
            # First, delete the existing record
            client.execute(
                "ALTER TABLE registered_devices DELETE WHERE device_ip = %(device_ip)s",
                {'device_ip': device_ip}
            )
            
            # Insert the updated record
            client.execute(
                """INSERT INTO registered_devices (device_ip, device_name, parser_type, enabled) 
                   VALUES (%(device_ip)s, %(device_name)s, %(parser_type)s, %(enabled)s)""",
                {
                    'device_ip': device_ip,
                    'device_name': device_name,
                    'parser_type': parser_type,
                    'enabled': 1 if enabled else 0
                }
            )
            
            # Also update the LogSource if it exists
            try:
                source = LogSource.objects.get(ip_address=device_ip)
                source.name = device_name
                source.device_type = parser_type
                source.status = 'approved' if enabled else 'inactive'
                source.save()
                
                # Log the update event
                LogSourceEvent.objects.create(
                    log_source=source,
                    event_type='configured',
                    description=f'Device updated: {device_name} ({device_ip})',
                    user=request.user.username if request.user.is_authenticated else 'admin'
                )
            except LogSource.DoesNotExist:
                pass
            
            return JsonResponse({
                'success': True,
                'message': f'Device {device_name} ({device_ip}) updated successfully'
            })
            
        except Exception as e:
            return JsonResponse({'success': False, 'error': f'Failed to update device: {str(e)}'})
    
    return JsonResponse({'success': False, 'error': 'Method not allowed'})


def delete_device_view(request, device_ip):
    """Delete a registered device from ClickHouse"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Method not allowed'})
    
    try:
        # Connect to ClickHouse
        client = Client(
            host=CH_HOST,
            port=CH_PORT,
            user=CH_USER,
            password=CH_PASSWORD,
            database=CH_DB
        )
        
        # Check if device exists
        device = client.execute(
            "SELECT device_name FROM registered_devices WHERE device_ip = %(device_ip)s",
            {'device_ip': device_ip}
        )
        
        if not device:
            return JsonResponse({'success': False, 'error': 'Device not found'})
        
        device_name = device[0][0]
        
        # Delete from ClickHouse
        client.execute(
            "ALTER TABLE registered_devices DELETE WHERE device_ip = %(device_ip)s",
            {'device_ip': device_ip}
        )
        
        # Also delete from LogSource if it exists
        try:
            source = LogSource.objects.get(ip_address=device_ip)
            
            # Log the deletion event before deleting
            LogSourceEvent.objects.create(
                log_source=source,
                event_type='deleted',
                description=f'Device deleted: {device_name} ({device_ip})',
                user=request.user.username if request.user.is_authenticated else 'admin'
            )
            
            source.delete()
        except LogSource.DoesNotExist:
            pass
        
        # Remove rsyslog configuration if it exists
        config_patterns = [
            f"/etc/rsyslog.d/*-{device_ip.replace('.', '-')}.conf",
            f"/etc/rsyslog.d/{device_ip.replace('.', '-')}-*.conf"
        ]
        
        import glob
        import os
        for pattern in config_patterns:
            for config_file in glob.glob(pattern):
                try:
                    os.remove(config_file)
                except Exception:
                    pass
        
        # Reload rsyslog
        try:
            subprocess.run(['sudo', 'systemctl', 'reload', 'rsyslog'], check=True)
        except Exception:
            pass
        
        return JsonResponse({
            'success': True,
            'message': f'Device {device_name} ({device_ip}) deleted successfully'
        })
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': f'Failed to delete device: {str(e)}'})
