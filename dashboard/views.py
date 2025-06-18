from django.shortcuts import render
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.http import JsonResponse
from django.utils.html import escape
from django.db.models import Sum, Count

import re
import math
import logging
from clickhouse_driver import Client
import os
import json
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
        WHERE timestamp >= parseDateTimeBestEffort('{since_str}')
          AND timestamp <= parseDateTimeBestEffort('{until_str}')
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
        WHERE timestamp >= parseDateTimeBestEffort('{since_str}')
          AND timestamp <= parseDateTimeBestEffort('{until_str}')
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
        WHERE timestamp >= parseDateTimeBestEffort('{since_str}')
          AND timestamp <= parseDateTimeBestEffort('{until_str}')
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
        WHERE timestamp >= parseDateTimeBestEffort('{since_str}')
          AND timestamp <= parseDateTimeBestEffort('{until_str}')
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
        WHERE timestamp >= parseDateTimeBestEffort('{since_str}')
          AND timestamp <= parseDateTimeBestEffort('{until_str}')
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
        WHERE timestamp >= parseDateTimeBestEffort('{since.strftime('%Y-%m-%d %H:%M:%S')}')
        """
        if time_range == 'custom' and 'until' in locals():
            conn_query += f" AND timestamp <= parseDateTimeBestEffort('{until.strftime('%Y-%m-%d %H:%M:%S')}')"
            
        conn_result = client.execute(conn_query)
        total_connections = conn_result[0][0] if conn_result else 0
        
        # Get total bytes transferred
        bytes_query = f"""
        SELECT SUM(sentbyte + rcvdbyte) 
        FROM fortigate_traffic 
        WHERE timestamp >= parseDateTimeBestEffort('{since.strftime('%Y-%m-%d %H:%M:%S')}')
        """
        if time_range == 'custom' and 'until' in locals():
            bytes_query += f" AND timestamp <= parseDateTimeBestEffort('{until.strftime('%Y-%m-%d %H:%M:%S')}')"
            
        bytes_result = client.execute(bytes_query)
        total_bytes = bytes_result[0][0] if bytes_result and bytes_result[0][0] else 0
        
        # Get active unique source IPs
        ips_query = f"""
        SELECT COUNT(DISTINCT srcip) 
        FROM fortigate_traffic 
        WHERE timestamp >= parseDateTimeBestEffort('{since.strftime('%Y-%m-%d %H:%M:%S')}')
        """
        if time_range == 'custom' and 'until' in locals():
            ips_query += f" AND timestamp <= parseDateTimeBestEffort('{until.strftime('%Y-%m-%d %H:%M:%S')}')"
            
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
    now = datetime.utcnow()  # Use UTC to match ClickHouse 'now()'
    until = None
    
    if time_range == 'last_6_hours':
        since = now - timedelta(hours=6)
    elif time_range == 'last_24_hours':
        since = now - timedelta(hours=24)
    elif time_range == 'last_7_days':
        since = now - timedelta(days=7)
    elif time_range == 'last_30_days':
        since = now - timedelta(days=30)
    elif time_range == 'custom':
        # Handle custom time range
        time_from = request.GET.get('time_from', '')
        time_to = request.GET.get('time_to', '')
        
        if time_from:
            try:
                since = datetime.strptime(time_from, '%Y-%m-%dT%H:%M')
            except ValueError:
                since = now - timedelta(hours=1)
        else:
            since = now - timedelta(hours=1)
            
        if time_to:
            try:
                until = datetime.strptime(time_to, '%Y-%m-%dT%H:%M')
            except ValueError:
                until = None
    else:  # default to last_hour
        since = now - timedelta(hours=1)
    
    since_str = since.strftime('%Y-%m-%d %H:%M:%S')
    
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
        where_clauses.append(f"devname = '{devname_filter}'")
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
    
    # --- Fetch available action values for dropdown ---
    action_query = f"""
        SELECT DISTINCT action 
        FROM fortigate_traffic 
        WHERE {where_clause}
        ORDER BY action
    """
    
    try:
        available_actions = [row[0] for row in client.execute(action_query)]
    except Exception as e:
        available_actions = []

    # --- Fetch available device names for dropdown ---
    device_query = f"""
        SELECT DISTINCT devname 
        FROM fortigate_traffic 
        WHERE {where_clause}  # Consider if devname filter should apply to its own dropdown population
        ORDER BY devname
    """
    try:
        available_devices = [row[0] for row in client.execute(device_query)]
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
        pa_where_clause = where_clause.replace('srcip', 'src_ip').replace('dstip', 'dst_ip').replace('srcport', 'src_port').replace('dstport', 'dst_port').replace('devname', 'device_name').replace('appcategory', 'app_category').replace('hostname', 'application').replace('username', 'src_user').replace('dstcountry', 'dst_country').replace('proto', 'protocol').replace('sentbyte', 'bytes_sent').replace('rcvdbyte', 'bytes_received')
        count_queries.append(f"SELECT count() FROM pa_traffic WHERE {pa_where_clause}")
    if has_threat_logs:
        threat_where_clause = where_clause.replace('srcip', 'source_address').replace('dstip', 'destination_address').replace('srcport', 'source_port').replace('dstport', 'destination_port').replace('devname', 'device_name').replace('appcategory', 'application_category').replace('hostname', 'application').replace('username', 'source_user').replace('dstcountry', 'destination_country').replace('proto', 'protocol').replace('sentbyte', 'bytes_sent').replace('rcvdbyte', 'bytes_received')
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
                devname as device_name,
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
        'time_from': request.GET.get('time_from', ''),
        'time_to': request.GET.get('time_to', ''),
        'log_source_filter': log_source_filter,
    }
    return render(request, 'dashboard/logs2.html', context)


def grouped_logs_view(request):
    client = Client(
        host=CH_HOST,
        port=CH_PORT,
        user=CH_USER,
        password=CH_PASSWORD,
        database=CH_DB
    )

    time_range = request.GET.get('time_range', 'last_hour')
    now = datetime.utcnow() # Use UTC to match ClickHouse 'now()'
    if time_range == 'last_24_hours':
        since = now - timedelta(hours=24)
    elif time_range == 'last_7_days':
        since = now - timedelta(days=7)
    elif time_range == 'last_30_days':
        since = now - timedelta(days=30)
    # Add other time ranges as needed or a custom range handler
    else: # Default to last_hour
        since = now - timedelta(hours=1)
    since_str = since.strftime('%Y-%m-%d %H:%M:%S')

    page = int(request.GET.get('page', 1)) # Page number for Paginator
    sort_by = request.GET.get('sort_by', 'last_seen') # Default sort: last_seen
    sort_order = request.GET.get('sort_order', 'desc')   # Default order: desc
    is_reverse_sort = sort_order == 'desc'

    # Get filter parameters
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

    # Build WHERE conditions
    where_conditions = [f"timestamp >= parseDateTimeBestEffort('{since_str}')"]
    
    if srcip_filter:
        where_conditions.append(f"srcip = '{srcip_filter}'")
    if dstip_filter:
        where_conditions.append(f"dstip = '{dstip_filter}'")
    if action_filter:
        where_conditions.append(f"action = '{action_filter}'")
    if devname_filter:
        where_conditions.append(f"devname = '{devname_filter}'")
    if appcategory_filter:
        where_conditions.append(f"appcategory = '{appcategory_filter}'")
    if hostname_filter:
        where_conditions.append(f"hostname = '{hostname_filter}'")
    if username_filter:
        where_conditions.append(f"username = '{username_filter}'")
    if dstcountry_filter:
        where_conditions.append(f"dstcountry = '{dstcountry_filter}'")
    
    # Handle port filters with ranges
    if srcport_filter:
        if '-' in srcport_filter:
            try:
                start, end = srcport_filter.split('-')
                where_conditions.append(f"srcport >= {int(start)} AND srcport <= {int(end)}")
            except:
                pass
        elif ',' in srcport_filter:
            ports = [p.strip() for p in srcport_filter.split(',') if p.strip().isdigit()]
            if ports:
                where_conditions.append(f"srcport IN ({','.join(ports)})")
        elif srcport_filter.isdigit():
            where_conditions.append(f"srcport = {srcport_filter}")
    
    if dstport_filter:
        if '-' in dstport_filter:
            try:
                start, end = dstport_filter.split('-')
                where_conditions.append(f"dstport >= {int(start)} AND dstport <= {int(end)}")
            except:
                pass
        elif ',' in dstport_filter:
            ports = [p.strip() for p in dstport_filter.split(',') if p.strip().isdigit()]
            if ports:
                where_conditions.append(f"dstport IN ({','.join(ports)})")
        elif dstport_filter.isdigit():
            where_conditions.append(f"dstport = {dstport_filter}")
    
    where_clause = " AND ".join(where_conditions)

    # Get total count of fine-grained groups for the selected time range
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
        # print(f"Error executing count query: {e}") # Debugging
        total_grouped_logs_count = 0 # Fallback on error

    # Query to group logs and count occurrences
    query = f"""
        SELECT
            srcip, dstip, dstport, action,
            count() as event_count,
            sum(sentbyte) as total_sent,
            sum(rcvdbyte) as total_rcvd,
            any(proto) as proto_val, 
            max(timestamp) as last_seen
        FROM fortigate_traffic
        WHERE {where_clause}
        GROUP BY srcip, dstip, dstport, action
        ORDER BY last_seen DESC
    """
    
    try:
        db_rows = client.execute(query)
    except Exception as e:
        db_rows = []
        # Consider logging error e

    processed_logs_from_db = []
    if db_rows:
        for row in db_rows:
            last_seen_dt = row[8]
            processed_logs_from_db.append({
                'srcip': row[0],
                'dstip': row[1],
                'dstport': row[2],
                'action': row[3],
                'event_count': row[4],
                'total_sent': row[5],
                'total_rcvd': row[6],
                'proto': PROTO_MAP.get(row[7], str(row[7])),
                'last_seen_display': last_seen_dt.strftime('%Y-%m-%d %H:%M:%S') if last_seen_dt else 'N/A',
                'last_seen_raw': last_seen_dt,
                'total_sent_display': format_bytes(row[5]),
                'total_rcvd_display': format_bytes(row[6]),
            })

    page_level_subnet_groups = defaultdict(lambda: {
        'summary_event_count': 0,
        'summary_total_sent': 0,
        'summary_total_rcvd': 0,
        'summary_last_seen_raw': None,
        'summary_protos': set(),
        'details': []
    })

    for log_entry in processed_logs_from_db:
        srcip_str = log_entry['srcip']
        try:
            network = ipaddress.ip_network(f"{srcip_str}/24", strict=False)
            src_subnet_repr = str(network.network_address) + "/24"
        except ValueError:
            src_subnet_repr = srcip_str

        page_group_key = (src_subnet_repr, log_entry['dstip'], log_entry['dstport'], log_entry['action'])
        group = page_level_subnet_groups[page_group_key]
        group['summary_event_count'] += log_entry['event_count']
        group['summary_total_sent'] += log_entry['total_sent']
        group['summary_total_rcvd'] += log_entry['total_rcvd']
        group['summary_protos'].add(log_entry['proto'])
        if group['summary_last_seen_raw'] is None or \
           (log_entry['last_seen_raw'] and log_entry['last_seen_raw'] > group['summary_last_seen_raw']):
            group['summary_last_seen_raw'] = log_entry['last_seen_raw']
        group['details'].append(log_entry)

    template_ready_subnet_groups = []
    for key, data in page_level_subnet_groups.items():
        src_subnet_disp, dstip_disp, dstport_disp, action_disp = key
        sorted_details = sorted(data['details'], key=lambda x: x['event_count'], reverse=True)
        template_ready_subnet_groups.append({
            'src_subnet_display': src_subnet_disp,
            'dstip': dstip_disp,
            'dstport': dstport_disp,
            'action': action_disp,
            'event_count': data['summary_event_count'],
            'total_sent_display': format_bytes(data['summary_total_sent']),
            'total_rcvd_display': format_bytes(data['summary_total_rcvd']),
            'proto_display': ', '.join(sorted(list(data['summary_protos']))) if data['summary_protos'] else 'N/A',
            'last_seen_display': data['summary_last_seen_raw'].strftime('%Y-%m-%d %H:%M:%S') if data['summary_last_seen_raw'] else 'N/A',
            'summary_last_seen_raw': data['summary_last_seen_raw'], # For accurate sorting
            'details': sorted_details,
            'group_id': f"subnetgroup-{str(src_subnet_disp).replace('/', '_').replace('.', '_')}-{str(dstip_disp).replace('.', '_')}-{dstport_disp}-{action_disp}".replace(' ', '_').lower()
        })
    # Sorting logic based on parameters
    if sort_by == 'dstip':
        template_ready_subnet_groups = sorted(template_ready_subnet_groups, key=lambda x: str(x.get('dstip', '')) , reverse=is_reverse_sort) # Ensure dstip is string for sorting
    elif sort_by == 'count':
        template_ready_subnet_groups = sorted(template_ready_subnet_groups, key=lambda x: x.get('event_count', 0), reverse=is_reverse_sort)
    elif sort_by == 'last_seen':
        template_ready_subnet_groups = sorted(
            template_ready_subnet_groups, 
            key=lambda x: x.get('summary_last_seen_raw') or datetime.min, # Use datetime.min for None values
            reverse=is_reverse_sort
        )
    else: # Default sort (last_seen desc if sort_by is unrecognized or not specified)
        template_ready_subnet_groups = sorted(
            template_ready_subnet_groups, 
            key=lambda x: x.get('summary_last_seen_raw') or datetime.min, 
            reverse=True # Default sort_order for last_seen is desc
        )

    # Paginate the template_ready_subnet_groups
    paginator = Paginator(template_ready_subnet_groups, SUBNET_GROUP_PAGE_SIZE)
    try:
        page_obj = paginator.page(request.GET.get('page', 1)) # 'page' is from request.GET.get('page',1)
    except PageNotAnInteger:
        page_obj = paginator.page(1)
    except EmptyPage:
        page_obj = paginator.page(paginator.num_pages)

    selected_time_range_display = time_range.replace('_', ' ').title()
    page_range_for_template = get_pagination_range(page_obj.number, paginator.num_pages)

    # Get available actions and devices for filters
    available_actions = []
    available_devices = []
    try:
        # Query for distinct actions
        actions_result = client.execute("SELECT DISTINCT action FROM fortigate_traffic WHERE action != '' ORDER BY action")
        available_actions = [row[0] for row in actions_result if row[0]]
        
        # Query for distinct device names
        devices_result = client.execute("SELECT DISTINCT devicename FROM fortigate_traffic WHERE devicename != '' ORDER BY devicename")
        available_devices = [row[0] for row in devices_result if row[0]]
    except:
        pass

    context = {
        'grouped_logs': page_obj, # Pass the Paginator page object
        'displayed_subnet_groups_count': len(page_obj.object_list),
        'total_subnet_groups_count': paginator.count, # Total /24 subnet groups
        'total_grouped_logs_count': total_grouped_logs_count, # Total fine-grained groups
        'selected_time_range': time_range,
        'selected_time_range_display': selected_time_range_display,
        'current_page': page_obj.number,
        'total_pages': paginator.num_pages, # Total pages of /24 subnet groups
        'page_range': page_range_for_template,
        'sort_by': sort_by,
        'sort_order': sort_order,
        'viewer_ip': request.META.get('REMOTE_ADDR'),
        # Filter values for template
        'srcip_filter': srcip_filter,
        'dstip_filter': dstip_filter,
        'srcport_filter': srcport_filter,
        'dstport_filter': dstport_filter,
        'action_filter': action_filter,
        'devname_filter': devname_filter,
        'appcategory_filter': appcategory_filter,
        'hostname_filter': hostname_filter,
        'username_filter': username_filter,
        'dstcountry_filter': dstcountry_filter,
        'available_actions': available_actions,
        'available_devices': available_devices,
    }
    return render(request, 'dashboard/grouped_logs.html', context)

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
    
    # Mock data for demonstration - in production this would come from a database
    mock_log_sources = [
        {
            'id': 1,
            'name': 'FortiGate Firewall',
            'description': 'Primary FortiGate firewall appliance',
            'ip_address': '192.168.100.221',
            'port': 514,
            'status': 'active',
            'save_logs': True,
            'logs_today': 15420,
            'logs_last_hour': 892,
            'total_logs': 2456781,
            'device_type': 'fortigate'
        },
        {
            'id': 2,
            'name': 'PaloAlto Firewall',
            'description': 'Secondary PaloAlto firewall appliance',
            'ip_address': '10.12.50.61',
            'port': 1004,
            'status': 'active',
            'save_logs': True,
            'logs_today': 8756,
            'logs_last_hour': 432,
            'total_logs': 1234567,
            'device_type': 'paloalto'
        },
        {
            'id': 3,
            'name': 'Unknown Device',
            'description': 'Unidentified device sending logs',
            'ip_address': '192.168.1.100',
            'port': 514,
            'status': 'pending',
            'save_logs': False,
            'logs_today': 245,
            'logs_last_hour': 12,
            'total_logs': 5642,
            'device_type': 'unknown'
        },
        {
            'id': 4,
            'name': 'Test Firewall',
            'description': 'Test environment firewall',
            'ip_address': '10.10.10.50',
            'port': 514,
            'status': 'inactive',
            'save_logs': False,
            'logs_today': 0,
            'logs_last_hour': 0,
            'total_logs': 123456,
            'device_type': 'fortigate'
        }
    ]
    
    # Calculate overview statistics
    total_sources = len(mock_log_sources)
    active_sources = len([s for s in mock_log_sources if s['status'] == 'active'])
    inactive_sources = len([s for s in mock_log_sources if s['status'] == 'inactive'])
    pending_sources = len([s for s in mock_log_sources if s['status'] == 'pending'])
    
    context = {
        'log_sources': mock_log_sources,
        'total_sources': total_sources,
        'active_sources': active_sources,
        'inactive_sources': inactive_sources,
        'pending_sources': pending_sources,
        'last_updated': datetime.now(),
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
        data = json.loads(request.body)
        source_id = data.get('source_id')
        action = data.get('action')
        
        if action not in ['approve', 'reject', 'enable', 'disable']:
            return JsonResponse({'success': False, 'error': 'Invalid action'})
        
        # In production, update the database and rsyslog configuration
        # For demonstration, we'll simulate the actions
        
        if action == 'approve':
            # Add source to allowed list and configure rsyslog
            message = f'Source {source_id} approved and configured'
        elif action == 'reject':
            # Block source and remove from configuration
            message = f'Source {source_id} rejected and blocked'
        elif action == 'enable':
            # Enable log processing for source
            message = f'Source {source_id} enabled'
        elif action == 'disable':
            # Disable log processing for source
            message = f'Source {source_id} disabled'
        
        # Restart rsyslog to apply changes
        try:
            subprocess.run(['sudo', 'systemctl', 'reload', 'rsyslog'], 
                         capture_output=True, text=True, check=True)
        except subprocess.CalledProcessError as e:
            return JsonResponse({
                'success': False, 
                'error': f'Failed to reload rsyslog: {e.stderr}'
            })
        
        return JsonResponse({'success': True, 'message': message})
        
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON data'})
    except Exception as e:
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

def scan_log_sources_view(request):
    """Scan network for potential log sources"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Method not allowed'})
    
    try:
        import subprocess
        import re
        
        # Scan common syslog ports on local network
        # This is a simplified scan - in production you'd want more sophisticated discovery
        discovered_sources = []
        
        # Get local network range
        try:
            # Get default gateway to determine network range
            route_result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                        capture_output=True, text=True)
            
            # For demonstration, we'll simulate discovering some devices
            discovered_sources = [
                {
                    'ip': '192.168.1.50',
                    'port': 514,
                    'device_type': 'unknown',
                    'status': 'pending'
                },
                {
                    'ip': '10.10.10.100',
                    'port': 514,
                    'device_type': 'cisco',
                    'status': 'pending'
                }
            ]
            
        except Exception as e:
            # Fallback to mock data
            discovered_sources = []
        
        return JsonResponse({
            'success': True,
            'discovered_count': len(discovered_sources),
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
    """Add a new log source (placeholder for future implementation)"""
    # This would render a form or handle POST data to add a new source
    return JsonResponse({'success': False, 'error': 'Not implemented yet'})

def configure_log_source_view(request, source_id):
    """Configure a specific log source"""
    from datetime import datetime
    
    # Mock data for demonstration - in production this would query the database
    mock_log_sources = {
        1: {
            'id': 1,
            'name': 'FortiGate Firewall',
            'description': 'Primary FortiGate firewall appliance',
            'ip_address': '192.168.100.221',
            'port': 514,
            'status': 'active',
            'save_logs': True,
            'logs_today': 15420,
            'logs_last_hour': 892,
            'total_logs': 2456781,
            'device_type': 'fortigate',
            'log_file_path': '/var/log/fortigate.log',
            'protocol': 'udp',
            'log_template': 'raw',
            'custom_template': '%rawmsg-after-pri%\\n',
            'parse_to_database': True
        },
        2: {
            'id': 2,
            'name': 'PaloAlto Firewall',
            'description': 'Secondary PaloAlto firewall appliance',
            'ip_address': '10.12.50.61',
            'port': 1004,
            'status': 'active',
            'save_logs': True,
            'logs_today': 8756,
            'logs_last_hour': 432,
            'total_logs': 1234567,
            'device_type': 'paloalto',
            'log_file_path': '/var/log/paloalto-1004.log',
            'protocol': 'udp',
            'log_template': 'detailed',
            'custom_template': '%timegenerated% %hostname% %rawmsg-after-pri%\\n',
            'parse_to_database': True
        },
        3: {
            'id': 3,
            'name': 'Unknown Device',
            'description': 'Unidentified device sending logs',
            'ip_address': '192.168.1.100',
            'port': 514,
            'status': 'pending',
            'save_logs': False,
            'logs_today': 245,
            'logs_last_hour': 12,
            'total_logs': 5642,
            'device_type': 'unknown',
            'log_file_path': '/var/log/unknown.log',
            'protocol': 'udp',
            'log_template': 'timestamp',
            'custom_template': '%timegenerated% %rawmsg-after-pri%\\n',
            'parse_to_database': False
        },
        4: {
            'id': 4,
            'name': 'Test Firewall',
            'description': 'Test environment firewall',
            'ip_address': '10.10.10.50',
            'port': 514,
            'status': 'inactive',
            'save_logs': False,
            'logs_today': 0,
            'logs_last_hour': 0,
            'total_logs': 123456,
            'device_type': 'fortigate',
            'log_file_path': '/var/log/test-firewall.log',
            'protocol': 'udp',
            'log_template': 'raw',
            'custom_template': '%rawmsg-after-pri%\\n',
            'parse_to_database': False
        }
    }
    
    source = mock_log_sources.get(int(source_id))
    if not source:
        return render(request, '404.html', {'message': 'Log source not found'}, status=404)
    
    context = {
        'source': source,
    }
    
    return render(request, 'dashboard/configure_log_source.html', context)

def save_log_source_config_view(request, source_id):
    """Save log source configuration"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Method not allowed'})
    
    try:
        import json
        import subprocess
        import os
        data = json.loads(request.body)
        
        # Validate required fields
        required_fields = ['name', 'ip_address', 'port', 'device_type']
        for field in required_fields:
            if not data.get(field):
                return JsonResponse({'success': False, 'error': f'Missing required field: {field}'})
        
        # Validate IP address format
        import ipaddress
        try:
            ipaddress.ip_address(data['ip_address'])
        except ValueError:
            return JsonResponse({'success': False, 'error': 'Invalid IP address format'})
        
        # Validate port range
        port = data.get('port')
        if not isinstance(port, int) or port < 1 or port > 65535:
            return JsonResponse({'success': False, 'error': 'Port must be between 1 and 65535'})
        
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
        
        # In production, you would:
        # 1. Update the database with the new configuration
        # 2. Write the rsyslog configuration file
        # 3. Reload rsyslog service
        # 4. Update any related services
        
        # For demonstration, we'll simulate writing the config file
        config_filename = f"/tmp/{device_type}-{ip_address.replace('.', '-')}.conf"
        
        try:
            with open(config_filename, 'w') as f:
                f.write(config_content)
            
            # Simulate rsyslog reload
            # In production: subprocess.run(['sudo', 'systemctl', 'reload', 'rsyslog'])
            
            return JsonResponse({
                'success': True,
                'message': f'Configuration saved successfully for {data["name"]}',
                'config_file': config_filename,
                'config_content': config_content
            })
            
        except IOError as e:
            return JsonResponse({
                'success': False,
                'error': f'Failed to write configuration file: {str(e)}'
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
