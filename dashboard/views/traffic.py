from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from clickhouse_driver import Client
import os
import json
import logging
from datetime import datetime, timedelta
import ipaddress

# ClickHouse connection settings
CH_HOST = os.getenv('CH_HOST', 'localhost')
CH_PORT = int(os.getenv('CH_PORT', '9000'))
CH_USER = os.getenv('CH_USER', 'default')
CH_PASSWORD = os.getenv('CH_PASSWORD', 'Read@123')
CH_DB = os.getenv('CH_DB', 'network_logs')
SUBNET_GROUP_PAGE_SIZE = 50

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

    # For non-custom ranges, set until to now
    if time_range != 'custom':
        until = now

    # ClickHouse expects ISO format
    since_str = since.strftime('%Y-%m-%d %H:%M:%S')
    until_str = until.strftime('%Y-%m-%d %H:%M:%S')

    # Determine since_interval for ClickHouse native time functions
    if time_range == '1h':
        since_interval = '1 HOUR'
    elif time_range == '1d':
        since_interval = '1 DAY'
    elif time_range == '7d':
        since_interval = '7 DAY'
    elif time_range == '1m':
        since_interval = '30 DAY'
    else: # Default or custom
        since_interval = '1 HOUR' # Fallback, though custom uses since_str directly

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
        WHERE timestamp >= toDateTime('{since_str}')
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
        WHERE timestamp >= toDateTime('{since_str}')
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
        WHERE timestamp >= toDateTime('{since_str}')
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
        WHERE timestamp >= toDateTime('{since_str}')
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
        WHERE timestamp >= toDateTime('{since_str}')
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
        WHERE timestamp >= toDateTime('{since_str}')
        """
        # Custom time range until clause not needed for standard intervals
            
        conn_result = client.execute(conn_query)
        total_connections = conn_result[0][0] if conn_result else 0
        
        # Get total bytes transferred
        bytes_query = f"""
        SELECT SUM(sentbyte + rcvdbyte) 
        FROM fortigate_traffic 
        WHERE timestamp >= toDateTime('{since_str}')
        """
        # Custom time range until clause not needed for standard intervals
            
        bytes_result = client.execute(bytes_query)
        total_bytes = bytes_result[0][0] if bytes_result and bytes_result[0][0] else 0
        
        # Get active unique source IPs
        ips_query = f"""
        SELECT COUNT(DISTINCT srcip) 
        FROM fortigate_traffic 
        WHERE timestamp >= toDateTime('{since_str}')
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
    policyname_filter = request.GET.get('policyname', '').strip()
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
    external_only_filter = request.GET.get('external_only', '').strip()
    
    # Build WHERE clauses based on filter inputs
    if use_clickhouse_time:
        where_clauses = [f"timestamp >= now() - INTERVAL {since_interval}"]
    else:
        where_clauses = [f"timestamp >= parseDateTimeBestEffort('{since_str}')"]
        # Add until clause if custom time range with end date
        if until:
            until_str = until.strftime('%Y-%m-%d %H:%M:%S')
            where_clauses.append(f"timestamp <= parseDateTimeBestEffort('{until_str}')") 
    
    def _get_ip_filter_clause(ip_filter, ip_field_name):
        if not ip_filter:
            return None
        
        if ip_filter == 'external_only':
            return f"""
                NOT (
                    {ip_field_name} LIKE '10.%' OR 
                    {ip_field_name} LIKE '192.168.%' OR 
                    {ip_field_name} LIKE '172.16.%' OR {ip_field_name} LIKE '172.17.%' OR {ip_field_name} LIKE '172.18.%' OR {ip_field_name} LIKE '172.19.%' OR
                    {ip_field_name} LIKE '172.20.%' OR {ip_field_name} LIKE '172.21.%' OR {ip_field_name} LIKE '172.22.%' OR {ip_field_name} LIKE '172.23.%' OR
                    {ip_field_name} LIKE '172.24.%' OR {ip_field_name} LIKE '172.25.%' OR {ip_field_name} LIKE '172.26.%' OR {ip_field_name} LIKE '172.27.%' OR
                    {ip_field_name} LIKE '172.28.%' OR {ip_field_name} LIKE '172.29.%' OR {ip_field_name} LIKE '172.30.%' OR {ip_field_name} LIKE '172.31.%' OR
                    {ip_field_name} = '127.0.0.1' OR {ip_field_name} LIKE '169.254.%'
                )
            """.strip()
        
        try:
            # Check if it's a CIDR notation
            network = ipaddress.ip_network(ip_filter, strict=False)
            if network.num_addresses == 1:
                # It's a single IP, treat as exact match
                return f"{ip_field_name} = '{str(network.network_address)}'"
            else:
                # It's a subnet, use IPv4NumToStringClassC or similar for ClickHouse
                # ClickHouse has functions like IPv4CIDRToIPv4Range, or we can use bitwise operations
                # For simplicity and broad compatibility, we'll use a range check
                # This assumes IPv4. For IPv6, more complex logic would be needed.
                
                # Convert network address and broadcast address to integers for range comparison
                # ClickHouse IP functions are more efficient, but this is a generic Python approach
                # For ClickHouse, `IPv4StringToNum(ip_field_name) BETWEEN IPv4StringToNum('start_ip') AND IPv4StringToNum('end_ip')`
                # or `IPv4ToIPv4Num(ip_field_name) IN (SELECT IPv4ToIPv4Num(ip) FROM ip_addresses_in_cidr_table)`
                # Given the current setup, string LIKE is often used, but for CIDR, BETWEEN is better.
                
                # Let's use ClickHouse's built-in IPv4CIDRToRange for better performance
                # This requires the IP field to be of type IPv4 in ClickHouse, or converted.
                # Assuming the IP fields are strings in ClickHouse, we'll use `IPv4StringToNum`
                
                # Example: 10.10.201.0/24
                # ClickHouse: IPv4StringToNum(srcip) >= IPv4StringToNum('10.10.201.0') AND IPv4StringToNum(srcip) <= IPv4StringToNum('10.10.201.255')
                
                # Get the first and last IP in the network
                first_ip = str(network.network_address)
                last_ip = str(network.broadcast_address)
                
                return f"IPv4StringToNum({ip_field_name}) >= IPv4StringToNum('{first_ip}') AND IPv4StringToNum({ip_field_name}) <= IPv4StringToNum('{last_ip}')"
        except ValueError:
            # Not a valid IP or CIDR, treat as exact match for now
            return f"{ip_field_name} = '{ip_filter}'"

    # Handle external_only filter separately
    if external_only_filter == 'true':
        # When external_only is specified, show logs where EITHER source OR destination is external
        external_check = """
            (
                NOT (
                    srcip LIKE '10.%' OR 
                    srcip LIKE '192.168.%' OR 
                    srcip LIKE '172.16.%' OR srcip LIKE '172.17.%' OR srcip LIKE '172.18.%' OR srcip LIKE '172.19.%' OR
                    srcip LIKE '172.20.%' OR srcip LIKE '172.21.%' OR srcip LIKE '172.22.%' OR srcip LIKE '172.23.%' OR
                    srcip LIKE '172.24.%' OR srcip LIKE '172.25.%' OR srcip LIKE '172.26.%' OR srcip LIKE '172.27.%' OR
                    srcip LIKE '172.28.%' OR srcip LIKE '172.29.%' OR srcip LIKE '172.30.%' OR srcip LIKE '172.31.%' OR
                    srcip = '127.0.0.1' OR srcip LIKE '169.254.%'
                )
                OR
                NOT (
                    dstip LIKE '10.%' OR 
                    dstip LIKE '192.168.%' OR 
                    dstip LIKE '172.16.%' OR dstip LIKE '172.17.%' OR dstip LIKE '172.18.%' OR dstip LIKE '172.19.%' OR
                    dstip LIKE '172.20.%' OR dstip LIKE '172.21.%' OR dstip LIKE '172.22.%' OR dstip LIKE '172.23.%' OR
                    dstip LIKE '172.24.%' OR dstip LIKE '172.25.%' OR dstip LIKE '172.26.%' OR dstip LIKE '172.27.%' OR
                    dstip LIKE '172.28.%' OR dstip LIKE '172.29.%' OR dstip LIKE '172.30.%' OR dstip LIKE '172.31.%' OR
                    dstip = '127.0.0.1' OR dstip LIKE '169.254.%'
                )
            )
        """.strip()
        where_clauses.append(external_check)
    
    # Process source IP filter (now independent of external_only)
    srcip_clause = _get_ip_filter_clause(srcip_filter, 'srcip')
    if srcip_clause:
        where_clauses.append(srcip_clause)
    
    # Process destination IP filter
    dstip_clause = _get_ip_filter_clause(dstip_filter, 'dstip')
    if dstip_clause:
        where_clauses.append(dstip_clause)
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
        # Map registered device names to actual device names used in logs
        actual_devname = devname_filter
        try:
            # Check if this is a registered device name that needs mapping
            device_mapping_query = "SELECT device_ip FROM registered_devices WHERE device_name = %(device_name)s AND enabled = 1"
            device_ip_result = client.execute(device_mapping_query, {'device_name': devname_filter})
            if device_ip_result:
                device_ip = device_ip_result[0][0]
                # Try to find actual device name in fortigate_traffic for this IP
                actual_name_query = "SELECT DISTINCT devname FROM fortigate_traffic WHERE devname IS NOT NULL AND devname <> '' AND (devname LIKE %(pattern1)s OR devname LIKE %(pattern2)s) LIMIT 1"
                actual_name_result = client.execute(actual_name_query, {
                    'pattern1': f'%{devname_filter.split("-")[-1]}%',  # Extract FW02 part
                    'pattern2': f'%FGT-{devname_filter.split("-")[-1]}%'  # Try FGT-FW02 pattern
                })
                if actual_name_result:
                    actual_devname = actual_name_result[0][0]
                    logging.info(f"Mapped device name '{devname_filter}' to '{actual_devname}'")
        except Exception as e:
            logging.warning(f"Error mapping device name {devname_filter}: {e}")
            # Fall back to original name
        
        # Use FortiGate field name in base clause; per-table clauses below
        # will map 'devname' to the appropriate device field (e.g., device_name)
        where_clauses.append(f"devname = '{actual_devname}'")
    if appcategory_filter:
        where_clauses.append(f"appcategory = '{appcategory_filter}'")
    if hostname_filter:
        where_clauses.append(f"hostname = '{hostname_filter}'")
    if username_filter:
        where_clauses.append(f"username = '{username_filter}'")
    if dstcountry_filter:
        where_clauses.append(f"dstcountry = '{dstcountry_filter}'")
    if policyname_filter:
        where_clauses.append(f"policyname = '{policyname_filter}'")
    
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
        pa_where_clause = (
            where_clause
            .replace('srcip', 'src_ip')
            .replace('dstip', 'dst_ip')
            .replace('srcport', 'src_port')
            .replace('dstport', 'dst_port')
            .replace('devname', 'device_name')
            .replace('appcategory', 'app_category')
            .replace('hostname', 'application')
            .replace('username', 'src_user')
            .replace('dstcountry', 'dst_country')
            .replace('proto', 'protocol')
            .replace('sentbyte', 'bytes_sent')
            .replace('rcvdbyte', 'bytes_received')
        )
        count_queries.append(f"SELECT count() FROM pa_traffic WHERE {pa_where_clause}")
    if has_threat_logs:
        threat_where_clause = (
            where_clause
            .replace('srcip', 'source_address')
            .replace('dstip', 'destination_address')
            .replace('srcport', 'source_port')
            .replace('dstport', 'destination_port')
            .replace('devname', 'device_name')
            .replace('appcategory', 'application_category')
            .replace('hostname', 'application')
            .replace('username', 'source_user')
            .replace('dstcountry', 'destination_country')
            .replace('proto', 'protocol')
            .replace('sentbyte', 'bytes_sent')
            .replace('rcvdbyte', 'bytes_received')
        )
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
        pa_where_clause = (
            where_clause
            .replace('srcip', 'src_ip')
            .replace('dstip', 'dst_ip')
            .replace('srcport', 'src_port')
            .replace('dstport', 'dst_port')
            .replace('devname', 'device_name')
            .replace('appcategory', 'app_category')
            .replace('hostname', 'application')
            .replace('username', 'src_user')
            .replace('dstcountry', 'dst_country')
            .replace('proto', 'protocol')
            .replace('sentbyte', 'bytes_sent')
            .replace('rcvdbyte', 'bytes_received')
            .replace('policyname', 'rule_name')
        )
        
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
        threat_where_clause = (
            where_clause
            .replace('srcip', 'source_address')
            .replace('dstip', 'destination_address')
            .replace('srcport', 'source_port')
            .replace('dstport', 'destination_port')
            .replace('devname', 'device_name')
            .replace('appcategory', 'application_category')
            .replace('hostname', 'application')
            .replace('username', 'source_user')
            .replace('dstcountry', 'destination_country')
            .replace('proto', 'protocol')
            .replace('sentbyte', 'bytes_sent')
            .replace('rcvdbyte', 'bytes_received')
            .replace('policyname', 'rule_name')
        )
        
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
        'policyname_filter': policyname_filter,
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