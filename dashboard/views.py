from django.shortcuts import render
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.http import JsonResponse
from django.utils.html import escape
from django.db.models import Sum, Count

import re
import math
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

def dmu_view(request):
    # Renders the static UI template
    return render(request, 'dashboard/index.html')

def top_summary_view(request):
    client = Client(
        host=CH_HOST,
        port=CH_PORT,
        user=CH_USER,
        password=CH_PASSWORD,
        database=CH_DB
    )
    # Get time_range from GET params
    time_range = request.GET.get('time_range', 'last_hour')
    now = datetime.now()
    if time_range == 'last_24_hours':
        since = now - timedelta(hours=24)
    elif time_range == 'last_7_days':
        since = now - timedelta(days=7)
    elif time_range == 'last_30_days':
        since = now - timedelta(days=30)
    elif time_range == 'custom':
        # Custom range not yet implemented; fallback to last hour
        since = now - timedelta(hours=1)
    else:
        since = now - timedelta(hours=1)

    # ClickHouse expects ISO format
    since_str = since.strftime('%Y-%m-%d %H:%M:%S')

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
    
    return render(request, 'dashboard/top_summary.html', {
        'top_traffic': top_traffic,
        'top_categories': top_categories,
        'top_urls': top_urls,
        'top_users': top_users,
        'top_countries': top_countries,
        'selected_time_range': time_range
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

    # Get client's real IP (for display or other purposes)
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        viewer_ip = x_forwarded_for.split(',')[0]
    else:
        viewer_ip = request.META.get('REMOTE_ADDR')

    # --- Time Filter ---
    time_range = request.GET.get('time_range', 'last_hour')
    now = datetime.utcnow()  # Use UTC to match ClickHouse 'now()'
    if time_range == 'last_24_hours':
        since = now - timedelta(hours=24)
    elif time_range == 'last_7_days':
        since = now - timedelta(days=7)
    elif time_range == 'last_30_days':
        since = now - timedelta(days=30)
    elif time_range == 'custom':
        # Custom range logic can be added here in the future
        since = now - timedelta(hours=1)
    else:
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
    
    # Build WHERE clauses based on filter inputs
    where_clauses = [f"timestamp >= parseDateTimeBestEffort('{since_str}')"] 
    
    if srcip_filter:
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
    
    # Update count query with filters
    count_query = f"SELECT count() FROM fortigate_traffic WHERE {where_clause}"
    
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

    # --- Fetch current page of logs from ClickHouse with filters ---
    query = f"""
        SELECT
            timestamp, raw_message, srcip, srcport, dstip, dstport, action, proto,
            rcvdbyte, sentbyte, sentpkt, rcvdpkt, duration, srcintf, dstintf, policyname, username, srccountry, dstcountry
        FROM fortigate_traffic
        WHERE {where_clause}
        ORDER BY timestamp DESC
        LIMIT {SUBNET_GROUP_PAGE_SIZE} OFFSET {offset}
    """
    
    try:
        db_rows = client.execute(query)
    except Exception:
        db_rows = []  # Fallback on error

    processed_logs_for_template = []
    for db_row in db_rows:
        # Unpack basic fields (adjust indices based on your SELECT statement)
        ts_obj = db_row[0]
        raw_message_val = db_row[1]
        srcip_val = db_row[2]
        srcport_val = db_row[3] # Added srcport
        dstip_val = db_row[4]
        dstport_val = db_row[5]
        action_val = db_row[6]
        proto_num = db_row[7]
        rcvdbyte_val = db_row[8]
        sentbyte_val = db_row[9]
        sentpkt_val = db_row[10] # Added sentpkt
        rcvdpkt_val = db_row[11] # Added rcvdpkt
        duration_val = db_row[12] if db_row[12] is not None else 0
        srcintf_val = db_row[13]
        dstintf_val = db_row[14]
        policyname_val = db_row[15]
        username_val = db_row[16] if len(db_row) > 16 and db_row[16] is not None else 'N/A'
        srccountry_val = db_row[17] if len(db_row) > 17 and db_row[17] is not None else 'N/A'
        dstcountry_val = db_row[18] if len(db_row) > 18 and db_row[18] is not None else 'N/A'

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
