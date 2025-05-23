from django.shortcuts import render

import re
import math
from clickhouse_driver import Client
import os
import json
from datetime import datetime, timedelta

# ClickHouse connection settings
CH_HOST = os.getenv('CH_HOST', 'localhost')
CH_PORT = int(os.getenv('CH_PORT', '9000'))
CH_USER = os.getenv('CH_USER', 'default')
CH_PASSWORD = os.getenv('CH_PASSWORD', 'Read@123')
CH_DB = os.getenv('CH_DB', 'network_logs')
PAGE_SIZE = 50

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

    query = f'''
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
    
    try:
        rows = client.execute(query)
    except Exception:
        rows = []
        
    top_summary = [
        {
            'srcip': row[0],
            'dstip': row[1],
            'dstport': row[2],
            'total_sent': row[3],
            'total_rcvd': row[4],
            'total_bytes': row[5],
        }
        for row in rows
    ]
    return render(request, 'dashboard/top_summary.html', {
        'top_summary': top_summary,
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

    # --- Pagination ---
    page = int(request.GET.get('page', 1))
    try:
        # Total logs count for the current filter
        total_logs_count_result = client.execute(f"SELECT count() FROM fortigate_traffic WHERE timestamp >= parseDateTimeBestEffort('{since_str}')")
        total_logs_count = total_logs_count_result[0][0] if total_logs_count_result else 0
    except Exception:
        total_logs_count = 0  # Fallback on error

    total_pages = (total_logs_count + PAGE_SIZE - 1) // PAGE_SIZE if PAGE_SIZE > 0 else 1
    offset = (page - 1) * PAGE_SIZE

    # --- Fetch current page of logs from ClickHouse ---
    query = f"""
        SELECT
            timestamp, raw_message, srcip, dstip, dstport, action, proto,
            rcvdbyte, sentbyte, duration
        FROM fortigate_traffic
        WHERE timestamp >= parseDateTimeBestEffort('{since_str}')
        ORDER BY timestamp DESC
        LIMIT {PAGE_SIZE} OFFSET {offset}
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
        dstip_val = db_row[3]
        dstport_val = db_row[4]
        action_val = db_row[5]
        proto_num = db_row[6]
        rcvdbyte_val = db_row[7]
        sentbyte_val = db_row[8]
        duration_val = db_row[9] if db_row[9] is not None else 0

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

            # Detailed fields for JavaScript expansion (Populate these from your data)
            'clientRTT': "N/A",                 # TODO: Fetch or derive
            'serverRTTLB': "N/A",               # TODO: Fetch or derive
            'appResponse': "N/A",               # TODO: Fetch or derive
            'dataTransfer': "N/A",              # TODO: Fetch or derive
            'totalTime': duration_display_str,  # Or a more specific total time if available

            'srcport_val': "N/A",               # TODO: Fetch source port if available for `log.srcport`
            'location': "Internal",             # Fallback for `log.srcport` if `srcport_val` is "N/A"
            
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

    context = {
        'logs_for_display': processed_logs_for_template, # For Django template to render table rows
        'logs_json_for_expansion': json.dumps(processed_logs_for_template, default=str), # For JS `logData`
        'viewer_ip': viewer_ip, # The IP of the person viewing the page
        'current_page': page,
        'total_pages': total_pages,
        'total_logs_count': total_logs_count,
        'page_range': page_range,
        'selected_time_range': time_range, # Pass to template for dropdown selection
        # Pass any other context variables your template needs
    }
    return render(request, 'dashboard/logs2.html', context)

