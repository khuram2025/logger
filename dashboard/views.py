from django.shortcuts import render
from elasticsearch import Elasticsearch
import re
import math
from clickhouse_driver import Client
import os
import json


PAGE_SIZE = 50

# ClickHouse connection settings (sync with fortigate_to_clickhouse.py)
CH_HOST = os.getenv('CH_HOST', 'localhost')
CH_PORT = int(os.getenv('CH_PORT', '9000'))
CH_USER = os.getenv('CH_USER', 'default')
CH_PASSWORD = os.getenv('CH_PASSWORD', 'Read@123')
CH_DB = os.getenv('CH_DB', 'network_logs')
PAGE_SIZE = 50

def dmu_view(request):
    # Renders the static UI template
    return render(request, 'dashboard/index.html')

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

    # Get client's real IP (for display or other purposes, not directly used in log data here)
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        viewer_ip = x_forwarded_for.split(',')[0]
    else:
        viewer_ip = request.META.get('REMOTE_ADDR')

    # --- Pagination ---
    page = int(request.GET.get('page', 1))
    try:
        total_logs_count_result = client.execute("SELECT count() FROM fortigate_traffic")
        total_logs_count = total_logs_count_result[0][0] if total_logs_count_result else 0
    except Exception as e:
        print(f"Error fetching total log count: {e}")
        total_logs_count = 0 # Fallback or handle error appropriately

    total_pages = (total_logs_count + PAGE_SIZE - 1) // PAGE_SIZE if PAGE_SIZE > 0 else 1
    offset = (page - 1) * PAGE_SIZE

    # --- Fetch current page of logs from ClickHouse ---
    # Adjust the SELECT statement to include all base fields you have
    query = f"""
        SELECT
            timestamp, srcip, dstip, dstport, action, proto,
            rcvdbyte, sentbyte, duration
        FROM fortigate_traffic
        ORDER BY timestamp DESC
        LIMIT {PAGE_SIZE} OFFSET {offset}
    """
    try:
        db_rows = client.execute(query)
    except Exception as e:
        print(f"Error fetching logs: {e}")
        db_rows = [] # Fallback or handle error

    processed_logs_for_template = []
    for db_row in db_rows:
        # Unpack basic fields (adjust indices based on your SELECT statement)
        ts_obj = db_row[0]
        srcip_val = db_row[1]
        dstip_val = db_row[2]
        dstport_val = db_row[3]
        action_val = db_row[4] # This might map to 'waf' status (e.g. "FLAGGED", "PASSED")
        proto_num = db_row[5]
        rcvdbyte_val = db_row[6]
        sentbyte_val = db_row[7]
        duration_val = db_row[8] if db_row[8] is not None else 0

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
        # Pass any other context variables your template needs
    }
    return render(request, 'dashboard/logs2.html', context)

def dashboard_view(request):
    es = Elasticsearch(
        ["http://localhost:9200"],
        headers={
            "Accept": "application/vnd.elasticsearch+json; compatible-with=8",
            "Content-Type": "application/vnd.elasticsearch+json; compatible-with=8"
        }
    )
    logs = []
    columns = []
    srcip = request.GET.get("srcip")
    dstip = request.GET.get("dstip")
    page = int(request.GET.get("page", 1))
    from_ = (page - 1) * PAGE_SIZE
    action = request.GET.get("action", "")
    date_from = request.GET.get("date_from", "")
    date_to = request.GET.get("date_to", "")
    sort = request.GET.get("sort", "timestamp")
    order = request.GET.get("order", "desc")

    # Build query
    must = []
    if srcip and srcip != "None":
        must.append({"term": {"srcip.keyword": srcip}})
    if dstip and dstip != "None":
        must.append({"term": {"dstip.keyword": dstip}})
    if action:
        must.append({"term": {"action.keyword": action}})
    
    # Add date range filter if provided
    if date_from or date_to:
        range_filter = {"range": {"@timestamp": {}}}
        if date_from:
            range_filter["range"]["@timestamp"]["gte"] = date_from + "T00:00:00Z"
        if date_to:
            range_filter["range"]["@timestamp"]["lte"] = date_to + "T23:59:59Z"
        must.append(range_filter)
    
    if must:
        query = {"bool": {"must": must}}
    else:
        query = {"match_all": {}}

    # Get logs with pagination and sorting
    sort_field = sort if sort else "@timestamp"
    sort_order = order if order else "desc"
    
    # Handle special case for timestamp field
    if sort_field == "timestamp":
        sort_field = "@timestamp"
    # For fields that are typically text but used for sorting, use .keyword
    elif sort_field in ["srcip", "dstip", "action", "dstport"]:
        sort_field = f"{sort_field}.keyword"
    
    body = {
        "query": query,
        "sort": [{sort_field: {"order": sort_order}}]
    }
    resp = es.search(
        index="fortigate-simple",
        size=PAGE_SIZE,
        from_=from_,
        body=body
    )
    for hit in resp["hits"]["hits"]:
        src = hit["_source"]
        logs.append(src)
    # Determine columns: union of all keys in the current page
    columns_set = set()
    for log in logs:
        columns_set.update(log.keys())
    # Add 'timestamp' field for template access
    for log in logs:
        if "@timestamp" in log:
            log["timestamp"] = log["@timestamp"]
        # Ensure all required fields are present
        for key in ["timestamp", "srcip", "dstip", "dstport", "action"]:
            if key not in log:
                log[key] = ""
    # Only show selected columns in desired order
    columns = ["timestamp", "srcip", "dstip", "dstport", "action"]
    print("COLUMNS being sent to template:", columns)
    print("SAMPLE LOG:", logs[0] if logs else "No logs found")

    # Pagination
    total = resp["hits"]["total"]["value"] if "total" in resp["hits"] else 0
    total_pages = max(1, math.ceil(total / PAGE_SIZE))
    page_numbers = list(range(1, total_pages + 1))
    # Get action filter if present
    action = request.GET.get("action", "")
    date_from = request.GET.get("date_from", "")
    date_to = request.GET.get("date_to", "")
    
    # Get sort parameters
    sort = request.GET.get("sort", "timestamp")
    order = request.GET.get("order", "desc")
    
    return render(request, "dashboard/dashboard.html", {
        "logs": logs,
        "columns": columns,
        "current_srcip": srcip,
        "current_dstip": dstip,
        "current_action": action,
        "current_date_from": date_from,
        "current_date_to": date_to,
        "sort": sort,
        "order": order,
        "page": page,
        "total_pages": total_pages,
        "total": total,
        "page_size": PAGE_SIZE,
        "page_numbers": page_numbers,
        "request": request,
    })
