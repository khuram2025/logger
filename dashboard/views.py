from django.shortcuts import render
from elasticsearch import Elasticsearch
import re
import math
from clickhouse_driver import Client
import os

PAGE_SIZE = 50

# ClickHouse connection settings (sync with fortigate_to_clickhouse.py)
CH_HOST = os.getenv('CH_HOST', 'localhost')
CH_PORT = int(os.getenv('CH_PORT', '9000'))
CH_USER = os.getenv('CH_USER', 'default')
CH_PASSWORD = os.getenv('CH_PASSWORD', 'Read@123')
CH_DB = os.getenv('CH_DB', 'network_logs')

def dmu_view(request):
    # Renders the static UI template
    return render(request, 'dashboard/index.html')


def clickhouse_logs_view(request):
    client = Client(
        host=CH_HOST,
        port=CH_PORT,
        user=CH_USER,
        password=CH_PASSWORD,
        database=CH_DB
    )
    # Adjust table name if needed
    def format_bytes(num):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if abs(num) < 1024.0:
                return f"{num:.0f} {unit}" if unit == 'B' else f"{num:.1f} {unit}"
            num /= 1024.0
        return f"{num:.1f} PB"

    PROTO_MAP = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP',
        47: 'GRE',
        50: 'ESP',
        51: 'AH',
        58: 'ICMPv6',
    }

    query = """
        SELECT timestamp, srcip, dstip, dstport, action, proto, rcvdbyte, sentbyte, duration
        FROM fortigate_traffic
        ORDER BY timestamp DESC
        LIMIT 100
    """
    rows = client.execute(query)
    logs = []
    for row in rows:
        # row: (timestamp, srcip, dstip, dstport, action, proto, rcvdbyte, sentbyte, duration)
        ts = row[0]
        date = ts.strftime('%Y-%m-%d') if ts else ''
        time = ts.strftime('%H:%M:%S') if ts else ''
        proto_num = row[5]
        proto_str = PROTO_MAP.get(proto_num, str(proto_num))
        rcvdbyte_str = format_bytes(row[6])
        sentbyte_str = format_bytes(row[7])
        duration_val = row[8]
        logs.append({
            'ts': f"{date} {time}",
            'srcip': row[1],
            'dstip': row[2],
            'dstport': row[3],
            'action': row[4],
            'proto': proto_str,
            'rcvdbyte': rcvdbyte_str,
            'sentbyte': sentbyte_str,
            'duration': f"{duration_val}ms",
            'tl': '|||',
            'dur': duration_val,
        })
    # PAGINATION LOGIC
    PAGE_SIZE = 50
    page = int(request.GET.get('page', 1))
    total_logs = len(logs)
    total_pages = (total_logs + PAGE_SIZE - 1) // PAGE_SIZE
    start = (page - 1) * PAGE_SIZE
    end = start + PAGE_SIZE
    logs_page = logs[start:end]
    # Get real client IP
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        source_ip = x_forwarded_for.split(',')[0]
    else:
        source_ip = request.META.get('REMOTE_ADDR')
    return render(request, 'dashboard/logs2.html', {
        'logs': logs_page,
        'source_ip': source_ip,
        'current_page': page,
        'total_pages': total_pages,
        'total_logs': total_logs
    })


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
