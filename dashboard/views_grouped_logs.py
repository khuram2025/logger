"""
Grouped Logs View - Network Traffic Analysis by Subnet Groups
"""

from django.shortcuts import render
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.http import JsonResponse, Http404
from django.utils.html import escape
from django.db.models import Sum, Count
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt

import re
import math
import logging
from clickhouse_driver import Client
import os
import json
import subprocess
from datetime import datetime, timedelta, timezone
from collections import defaultdict
import ipaddress

# ClickHouse connection settings
CH_HOST = os.getenv('CH_HOST', 'localhost')
CH_PORT = int(os.getenv('CH_PORT', '9000'))
CH_USER = os.getenv('CH_USER', 'default')
CH_PASSWORD = os.getenv('CH_PASSWORD', 'Read@123')
CH_DB = os.getenv('CH_DB', 'network_logs')
SUBNET_GROUP_PAGE_SIZE = 50

# Protocol mapping
PROTO_MAP = {
    1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 50: 'ESP', 51: 'AH',
    89: 'OSPF', 103: 'PIM', 132: 'SCTP'
}

def format_bytes(byte_count):
    """Format bytes into human readable format"""
    if byte_count is None:
        return "0 B"
    
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if byte_count < 1024.0:
            return f"{byte_count:.1f} {unit}"
        byte_count /= 1024.0
    return f"{byte_count:.1f} PB"

def get_pagination_range(current_page, total_pages, max_pages=10):
    """Get pagination range for template"""
    if total_pages <= max_pages:
        return range(1, total_pages + 1)
    
    # Calculate start and end pages
    start = max(1, current_page - max_pages // 2)
    end = min(total_pages + 1, start + max_pages)
    
    # Adjust start if end is at the boundary
    if end - start < max_pages:
        start = max(1, end - max_pages)
    
    return range(start, end)

def grouped_logs_view(request):
    """Network traffic analysis grouped by subnet and destination"""
    client = Client(
        host=CH_HOST,
        port=CH_PORT,
        user=CH_USER,
        password=CH_PASSWORD,
        database=CH_DB
    )

    # Time filter - use ClickHouse native time to avoid timezone issues
    time_range = request.GET.get('time_range', 'last_hour')
    use_clickhouse_time = True
    
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
    if use_clickhouse_time:
        where_conditions = [f"timestamp >= now() - INTERVAL {since_interval}"]
    else:
        where_conditions = [f"timestamp >= parseDateTimeBestEffort('{since_str}')"]
    
    if srcip_filter:
        where_conditions.append(f"srcip = '{srcip_filter}'")
    if dstip_filter:
        where_conditions.append(f"dstip = '{dstip_filter}'")
    if action_filter:
        where_conditions.append(f"action = '{action_filter}'")
    if devname_filter:
        where_conditions.append(f"devicename = '{devname_filter}'")
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
    return render(request, 'dashboard/grouped_logs_new.html', context)