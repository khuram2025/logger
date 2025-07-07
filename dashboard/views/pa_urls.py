from django.shortcuts import render
from django.http import JsonResponse
from clickhouse_driver import Client
import os
import json
import math
import logging
from datetime import datetime, timedelta

# ClickHouse connection settings
CH_HOST = os.getenv('CH_HOST', 'localhost')
CH_PORT = int(os.getenv('CH_PORT', '9000'))
CH_USER = os.getenv('CH_USER', 'default')
CH_PASSWORD = os.getenv('CH_PASSWORD', 'Read@123')
CH_DB = os.getenv('CH_DB', 'network_logs')


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
    use_custom_time = False # Initialize here
    
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
    rule_filter = request.GET.get('rule', '').strip()
    
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
    if rule_filter:
        where_conditions.append(f"rule_name ILIKE '%{rule_filter}%'")
    
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
        'rule_filter': rule_filter,
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