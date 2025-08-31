"""
System Configuration Views

This module contains views for managing system configuration including:
- Service management and monitoring
- Log configuration management
- System testing and validation
"""

from django.shortcuts import render
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
import subprocess
import json
import os
import glob
import socket
from datetime import datetime

from dashboard.auth.decorators import require_permission, admin_required


@require_permission('system_config')
def system_config_view(request):
    """System Configuration view with service status dashboard"""
    
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


@require_permission('system_config')
def service_action_view(request):
    """Handle service start/stop/restart actions via AJAX"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Method not allowed'})
    
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


@require_permission('configure_sources')
def logs_config_view(request):
    """Logs Configuration view for managing firewall log settings"""
    
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


@require_permission('configure_sources')
def logs_config_save_view(request):
    """Save logs configuration changes"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Method not allowed'})
    
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


@require_permission('configure_sources')
def logs_config_test_view(request):
    """Test log configuration and connectivity"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Method not allowed'})
    
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