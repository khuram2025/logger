"""
Log Sources Management Views
Contains all views related to log source management, configuration, and device registration.
"""

from django.shortcuts import render
from django.http import JsonResponse, Http404
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from django.contrib.auth.decorators import login_required
from dashboard.models import LogSource, LogSourceEvent
from dashboard.auth.decorators import require_permission, admin_required

import re
import logging
import json
import subprocess
import socket
import ipaddress
import os
from datetime import datetime, timedelta
from clickhouse_driver import Client

# ClickHouse connection settings
CH_HOST = os.getenv('CH_HOST', 'localhost')
CH_PORT = int(os.getenv('CH_PORT', '9000'))
CH_USER = os.getenv('CH_USER', 'default')
CH_PASSWORD = os.getenv('CH_PASSWORD', 'Read@123')
CH_DB = os.getenv('CH_DB', 'network_logs')


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


@require_permission('configure_sources')
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

        # Get corresponding LogSource objects from Django DB
        device_ips = [d[0] for d in devices]
        log_source_map = {
            ls.ip_address: ls for ls in LogSource.objects.filter(ip_address__in=device_ips)
        }

        for device in devices:
            device_ip, device_name, parser_type, enabled, created_at = device
            
            log_source_obj = log_source_map.get(device_ip)

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
                'id': log_source_obj.id if log_source_obj else None,
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


@require_permission('manage_devices')
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