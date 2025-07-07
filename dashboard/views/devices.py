from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from clickhouse_driver import Client
import json
import logging
import subprocess
import glob
import os

from ..models import LogSource, LogSourceEvent

# Set up logging
logger = logging.getLogger(__name__)

# ClickHouse connection settings
CH_HOST = os.getenv('CH_HOST', 'localhost')
CH_PORT = int(os.getenv('CH_PORT', '9000'))
CH_USER = os.getenv('CH_USER', 'default')
CH_PASSWORD = os.getenv('CH_PASSWORD', 'Read@123')
CH_DB = os.getenv('CH_DB', 'network_logs')


def edit_device_view(request, device_ip):
    """Edit a registered device in ClickHouse"""
    if request.method == 'GET':
        try:
            # Connect to ClickHouse
            client = Client(
                host=CH_HOST,
                port=CH_PORT,
                user=CH_USER,
                password=CH_PASSWORD,
                database=CH_DB
            )
            
            # Get device details
            device = client.execute(
                "SELECT device_ip, device_name, parser_type, enabled FROM registered_devices WHERE device_ip = %(device_ip)s",
                {'device_ip': device_ip}
            )
            
            if not device:
                return JsonResponse({'success': False, 'error': 'Device not found'})
            
            device_data = {
                'device_ip': device[0][0],
                'device_name': device[0][1],
                'parser_type': device[0][2],
                'enabled': bool(device[0][3])
            }
            
            return JsonResponse({'success': True, 'device': device_data})
            
        except Exception as e:
            return JsonResponse({'success': False, 'error': f'Failed to fetch device: {str(e)}'})
    
    elif request.method == 'POST':
        try:
            # Parse request data
            data = json.loads(request.body)
            
            device_name = data.get('device_name', '').strip()
            parser_type = data.get('parser_type', 'fortigate')
            enabled = data.get('enabled', True)
            
            if not device_name:
                return JsonResponse({'success': False, 'error': 'Device name is required'})
            
            # Connect to ClickHouse
            client = Client(
                host=CH_HOST,
                port=CH_PORT,
                user=CH_USER,
                password=CH_PASSWORD,
                database=CH_DB
            )
            
            # Since ClickHouse doesn't support UPDATE easily, we'll delete and re-insert
            # First, delete the existing record
            client.execute(
                "ALTER TABLE registered_devices DELETE WHERE device_ip = %(device_ip)s",
                {'device_ip': device_ip}
            )
            
            # Insert the updated record
            client.execute(
                """INSERT INTO registered_devices (device_ip, device_name, parser_type, enabled) 
                   VALUES (%(device_ip)s, %(device_name)s, %(parser_type)s, %(enabled)s)""",
                {
                    'device_ip': device_ip,
                    'device_name': device_name,
                    'parser_type': parser_type,
                    'enabled': 1 if enabled else 0
                }
            )
            
            # Also update the LogSource if it exists
            try:
                source = LogSource.objects.get(ip_address=device_ip)
                source.name = device_name
                source.device_type = parser_type
                source.status = 'approved' if enabled else 'inactive'
                source.save()
                
                # Log the update event
                LogSourceEvent.objects.create(
                    log_source=source,
                    event_type='configured',
                    description=f'Device updated: {device_name} ({device_ip})',
                    user=request.user.username if request.user.is_authenticated else 'admin'
                )
            except LogSource.DoesNotExist:
                pass
            
            return JsonResponse({
                'success': True,
                'message': f'Device {device_name} ({device_ip}) updated successfully'
            })
            
        except Exception as e:
            return JsonResponse({'success': False, 'error': f'Failed to update device: {str(e)}'})
    
    return JsonResponse({'success': False, 'error': 'Method not allowed'})


def delete_device_view(request, device_ip):
    """Delete a registered device from ClickHouse"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Method not allowed'})
    
    try:
        # Connect to ClickHouse
        client = Client(
            host=CH_HOST,
            port=CH_PORT,
            user=CH_USER,
            password=CH_PASSWORD,
            database=CH_DB
        )
        
        # Check if device exists
        device = client.execute(
            "SELECT device_name FROM registered_devices WHERE device_ip = %(device_ip)s",
            {'device_ip': device_ip}
        )
        
        if not device:
            return JsonResponse({'success': False, 'error': 'Device not found'})
        
        device_name = device[0][0]
        
        # Delete from ClickHouse
        client.execute(
            "ALTER TABLE registered_devices DELETE WHERE device_ip = %(device_ip)s",
            {'device_ip': device_ip}
        )
        
        # Also delete from LogSource if it exists
        try:
            source = LogSource.objects.get(ip_address=device_ip)
            
            # Log the deletion event before deleting
            LogSourceEvent.objects.create(
                log_source=source,
                event_type='deleted',
                description=f'Device deleted: {device_name} ({device_ip})',
                user=request.user.username if request.user.is_authenticated else 'admin'
            )
            
            source.delete()
        except LogSource.DoesNotExist:
            pass
        
        # Remove rsyslog configuration if it exists
        config_patterns = [
            f"/etc/rsyslog.d/*-{device_ip.replace('.', '-')}.conf",
            f"/etc/rsyslog.d/{device_ip.replace('.', '-')}-*.conf"
        ]
        
        for pattern in config_patterns:
            for config_file in glob.glob(pattern):
                try:
                    os.remove(config_file)
                except Exception:
                    pass
        
        # Reload rsyslog
        try:
            subprocess.run(['sudo', 'systemctl', 'reload', 'rsyslog'], check=True)
        except Exception:
            pass
        
        return JsonResponse({
            'success': True,
            'message': f'Device {device_name} ({device_ip}) deleted successfully'
        })
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': f'Failed to delete device: {str(e)}'})