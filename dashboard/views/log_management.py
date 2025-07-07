"""
Log management views for dashboard application.
Contains views for log management status, service control, and storage management.
"""

import json
import os
import time
import subprocess
import logging
from datetime import datetime
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from clickhouse_driver import Client


def format_bytes(bytes_val):
    """Format bytes to human readable format"""
    if bytes_val == 0:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.1f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.1f} PB"


def log_management_status_view(request):
    """View for displaying log management and rotation status"""
    import json
    import os
    import time
    import subprocess
    from datetime import datetime
    
    STATUS_FILE = '/var/lib/log-manager/status.json'
    
    try:
        # Load status from log monitor
        status_data = {}
        if os.path.exists(STATUS_FILE):
            with open(STATUS_FILE, 'r') as f:
                status_data = json.load(f)
        
        # If no status file exists, create basic status
        if not status_data:
            status_data = {
                'timestamp': time.time(),
                'timestamp_formatted': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'overall_status': 'unknown',
                'files': {},
                'processing_lag': {},
                'rotation': {},
                'summary': {
                    'total_files': 0,
                    'total_size': 0,
                    'total_size_formatted': '0 B'
                },
                'alerts': []
            }
            
            # Get basic file info
            log_files = {
                '/var/log/fortigate.log': 'FortiGate Traffic',
                '/var/log/paloalto-1004.log': 'PaloAlto Traffic'
            }
            
            for filepath, description in log_files.items():
                if os.path.exists(filepath):
                    stat = os.stat(filepath)
                    size = stat.st_size
                    
                    status_data['files'][filepath] = {
                        'exists': True,
                        'size': size,
                        'size_formatted': format_bytes(size),
                        'description': description,
                        'last_modified': stat.st_mtime,
                        'last_modified_formatted': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                        'alert_level': 'warning' if size > 1.5 * 1024 * 1024 * 1024 else 'ok',
                        'percentage_of_limit': (size / (2 * 1024 * 1024 * 1024)) * 100
                    }
                    
                    status_data['processing_lag'][filepath] = {
                        'lag_bytes': 0,
                        'lag_formatted': '0 B',
                        'alert_level': 'unknown',
                        'last_processed_time_formatted': 'Unknown'
                    }
                else:
                    status_data['files'][filepath] = {
                        'exists': False,
                        'description': description,
                        'alert_level': 'error'
                    }
            
            # Update summary
            total_size = sum(f.get('size', 0) for f in status_data['files'].values())
            status_data['summary'].update({
                'total_files': len([f for f in status_data['files'].values() if f.get('exists')]),
                'total_size': total_size,
                'total_size_formatted': format_bytes(total_size)
            })
        
        # Add service status information
        service_status = {}
        services = [
            'log-manager.service',
            'fortigate_to_clickhouse.service', 
            'paloalto_to_clickhouse.service',
            'paloalto-url-loader.service'
        ]
        
        for service_name in services:
            try:
                result = subprocess.run(
                    ['systemctl', 'is-active', service_name],
                    capture_output=True, text=True, timeout=5
                )
                is_active = result.stdout.strip() == 'active'
                
                # Get detailed status
                status_result = subprocess.run(
                    ['systemctl', 'status', service_name],
                    capture_output=True, text=True, timeout=5
                )
                
                # Parse memory usage and PID
                main_pid = None
                memory_usage = None
                for line in status_result.stdout.split('\n'):
                    if 'Main PID:' in line:
                        main_pid = line.split('Main PID:')[1].strip().split(' ')[0]
                    elif 'Memory:' in line:
                        memory_usage = line.split('Memory:')[1].strip().split(' ')[0]
                
                service_status[service_name] = {
                    'active': is_active,
                    'status': result.stdout.strip(),
                    'main_pid': main_pid,
                    'memory_usage': memory_usage
                }
                
            except Exception as e:
                service_status[service_name] = {
                    'active': False,
                    'status': 'error',
                    'error': str(e)
                }
        
        status_data['services'] = service_status
        
        return render(request, 'dashboard/log_management.html', {
            'status': status_data,
            'refresh_interval': 30  # Auto-refresh every 30 seconds
        })
        
    except Exception as e:
        logging.error(f"Error loading log management status: {e}")
        return render(request, 'dashboard/log_management.html', {
            'status': {
                'error': str(e),
                'overall_status': 'error'
            },
            'refresh_interval': 30
        })


def clickhouse_storage_view(request):
    """Get ClickHouse storage usage information"""
    import json
    import os
    import subprocess
    from django.http import JsonResponse
    from clickhouse_driver import Client
    
    try:
        # Connect to ClickHouse
        client = Client(
            host='localhost',
            port=9000,
            user='default',
            password='Read@123'
        )
        
        # Get database sizes
        db_sizes_query = """
        SELECT 
            database,
            formatReadableSize(sum(bytes_on_disk)) AS size,
            sum(bytes_on_disk) AS bytes,
            count() AS tables,
            formatReadableSize(sum(data_compressed_bytes)) AS compressed_size,
            sum(data_compressed_bytes) AS compressed_bytes,
            formatReadableSize(sum(data_uncompressed_bytes)) AS uncompressed_size,
            sum(data_uncompressed_bytes) AS uncompressed_bytes
        FROM system.parts
        WHERE active
        GROUP BY database
        ORDER BY sum(bytes_on_disk) DESC
        """
        
        db_sizes = client.execute(db_sizes_query)
        
        # Get table sizes for network_logs database
        table_sizes_query = """
        SELECT 
            table,
            formatReadableSize(sum(bytes_on_disk)) AS size,
            sum(bytes_on_disk) AS bytes,
            formatReadableSize(sum(data_compressed_bytes)) AS compressed_size,
            sum(data_compressed_bytes) AS compressed_bytes,
            formatReadableSize(sum(data_uncompressed_bytes)) AS uncompressed_size,
            sum(data_uncompressed_bytes) AS uncompressed_bytes,
            sum(rows) AS row_count,
            count() AS parts
        FROM system.parts
        WHERE active AND database = 'network_logs'
        GROUP BY table
        ORDER BY sum(bytes_on_disk) DESC
        """
        
        table_sizes = client.execute(table_sizes_query)
        
        # Get data path from ClickHouse
        data_path_query = "SELECT path FROM system.disks WHERE name = 'default'"
        try:
            data_path_result = client.execute(data_path_query)
            data_path = data_path_result[0][0] if data_path_result else '/var/lib/clickhouse/'
        except:
            data_path = '/var/lib/clickhouse/'
        
        # Get actual filesystem information
        def get_filesystem_info(path):
            """Get filesystem space information for the given path"""
            import shutil
            try:
                total, used, free = shutil.disk_usage(path)
                return {
                    'total_bytes': total,
                    'used_bytes': used,
                    'free_bytes': free,
                    'total_formatted': format_bytes(total),
                    'used_formatted': format_bytes(used),
                    'free_formatted': format_bytes(free),
                    'used_percentage': round((used / total) * 100, 1)
                }
            except Exception as e:
                logging.warning(f"Failed to get filesystem info for {path}: {e}")
                return None
        
        filesystem_info = get_filesystem_info(data_path)
        
        # Get actual disk usage using Python os.walk
        def get_directory_size(path):
            total_size = 0
            try:
                for dirpath, dirnames, filenames in os.walk(path):
                    for filename in filenames:
                        try:
                            filepath = os.path.join(dirpath, filename)
                            if os.path.exists(filepath):
                                total_size += os.path.getsize(filepath)
                        except (OSError, IOError):
                            continue
            except (OSError, IOError, PermissionError):
                return None
            return total_size
        
        # Try to read disk usage from monitoring file
        def read_disk_usage_from_file():
            try:
                with open('/home/net/analyzer/config/clickhouse_disk_usage.json', 'r') as f:
                    data = json.load(f)
                    if data.get('status') == 'success' and data.get('usage_bytes'):
                        return data['usage_bytes']
            except:
                pass
            return None
        
        actual_usage_bytes = read_disk_usage_from_file()
        
        # If file method failed, try the directory size method as fallback
        if actual_usage_bytes is None:
            actual_usage_bytes = get_directory_size(data_path)
        
        # Skip disk space information for now due to ClickHouse type issues
        disk_info = []
        
        # Get allocated space from configuration with filesystem validation
        CONFIG_FILE = '/home/net/analyzer/config/clickhouse_storage.json'
        
        # Calculate reasonable default based on filesystem
        if filesystem_info:
            # Suggest 70% of available space as reasonable allocation
            suggested_allocation_gb = round((filesystem_info['free_bytes'] * 0.7) / (1024**3))
            max_possible_gb = round(filesystem_info['free_bytes'] / (1024**3))
        else:
            suggested_allocation_gb = 20  # Conservative fallback
            max_possible_gb = 50
        
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    allocated_space_gb = config.get('allocated_space_gb', suggested_allocation_gb)
                    warning_threshold = config.get('warning_threshold_percentage', 80)
                    critical_threshold = config.get('critical_threshold_percentage', 90)
            else:
                allocated_space_gb = suggested_allocation_gb
                warning_threshold = 80
                critical_threshold = 90
        except:
            allocated_space_gb = suggested_allocation_gb
            warning_threshold = 80
            critical_threshold = 90
        
        allocated_space_bytes = allocated_space_gb * 1024 * 1024 * 1024
        
        # Calculate total usage from ClickHouse parts
        clickhouse_reported_bytes = sum(row[2] for row in db_sizes)
        
        # Use actual disk usage if available, otherwise fall back to ClickHouse reported
        if actual_usage_bytes is not None and actual_usage_bytes > 0:
            total_usage_bytes = actual_usage_bytes
            usage_source = "filesystem"
        else:
            total_usage_bytes = clickhouse_reported_bytes
            usage_source = "clickhouse"
        
        usage_percentage = round((total_usage_bytes / allocated_space_bytes) * 100, 2)
        
        response_data = {
            'success': True,
            'databases': [
                {
                    'name': row[0],
                    'size': row[1],
                    'bytes': row[2],
                    'tables': row[3],
                    'compressed_size': row[4],
                    'compressed_bytes': row[5],
                    'uncompressed_size': row[6],
                    'uncompressed_bytes': row[7]
                } for row in db_sizes
            ],
            'tables': [
                {
                    'name': row[0],
                    'size': row[1],
                    'bytes': row[2],
                    'compressed_size': row[3],
                    'compressed_bytes': row[4],
                    'uncompressed_size': row[5],
                    'uncompressed_bytes': row[6],
                    'rows': row[7],
                    'parts': row[8]
                } for row in table_sizes
            ],
            'disks': [
                {
                    'name': row[0],
                    'path': row[1],
                    'free_space': row[2],
                    'free_bytes': row[3],
                    'total_space': row[4],
                    'total_bytes': row[5],
                    'used_space': row[6],
                    'used_bytes': row[7],
                    'used_percentage': row[8]
                } for row in disk_info
            ],
            'summary': {
                'total_usage': format_bytes(total_usage_bytes),
                'total_usage_bytes': total_usage_bytes,
                'clickhouse_reported': format_bytes(clickhouse_reported_bytes),
                'clickhouse_reported_bytes': clickhouse_reported_bytes,
                'actual_disk_usage': format_bytes(actual_usage_bytes) if actual_usage_bytes else 'N/A',
                'actual_disk_usage_bytes': actual_usage_bytes,
                'usage_source': usage_source,
                'allocated_space': format_bytes(allocated_space_bytes),
                'allocated_space_bytes': allocated_space_bytes,
                'usage_percentage': usage_percentage,
                'remaining_space': format_bytes(allocated_space_bytes - total_usage_bytes),
                'remaining_bytes': allocated_space_bytes - total_usage_bytes,
                'warning_threshold': warning_threshold,
                'critical_threshold': critical_threshold,
                'storage_path': data_path,
                'status': 'critical' if usage_percentage >= critical_threshold else 'warning' if usage_percentage >= warning_threshold else 'ok',
                'suggested_allocation_gb': suggested_allocation_gb,
                'max_possible_gb': max_possible_gb
            },
            'filesystem': filesystem_info
        }
        
        return JsonResponse(response_data)
        
    except Exception as e:
        logging.error(f"Error getting ClickHouse storage info: {e}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@csrf_exempt
def storage_allocation_view(request):
    """Get or update ClickHouse storage allocation settings"""
    import json
    import os
    from django.http import JsonResponse
    from datetime import datetime
    
    CONFIG_FILE = '/home/net/analyzer/config/clickhouse_storage.json'
    
    # Ensure config directory exists
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    
    # Load current settings
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                settings = json.load(f)
        except:
            settings = {
                "allocated_space_gb": 100,
                "storage_path": "/var/lib/clickhouse",
                "warning_threshold_percentage": 80,
                "critical_threshold_percentage": 90,
                "data_retention_days": 90,
                "enable_auto_cleanup": True
            }
    else:
        settings = {
            "allocated_space_gb": 100,
            "storage_path": "/var/lib/clickhouse",
            "warning_threshold_percentage": 80,
            "critical_threshold_percentage": 90,
            "data_retention_days": 90,
            "enable_auto_cleanup": True
        }
    
    if request.method == 'POST':
        try:
            # Parse request data
            data = json.loads(request.body)
            
            # Get filesystem info for validation
            import shutil
            try:
                total, used, free = shutil.disk_usage('/var/lib/clickhouse/')
                max_available_gb = round(free / (1024**3))
                recommended_max_gb = round((free * 0.8) / (1024**3))  # 80% of free space
            except:
                max_available_gb = 50  # Fallback
                recommended_max_gb = 40
            
            # Update settings
            if 'allocated_space_gb' in data:
                allocated_gb = int(data['allocated_space_gb'])
                if allocated_gb < 5:
                    return JsonResponse({
                        'success': False,
                        'error': 'Allocated space must be at least 5 GB'
                    }, status=400)
                if allocated_gb > max_available_gb:
                    return JsonResponse({
                        'success': False,
                        'error': f'Allocated space cannot exceed available filesystem space ({max_available_gb} GB available)'
                    }, status=400)
                if allocated_gb > recommended_max_gb:
                    # Warning but allow it
                    logging.warning(f"Allocation {allocated_gb}GB exceeds recommended maximum {recommended_max_gb}GB")
                
                settings['allocated_space_gb'] = allocated_gb
            
            if 'storage_path' in data:
                settings['storage_path'] = data['storage_path']
            
            if 'warning_threshold_percentage' in data:
                warning_threshold = int(data['warning_threshold_percentage'])
                if not 50 <= warning_threshold <= 95:
                    return JsonResponse({
                        'success': False,
                        'error': 'Warning threshold must be between 50% and 95%'
                    }, status=400)
                settings['warning_threshold_percentage'] = warning_threshold
            
            if 'critical_threshold_percentage' in data:
                critical_threshold = int(data['critical_threshold_percentage'])
                if not 60 <= critical_threshold <= 99:
                    return JsonResponse({
                        'success': False,
                        'error': 'Critical threshold must be between 60% and 99%'
                    }, status=400)
                settings['critical_threshold_percentage'] = critical_threshold
            
            if 'data_retention_days' in data:
                retention_days = int(data['data_retention_days'])
                if not 30 <= retention_days <= 365:
                    return JsonResponse({
                        'success': False,
                        'error': 'Data retention must be between 30 and 365 days'
                    }, status=400)
                settings['data_retention_days'] = retention_days
            
            if 'enable_auto_cleanup' in data:
                settings['enable_auto_cleanup'] = bool(data['enable_auto_cleanup'])
            
            # Add metadata
            settings['last_updated'] = datetime.now().isoformat()
            settings['updated_by'] = request.user.username if request.user.is_authenticated else 'anonymous'
            
            # Save settings
            with open(CONFIG_FILE, 'w') as f:
                json.dump(settings, f, indent=4)
            
            return JsonResponse({
                'success': True,
                'message': 'Storage allocation settings updated successfully',
                'settings': settings
            })
            
        except Exception as e:
            logging.error(f"Error updating storage allocation: {e}")
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=500)
    
    else:  # GET request
        # Get actual ClickHouse data path and filesystem info
        try:
            from clickhouse_driver import Client
            client = Client(
                host='localhost',
                port=9000,
                user='default',
                password='Read@123'
            )
            
            data_path_result = client.execute("SELECT path FROM system.disks WHERE name = 'default'")
            if data_path_result:
                settings['actual_storage_path'] = data_path_result[0][0]
        except:
            settings['actual_storage_path'] = settings.get('storage_path', '/var/lib/clickhouse')
        
        # Add filesystem information
        import shutil
        try:
            total, used, free = shutil.disk_usage(settings['actual_storage_path'])
            settings['filesystem'] = {
                'total_space': f"{total / (1024**3):.1f} GB",
                'used_space': f"{used / (1024**3):.1f} GB", 
                'free_space': f"{free / (1024**3):.1f} GB",
                'used_percentage': round((used / total) * 100, 1),
                'max_allocation_gb': round(free / (1024**3)),
                'recommended_max_gb': round((free * 0.8) / (1024**3))
            }
        except:
            settings['filesystem'] = None
        
        return JsonResponse({
            'success': True,
            'settings': settings
        })


@require_http_methods(["POST"])
def service_control_view(request):
    """Handle service control actions (start, stop, restart)"""
    import json
    import subprocess
    from django.http import JsonResponse
    from django.views.decorators.csrf import csrf_exempt
    
    try:
        # Parse JSON request body
        data = json.loads(request.body)
        service_name = data.get('service')
        action = data.get('action')
        
        # Validate inputs
        allowed_services = [
            'log-manager.service',
            'fortigate_to_clickhouse.service', 
            'paloalto_to_clickhouse.service',
            'paloalto-url-loader.service'
        ]
        
        allowed_actions = ['start', 'stop', 'restart']
        
        if service_name not in allowed_services:
            return JsonResponse({
                'success': False,
                'message': f'Service "{service_name}" is not allowed to be controlled'
            }, status=400)
            
        if action not in allowed_actions:
            return JsonResponse({
                'success': False,
                'message': f'Action "{action}" is not allowed'
            }, status=400)
        
        # Execute systemctl command with sudo
        try:
            cmd = ['sudo', '-S', 'systemctl', action, service_name]
            result = subprocess.run(
                cmd,
                input='Read@123\n',
                text=True,
                capture_output=True,
                timeout=30
            )
            
            if result.returncode == 0:
                return JsonResponse({
                    'success': True,
                    'message': f'Successfully {action}ed {service_name}'
                })
            else:
                error_msg = result.stderr.strip() if result.stderr else 'Unknown error'
                return JsonResponse({
                    'success': False,
                    'message': f'Failed to {action} {service_name}: {error_msg}'
                }, status=500)
                
        except subprocess.TimeoutExpired:
            return JsonResponse({
                'success': False,
                'message': f'Timeout while trying to {action} {service_name}'
            }, status=500)
        except Exception as e:
            return JsonResponse({
                'success': False,
                'message': f'Error executing {action} on {service_name}: {str(e)}'
            }, status=500)
            
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'message': 'Invalid JSON in request body'
        }, status=400)
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': f'Unexpected error: {str(e)}'
        }, status=500)