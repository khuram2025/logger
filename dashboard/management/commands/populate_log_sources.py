from django.core.management.base import BaseCommand
from dashboard.models import LogSource, LogSourceEvent
from datetime import datetime, timedelta

class Command(BaseCommand):
    help = 'Populate database with initial log sources based on current configuration'
    
    def handle(self, *args, **options):
        # Create existing log sources
        sources_data = [
            {
                'name': 'FortiGate Firewall',
                'description': 'Primary FortiGate firewall appliance',
                'ip_address': '192.168.100.221',
                'hostname': 'FG-MAIN',
                'device_type': 'fortigate',
                'device_model': 'FortiGate 100F',
                'port': 514,
                'status': 'active',
                'save_logs': True,
                'logs_today': 15420,
                'logs_last_hour': 892,
                'total_logs': 2456781,
                'log_file_path': '/var/log/fortigate.log',
                'log_template': 'fortigate_default',
                'parse_to_database': True
            },
            {
                'name': 'PaloAlto Firewall',
                'description': 'Secondary PaloAlto firewall appliance',
                'ip_address': '10.12.50.61',
                'hostname': 'PA-1004',
                'device_type': 'paloalto',
                'device_model': 'PA-1004',
                'port': 1004,
                'status': 'active',
                'save_logs': True,
                'logs_today': 8756,
                'logs_last_hour': 432,
                'total_logs': 1234567,
                'log_file_path': '/var/log/paloalto-1004.log',
                'log_template': 'paloalto_default',
                'parse_to_database': True
            },
            {
                'name': 'Unknown Device',
                'description': 'Unidentified device sending logs',
                'ip_address': '192.168.1.100',
                'hostname': '',
                'device_type': 'unknown',
                'device_model': '',
                'port': 514,
                'status': 'pending',
                'save_logs': False,
                'logs_today': 245,
                'logs_last_hour': 12,
                'total_logs': 5642,
                'log_file_path': '',
                'log_template': 'raw',
                'parse_to_database': False
            },
            {
                'name': 'Test Firewall',
                'description': 'Test environment firewall',
                'ip_address': '10.10.10.50',
                'hostname': 'TEST-FW',
                'device_type': 'fortigate',
                'device_model': 'FortiGate VM',
                'port': 514,
                'status': 'inactive',
                'save_logs': False,
                'logs_today': 0,
                'logs_last_hour': 0,
                'total_logs': 123456,
                'log_file_path': '/var/log/test-firewall.log',
                'log_template': 'fortigate_default',
                'parse_to_database': False
            },
            {
                'name': 'Cisco ASA',
                'description': 'Cisco ASA firewall requiring approval',
                'ip_address': '172.16.1.10',
                'hostname': 'ASA-MAIN',
                'device_type': 'cisco',
                'device_model': 'ASA 5515-X',
                'port': 514,
                'status': 'pending',
                'save_logs': False,
                'logs_today': 892,
                'logs_last_hour': 45,
                'total_logs': 15632,
                'log_file_path': '',
                'log_template': 'timestamp',
                'parse_to_database': False
            }
        ]
        
        created_count = 0
        updated_count = 0
        
        for source_data in sources_data:
            source, created = LogSource.objects.get_or_create(
                ip_address=source_data['ip_address'],
                defaults=source_data
            )
            
            if created:
                created_count += 1
                self.stdout.write(f"Created: {source.name} ({source.ip_address})")
                
                # Create initial event
                LogSourceEvent.objects.create(
                    log_source=source,
                    event_type='detected',
                    description=f"Log source imported from existing configuration",
                    user='system',
                    metadata={'import_type': 'initial_population'}
                )
                
                # For approved sources, add approval event
                if source.status in ['active', 'approved']:
                    source.approved_by = 'system'
                    source.approved_at = datetime.now()
                    source.save()
                    
                    LogSourceEvent.objects.create(
                        log_source=source,
                        event_type='approved',
                        description=f"Log source approved during initial setup",
                        user='system',
                        metadata={'import_type': 'initial_population'}
                    )
            else:
                # Update existing source with new data
                for key, value in source_data.items():
                    if key != 'ip_address':  # Don't update the key field
                        setattr(source, key, value)
                source.save()
                updated_count += 1
                self.stdout.write(f"Updated: {source.name} ({source.ip_address})")
        
        self.stdout.write(
            self.style.SUCCESS(
                f'Successfully populated log sources: {created_count} created, {updated_count} updated'
            )
        )