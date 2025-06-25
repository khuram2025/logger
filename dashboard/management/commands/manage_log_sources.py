#!/usr/bin/env python3
"""
Django management command for log source operations
"""

from django.core.management.base import BaseCommand
from django.utils import timezone
from dashboard.models import LogSource, LogSourceEvent
import sys
import os

# Add scripts directory to path
sys.path.append('/home/net/analyzer/scripts')

class Command(BaseCommand):
    help = 'Manage log sources: scan, approve, configure, etc.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--scan',
            action='store_true',
            help='Scan for new log sources'
        )
        parser.add_argument(
            '--scan-type',
            type=str,
            default='quick',
            choices=['quick', 'active', 'discover'],
            help='Type of scan to perform'
        )
        parser.add_argument(
            '--approve',
            type=int,
            help='Approve log source by ID'
        )
        parser.add_argument(
            '--approve-all',
            action='store_true',
            help='Approve all pending log sources'
        )
        parser.add_argument(
            '--reject',
            type=int,
            help='Reject log source by ID'
        )
        parser.add_argument(
            '--configure',
            type=int,
            help='Generate rsyslog config for log source by ID'
        )
        parser.add_argument(
            '--configure-all',
            action='store_true',
            help='Generate rsyslog configs for all approved sources'
        )
        parser.add_argument(
            '--list',
            action='store_true',
            help='List all log sources'
        )
        parser.add_argument(
            '--status',
            type=str,
            help='Filter by status (pending, approved, active, etc.)'
        )
        parser.add_argument(
            '--auto-approve',
            action='store_true',
            help='Auto-approve known device types (fortigate, paloalto)'
        )
        
    def handle(self, *args, **options):
        if options['scan']:
            self.scan_sources(options['scan_type'])
        elif options['approve']:
            self.approve_source(options['approve'])
        elif options['approve_all']:
            self.approve_all_sources()
        elif options['reject']:
            self.reject_source(options['reject'])
        elif options['configure']:
            self.configure_source(options['configure'])
        elif options['configure_all']:
            self.configure_all_sources()
        elif options['list']:
            self.list_sources(options.get('status'))
        elif options['auto_approve']:
            self.auto_approve_sources()
        else:
            self.stdout.write(self.style.WARNING('No action specified. Use --help for options.'))
            
    def scan_sources(self, scan_type):
        """Scan for new log sources"""
        try:
            from network_scanner import NetworkScanner
            
            self.stdout.write(f"Starting {scan_type} scan...")
            scanner = NetworkScanner()
            
            if scan_type == 'active':
                results = scanner.active_scan()
            elif scan_type == 'discover':
                results = scanner.discover_from_logs(hours=24)
            else:
                results = scanner.quick_scan(duration=30)
            
            new_count = 0
            updated_count = 0
            
            for result in results:
                if not result['in_database']:
                    # Create new source
                    source, created = LogSource.objects.get_or_create(
                        ip_address=result['ip'],
                        defaults={
                            'name': result.get('hostname') or f"Device-{result['ip']}",
                            'hostname': result.get('hostname', ''),
                            'device_type': result.get('device_type', 'unknown'),
                            'status': 'pending'
                        }
                    )
                    if created:
                        new_count += 1
                        LogSourceEvent.objects.create(
                            log_source=source,
                            event_type='detected',
                            description=f'Detected via {scan_type} scan'
                        )
                        self.stdout.write(f"  📡 New: {result['ip']} ({result.get('device_type', 'unknown')})")
                else:
                    # Update existing
                    try:
                        source = LogSource.objects.get(ip_address=result['ip'])
                        source.last_seen = timezone.now()
                        source.save()
                        updated_count += 1
                        self.stdout.write(f"  🔄 Updated: {result['ip']}")
                    except LogSource.DoesNotExist:
                        pass
            
            self.stdout.write(self.style.SUCCESS(
                f'Scan complete: {new_count} new sources, {updated_count} updated'
            ))
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Scan failed: {str(e)}'))
            
    def approve_source(self, source_id):
        """Approve a specific log source"""
        try:
            source = LogSource.objects.get(id=source_id)
            source.approve('admin')
            self.stdout.write(self.style.SUCCESS(f'✅ Approved: {source.name} ({source.ip_address})'))
            
            # Generate configuration
            self.configure_source(source_id)
            
        except LogSource.DoesNotExist:
            self.stdout.write(self.style.ERROR(f'❌ Log source {source_id} not found'))
            
    def approve_all_sources(self):
        """Approve all pending sources"""
        pending_sources = LogSource.objects.filter(status='pending')
        
        if not pending_sources.exists():
            self.stdout.write('No pending sources to approve')
            return
            
        for source in pending_sources:
            source.approve('admin')
            self.stdout.write(f'✅ Approved: {source.name} ({source.ip_address})')
            
        self.stdout.write(self.style.SUCCESS(f'Approved {pending_sources.count()} sources'))
        
    def auto_approve_sources(self):
        """Auto-approve known device types"""
        known_types = ['fortigate', 'paloalto', 'cisco', 'checkpoint']
        
        pending_sources = LogSource.objects.filter(
            status='pending',
            device_type__in=known_types
        )
        
        if not pending_sources.exists():
            self.stdout.write('No known device types pending approval')
            return
            
        for source in pending_sources:
            source.approve('auto-admin')
            self.stdout.write(f'✅ Auto-approved: {source.name} ({source.get_device_type_display()})')
            
            # Auto-configure known types
            self.configure_source(source.id, quiet=True)
            
        self.stdout.write(self.style.SUCCESS(f'Auto-approved {pending_sources.count()} sources'))
        
    def reject_source(self, source_id):
        """Reject a log source"""
        try:
            source = LogSource.objects.get(id=source_id)
            source.reject('Rejected via management command')
            self.stdout.write(self.style.WARNING(f'❌ Rejected: {source.name} ({source.ip_address})'))
        except LogSource.DoesNotExist:
            self.stdout.write(self.style.ERROR(f'Log source {source_id} not found'))
            
    def configure_source(self, source_id, quiet=False):
        """Generate rsyslog configuration for a source"""
        try:
            from rsyslog_config_manager import RsyslogConfigManager
            
            source = LogSource.objects.get(id=source_id)
            manager = RsyslogConfigManager()
            
            success, message = manager.create_config(source)
            
            if success:
                if not quiet:
                    self.stdout.write(self.style.SUCCESS(f'🔧 {message}'))
            else:
                self.stdout.write(self.style.ERROR(f'❌ Configuration failed: {message}'))
                
        except LogSource.DoesNotExist:
            self.stdout.write(self.style.ERROR(f'Log source {source_id} not found'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Configuration error: {str(e)}'))
            
    def configure_all_sources(self):
        """Generate configurations for all approved sources"""
        try:
            from rsyslog_config_manager import RsyslogConfigManager
            
            manager = RsyslogConfigManager()
            results = manager.update_all_configs()
            
            success_count = sum(1 for r in results if r['success'])
            total_count = len(results)
            
            for result in results:
                status = '✅' if result['success'] else '❌'
                self.stdout.write(f"{status} {result['source']}: {result['message']}")
                
            self.stdout.write(self.style.SUCCESS(
                f'Configuration complete: {success_count}/{total_count} successful'
            ))
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Configuration error: {str(e)}'))
            
    def list_sources(self, status_filter=None):
        """List all log sources"""
        sources = LogSource.objects.all()
        
        if status_filter:
            sources = sources.filter(status=status_filter)
            
        if not sources.exists():
            self.stdout.write('No log sources found')
            return
            
        self.stdout.write(f'Found {sources.count()} log sources:')
        self.stdout.write('')
        
        for source in sources:
            status_icon = {
                'pending': '⏳',
                'approved': '✅',
                'active': '🟢',
                'inactive': '🔴',
                'rejected': '❌',
                'error': '⚠️'
            }.get(source.status, '❓')
            
            type_icon = {
                'fortigate': '🛡️',
                'paloalto': '🔥',
                'cisco': '🌐',
                'checkpoint': '🔒',
                'unknown': '❓'
            }.get(source.device_type, '📡')
            
            self.stdout.write(
                f'{status_icon} {type_icon} {source.name} ({source.ip_address}) '
                f'- {source.get_status_display()} - {source.get_device_type_display()}'
            )
            
            if source.hostname:
                self.stdout.write(f'    Hostname: {source.hostname}')
            if source.last_seen:
                self.stdout.write(f'    Last seen: {source.last_seen}')
            self.stdout.write('')