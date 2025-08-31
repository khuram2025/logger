"""
Initialize Authentication System

Management command to set up the authentication system with default roles,
create a superuser account, and perform initial system configuration.
"""

from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.db import transaction
import getpass
import sys

from dashboard.models.auth import Role, AuditLog

User = get_user_model()


class Command(BaseCommand):
    help = 'Initialize the authentication system with default roles and superuser'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--skip-superuser',
            action='store_true',
            help='Skip superuser creation',
        )
        
        parser.add_argument(
            '--superuser-username',
            type=str,
            help='Username for superuser (non-interactive)',
        )
        
        parser.add_argument(
            '--superuser-password',
            type=str,
            help='Password for superuser (non-interactive)',
        )
        
        parser.add_argument(
            '--superuser-email',
            type=str,
            help='Email for superuser (non-interactive)',
        )
        
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force recreation of existing roles',
        )
    
    def handle(self, *args, **options):
        """
        Main command handler
        """
        self.stdout.write(
            self.style.SUCCESS('Initializing Network Analyzer Authentication System...\n')
        )
        
        try:
            with transaction.atomic():
                # Create default roles
                self.create_default_roles(force=options.get('force', False))
                
                # Create superuser if requested
                if not options.get('skip_superuser'):
                    self.create_superuser(
                        username=options.get('superuser_username'),
                        password=options.get('superuser_password'),
                        email=options.get('superuser_email')
                    )
                
                # Create directories for logs if needed
                self.setup_logging()
                
                self.stdout.write(
                    self.style.SUCCESS('\n✓ Authentication system initialized successfully!')
                )
                
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error initializing authentication system: {e}')
            )
            raise CommandError(f'Initialization failed: {e}')
    
    def create_default_roles(self, force=False):
        """
        Create default roles for the system
        """
        self.stdout.write('Setting up default roles...')
        
        # Check if roles already exist
        existing_roles = Role.objects.count()
        if existing_roles > 0 and not force:
            self.stdout.write(
                self.style.WARNING(
                    f'  Found {existing_roles} existing roles. Use --force to recreate.'
                )
            )
            return
        
        # Define default roles
        default_roles = [
            {
                'name': 'Viewer',
                'level': 'viewer',
                'description': 'Can view logs and basic analytics only',
                'permissions': {
                    'can_view_logs': True,
                    'can_view_analytics': True,
                    'can_export_logs': False,
                    'can_manage_devices': False,
                    'can_configure_sources': False,
                    'can_manage_users': False,
                    'can_view_audit': False,
                    'can_system_config': False,
                }
            },
            {
                'name': 'Analyst',
                'level': 'analyst',
                'description': 'Can view, analyze and export log data',
                'permissions': {
                    'can_view_logs': True,
                    'can_view_analytics': True,
                    'can_export_logs': True,
                    'can_manage_devices': False,
                    'can_configure_sources': False,
                    'can_manage_users': False,
                    'can_view_audit': False,
                    'can_system_config': False,
                }
            },
            {
                'name': 'Administrator',
                'level': 'admin',
                'description': 'Full system administration capabilities',
                'permissions': {
                    'can_view_logs': True,
                    'can_view_analytics': True,
                    'can_export_logs': True,
                    'can_manage_devices': True,
                    'can_configure_sources': True,
                    'can_manage_users': True,
                    'can_view_audit': True,
                    'can_system_config': True,
                }
            },
            {
                'name': 'Super Administrator',
                'level': 'superuser',
                'description': 'Ultimate system access with all permissions',
                'permissions': {
                    'can_view_logs': True,
                    'can_view_analytics': True,
                    'can_export_logs': True,
                    'can_manage_devices': True,
                    'can_configure_sources': True,
                    'can_manage_users': True,
                    'can_view_audit': True,
                    'can_system_config': True,
                }
            }
        ]
        
        # Create or update roles
        created_count = 0
        updated_count = 0
        
        for role_data in default_roles:
            permissions = role_data.pop('permissions')
            
            role, created = Role.objects.update_or_create(
                name=role_data['name'],
                defaults=role_data
            )
            
            # Set permissions
            for perm_name, perm_value in permissions.items():
                setattr(role, perm_name, perm_value)
            role.save()
            
            if created:
                created_count += 1
                self.stdout.write(f'  ✓ Created role: {role.name}')
            else:
                updated_count += 1
                self.stdout.write(f'  ✓ Updated role: {role.name}')
        
        self.stdout.write(
            self.style.SUCCESS(
                f'  Roles setup complete: {created_count} created, {updated_count} updated\n'
            )
        )
    
    def create_superuser(self, username=None, password=None, email=None):
        """
        Create superuser account
        """
        self.stdout.write('Setting up superuser account...')
        
        # Check if superuser already exists
        if User.objects.filter(is_superuser=True).exists():
            self.stdout.write(
                self.style.WARNING('  Superuser already exists. Skipping creation.\n')
            )
            return
        
        # Get superuser details
        if not username:
            username = input('Superuser username: ')
        
        if not email:
            email = input('Superuser email: ')
        
        if not password:
            password = getpass.getpass('Superuser password: ')
            password_confirm = getpass.getpass('Confirm password: ')
            
            if password != password_confirm:
                raise CommandError('Passwords do not match')
        
        # Validate inputs
        if not username or not password:
            raise CommandError('Username and password are required')
        
        if User.objects.filter(username=username).exists():
            raise CommandError(f'User {username} already exists')
        
        # Get Super Administrator role
        try:
            super_admin_role = Role.objects.get(level='superuser')
        except Role.DoesNotExist:
            self.stdout.write(
                self.style.WARNING('  Super Administrator role not found. Creating user without role.')
            )
            super_admin_role = None
        
        # Create superuser
        user = User.objects.create_superuser(
            username=username,
            email=email,
            password=password,
            full_name='System Administrator',
            role=super_admin_role
        )
        
        # Log the creation
        AuditLog.log_action(
            user=None,
            action_type='user_mgmt',
            action=f'Superuser account created: {username}',
            result='success',
            ip_address='127.0.0.1',
            user_agent='Management Command',
            details={
                'created_user_id': str(user.id),
                'created_via': 'init_auth_command'
            }
        )
        
        self.stdout.write(
            self.style.SUCCESS(f'  ✓ Superuser {username} created successfully\n')
        )
    
    def setup_logging(self):
        """
        Create logging directories if they don't exist
        """
        self.stdout.write('Setting up logging...')
        
        import os
        from django.conf import settings
        
        log_dir = settings.BASE_DIR / 'logs'
        if not log_dir.exists():
            log_dir.mkdir(parents=True, exist_ok=True)
            self.stdout.write('  ✓ Created logs directory')
        
        # Create log files if they don't exist
        log_files = ['django.log', 'security.log']
        for log_file in log_files:
            log_path = log_dir / log_file
            if not log_path.exists():
                log_path.touch()
                self.stdout.write(f'  ✓ Created {log_file}')
        
        self.stdout.write(self.style.SUCCESS('  Logging setup complete\n'))
    
    def show_summary(self):
        """
        Show summary of the authentication system
        """
        self.stdout.write(self.style.SUCCESS('Authentication System Summary:'))
        self.stdout.write('-' * 50)
        
        # Roles
        roles = Role.objects.all().order_by('level')
        self.stdout.write(f'Roles: {roles.count()}')
        for role in roles:
            self.stdout.write(f'  - {role.name} ({role.get_level_display()})')
        
        # Users
        users = User.objects.all()
        self.stdout.write(f'\nUsers: {users.count()}')
        self.stdout.write(f'  - Superusers: {users.filter(is_superuser=True).count()}')
        self.stdout.write(f'  - Active users: {users.filter(is_active=True).count()}')
        
        # Recent audit logs
        recent_logs = AuditLog.objects.count()
        self.stdout.write(f'\nAudit logs: {recent_logs}')
        
        self.stdout.write('\n' + '=' * 50)
        self.stdout.write(self.style.SUCCESS('System ready for use!'))
        self.stdout.write('Next steps:')
        self.stdout.write('1. Start the Django server: python manage.py runserver')
        self.stdout.write('2. Visit /auth/login/ to log in')
        self.stdout.write('3. Create additional users via /auth/users/ (admin only)')
        self.stdout.write('4. Configure IP restrictions if needed')
        self.stdout.write('5. Review audit logs at /auth/audit/')