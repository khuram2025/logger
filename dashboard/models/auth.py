"""
Authentication and Authorization Models

This module defines the core authentication and authorization models for the 
network analyzer platform, implementing role-based access control (RBAC),
session management, and comprehensive audit logging.
"""

import uuid
from django.contrib.auth.models import AbstractUser, Permission
from django.contrib.contenttypes.models import ContentType
from django.db import models
from django.utils import timezone
from django.core.validators import MinLengthValidator
from django.contrib.auth.hashers import make_password
from django.conf import settings
from datetime import timedelta
import json


class Role(models.Model):
    """
    Role model for RBAC system with hierarchical permissions
    """
    ROLE_LEVELS = [
        ('viewer', 'Viewer'),
        ('analyst', 'Analyst'), 
        ('admin', 'Administrator'),
        ('superuser', 'Super Administrator'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True, help_text="Role name")
    level = models.CharField(max_length=20, choices=ROLE_LEVELS, help_text="Role hierarchy level")
    description = models.TextField(blank=True, help_text="Role description")
    
    # Permission flags for fine-grained control
    can_view_logs = models.BooleanField(default=True, help_text="Can view firewall logs")
    can_export_logs = models.BooleanField(default=False, help_text="Can export log data")
    can_manage_devices = models.BooleanField(default=False, help_text="Can manage registered devices")
    can_configure_sources = models.BooleanField(default=False, help_text="Can configure log sources")
    can_view_analytics = models.BooleanField(default=True, help_text="Can view analytics dashboards")
    can_manage_users = models.BooleanField(default=False, help_text="Can manage user accounts")
    can_view_audit = models.BooleanField(default=False, help_text="Can view audit logs")
    can_system_config = models.BooleanField(default=False, help_text="Can modify system configuration")
    
    # Django permissions (many-to-many relationship)
    permissions = models.ManyToManyField(
        Permission,
        blank=True,
        help_text="Django permissions for this role"
    )
    
    is_active = models.BooleanField(default=True, help_text="Is this role active")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'auth_roles'
        ordering = ['level', 'name']
        verbose_name = 'Role'
        verbose_name_plural = 'Roles'
    
    def __str__(self):
        return f"{self.name} ({self.get_level_display()})"
    
    def get_permission_list(self):
        """Get list of custom permissions for this role"""
        permissions = []
        if self.can_view_logs:
            permissions.append('view_logs')
        if self.can_export_logs:
            permissions.append('export_logs')
        if self.can_manage_devices:
            permissions.append('manage_devices')
        if self.can_configure_sources:
            permissions.append('configure_sources')
        if self.can_view_analytics:
            permissions.append('view_analytics')
        if self.can_manage_users:
            permissions.append('manage_users')
        if self.can_view_audit:
            permissions.append('view_audit')
        if self.can_system_config:
            permissions.append('system_config')
        return permissions
    
    @classmethod
    def create_default_roles(cls):
        """Create default roles for the system"""
        default_roles = [
            {
                'name': 'Viewer',
                'level': 'viewer',
                'description': 'Can view logs and basic analytics only',
                'permissions': {
                    'can_view_logs': True,
                    'can_view_analytics': True,
                }
            },
            {
                'name': 'Analyst',
                'level': 'analyst',
                'description': 'Can view, analyze and export log data',
                'permissions': {
                    'can_view_logs': True,
                    'can_export_logs': True,
                    'can_view_analytics': True,
                }
            },
            {
                'name': 'Administrator',
                'level': 'admin',
                'description': 'Full system administration capabilities',
                'permissions': {
                    'can_view_logs': True,
                    'can_export_logs': True,
                    'can_manage_devices': True,
                    'can_configure_sources': True,
                    'can_view_analytics': True,
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
                    'can_export_logs': True,
                    'can_manage_devices': True,
                    'can_configure_sources': True,
                    'can_view_analytics': True,
                    'can_manage_users': True,
                    'can_view_audit': True,
                    'can_system_config': True,
                }
            }
        ]
        
        for role_data in default_roles:
            permissions = role_data.pop('permissions')
            role, created = cls.objects.get_or_create(
                name=role_data['name'],
                defaults=role_data
            )
            if created:
                for perm_name, perm_value in permissions.items():
                    setattr(role, perm_name, perm_value)
                role.save()


class User(AbstractUser):
    """
    Extended User model with UUID primary key and additional security features
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Override username to allow longer names
    username = models.CharField(
        max_length=150,
        unique=True,
        validators=[MinLengthValidator(3)],
        help_text="Username (3-150 characters)"
    )
    
    # Extended profile fields
    full_name = models.CharField(max_length=255, blank=True, help_text="Full display name")
    department = models.CharField(max_length=100, blank=True, help_text="Department or team")
    phone = models.CharField(max_length=20, blank=True, help_text="Phone number")
    
    # Role and permissions
    role = models.ForeignKey(
        Role,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='users',
        help_text="User's primary role"
    )
    
    # Security settings
    password_expires = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When password expires (null = never)"
    )
    require_password_change = models.BooleanField(
        default=False,
        help_text="Force password change on next login"
    )
    account_locked = models.BooleanField(
        default=False,
        help_text="Account locked due to security policy"
    )
    account_locked_until = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Account unlocked automatically after this time"
    )
    failed_login_attempts = models.PositiveIntegerField(
        default=0,
        help_text="Number of consecutive failed login attempts"
    )
    last_failed_login = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp of last failed login attempt"
    )
    
    # Session management
    max_concurrent_sessions = models.PositiveIntegerField(
        default=3,
        help_text="Maximum number of concurrent sessions allowed"
    )
    session_timeout_minutes = models.PositiveIntegerField(
        default=480,  # 8 hours
        help_text="Session timeout in minutes"
    )
    
    # IP restrictions
    allowed_ip_addresses = models.JSONField(
        default=list,
        blank=True,
        help_text="List of allowed IP addresses (empty = no restrictions)"
    )
    
    # Activity tracking
    last_password_change = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When password was last changed"
    )
    last_activity = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Last recorded activity"
    )
# created_by will be added in a separate migration to avoid circular reference
    # created_by = models.ForeignKey(
    #     'dashboard.User',
    #     on_delete=models.SET_NULL,
    #     null=True,
    #     blank=True,
    #     related_name='created_users',
    #     help_text="User who created this account"
    # )
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'auth_users'
        ordering = ['username']
        verbose_name = 'User'
        verbose_name_plural = 'Users'
    
    def __str__(self):
        return self.full_name or self.username
    
    def get_display_name(self):
        """Get the best display name for the user"""
        return self.full_name or self.username
    
    def is_account_locked(self):
        """Check if account is currently locked"""
        if not self.account_locked:
            return False
        
        # Check if temporary lock has expired
        if self.account_locked_until and timezone.now() > self.account_locked_until:
            self.unlock_account()
            return False
        
        return True
    
    def lock_account(self, duration_hours=None):
        """Lock the user account"""
        self.account_locked = True
        if duration_hours:
            self.account_locked_until = timezone.now() + timedelta(hours=duration_hours)
        self.save(update_fields=['account_locked', 'account_locked_until'])
    
    def unlock_account(self):
        """Unlock the user account"""
        self.account_locked = False
        self.account_locked_until = None
        self.failed_login_attempts = 0
        self.last_failed_login = None
        self.save(update_fields=[
            'account_locked', 
            'account_locked_until', 
            'failed_login_attempts', 
            'last_failed_login'
        ])
    
    def record_failed_login(self):
        """Record a failed login attempt"""
        self.failed_login_attempts += 1
        self.last_failed_login = timezone.now()
        
        # Auto-lock after 5 failed attempts
        if self.failed_login_attempts >= 5:
            self.lock_account(duration_hours=1)  # Lock for 1 hour
        
        self.save(update_fields=['failed_login_attempts', 'last_failed_login', 'account_locked', 'account_locked_until'])
    
    def record_successful_login(self):
        """Record a successful login"""
        self.failed_login_attempts = 0
        self.last_failed_login = None
        self.last_login = timezone.now()
        self.last_activity = timezone.now()
        self.save(update_fields=['failed_login_attempts', 'last_failed_login', 'last_login', 'last_activity'])
    
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = timezone.now()
        self.save(update_fields=['last_activity'])
    
    def has_permission(self, permission):
        """Check if user has a specific custom permission"""
        if not self.role:
            return False
        
        permission_map = {
            'view_logs': self.role.can_view_logs,
            'export_logs': self.role.can_export_logs,
            'manage_devices': self.role.can_manage_devices,
            'configure_sources': self.role.can_configure_sources,
            'view_analytics': self.role.can_view_analytics,
            'manage_users': self.role.can_manage_users,
            'view_audit': self.role.can_view_audit,
            'system_config': self.role.can_system_config,
        }
        
        return permission_map.get(permission, False) or self.is_superuser
    
    def get_active_sessions(self):
        """Get active sessions for this user"""
        return self.sessions.filter(
            is_active=True,
            expires_at__gt=timezone.now()
        )
    
    def can_create_session(self):
        """Check if user can create a new session"""
        active_sessions = self.get_active_sessions().count()
        return active_sessions < self.max_concurrent_sessions
    
    def is_ip_allowed(self, ip_address):
        """Check if IP address is allowed for this user"""
        if not self.allowed_ip_addresses:
            return True
        return ip_address in self.allowed_ip_addresses


class UserSession(models.Model):
    """
    Track user sessions for security and concurrency control
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='sessions')
    session_key = models.CharField(max_length=40, unique=True, help_text="Django session key")
    
    # Session information
    ip_address = models.GenericIPAddressField(help_text="Client IP address")
    user_agent = models.TextField(help_text="Client user agent string")
    
    # Timing
    created_at = models.DateTimeField(auto_now_add=True, help_text="Session start time")
    last_activity = models.DateTimeField(auto_now=True, help_text="Last activity time")
    expires_at = models.DateTimeField(help_text="Session expiration time")
    
    # Status
    is_active = models.BooleanField(default=True, help_text="Is session currently active")
    ended_at = models.DateTimeField(null=True, blank=True, help_text="When session ended")
    end_reason = models.CharField(
        max_length=50,
        blank=True,
        choices=[
            ('logout', 'User Logout'),
            ('timeout', 'Session Timeout'),
            ('admin_end', 'Ended by Administrator'),
            ('concurrent_limit', 'Concurrent Session Limit'),
            ('security_end', 'Security Policy'),
        ],
        help_text="Reason session ended"
    )
    
    class Meta:
        db_table = 'auth_user_sessions'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'is_active']),
            models.Index(fields=['session_key']),
            models.Index(fields=['expires_at']),
        ]
    
    def __str__(self):
        return f"{self.user.username} - {self.ip_address} ({self.created_at.strftime('%Y-%m-%d %H:%M')})"
    
    def is_expired(self):
        """Check if session is expired"""
        return timezone.now() > self.expires_at
    
    def extend_session(self, minutes=None):
        """Extend session expiration"""
        if minutes is None:
            minutes = self.user.session_timeout_minutes
        
        self.expires_at = timezone.now() + timedelta(minutes=minutes)
        self.save(update_fields=['expires_at'])
    
    def end_session(self, reason='logout'):
        """End the session"""
        self.is_active = False
        self.ended_at = timezone.now()
        self.end_reason = reason
        self.save(update_fields=['is_active', 'ended_at', 'end_reason'])


class AuditLog(models.Model):
    """
    Comprehensive audit logging for security and compliance
    """
    ACTION_TYPES = [
        ('auth', 'Authentication'),
        ('user_mgmt', 'User Management'),
        ('role_mgmt', 'Role Management'),
        ('device_mgmt', 'Device Management'),
        ('log_access', 'Log Access'),
        ('log_export', 'Log Export'),
        ('config_change', 'Configuration Change'),
        ('system_access', 'System Access'),
        ('security', 'Security Event'),
        ('data_modify', 'Data Modification'),
    ]
    
    RESULT_TYPES = [
        ('success', 'Success'),
        ('failure', 'Failure'),
        ('denied', 'Access Denied'),
        ('error', 'Error'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Who did what
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_logs',
        help_text="User who performed the action (null for system actions)"
    )
    username = models.CharField(
        max_length=150,
        help_text="Username at time of action (preserved if user deleted)"
    )
    
    # What happened
    action_type = models.CharField(max_length=20, choices=ACTION_TYPES, help_text="Type of action performed")
    action = models.CharField(max_length=100, help_text="Specific action description")
    result = models.CharField(max_length=10, choices=RESULT_TYPES, help_text="Action result")
    
    # Context information
    resource_type = models.CharField(max_length=50, blank=True, help_text="Type of resource affected")
    resource_id = models.CharField(max_length=100, blank=True, help_text="ID of resource affected")
    resource_name = models.CharField(max_length=255, blank=True, help_text="Name of resource affected")
    
    # Technical details
    ip_address = models.GenericIPAddressField(help_text="Client IP address")
    user_agent = models.TextField(help_text="Client user agent string")
    session_key = models.CharField(max_length=40, null=True, blank=True, help_text="Session key if available")
    
    # Request details
    method = models.CharField(max_length=10, blank=True, help_text="HTTP method")
    path = models.CharField(max_length=500, blank=True, help_text="Request path")
    
    # Additional data
    details = models.JSONField(default=dict, help_text="Additional action details")
    old_values = models.JSONField(default=dict, help_text="Previous values (for modifications)")
    new_values = models.JSONField(default=dict, help_text="New values (for modifications)")
    
    # Error information
    error_message = models.TextField(blank=True, help_text="Error message if action failed")
    
    # Timing
    timestamp = models.DateTimeField(auto_now_add=True, help_text="When action occurred")
    
    class Meta:
        db_table = 'auth_audit_logs'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['action_type', 'timestamp']),
            models.Index(fields=['result', 'timestamp']),
            models.Index(fields=['ip_address', 'timestamp']),
            models.Index(fields=['timestamp']),
        ]
    
    def __str__(self):
        return f"{self.username} - {self.action} - {self.result} ({self.timestamp.strftime('%Y-%m-%d %H:%M:%S')})"
    
    @classmethod
    def log_action(cls, user, action_type, action, result='success', **kwargs):
        """
        Log an audit action
        
        Args:
            user: User object or None for system actions
            action_type: Type of action (from ACTION_TYPES)
            action: Specific action description
            result: Action result (from RESULT_TYPES)
            **kwargs: Additional fields (ip_address, resource_type, etc.)
        """
        # Extract common fields from request if available
        request = kwargs.pop('request', None)
        if request:
            kwargs.setdefault('ip_address', cls._get_client_ip(request))
            kwargs.setdefault('user_agent', request.META.get('HTTP_USER_AGENT', ''))
            kwargs.setdefault('method', request.method)
            kwargs.setdefault('path', request.path)
            if hasattr(request, 'session') and hasattr(request.session, 'session_key'):
                session_key = request.session.session_key
                if session_key:  # Only set if not None or empty
                    kwargs.setdefault('session_key', session_key)
        
        # Create audit log entry
        return cls.objects.create(
            user=user,
            username=user.username if user else 'system',
            action_type=action_type,
            action=action,
            result=result,
            **kwargs
        )
    
    @staticmethod
    def _get_client_ip(request):
        """Extract client IP from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class PasswordHistory(models.Model):
    """
    Track password history to prevent reuse
    """
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='password_history')
    password_hash = models.CharField(max_length=128, help_text="Hashed password")
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'auth_password_history'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'created_at']),
        ]
    
    def __str__(self):
        return f"{self.user.username} - {self.created_at.strftime('%Y-%m-%d %H:%M')}"
    
    @classmethod
    def add_password(cls, user, password):
        """Add a password to history"""
        password_hash = make_password(password)
        cls.objects.create(user=user, password_hash=password_hash)
        
        # Keep only last 12 passwords
        old_passwords = cls.objects.filter(user=user).order_by('-created_at')[12:]
        if old_passwords:
            cls.objects.filter(
                user=user,
                id__in=[p.id for p in old_passwords]
            ).delete()
    
    @classmethod
    def is_password_used_recently(cls, user, password, count=5):
        """Check if password was used in last N passwords"""
        from django.contrib.auth.hashers import check_password
        
        recent_passwords = cls.objects.filter(user=user).order_by('-created_at')[:count]
        for history_entry in recent_passwords:
            if check_password(password, history_entry.password_hash):
                return True
        return False


class LoginAttempt(models.Model):
    """
    Track login attempts for security monitoring
    """
    ATTEMPT_TYPES = [
        ('success', 'Successful Login'),
        ('failure', 'Failed Login'),
        ('blocked', 'Blocked Attempt'),
    ]
    
    username = models.CharField(max_length=150, help_text="Username attempted")
    ip_address = models.GenericIPAddressField(help_text="Client IP address")
    user_agent = models.TextField(help_text="Client user agent string")
    
    attempt_type = models.CharField(max_length=10, choices=ATTEMPT_TYPES, help_text="Type of login attempt")
    failure_reason = models.CharField(
        max_length=100,
        blank=True,
        choices=[
            ('invalid_credentials', 'Invalid Username/Password'),
            ('account_locked', 'Account Locked'),
            ('account_disabled', 'Account Disabled'),
            ('ip_blocked', 'IP Address Blocked'),
            ('rate_limited', 'Rate Limited'),
            ('other', 'Other Reason'),
        ],
        help_text="Reason for failure (if applicable)"
    )
    
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='login_attempts',
        help_text="User account (null if username not found)"
    )
    
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'auth_login_attempts'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['username', 'timestamp']),
            models.Index(fields=['ip_address', 'timestamp']),
            models.Index(fields=['attempt_type', 'timestamp']),
        ]
    
    def __str__(self):
        return f"{self.username} from {self.ip_address} - {self.get_attempt_type_display()} ({self.timestamp.strftime('%Y-%m-%d %H:%M:%S')})"
    
    @classmethod
    def log_attempt(cls, username, ip_address, user_agent, attempt_type, user=None, failure_reason=None):
        """Log a login attempt"""
        return cls.objects.create(
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            attempt_type=attempt_type,
            user=user,
            failure_reason=failure_reason
        )