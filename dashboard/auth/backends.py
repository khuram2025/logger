"""
Enhanced Authentication Backend

Implements enhanced authentication with account locking, IP restrictions,
failed login tracking, and comprehensive security features.
"""

from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.core.cache import cache
from django.contrib.auth.hashers import check_password
from datetime import timedelta
import logging

from dashboard.models.auth import LoginAttempt, AuditLog

logger = logging.getLogger(__name__)

User = get_user_model()


class EnhancedAuthBackend(BaseBackend):
    """
    Enhanced authentication backend with security features:
    - Account locking after failed attempts
    - IP address restrictions
    - Session management
    - Comprehensive audit logging
    - Permission caching
    """
    
    def authenticate(self, request, username=None, password=None, **kwargs):
        """
        Enhanced authentication with security checks
        """
        if username is None or password is None:
            return None
        
        # Get client IP and user agent
        client_ip = self._get_client_ip(request) if request else '0.0.0.0'
        user_agent = request.META.get('HTTP_USER_AGENT', '') if request else ''
        
        try:
            # Try to get user
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                # Log failed attempt for non-existent user
                LoginAttempt.log_attempt(
                    username=username,
                    ip_address=client_ip,
                    user_agent=user_agent,
                    attempt_type='failure',
                    failure_reason='invalid_credentials'
                )
                
                AuditLog.log_action(
                    user=None,
                    action_type='auth',
                    action=f'Login attempt with invalid username: {username}',
                    result='failure',
                    request=request,
                    details={'username': username}
                )
                
                return None
            
            # Check if account is locked
            if user.is_account_locked():
                LoginAttempt.log_attempt(
                    username=username,
                    ip_address=client_ip,
                    user_agent=user_agent,
                    attempt_type='blocked',
                    user=user,
                    failure_reason='account_locked'
                )
                
                AuditLog.log_action(
                    user=user,
                    action_type='auth',
                    action='Login attempt on locked account',
                    result='denied',
                    request=request,
                    details={'lock_reason': 'account_locked'}
                )
                
                return None
            
            # Check if account is active
            if not user.is_active:
                LoginAttempt.log_attempt(
                    username=username,
                    ip_address=client_ip,
                    user_agent=user_agent,
                    attempt_type='blocked',
                    user=user,
                    failure_reason='account_disabled'
                )
                
                AuditLog.log_action(
                    user=user,
                    action_type='auth',
                    action='Login attempt on disabled account',
                    result='denied',
                    request=request
                )
                
                return None
            
            # Check IP restrictions
            if not user.is_ip_allowed(client_ip):
                LoginAttempt.log_attempt(
                    username=username,
                    ip_address=client_ip,
                    user_agent=user_agent,
                    attempt_type='blocked',
                    user=user,
                    failure_reason='ip_blocked'
                )
                
                AuditLog.log_action(
                    user=user,
                    action_type='security',
                    action=f'Login blocked due to IP restriction: {client_ip}',
                    result='denied',
                    request=request,
                    details={'blocked_ip': client_ip}
                )
                
                return None
            
            # Check rate limiting
            if self._is_rate_limited(client_ip, username):
                LoginAttempt.log_attempt(
                    username=username,
                    ip_address=client_ip,
                    user_agent=user_agent,
                    attempt_type='blocked',
                    user=user,
                    failure_reason='rate_limited'
                )
                
                AuditLog.log_action(
                    user=user,
                    action_type='security',
                    action=f'Login rate limited for IP: {client_ip}',
                    result='denied',
                    request=request
                )
                
                return None
            
            # Check password
            if check_password(password, user.password):
                # Successful authentication
                user.record_successful_login()
                
                LoginAttempt.log_attempt(
                    username=username,
                    ip_address=client_ip,
                    user_agent=user_agent,
                    attempt_type='success',
                    user=user
                )
                
                AuditLog.log_action(
                    user=user,
                    action_type='auth',
                    action='Successful login',
                    result='success',
                    request=request,
                    details={
                        'ip_address': client_ip,
                        'user_agent': user_agent[:100]  # Truncate for storage
                    }
                )
                
                # Clear rate limiting cache for successful login
                self._clear_rate_limit(client_ip, username)
                
                return user
            
            else:
                # Failed password
                user.record_failed_login()
                
                LoginAttempt.log_attempt(
                    username=username,
                    ip_address=client_ip,
                    user_agent=user_agent,
                    attempt_type='failure',
                    user=user,
                    failure_reason='invalid_credentials'
                )
                
                AuditLog.log_action(
                    user=user,
                    action_type='auth',
                    action='Failed login - invalid password',
                    result='failure',
                    request=request,
                    details={'failed_attempts': user.failed_login_attempts}
                )
                
                # Update rate limiting
                self._update_rate_limit(client_ip, username)
                
                return None
        
        except Exception as e:
            logger.exception(f"Authentication error for user {username}: {e}")
            
            AuditLog.log_action(
                user=None,
                action_type='auth',
                action=f'Authentication system error',
                result='error',
                request=request,
                error_message=str(e),
                details={'username': username}
            )
            
            return None
    
    def get_user(self, user_id):
        """
        Get user by ID with caching
        """
        cache_key = f"user:{user_id}"
        user = cache.get(cache_key)
        
        if user is None:
            try:
                user = User.objects.select_related('role').get(pk=user_id)
                # Cache user for 15 minutes
                cache.set(cache_key, user, 900)
            except User.DoesNotExist:
                return None
        
        return user
    
    def has_perm(self, user_obj, perm, obj=None):
        """
        Check if user has permission with caching
        """
        if not user_obj or not user_obj.is_active:
            return False
        
        if user_obj.is_superuser:
            return True
        
        # Use custom permission system
        if hasattr(user_obj, 'has_permission'):
            return user_obj.has_permission(perm)
        
        return False
    
    def get_user_permissions(self, user_obj, obj=None):
        """
        Get all permissions for user
        """
        if not user_obj or not user_obj.is_active:
            return set()
        
        if user_obj.is_superuser:
            # Return all possible permissions for superuser
            return {
                'view_logs', 'export_logs', 'manage_devices', 
                'configure_sources', 'view_analytics', 
                'manage_users', 'view_audit', 'system_config'
            }
        
        if user_obj.role:
            return set(user_obj.role.get_permission_list())
        
        return set()
    
    def get_group_permissions(self, user_obj, obj=None):
        """
        Get group permissions (not used in our role-based system)
        """
        return set()
    
    def get_all_permissions(self, user_obj, obj=None):
        """
        Get all permissions for user
        """
        return self.get_user_permissions(user_obj, obj)
    
    def _get_client_ip(self, request):
        """
        Extract client IP from request
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '0.0.0.0')
        return ip
    
    def _is_rate_limited(self, ip_address, username):
        """
        Check if IP/username combination is rate limited
        """
        # Check IP-based rate limiting (5 attempts per minute)
        ip_key = f"rate_limit:ip:{ip_address}"
        ip_attempts = cache.get(ip_key, 0)
        if ip_attempts >= 5:
            return True
        
        # Check username-based rate limiting (10 attempts per 5 minutes)
        user_key = f"rate_limit:user:{username}"
        user_attempts = cache.get(user_key, 0)
        if user_attempts >= 10:
            return True
        
        return False
    
    def _update_rate_limit(self, ip_address, username):
        """
        Update rate limiting counters
        """
        # Update IP-based counter (1 minute window)
        ip_key = f"rate_limit:ip:{ip_address}"
        ip_attempts = cache.get(ip_key, 0)
        cache.set(ip_key, ip_attempts + 1, 60)
        
        # Update username-based counter (5 minute window)
        user_key = f"rate_limit:user:{username}"
        user_attempts = cache.get(user_key, 0)
        cache.set(user_key, user_attempts + 1, 300)
    
    def _clear_rate_limit(self, ip_address, username):
        """
        Clear rate limiting for successful authentication
        """
        ip_key = f"rate_limit:ip:{ip_address}"
        user_key = f"rate_limit:user:{username}"
        cache.delete(ip_key)
        cache.delete(user_key)


class PermissionCache:
    """
    Utility class for caching user permissions
    """
    
    @staticmethod
    def get_cached_permissions(user):
        """
        Get cached permissions for user
        """
        if not user or not user.is_active:
            return set()
        
        cache_key = f"permissions:{user.id}"
        permissions = cache.get(cache_key)
        
        if permissions is None:
            permissions = EnhancedAuthBackend().get_user_permissions(user)
            # Cache permissions for 10 minutes
            cache.set(cache_key, permissions, 600)
        
        return permissions
    
    @staticmethod
    def clear_cached_permissions(user):
        """
        Clear cached permissions for user
        """
        cache_key = f"permissions:{user.id}"
        cache.delete(cache_key)
        
        # Also clear user cache
        user_cache_key = f"user:{user.id}"
        cache.delete(user_cache_key)
    
    @staticmethod
    def has_permission(user, permission):
        """
        Check if user has permission using cache
        """
        permissions = PermissionCache.get_cached_permissions(user)
        return permission in permissions or (user and user.is_superuser)