"""
Authentication and Permission Decorators

Provides decorators for role-based access control and permission checking
in the network analyzer platform.
"""

from functools import wraps
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect
from django.contrib import messages
from django.http import JsonResponse, HttpResponseForbidden
from django.template.loader import render_to_string
from django.utils.decorators import method_decorator

from dashboard.models.auth import AuditLog
from dashboard.auth.backends import PermissionCache


def require_permission(permission, raise_exception=True, redirect_url=None):
    """
    Decorator to require specific permission for view access
    
    Args:
        permission: The permission string to check (e.g., 'view_logs', 'manage_devices')
        raise_exception: Whether to raise PermissionDenied or redirect (default: True)
        redirect_url: Where to redirect if permission denied and raise_exception=False
    """
    def decorator(view_func):
        @wraps(view_func)
        @login_required
        def _wrapped_view(request, *args, **kwargs):
            # Check if user has the required permission
            if not PermissionCache.has_permission(request.user, permission):
                # Log the access attempt
                AuditLog.log_action(
                    user=request.user,
                    action_type='security',
                    action=f'Access denied - missing permission: {permission}',
                    result='denied',
                    request=request,
                    details={'required_permission': permission, 'view': view_func.__name__}
                )
                
                if raise_exception:
                    raise PermissionDenied(f"You don't have permission to access this resource. Required permission: {permission}")
                else:
                    messages.error(request, f'Access denied. You need the "{permission}" permission to access this page.')
                    return redirect(redirect_url or 'index')
            
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator


def require_role(role_level, raise_exception=True):
    """
    Decorator to require minimum role level for view access
    
    Args:
        role_level: Minimum role level required ('viewer', 'analyst', 'admin', 'superuser')
        raise_exception: Whether to raise PermissionDenied or redirect
    """
    role_hierarchy = {
        'viewer': 1,
        'analyst': 2,
        'admin': 3,
        'superuser': 4
    }
    
    def decorator(view_func):
        @wraps(view_func)
        @login_required
        def _wrapped_view(request, *args, **kwargs):
            user_role_level = 0
            if request.user.role:
                user_role_level = role_hierarchy.get(request.user.role.level, 0)
            
            required_level = role_hierarchy.get(role_level, 999)
            
            # Superuser always has access
            if request.user.is_superuser or user_role_level >= required_level:
                return view_func(request, *args, **kwargs)
            
            # Log the access attempt
            AuditLog.log_action(
                user=request.user,
                action_type='security',
                action=f'Access denied - insufficient role level: {role_level}',
                result='denied',
                request=request,
                details={
                    'required_role': role_level,
                    'user_role': request.user.role.level if request.user.role else 'none',
                    'view': view_func.__name__
                }
            )
            
            if raise_exception:
                raise PermissionDenied(f"Access denied. Minimum role required: {role_level}")
            else:
                messages.error(request, f'Access denied. You need at least "{role_level}" role to access this page.')
                return redirect('index')
        
        return _wrapped_view
    return decorator


def admin_required(view_func=None, raise_exception=True):
    """
    Decorator to require admin role or higher
    """
    def decorator(func):
        return require_role('admin', raise_exception=raise_exception)(func)
    
    if view_func:
        return decorator(view_func)
    return decorator


def analyst_required(view_func=None, raise_exception=True):
    """
    Decorator to require analyst role or higher
    """
    def decorator(func):
        return require_role('analyst', raise_exception=raise_exception)(func)
    
    if view_func:
        return decorator(view_func)
    return decorator


def viewer_or_higher(view_func=None, raise_exception=True):
    """
    Decorator to require viewer role or higher (essentially any authenticated user with a role)
    """
    def decorator(func):
        return require_role('viewer', raise_exception=raise_exception)(func)
    
    if view_func:
        return decorator(view_func)
    return decorator


def ajax_permission_required(permission):
    """
    Decorator for AJAX views that require specific permission
    Returns JSON error response instead of HTML error page
    """
    def decorator(view_func):
        @wraps(view_func)
        @login_required
        def _wrapped_view(request, *args, **kwargs):
            if not PermissionCache.has_permission(request.user, permission):
                # Log the access attempt
                AuditLog.log_action(
                    user=request.user,
                    action_type='security',
                    action=f'AJAX access denied - missing permission: {permission}',
                    result='denied',
                    request=request,
                    details={'required_permission': permission, 'view': view_func.__name__}
                )
                
                return JsonResponse({
                    'error': 'Permission denied',
                    'message': f'You need the "{permission}" permission to perform this action.',
                    'required_permission': permission
                }, status=403)
            
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator


def user_passes_test_with_audit(test_func, login_url=None, redirect_field_name='next', 
                               audit_action=None, audit_details=None):
    """
    Enhanced version of user_passes_test that includes audit logging
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if test_func(request.user):
                return view_func(request, *args, **kwargs)
            
            # Log the failed test
            if audit_action and request.user.is_authenticated:
                AuditLog.log_action(
                    user=request.user,
                    action_type='security',
                    action=audit_action,
                    result='denied',
                    request=request,
                    details=audit_details or {'view': view_func.__name__}
                )
            
            # Handle unauthenticated users
            if not request.user.is_authenticated:
                from django.contrib.auth.views import redirect_to_login
                return redirect_to_login(request.get_full_path(), login_url, redirect_field_name)
            
            # Handle permission denied for authenticated users
            raise PermissionDenied("You don't have permission to access this resource.")
        
        return _wrapped_view
    return decorator


def superuser_required(view_func=None):
    """
    Decorator to require superuser access
    """
    def test_superuser(user):
        return user.is_superuser
    
    actual_decorator = user_passes_test_with_audit(
        test_superuser,
        audit_action='Superuser access denied',
        audit_details={'required_access': 'superuser'}
    )
    
    if view_func:
        return actual_decorator(view_func)
    return actual_decorator


def can_manage_users(view_func=None):
    """
    Decorator to check if user can manage other users
    """
    def test_user_management(user):
        return PermissionCache.has_permission(user, 'manage_users')
    
    actual_decorator = user_passes_test_with_audit(
        test_user_management,
        audit_action='User management access denied',
        audit_details={'required_permission': 'manage_users'}
    )
    
    if view_func:
        return actual_decorator(view_func)
    return actual_decorator


def can_export_data(view_func=None):
    """
    Decorator to check if user can export data
    """
    def test_data_export(user):
        return PermissionCache.has_permission(user, 'export_logs')
    
    actual_decorator = user_passes_test_with_audit(
        test_data_export,
        audit_action='Data export access denied',
        audit_details={'required_permission': 'export_logs'}
    )
    
    if view_func:
        return actual_decorator(view_func)
    return actual_decorator


def can_configure_system(view_func=None):
    """
    Decorator to check if user can configure system settings
    """
    def test_system_config(user):
        return PermissionCache.has_permission(user, 'system_config')
    
    actual_decorator = user_passes_test_with_audit(
        test_system_config,
        audit_action='System configuration access denied',
        audit_details={'required_permission': 'system_config'}
    )
    
    if view_func:
        return actual_decorator(view_func)
    return actual_decorator


class MethodPermissionMixin:
    """
    Mixin for class-based views to add method-level permission checking
    """
    permission_required = None
    permission_denied_message = None
    raise_exception = True
    
    def check_permissions(self, request):
        """
        Check if the user has required permissions
        """
        if not self.permission_required:
            return True
        
        # Handle both string and list/tuple of permissions
        if isinstance(self.permission_required, str):
            permissions = [self.permission_required]
        else:
            permissions = self.permission_required
        
        # Check all required permissions
        for permission in permissions:
            if not PermissionCache.has_permission(request.user, permission):
                return False
        
        return True
    
    def dispatch(self, request, *args, **kwargs):
        """
        Override dispatch to check permissions before processing request
        """
        # Check if user is authenticated
        if not request.user.is_authenticated:
            from django.contrib.auth.views import redirect_to_login
            return redirect_to_login(request.get_full_path())
        
        # Check permissions
        if not self.check_permissions(request):
            # Log the access attempt
            AuditLog.log_action(
                user=request.user,
                action_type='security',
                action=f'CBV access denied - missing permission',
                result='denied',
                request=request,
                details={
                    'required_permissions': self.permission_required,
                    'view_class': self.__class__.__name__,
                    'method': request.method
                }
            )
            
            if self.raise_exception:
                raise PermissionDenied(
                    self.permission_denied_message or 
                    f"You don't have permission to access this resource. Required permissions: {self.permission_required}"
                )
            else:
                messages.error(
                    request, 
                    self.permission_denied_message or 
                    'Access denied. You do not have the required permissions.'
                )
                return redirect('index')
        
        return super().dispatch(request, *args, **kwargs)


# Convenience method decorators for class-based views
def method_permission_required(permission):
    """
    Method decorator for class-based views
    """
    def decorator(cls):
        cls.permission_required = permission
        return type(cls.__name__, (MethodPermissionMixin, cls), {})
    
    return decorator


def method_admin_required(cls):
    """
    Class decorator to require admin permissions for all methods
    """
    return method_permission_required(['manage_devices', 'configure_sources', 'manage_users'])(cls)


def method_analyst_required(cls):
    """
    Class decorator to require analyst permissions for all methods
    """
    return method_permission_required(['view_logs', 'view_analytics'])(cls)


# Template tag helpers for permission checking in templates
def user_has_permission(user, permission):
    """
    Template-friendly permission check function
    """
    return PermissionCache.has_permission(user, permission)


def user_has_role_level(user, role_level):
    """
    Template-friendly role level check function
    """
    if not user or not user.is_authenticated or not user.role:
        return False
    
    role_hierarchy = {
        'viewer': 1,
        'analyst': 2,
        'admin': 3,
        'superuser': 4
    }
    
    user_level = role_hierarchy.get(user.role.level, 0)
    required_level = role_hierarchy.get(role_level, 999)
    
    return user.is_superuser or user_level >= required_level