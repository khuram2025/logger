# Views module for dashboard application
# This file imports all views for backward compatibility

# Import all views from the new modular structure
from .base import uitest_view, header_test_view
from .traffic import top_summary_view, clickhouse_logs_view
from .system_config import (
    system_config_view, service_action_view, logs_config_view,
    logs_config_save_view, logs_config_test_view
)
from .log_sources import (
    log_sources_view, toggle_save_logs_view, log_source_action_view,
    test_log_source_view, scan_log_sources_view, log_sources_status_view,
    add_log_source_view, device_registration_view, device_list_view,
    configure_log_source_view, save_log_source_config_view
)
from .log_management import (
    log_management_status_view, service_control_view, clickhouse_storage_view,
    storage_allocation_view
)
from .pa_urls import pa_url_logs_view, url_summary_view
from .devices import edit_device_view, delete_device_view
from .topology import (
    device_topology_view, device_zones_view, add_zone_view, edit_zone_view,
    delete_zone_view, device_subnets_view, add_subnet_view, edit_subnet_view,
    delete_subnet_view, device_interfaces_view, add_interface_view,
    edit_interface_view, delete_interface_view, ajax_device_zones,
    ajax_device_subnets, ajax_zone_subnets
)

# Import utility functions for backward compatibility
from ..utils.rsyslog import create_rsyslog_config
from ..utils.pagination import get_pagination_range
from ..utils.formatting import format_bytes
from ..utils.network import get_ip_filter_clause
from ..utils.system import get_filesystem_info, get_directory_size
from ..utils.analytics import calculate_trend
from ..utils.clickhouse import get_clickhouse_client

# Import constants for backward compatibility
from ..constants import (
    CH_HOST, CH_PORT, CH_USER, CH_PASSWORD, CH_DB, 
    SUBNET_GROUP_PAGE_SIZE, PROTO_MAP
)

# All views that can be imported from dashboard.views
__all__ = [
    # Base views
    'uitest_view',
    
    # Traffic views
    'top_summary_view', 'clickhouse_logs_view',
    
    # System config views
    'system_config_view', 'service_action_view', 'logs_config_view',
    'logs_config_save_view', 'logs_config_test_view',
    
    # Log sources views
    'log_sources_view', 'toggle_save_logs_view', 'log_source_action_view',
    'test_log_source_view', 'scan_log_sources_view', 'log_sources_status_view',
    'add_log_source_view', 'device_registration_view', 'device_list_view',
    'configure_log_source_view', 'save_log_source_config_view',
    
    # Log management views
    'log_management_status_view', 'service_control_view', 'clickhouse_storage_view',
    'storage_allocation_view',
    
    # PaloAlto URL views
    'pa_url_logs_view', 'url_summary_view',
    
    # Device management views
    'edit_device_view', 'delete_device_view',
    
    # Topology views
    'device_topology_view', 'device_zones_view', 'add_zone_view', 'edit_zone_view',
    'delete_zone_view', 'device_subnets_view', 'add_subnet_view', 'edit_subnet_view',
    'delete_subnet_view', 'device_interfaces_view', 'add_interface_view',
    'edit_interface_view', 'delete_interface_view', 'ajax_device_zones',
    'ajax_device_subnets', 'ajax_zone_subnets',
    
    # Utility functions
    'create_rsyslog_config', 'get_pagination_range', 'format_bytes',
    'get_ip_filter_clause', 'get_filesystem_info', 'get_directory_size',
    'calculate_trend', 'get_clickhouse_client',
    
    # Constants
    'CH_HOST', 'CH_PORT', 'CH_USER', 'CH_PASSWORD', 'CH_DB',
    'SUBNET_GROUP_PAGE_SIZE', 'PROTO_MAP'
]