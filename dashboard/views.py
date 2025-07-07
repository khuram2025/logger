# Dashboard views - Refactored and organized into modular structure
# This file imports all views from the new modular structure for backward compatibility

# Import all views from the new structure
from .views import *

# Additional backward compatibility imports
from .constants import *
from .utils.rsyslog import create_rsyslog_config
from .utils.pagination import get_pagination_range  
from .utils.formatting import format_bytes
from .utils.network import get_ip_filter_clause
from .utils.system import get_filesystem_info, get_directory_size
from .utils.analytics import calculate_trend
from .utils.clickhouse import get_clickhouse_client

# Note: All view functions have been moved to appropriate modules in dashboard/views/
# - Traffic analytics: dashboard/views/traffic.py
# - System configuration: dashboard/views/system_config.py  
# - Log sources management: dashboard/views/log_sources.py
# - Log management: dashboard/views/log_management.py
# - PaloAlto URL filtering: dashboard/views/pa_urls.py
# - Device management: dashboard/views/devices.py
# - Network topology: dashboard/views/topology.py
# - Utility functions: dashboard/utils/
# - Constants: dashboard/constants.py