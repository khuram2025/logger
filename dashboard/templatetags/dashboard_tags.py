from django import template
from datetime import datetime

register = template.Library()

@register.filter(name='timestamp_to_datetime')
def timestamp_to_datetime(timestamp_float):
    """
    Converts a Unix timestamp (float or int) to a human-readable
    date/time string.
    Returns "Never" if timestamp is 0 or None, "Invalid Timestamp" for errors.
    """
    if timestamp_float is None or timestamp_float == 0:
        return "Never"
    try:
        ts = float(timestamp_float)
        return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError, OSError):
        return "Invalid Timestamp"

# It's good practice to ensure the __init__.py file exists in the templatetags directory.
# I will create it if it's not there, though usually manage.py startapp handles this.
# For this task, I will assume it should exist or be created.
# However, the tool 'create_file_with_block' can only create one file at a time.
# I will create this __init__.py in a separate step if needed, after listing files.
