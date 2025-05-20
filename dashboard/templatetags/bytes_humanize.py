from django import template

register = template.Library()

@register.filter
def bytes_humanize(value):
    """Convert a byte value into a human-readable MB/GB string."""
    try:
        bytes_val = float(value)
    except (TypeError, ValueError):
        return value
    if bytes_val < 1024:
        return f"{bytes_val:.0f} B"
    elif bytes_val < 1024 ** 2:
        return f"{bytes_val/1024:.2f} KB"
    elif bytes_val < 1024 ** 3:
        return f"{bytes_val/1024**2:.2f} MB"
    elif bytes_val < 1024 ** 4:
        return f"{bytes_val/1024**3:.2f} GB"
    else:
        return f"{bytes_val/1024**4:.2f} TB"
