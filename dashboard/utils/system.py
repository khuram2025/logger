import os
import shutil
import logging
from .formatting import format_bytes

def get_filesystem_info(path):
    """Get filesystem space information for the given path"""
    try:
        total, used, free = shutil.disk_usage(path)
        return {
            'total_bytes': total,
            'used_bytes': used,
            'free_bytes': free,
            'total_formatted': format_bytes(total),
            'used_formatted': format_bytes(used),
            'free_formatted': format_bytes(free),
            'used_percentage': round((used / total) * 100, 1)
        }
    except Exception as e:
        logging.warning(f"Failed to get filesystem info for {path}: {e}")
        return None

def get_directory_size(path):
    """Calculate total size of a directory"""
    total_size = 0
    try:
        for dirpath, dirnames, filenames in os.walk(path):
            for filename in filenames:
                try:
                    filepath = os.path.join(dirpath, filename)
                    if os.path.exists(filepath):
                        total_size += os.path.getsize(filepath)
                except (OSError, IOError):
                    continue
    except (OSError, IOError, PermissionError):
        return None
    return total_size