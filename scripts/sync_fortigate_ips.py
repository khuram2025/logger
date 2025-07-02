
import os
import django
import toml
import subprocess
import sys

# Set up Django environment
sys.path.append('/home/net/analyzer')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'fwanalyzer.settings')
django.setup()

from dashboard.models import LogSource

CONFIG_PATH = '/home/net/analyzer/fortigate-syslog-rust/config.toml'
SERVICE_NAME = 'fortigate-syslog.service'

def get_fortigate_ips():
    """Fetches approved and active FortiGate IP addresses from the database."""
    fortigate_ips = []
    try:
        # Filter for FortiGate devices that are approved or active and parse_to_database is True
        sources = LogSource.objects.filter(
            device_type='fortigate',
            parse_to_database=True
        ).filter(
            status__in=['approved', 'active']
        ).values_list('ip_address', flat=True)
        fortigate_ips = list(sources)
    except Exception as e:
        print(f"Error fetching FortiGate IPs from database: {e}")
    return fortigate_ips

def update_config_file(ips):
    """Updates the config.toml file with the new list of allowed IPs."""
    try:
        with open(CONFIG_PATH, 'r') as f:
            config = toml.load(f)

        current_ips = config.get('syslog', {}).get('allowed_sources', [])
        
        # Only update if there's a change to avoid unnecessary service restarts
        if sorted(current_ips) == sorted(ips):
            print("No changes to allowed_sources. Skipping config update.")
            return False

        config['syslog']['allowed_sources'] = ips
        
        with open(CONFIG_PATH, 'w') as f:
            toml.dump(config, f)
        print(f"Updated {CONFIG_PATH} with new allowed_sources: {ips}")
        return True
    except Exception as e:
        print(f"Error updating config file: {e}")
        return False

def restart_service():
    """Restarts the fortigate-syslog.service."""
    try:
        print(f"Restarting {SERVICE_NAME}...")
        subprocess.run(['sudo', 'systemctl', 'restart', SERVICE_NAME], check=True)
        print(f"{SERVICE_NAME} restarted successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error restarting service: {e}")
    except Exception as e:
        print(f"An unexpected error occurred during service restart: {e}")

if __name__ == "__main__":
    allowed_ips = get_fortigate_ips()
    if update_config_file(allowed_ips):
        restart_service()
    else:
        print("Config file not updated, service not restarted.")
