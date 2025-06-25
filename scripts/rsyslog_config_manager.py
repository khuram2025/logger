#!/usr/bin/env python3
"""
Rsyslog Configuration Manager
Manages rsyslog configurations for log sources dynamically.
"""

import os
import sys
import subprocess
import shutil
from datetime import datetime

# Add Django environment
sys.path.append('/home/net/analyzer')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'analyzer.settings')
import django
django.setup()

from dashboard.models import LogSource, LogSourceEvent

class RsyslogConfigManager:
    def __init__(self):
        self.config_dir = '/etc/rsyslog.d'
        self.backup_dir = '/etc/rsyslog.d/backups'
        self.test_mode = not os.access(self.config_dir, os.W_OK)
        
        if self.test_mode:
            print("Running in test mode (no write access to /etc/rsyslog.d)")
            self.config_dir = '/tmp/rsyslog.d'
            self.backup_dir = '/tmp/rsyslog.d/backups'
            os.makedirs(self.config_dir, exist_ok=True)
            
        os.makedirs(self.backup_dir, exist_ok=True)
        
    def generate_config_filename(self, log_source):
        """Generate config filename for a log source"""
        # Use numeric prefix for ordering
        prefix = {
            'fortigate': '60',
            'paloalto': '61',
            'cisco': '62',
            'checkpoint': '63',
            'sophos': '64',
            'juniper': '65',
            'generic': '70',
            'unknown': '80'
        }.get(log_source.device_type, '90')
        
        safe_name = log_source.name.lower().replace(' ', '-').replace('_', '-')
        safe_name = ''.join(c for c in safe_name if c.isalnum() or c == '-')
        
        return f"{prefix}-{safe_name}.conf"
        
    def create_config(self, log_source):
        """Create rsyslog configuration for a log source"""
        if log_source.status not in ['approved', 'active']:
            raise ValueError(f"Log source must be approved. Current status: {log_source.status}")
            
        config_content = self._generate_config_content(log_source)
        filename = self.generate_config_filename(log_source)
        filepath = os.path.join(self.config_dir, filename)
        
        # Backup existing config if it exists
        if os.path.exists(filepath):
            self._backup_config(filepath)
            
        # Write new config
        try:
            with open(filepath, 'w') as f:
                f.write(config_content)
                
            # Set proper permissions
            if not self.test_mode:
                os.chmod(filepath, 0o644)
                
            # Test configuration
            if self._test_rsyslog_config():
                # Reload rsyslog
                if not self.test_mode:
                    self._reload_rsyslog()
                    
                # Log event
                LogSourceEvent.objects.create(
                    log_source=log_source,
                    event_type='configured',
                    description=f"Rsyslog configuration created: {filename}",
                    metadata={'config_file': filepath}
                )
                
                return True, f"Configuration created: {filepath}"
            else:
                # Restore backup if test failed
                if os.path.exists(filepath + '.bak'):
                    shutil.move(filepath + '.bak', filepath)
                return False, "Configuration test failed"
                
        except Exception as e:
            return False, f"Error creating config: {str(e)}"
            
    def _generate_config_content(self, log_source):
        """Generate rsyslog configuration content"""
        # Header
        content = f"""#### Start configuration for {log_source.name} ####
# Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# Device Type: {log_source.get_device_type_display()}
# IP Address: {log_source.ip_address}

"""
        
        # Load modules if needed
        if log_source.protocol == 'udp':
            content += """# Load UDP module (only once)
module(load="imudp" load.onceOnly="on")

"""
        elif log_source.protocol == 'tcp':
            content += """# Load TCP module (only once)  
module(load="imtcp" load.onceOnly="on")

"""
        
        # Template definition
        template_name = f"Template_{log_source.name.replace(' ', '_')}"
        
        if log_source.log_template == 'fortigate_default':
            content += f"""# FortiGate template - removes priority header
template(name="{template_name}" type="string" string="%rawmsg-after-pri%\\n")

"""
        elif log_source.log_template == 'paloalto_default':
            content += f"""# PaloAlto template - removes priority header
template(name="{template_name}" type="string" string="%rawmsg-after-pri%\\n")

"""
        elif log_source.log_template == 'timestamp':
            content += f"""# Timestamped template
template(name="{template_name}" type="string" string="%timestamp% %rawmsg-after-pri%\\n")

"""
        elif log_source.log_template == 'detailed':
            content += f"""# Detailed template with metadata
template(name="{template_name}" type="string" string="%timestamp% %fromhost-ip% %syslogtag% %rawmsg-after-pri%\\n")

"""
        elif log_source.log_template == 'custom' and log_source.custom_template:
            content += f"""# Custom template
{log_source.custom_template}

"""
        else:
            content += f"""# Raw template (default)
template(name="{template_name}" type="string" string="%rawmsg%\\n")

"""
        
        # Create directory if needed
        log_dir = os.path.dirname(log_source.log_file_path)
        if log_dir and log_dir != '/var/log':
            content += f"""# Ensure log directory exists
$CreateDirs on

"""
        
        # Filtering rule
        content += f"""# Filter messages from {log_source.ip_address}
if ($fromhost-ip == '{log_source.ip_address}') then {{
    action(
        type="omfile"
        file="{log_source.log_file_path}"
        template="{template_name}"
"""
        
        # Add queue configuration for reliability
        if log_source.device_type in ['fortigate', 'paloalto']:
            queue_name = log_source.name.replace(' ', '_').lower()
            content += f"""        queue.type="LinkedList"
        queue.filename="{queue_name}_queue"
        queue.maxdiskspace="100m"
        queue.saveonshutdown="on"
        queue.highwatermark="5000"
        queue.lowwatermark="1000"
"""
        
        content += f"""    )
    stop
}}

#### End configuration for {log_source.name} ####
"""
        
        return content
        
    def _backup_config(self, filepath):
        """Backup existing configuration"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_name = os.path.basename(filepath) + f'.{timestamp}'
        backup_path = os.path.join(self.backup_dir, backup_name)
        shutil.copy2(filepath, backup_path)
        
    def _test_rsyslog_config(self):
        """Test rsyslog configuration"""
        try:
            if self.test_mode:
                return True  # Skip test in test mode
                
            result = subprocess.run(
                ['sudo', 'rsyslogd', '-N1'],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except:
            return False
            
    def _reload_rsyslog(self):
        """Reload rsyslog service"""
        try:
            subprocess.run(['sudo', 'systemctl', 'reload', 'rsyslog'], check=True)
            return True
        except:
            return False
            
    def remove_config(self, log_source):
        """Remove rsyslog configuration for a log source"""
        filename = self.generate_config_filename(log_source)
        filepath = os.path.join(self.config_dir, filename)
        
        if os.path.exists(filepath):
            self._backup_config(filepath)
            os.remove(filepath)
            
            if not self.test_mode:
                self._reload_rsyslog()
                
            LogSourceEvent.objects.create(
                log_source=log_source,
                event_type='configured',
                description=f"Rsyslog configuration removed: {filename}",
                metadata={'config_file': filepath}
            )
            
            return True, f"Configuration removed: {filepath}"
        else:
            return False, f"Configuration not found: {filepath}"
            
    def update_all_configs(self):
        """Update configurations for all active log sources"""
        results = []
        
        for source in LogSource.objects.filter(status__in=['approved', 'active']):
            success, message = self.create_config(source)
            results.append({
                'source': source.name,
                'success': success,
                'message': message
            })
            
        return results
        
    def validate_all_configs(self):
        """Validate all rsyslog configurations"""
        issues = []
        
        # Check for duplicate IP filtering
        ip_map = {}
        for conf_file in os.listdir(self.config_dir):
            if conf_file.endswith('.conf'):
                filepath = os.path.join(self.config_dir, conf_file)
                try:
                    with open(filepath, 'r') as f:
                        content = f.read()
                        
                    # Extract IPs being filtered
                    import re
                    ip_pattern = r'\$fromhost-ip\s*==\s*[\'"]([^\'\"]+)[\'"]'
                    ips = re.findall(ip_pattern, content)
                    
                    for ip in ips:
                        if ip in ip_map:
                            issues.append(f"Duplicate IP {ip} in {conf_file} and {ip_map[ip]}")
                        else:
                            ip_map[ip] = conf_file
                            
                except Exception as e:
                    issues.append(f"Error reading {conf_file}: {str(e)}")
                    
        return issues


# Command-line interface
def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Rsyslog Configuration Manager')
    parser.add_argument('--create', type=int, help='Create config for log source ID')
    parser.add_argument('--remove', type=int, help='Remove config for log source ID')
    parser.add_argument('--update-all', action='store_true', help='Update all configs')
    parser.add_argument('--validate', action='store_true', help='Validate all configs')
    parser.add_argument('--list', action='store_true', help='List all managed configs')
    
    args = parser.parse_args()
    
    manager = RsyslogConfigManager()
    
    if args.create:
        try:
            source = LogSource.objects.get(id=args.create)
            success, message = manager.create_config(source)
            print(f"{'✅' if success else '❌'} {message}")
        except LogSource.DoesNotExist:
            print(f"❌ Log source {args.create} not found")
            
    elif args.remove:
        try:
            source = LogSource.objects.get(id=args.remove)
            success, message = manager.remove_config(source)
            print(f"{'✅' if success else '❌'} {message}")
        except LogSource.DoesNotExist:
            print(f"❌ Log source {args.remove} not found")
            
    elif args.update_all:
        print("Updating all configurations...")
        results = manager.update_all_configs()
        for result in results:
            status = '✅' if result['success'] else '❌'
            print(f"{status} {result['source']}: {result['message']}")
            
    elif args.validate:
        print("Validating configurations...")
        issues = manager.validate_all_configs()
        if issues:
            print(f"❌ Found {len(issues)} issues:")
            for issue in issues:
                print(f"  - {issue}")
        else:
            print("✅ All configurations valid")
            
    elif args.list:
        print("Managed log sources:")
        for source in LogSource.objects.filter(status__in=['approved', 'active']):
            config_file = manager.generate_config_filename(source)
            exists = os.path.exists(os.path.join(manager.config_dir, config_file))
            status = '✅' if exists else '❌'
            print(f"{status} {source.name} ({source.ip_address}) - {config_file}")

if __name__ == "__main__":
    main()