import os
import subprocess

def create_rsyslog_config(log_source):
    """
    Create rsyslog configuration for a log source device
    Adds device to appropriate config file based on device type
    """
    device_type = log_source.device_type
    ip_address = log_source.ip_address
    
    try:
        # Determine target config file based on device type
        if device_type == 'fortigate':
            config_file = '/etc/rsyslog.d/fortigate.conf'
            template_name = "FortiGateRaw"  # Use existing template
        elif device_type == 'paloalto':
            config_file = '/etc/rsyslog.d/02-paloalto.conf'
            template_name = "PaloAltoRaw"  # Use existing template
        else:
            # For other device types, create a generic config file
            config_file = f'/etc/rsyslog.d/99-device-{ip_address.replace(".", "-")}.conf'
            template_name = f"DeviceRaw_{ip_address.replace('.', '_')}"
        
        # Generate log file path (use existing patterns)
        if device_type == 'fortigate':
            log_file = '/var/log/fortigate.log'  # All FortiGate devices use same file
        elif device_type == 'paloalto':
            # PaloAlto uses format like paloalto-1002.log, paloalto-1004.log
            ip_suffix = ip_address.split('.')[-1]  # Get last octet
            log_file = f'/var/log/paloalto-{ip_suffix}.log'
        else:
            log_file = f'/var/log/device-{ip_address.replace(".", "-")}.log'
        
        # Update log source with log file path
        log_source.log_file_path = log_file
        log_source.save()
        
        # Check if device already exists in config
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                content = f.read()
                if ip_address in content:
                    return {
                        'success': True,
                        'message': f'Device {ip_address} already configured in {config_file}'
                    }
        
        # Generate new config entry
        if device_type in ['fortigate', 'paloalto']:
            # Add to existing config file
            new_config_entry = f"""
if ($fromhost-ip == '{ip_address}') then {{
    action(
        type="omfile"
        file="{log_file}"
        template="{template_name}"
    )
    stop
}}
"""
            
            # Read existing config
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    existing_content = f.read()
                
                # Find insertion point (before the last #### end comment)
                if device_type == 'fortigate':
                    insertion_point = existing_content.rfind('#### end fortigate.conf ####')
                elif device_type == 'paloalto':
                    insertion_point = existing_content.rfind('#### end paloalto.conf ####')
                
                if insertion_point != -1:
                    # Insert new config before the end comment
                    new_content = (existing_content[:insertion_point] + 
                                 new_config_entry + 
                                 existing_content[insertion_point:])
                else:
                    # Append to end if no end comment found
                    new_content = existing_content + new_config_entry
            else:
                return {
                    'success': False,
                    'error': f'Config file {config_file} does not exist'
                }
        else:
            # Create new config file for other device types
            new_content = f"""#### start device-{ip_address.replace('.', '-')}.conf ####

template(name="{template_name}" type="string" string="%rawmsg-after-pri%\\n")

if ($fromhost-ip == '{ip_address}') then {{
    action(
        type="omfile"
        file="{log_file}"
        template="{template_name}"
    )
    stop
}}

#### end device-{ip_address.replace('.', '-')}.conf ####
"""
        
        # Write config file using subprocess to handle permissions
        try:
            # Write to temp file first
            temp_file = f'/tmp/rsyslog_config_{ip_address.replace(".", "_")}.conf'
            with open(temp_file, 'w') as f:
                f.write(new_content)
            
            # Try to copy to target location
            try:
                subprocess.run(['sudo', 'cp', temp_file, config_file], check=True, input=b'\n', timeout=5)
                subprocess.run(['rm', temp_file], check=True)
                
                # Restart rsyslog to apply changes
                subprocess.run(['sudo', 'systemctl', 'restart', 'rsyslog'], check=True, input=b'\n', timeout=10)
                
                return {
                    'success': True,
                    'message': f'Added {ip_address} to {config_file} and restarted rsyslog'
                }
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                # If sudo fails, provide manual instructions
                return {
                    'success': False,
                    'error': f'Config created at {temp_file}. Please run: sudo cp {temp_file} {config_file} && sudo systemctl restart rsyslog',
                    'temp_file': temp_file,
                    'config_content': new_content
                }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to create rsyslog config: {str(e)}'
            }
            
    except Exception as e:
        return {
            'success': False,
            'error': f'Error creating rsyslog config: {str(e)}'
        }