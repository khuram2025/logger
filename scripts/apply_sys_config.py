#!/usr/bin/env python3
import argparse
import subprocess
import os
import tempfile
import shutil
import re # For get_recent_ips
from datetime import datetime # For get_last_modified_time

# --- Configuration Constants ---
FWANALYZER_RSYSLOG_CONF_FILE = '/etc/rsyslog.d/90-fwanalyzer-hosts.conf' # Specific name
RSYSLOG_MARKER_BEGIN = '# BEGIN FWANALYZER MANAGED RSYSLOG CONFIG' # Updated markers
RSYSLOG_MARKER_END = '# END FWANALYZER MANAGED RSYSLOG CONFIG'
FWANALYZER_LOG_DIR = '/var/log/fwanalyzer-hosts'
RSYSLOG_PER_HOST_TEMPLATE_NAME = "FWAnalyzerPerHostFile"
RSYSLOG_RAW_MSG_TEMPLATE_NAME = "FWAnalyzerRawMsg"

FWANALYZER_LOGROTATE_CONF_FILE = '/etc/logrotate.d/fwanalyzer-hosts'


def manage_rsyslog(ip_addresses):
    """
    Manages the rsyslog configuration for per-host FortiGate logs.
    """
    print("--- Managing Rsyslog Configuration ---")

    try:
        if not os.path.exists(FWANALYZER_LOG_DIR):
            os.makedirs(FWANALYZER_LOG_DIR, exist_ok=True)
            # Attempt to set permissions. This is best-effort if script is not root.
            # For production, ensure syslog user can write here.
            # Example: sudo chown syslog:adm /var/log/fwanalyzer-hosts && sudo chmod 0750 /var/log/fwanalyzer-hosts
            print(f"Created log directory: {FWANALYZER_LOG_DIR}. Manual permission review may be needed.")
    except OSError as e:
        print(f"Error creating directory {FWANALYZER_LOG_DIR}: {e}. Check permissions. Skipping rsyslog management.")
        return False
    
    rsyslog_conf_dir = os.path.dirname(FWANALYZER_RSYSLOG_CONF_FILE)
    if not os.path.exists(rsyslog_conf_dir):
        try:
            os.makedirs(rsyslog_conf_dir, exist_ok=True)
            print(f"Created rsyslog configuration directory: {rsyslog_conf_dir}")
        except OSError as e:
            print(f"Error creating rsyslog configuration directory {rsyslog_conf_dir}: {e}. Skipping rsyslog management.")
            return False

    # Define Rsyslog templates and rules
    raw_msg_template_definition = f'template(name="{RSYSLOG_RAW_MSG_TEMPLATE_NAME}" type="string" string="%rawmsg-after-pri%\\n")'
    per_host_file_template_definition = f'template(name="{RSYSLOG_PER_HOST_TEMPLATE_NAME}" type="string" string="{FWANALYZER_LOG_DIR}/%FROMHOST-IP%.log")'

    rules_content = ""
    if ip_addresses:
        conditions = " or ".join([f"$fromhost-ip == '{ip}'" for ip in ip_addresses])
        rules_content = f"""if ({conditions}) then {{
    action(type="omfile" dynaFile="{RSYSLOG_PER_HOST_TEMPLATE_NAME}" template="{RSYSLOG_RAW_MSG_TEMPLATE_NAME}")
    stop
}}"""
    else:
        rules_content = """if ($fromhost-ip == '255.255.255.255' and $fromhost-ip == '255.255.255.254') then {
    # This block is intentionally made to almost never match when no IPs are whitelisted.
    action(type="omfile" dynaFile="{RSYSLOG_PER_HOST_TEMPLATE_NAME}" template="{RSYSLOG_RAW_MSG_TEMPLATE_NAME}")
    stop
}"""
    
    new_block_content = f"{raw_msg_template_definition}\n{per_host_file_template_definition}\n{rules_content}"

    current_rsyslog_file_content = ""
    original_content_between_markers = None
    pre_marker_content = ""
    post_marker_content = ""

    try:
        if not os.path.exists(FWANALYZER_RSYSLOG_CONF_FILE):
            print(f"Warning: Rsyslog config file {FWANALYZER_RSYSLOG_CONF_FILE} not found. Creating new file.")
            # Base content needed if file is created fresh (module load)
            base_content = "# Load UDP syslog listener if not already loaded globally\n# module(load=\"imudp\")\n\n"
            current_rsyslog_file_content = f"{base_content}{RSYSLOG_MARKER_BEGIN}\n{new_block_content}\n{RSYSLOG_MARKER_END}\n"
        else:
            with open(FWANALYZER_RSYSLOG_CONF_FILE, 'r') as f:
                existing_content = f.read()
            
            marker_begin_idx = existing_content.find(RSYSLOG_MARKER_BEGIN)
            marker_end_idx = existing_content.find(RSYSLOG_MARKER_END)

            if marker_begin_idx == -1 or marker_end_idx == -1 or marker_begin_idx >= marker_end_idx:
                print(f"Error: Markers not found or in wrong order in {FWANALYZER_RSYSLOG_CONF_FILE}.")
                print("Appending new configuration block. Manual review of the file is recommended.")
                current_rsyslog_file_content = existing_content + f"\n{RSYSLOG_MARKER_BEGIN}\n{new_block_content}\n{RSYSLOG_MARKER_END}\n"
            else:
                original_content_between_markers = existing_content[marker_begin_idx + len(RSYSLOG_MARKER_BEGIN) : marker_end_idx].strip()
                pre_marker_content = existing_content[:marker_begin_idx + len(RSYSLOG_MARKER_BEGIN)]
                post_marker_content = existing_content[marker_end_idx:]
                current_rsyslog_file_content = f"{pre_marker_content}\n{new_block_content}\n{post_marker_content}"
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, prefix="rsyslog_conf_", dir=".") as tmp_file:
            tmp_file.write(current_rsyslog_file_content)
        
        shutil.move(tmp_file.name, FWANALYZER_RSYSLOG_CONF_FILE)
        print(f"Rsyslog configuration written to {FWANALYZER_RSYSLOG_CONF_FILE}")

        validation_cmd = ['sudo', 'rsyslogd', '-N1']
        print(f"Validating rsyslog configuration with: {' '.join(validation_cmd)}")
        validation_process = subprocess.run(validation_cmd, capture_output=True, text=True, check=False)

        if validation_process.returncode != 0:
            print(f"Error: Rsyslog configuration validation failed.")
            print(f"Stdout: {validation_process.stdout}")
            print(f"Stderr: {validation_process.stderr}")
            # Attempt to revert if possible
            if original_content_between_markers is not None and marker_begin_idx != -1 and marker_end_idx != -1 :
                print(f"Reverting changes in {FWANALYZER_RSYSLOG_CONF_FILE}...")
                reverted_content = f"{pre_marker_content}\n{original_content_between_markers}\n{post_marker_content}"
                with tempfile.NamedTemporaryFile(mode='w', delete=False, prefix="rsyslog_revert_", dir=".") as tmp_revert_file:
                    tmp_revert_file.write(reverted_content)
                shutil.move(tmp_revert_file.name, FWANALYZER_RSYSLOG_CONF_FILE)
                print("Changes reverted.")
            else:
                print("Could not automatically revert changes (no clear previous state or markers were missing).")
            return False
        else:
            print("Rsyslog configuration validated successfully.")

        reload_cmd = ['sudo', 'systemctl', 'reload', 'rsyslog']
        print(f"Reloading rsyslog with: {' '.join(reload_cmd)}")
        reload_process = subprocess.run(reload_cmd, capture_output=True, text=True, check=False)
        if reload_process.returncode != 0:
            print(f"Error: Failed to reload rsyslog.")
            print(f"Stdout: {reload_process.stdout}")
            print(f"Stderr: {reload_process.stderr}")
            return False
        else:
            print("Rsyslog reloaded successfully.")
            return True

    except Exception as e:
        print(f"An unexpected error occurred during rsyslog management: {e}")
        # Simplified revert for unexpected errors
        if original_content_between_markers is not None and marker_begin_idx != -1 and marker_end_idx != -1:
            try:
                print(f"Attempting to revert {FWANALYZER_RSYSLOG_CONF_FILE} due to exception...")
                reverted_content = f"{pre_marker_content}\n{original_content_between_markers}\n{post_marker_content}"
                with tempfile.NamedTemporaryFile(mode='w', delete=False, prefix="rsyslog_except_revert_", dir=".") as tmp_revert_file:
                    tmp_revert_file.write(reverted_content)
                shutil.move(tmp_revert_file.name, FWANALYZER_RSYSLOG_CONF_FILE)
                print("Changes reverted due to exception.")
            except Exception as revert_e:
                print(f"Could not revert changes during exception handling: {revert_e}")
        return False


def manage_logrotate(enabled, interval, max_size, keep_rotations):
    """
    Manages the logrotate configuration for per-host FortiGate logs.
    """
    print("\n--- Managing Logrotate Configuration ---")
    
    logrotate_conf_dir = os.path.dirname(FWANALYZER_LOGROTATE_CONF_FILE)
    if not os.path.exists(logrotate_conf_dir):
        try:
            os.makedirs(logrotate_conf_dir, exist_ok=True)
            print(f"Created logrotate configuration directory: {logrotate_conf_dir}")
        except OSError as e:
            print(f"Error: Could not create logrotate directory {logrotate_conf_dir}: {e}. Skipping logrotate management.")
            return False

    if not enabled:
        if os.path.exists(FWANALYZER_LOGROTATE_CONF_FILE):
            try:
                os.remove(FWANALYZER_LOGROTATE_CONF_FILE)
                print(f"Logrotate disabled. Removed {FWANALYZER_LOGROTATE_CONF_FILE}.")
                return True
            except OSError as e:
                print(f"Error: Could not remove {FWANALYZER_LOGROTATE_CONF_FILE}: {e}. Check permissions.")
                return False
        else:
            print("Logrotate already disabled (config file does not exist).")
            return True

    log_path_to_rotate = os.path.join(FWANALYZER_LOG_DIR, '*.log') # Target all .log files in the directory
    
    logrotate_content_parts = [f"{log_path_to_rotate} {{"]
    if interval:
        logrotate_content_parts.append(f"    {interval}")
    if max_size:
        logrotate_content_parts.append(f"    size {max_size}")
    if keep_rotations is not None:
        logrotate_content_parts.append(f"    rotate {keep_rotations}")
    
    logrotate_content_parts.extend([
        "    missingok",
        "    notifempty",
        "    compress",
        "    delaycompress",
        # "    sharedscripts", # Consider if postrotate/prerotate scripts are added
        "}"
    ])
    logrotate_config = "\n".join(logrotate_content_parts)

    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, prefix="logrotate_conf_", dir=".") as tmp_file:
            tmp_file.write(logrotate_config)
        
        shutil.move(tmp_file.name, FWANALYZER_LOGROTATE_CONF_FILE)
        print(f"Logrotate configuration written to {FWANALYZER_LOGROTATE_CONF_FILE}:")
        print(logrotate_config)
        return True
    except Exception as e:
        print(f"Error writing logrotate configuration: {e}")
        if 'tmp_file' in locals() and os.path.exists(tmp_file.name):
            try:
                os.remove(tmp_file.name)
            except OSError:
                pass
        return False

def get_rsyslog_status():
    try:
        status_cmd = ['sudo', 'systemctl', 'status', 'rsyslog']
        process = subprocess.run(status_cmd, capture_output=True, text=True, check=False, timeout=10)
        stdout = process.stdout.lower()
        if process.returncode == 0 or process.returncode == 3:
            if "active (running)" in stdout: print("Running"); return True
            elif "inactive (dead)" in stdout or "active (exited)" in stdout: print("Stopped"); return True
            elif "activating (auto-restart)" in stdout: print("Activating"); return True
            elif "failed" in stdout: print("Failed"); return False
            print("Status Unknown"); return False
        else:
            print(f"Error (code {process.returncode}): {process.stderr.strip() if process.stderr else 'No stderr'}", file=os.sys.stderr)
            print("Status Unknown"); return False
    except Exception as e:
        print(f"Exception checking rsyslog status: {e}", file=os.sys.stderr)
        print("Status Unknown"); return False

def humanize_bytes(num_bytes):
    if num_bytes is None: return "N/A"
    if num_bytes < 1024.0: return f"{num_bytes} Bytes"
    elif num_bytes < 1024.0**2: return f"{num_bytes/1024.0:.2f} KB"
    elif num_bytes < 1024.0**3: return f"{num_bytes/(1024.0**2):.2f} MB"
    else: return f"{num_bytes/(1024.0**3):.2f} GB"

def get_file_size(filepath):
    try:
        if not os.path.exists(filepath): print(f"Error: File not found - {filepath}", file=os.sys.stderr); return False
        if not os.access(filepath, os.R_OK): print(f"Error: Cannot access file (permission denied) - {filepath}", file=os.sys.stderr); return False
        size_bytes = os.path.getsize(filepath)
        print(humanize_bytes(size_bytes)); return True
    except Exception as e:
        print(f"Error getting file size for {filepath}: {e}", file=os.sys.stderr); return False

def get_last_modified_time(filepath):
    try:
        if not os.path.exists(filepath): print("0"); return True # "0" for non-existent as per requirement
        if not os.access(filepath, os.R_OK): print(f"Error: Cannot access file (permission denied) - {filepath}", file=os.sys.stderr); return False
        mtime = os.path.getmtime(filepath)
        print(str(int(mtime))); return True
    except Exception as e:
        print(f"Error getting modification time for {filepath}: {e}", file=os.sys.stderr); return False

def get_recent_ips(logfile, lines_to_check):
    if not os.path.exists(logfile): print(f"Error: Logfile not found - {logfile}", file=os.sys.stderr); return False
    if not os.access(logfile, os.R_OK): print(f"Error: Cannot access logfile (permission denied) - {logfile}", file=os.sys.stderr); return False
    try:
        tail_cmd = ['tail', '-n', str(lines_to_check), logfile]
        process = subprocess.run(tail_cmd, capture_output=True, text=True, check=False)
        if process.returncode != 0 and process.stderr:
            print(f"Error reading logfile with tail: {process.stderr.strip()}", file=os.sys.stderr); return False
        
        unique_ips = set(re.findall(r'srcip=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', process.stdout))
        print(",".join(sorted(list(unique_ips)))); return True
    except FileNotFoundError: print("Error: 'tail' command not found.", file=os.sys.stderr); return False
    except Exception as e: print(f"Error getting recent IPs: {e}", file=os.sys.stderr); return False

def main():
    parser = argparse.ArgumentParser(description="Manage rsyslog and logrotate configurations for FWAnalyzer.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--get-rsyslog-status', action='store_true', help='Get rsyslog service status.')
    group.add_argument('--get-file-size', type=str, metavar='FILEPATH', help='Get size of a file.')
    group.add_argument('--get-last-modified-time', type=str, metavar='FILEPATH', help='Get last modified time (Unix timestamp) of a file.')
    group.add_argument('--get-recent-ips', type=str, metavar='LOGFILE', help='Get recent IPs from a logfile.')
    
    parser.add_argument('--lines', type=int, default=5000, metavar='N', help='Lines to check for --get-recent-ips (default: 5000).')
    parser.add_argument('--ips', type=str, help='Comma-separated IP addresses for rsyslog whitelist.')
    parser.add_argument('--logrotate-enabled', type=str, choices=['true', 'false'], help='Enable/disable logrotate.')
    parser.add_argument('--logrotate-interval', type=str, choices=['daily', 'weekly', 'monthly', 'yearly'], help='Logrotate interval.')
    parser.add_argument('--logrotate-max-size', type=str, help='Logrotate max size (e.g., 100M, 1G).')
    parser.add_argument('--logrotate-keep', type=int, help='Number of log rotations to keep.')

    args = parser.parse_args()

    if args.get_rsyslog_status: exit(0) if get_rsyslog_status() else exit(1)
    if args.get_file_size: exit(0) if get_file_size(args.get_file_size) else exit(1)
    if args.get_last_modified_time: exit(0) if get_last_modified_time(args.get_last_modified_time) else exit(1)
    if args.get_recent_ips:
        if not args.lines > 0: print("Error: --lines must be positive.", file=os.sys.stderr); exit(1)
        exit(0) if get_recent_ips(args.get_recent_ips, args.lines) else exit(1)

    # --- Standard Operations ---
    if args.ips is None or args.logrotate_enabled is None:
        parser.error("--ips and --logrotate-enabled are required for standard configuration operations.")
    
    logrotate_enabled_bool = args.logrotate_enabled.lower() == 'true'
    if logrotate_enabled_bool:
        if not args.logrotate_interval: parser.error("--logrotate-interval is required if logrotate is enabled.")
        if args.logrotate_keep is None: parser.error("--logrotate-keep is required if logrotate is enabled.")
            
    ip_list = [ip.strip() for ip in args.ips.split(',') if ip.strip()] if args.ips else []
    
    print("Starting system configuration update...")
    rsyslog_ok = manage_rsyslog(ip_list)
    logrotate_ok = manage_logrotate(
        enabled=logrotate_enabled_bool,
        interval=args.logrotate_interval,
        max_size=args.logrotate_max_size if args.logrotate_max_size else "",
        keep_rotations=args.logrotate_keep
    )

    print("\n--- Summary ---")
    print(f"Rsyslog configuration: {'Success' if rsyslog_ok else 'Failed'}")
    print(f"Logrotate configuration: {'Success' if logrotate_ok else 'Failed'}")
    exit(0) if rsyslog_ok and logrotate_ok else exit(1)

if __name__ == '__main__':
    main()
