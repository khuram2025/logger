net@edl:/etc/rsyslog.d$ cat 50-default.conf
#  Default log rules for rsyslog on Ubuntu:

# Log all the mail messages in one place.
mail.*            -/var/log/mail.log

# Emergencies are sent to everybody logged in.
*.emerg           :omusrmsg:*

if ($fromhost-ip != '192.168.100.221') then {
    *.info;mail.none;authpriv.none;cron.none    /var/log/syslog
}

# Authentication logs
auth,authpriv.*   /var/log/auth.log

# Cron logs
cron.*            /var/log/cron.log

# Kernel messages
kern.*            -/var/log/kern.log

# FTP logins
auth.*;mail.none  /var/log/auth.log

# News server
news.crit         /var/log/news/news.crit
news.err          /var/log/news/news.err
news.notice       /var/log/news/news.notice
net@edl:/etc/rsyslog.d$ cat fortigate.conf
#### start fortigate.conf ####

# Load UDP syslog listener only once
module(load="imudp")

# Template for clean FortiGate messages (without PRI)
template(name="FortiGateRaw" type="string" string="%rawmsg-after-pri%\n")

# Log all messages coming from 192.168.100.221 only
if ($fromhost-ip == '192.168.100.221') then {
    action(
        type="omfile"
        file="/var/log/fortigate.log"
        template="FortiGateRaw"
    )
    stop
}

#### end fortigate.conf ####


echo -e "\n-- Current FortiGate Log File --"; stat /var/log/fortigate.log; echo -e "\n-- Rotated Log Files --"; ls -lh /var/log/fortigate.log* | sort -V

## Troubleshooting System Configuration Features

If you encounter issues with the Rsyslog host whitelisting or Log Retention features managed from the Django dashboard, here are some commands to run on the server's command line interface (CLI) for diagnostics:

### Rsyslog Issues

1.  **Check Rsyslog Service Status:**
    ```bash
    sudo systemctl status rsyslog
    ```
    (Look for "Active: active (running)" and any error messages.)

2.  **Validate Rsyslog Configuration:**
    ```bash
    sudo rsyslogd -N1
    ```
    (This will report syntax errors in any rsyslog configuration files.)

3.  **View Live FortiGate Logs:**
    ```bash
    sudo tail -f /var/log/fortigate.log
    ```
    (To see if logs from expected IPs are appearing after configuration changes.)

4.  **Inspect Managed Rsyslog Rule File:**
    ```bash
    sudo cat /etc/rsyslog.d/fortigate.conf
    ```
    (Verify the `if ($fromhost-ip == ...)` block reflects the IPs configured in the dashboard. Pay attention to the `# BEGIN FWANALYZER MANAGED HOSTS` and `# END FWANALYZER MANAGED HOSTS` markers.)

5.  **Manually Reload Rsyslog (if needed):**
    ```bash
    sudo systemctl reload rsyslog
    ```

### Logrotate Issues

1.  **Inspect Managed Logrotate Configuration File:**
    ```bash
    sudo cat /etc/logrotate.d/fwanalyzer-fortigate
    ```
    (Verify it reflects the policy set in the dashboard. The filename `fwanalyzer-fortigate` is based on the helper script; adjust if different.)

2.  **Debug Logrotate for the Specific Configuration (Dry Run):**
    ```bash
    sudo logrotate -df /etc/logrotate.d/fwanalyzer-fortigate
    ```
    (This shows what logrotate *would* do without actually rotating files. Look for errors or misinterpretations of the config.)

3.  **Force Logrotate for the Specific Configuration:**
    ```bash
    sudo logrotate -f /etc/logrotate.d/fwanalyzer-fortigate
    ```
    (Use with caution. This forces rotation for this specific file.)

4.  **Check General Logrotate Status (often logged by cron):**
    ```bash
    # Check cron logs, may vary by system (e.g., /var/log/cron or journalctl -u cron)
    # Look for logrotate job executions and any errors.
    # Logrotate status might also be in /var/lib/logrotate/status or similar.
    ```

### Helper Script and Permissions

1.  **Verify Sudoers Configuration:**
    Ensure your `/etc/sudoers` file (or a file in `/etc/sudoers.d/`) correctly allows the web server user (e.g., `www-data`) to run the `scripts/apply_sys_config.py` script without a password.
    Example line (replace user and path):
    `www-data ALL=(ALL) NOPASSWD: /path/to/your/project/scripts/apply_sys_config.py`
    Use `sudo visudo` to edit.

2.  **Check Helper Script Path:**
    Verify the absolute path to `scripts/apply_sys_config.py` used in `dashboard/views.py` is correct for your server environment.

3.  **Manually Run Helper Script (for deep debugging):**
    You can try running the script manually from the command line with the same arguments the Django view would use. This can help isolate issues.
    Example (adjust path and arguments as needed):
    ```bash
    sudo /path/to/your/project/env/bin/python /path/to/your/project/scripts/apply_sys_config.py --ips "1.2.3.4" 
    # (You might need to activate your virtualenv if running directly)
    ```
    Observe any errors printed by the script.

