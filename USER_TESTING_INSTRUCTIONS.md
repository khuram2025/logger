# User Testing Instructions for System Configuration

These instructions will guide you through testing the new System Configuration features, which allow managing rsyslog whitelisted IPs and logrotate policies for FortiGate logs.

## I. Prerequisite: Sudo Permissions

Before you begin, it is **CRITICAL** to ensure that the user running the Django web server (commonly `www-data`, but it might differ based on your setup) has passwordless sudo permission to execute the `scripts/apply_sys_config.py` script.

1.  **Identify the web server user:**
    *   If you are using Apache, it's often `www-data`.
    *   If you are using Nginx, it might also be `www-data` or `nginx`.
    *   If running the Django development server (`manage.py runserver`), it's the user you're currently logged in as. For production-like testing, ensure you test with the actual production web server user in mind.

2.  **Edit the sudoers file:**
    *   Open the sudoers file for editing by running: `sudo visudo`
    *   Add the following line at the end of the file, replacing `/path/to/your/project/scripts/apply_sys_config.py` with the **absolute path** to the script in your deployment, and `your_web_server_user` with the correct user:
        ```
        your_web_server_user ALL=(ALL) NOPASSWD: /path/to/your/project/scripts/apply_sys_config.py
        ```
        **Example:** If your project is in `/srv/fwanalyzer` and your web server user is `www-data`, the line would be:
        ```
        www-data ALL=(ALL) NOPASSWD: /srv/fwanalyzer/scripts/apply_sys_config.py
        ```

3.  **Save and exit** the editor. `visudo` will check the syntax before saving.

**Warning:** Incorrectly editing the `sudoers` file can lock you out of `sudo`. Be very careful.

## II. Navigating to System Configuration

1.  Start the Django application.
2.  Open your web browser and navigate to the Django dashboard.
3.  Find and click on the "System Configuration" link/menu item. (Assuming this link is added to `dashboard/base.html` or a similar navigation template, which was not part of this series of subtasks. If not present, you might need to navigate directly to the URL, typically `/system-config/`).

## III. Testing Rsyslog Whitelisted IPs

You'll need a way to send syslog messages from different IP addresses to test this. You can use tools like `logger` or a dedicated syslog sender. Ensure your rsyslog server is configured to listen on UDP port 514 (this is standard but check your main rsyslog config if issues arise).

### A. Adding a New Whitelisted IP

1.  On the "System Configuration" page, find the "Rsyslog Hosts" section.
2.  In the input field under "Add Host", enter a valid IP address (e.g., `192.168.1.100`) that you can send syslog messages from.
3.  Click the "Add Host" button.
4.  **Verification:**
    *   **UI:** The IP address should appear in the "Current Hosts" list on the page. A success message should be displayed.
    *   **UI:** The IP address should appear in the "Current Whitelisted Hosts" table. A success message should be displayed. The "Log Size" for this new IP should initially be small or "N/A" (if no logs yet). "Last Seen" might show "Never" or an old date. "Status" might be "Inactive".
    *   **Rsyslog System File:** Open `/etc/rsyslog.d/90-fwanalyzer-hosts.conf` (or the filename specified in `scripts/apply_sys_config.py` as `FWANALYZER_RSYSLOG_CONF_FILE`) on your server (requires sudo).
        *   Look for the block managed by FWAnalyzer (between `# BEGIN FWANALYZER MANAGED RSYSLOG CONFIG` and `# END FWANALYZER MANAGED RSYSLOG CONFIG` markers).
        *   Confirm the presence of these templates:
            ```
            template(name="FWAnalyzerRawMsg" type="string" string="%rawmsg-after-pri%\\n")
            template(name="FWAnalyzerPerHostFile" type="string" string="/var/log/fwanalyzer-hosts/%FROMHOST-IP%.log")
            ```
        *   Confirm your new IP is present in the `if (...)` condition:
            ```
            if ($fromhost-ip == '192.168.1.100') then {
                action(type="omfile" dynaFile="FWAnalyzerPerHostFile" template="FWAnalyzerRawMsg")
                stop
            }
            ```
    *   **Rsyslog Service:** The script attempts to reload rsyslog. Check its status: `sudo systemctl status rsyslog`. Look for recent reload messages.
    *   **Log Directory Creation:** Verify the directory `/var/log/fwanalyzer-hosts/` exists:
        ```bash
        ls -ld /var/log/fwanalyzer-hosts/
        ```
        (Check its permissions too; it should be writable by the syslog user/group).
    *   **Log Processing & Per-Host File Creation:** Send a test syslog message from the whitelisted IP.
        Example using `logger` (run from the machine with the whitelisted IP, assuming it can reach the rsyslog server):
        ```bash
        logger -n <your_rsyslog_server_ip> -P 514 -T "This is a per-host test log from 192.168.1.100" 
        ```
        Then, check for the individual log file in `/var/log/fwanalyzer-hosts/`:
        ```bash
        sudo ls -l /var/log/fwanalyzer-hosts/
        sudo tail -f /var/log/fwanalyzer-hosts/192.168.1.100.log 
        ```
        You should see your test message in the `192.168.1.100.log` file.
    *   **UI Update (after a minute or page refresh):**
        *   Refresh the "System Configuration" page.
        *   The "Log Size" for `192.168.1.100` should update to reflect the size of the new log file.
        *   The "Status" should change to "Active".
        *   The "Last Seen" time should update to the current time (or very recent).

### B. Adding Another Whitelisted IP

1.  Add a second IP address (e.g., `192.168.1.101`) following the same steps as above.
2.  **Verification:**
    *   **UI:** Both IPs should now be listed, each with its own log size, status, and last seen time.
    *   **Rsyslog System File:** `/etc/rsyslog.d/90-fwanalyzer-hosts.conf` should now include both IPs in the condition:
        ```
        if ($fromhost-ip == '192.168.1.100' or $fromhost-ip == '192.168.1.101') then { ... }
        ```
    *   **Log Processing:** Send test logs from both IPs. Verify that:
        *   `192.168.1.100.log` gets logs from `192.168.1.100`.
        *   `192.168.1.101.log` gets logs from `192.168.1.101`.
        *   Refresh the UI to see updated sizes, "Active" status, and "Last Seen" times for both.

### C. Deleting a Whitelisted IP

1.  In the "Current Whitelisted Hosts" table, find one of the IPs you added (e.g., `192.168.1.100`).
2.  Click the "Delete" button next to it. Confirm if prompted.
3.  **Verification:**
    *   **UI:** The IP `192.168.1.100` should be removed from the list. The other IP (`192.168.1.101`) should remain.
    *   **Rsyslog System File:** `/etc/rsyslog.d/90-fwanalyzer-hosts.conf` should be updated to only include the remaining IP:
        ```
        if ($fromhost-ip == '192.168.1.101') then { ... }
        ```
    *   **Log Processing:**
        *   Send a test log from the remaining IP (`192.168.1.101`). It **should** appear in `/var/log/fwanalyzer-hosts/192.168.1.101.log`.
        *   The individual log file `/var/log/fwanalyzer-hosts/192.168.1.100.log` will **remain on the filesystem** (rsyslog doesn't delete it), but no new logs should be added to it.
        *   After some time (e.g., > 24 hours, or if you manually make the file older), its status on the UI might revert to "Inactive" if it were re-added, but since it's deleted from UI, it won't be shown.

### D. Deleting All Whitelisted IPs

1.  Delete the last remaining IP from the list.
2.  **Verification:**
    *   **UI:** The "Current Whitelisted Hosts" table should indicate no hosts are configured.
    *   **Rsyslog System File:** `/etc/rsyslog.d/90-fwanalyzer-hosts.conf` should still define the templates but the condition block will be effectively always false:
        ```
        if ($fromhost-ip == '255.255.255.255' and $fromhost-ip == '255.255.255.254') then { ... }
        ```
    *   **Log Processing:** Send test logs from any of the previously whitelisted IPs. None should appear in any files within `/var/log/fwanalyzer-hosts/`. (The old files will still be there but won't be updated).

### E. Testing Invalid IP Input

1.  Try adding an invalid IP address (e.g., "notanip", "192.168.1.300").
2.  **Verification:**
    *   **UI:** An error message should be displayed on the page indicating the input is invalid. The IP should not be added to the list.
    *   **System File:** `/etc/rsyslog.d/fortigate.conf` should not have changed.

## IV. Testing Log Retention Policy

### A. Setting an Initial Policy

1.  On the "System Configuration" page, find the "Log Retention Policy" section.
2.  Configure the policy as follows:
    *   **Enabled:** Check the box (true).
    *   **Interval:** Select "Daily".
    *   **Max Size:** Enter `10M` (10 Megabytes).
    *   **Keep Rotations:** Enter `3`.
3.  Click "Save Retention Policy".
4.  **Verification:**
    *   **UI:** The form fields should retain your saved values. A success message should be displayed.
    *   **System File:** Check the content of `/etc/logrotate.d/fwanalyzer-hosts` (or the filename specified in `scripts/apply_sys_config.py` as `FWANALYZER_LOGROTATE_CONF_FILE`). It should now target the per-host log directory:
        ```
        /var/log/fwanalyzer-hosts/*.log {
            daily
            size 10M
            rotate 3
            missingok
            notifempty
            compress
            delaycompress
        }
        ```
    *   **UI Note:** The "Current FortiGate Log Size" displayed on the UI still refers to the main `/var/log/fortigate.log`. This is separate from the per-host log sizes.

### B. Testing Log Rotation (Requires Generating Logs and Time)

This testing is now for the individual log files in `/var/log/fwanalyzer-hosts/`.

1.  **Generate Logs for Whitelisted IPs:** Ensure enough logs are being sent from your whitelisted IPs (e.g., `192.168.1.101`) to their respective files in `/var/log/fwanalyzer-hosts/` to exceed the `10M` size limit for at least one of them.
    ```bash
    # Example: send many logs to 192.168.1.101.log
    for i in $(seq 1 200000); do logger -n <your_rsyslog_server_ip> -P 514 -T "Large volume test log entry $i for 192.168.1.101"; done 
    ```
    Check the size of individual log files: `ls -lh /var/log/fwanalyzer-hosts/`.

2.  **Force Logrotate (Option 1):**
    *   To test the rotation for the per-host logs:
        ```bash
        sudo logrotate -f /etc/logrotate.d/fwanalyzer-hosts 
        ```
    *   After running, check the `/var/log/fwanalyzer-hosts/` directory:
        ```bash
        ls -l /var/log/fwanalyzer-hosts/
        ```
        You should see rotated files like `192.168.1.101.log.1`, `192.168.1.101.log.2.gz`, etc., for any file that met the rotation criteria. The original files (e.g., `192.168.1.101.log`) should be smaller if they were rotated.

3.  **Wait for Scheduled Rotation (Option 2):**
    *   As before, wait for the system's daily cron job.
    *   Check the `/var/log/fwanalyzer-hosts/` directory the next day.

4.  **Verify Rotation Count:** For each IP that has rotated, verify that no more than 3 rotated logs are kept, plus the active log file for that IP.

### C. Changing Log Retention Policy

1.  Change the policy in the UI:
    *   **Max Size:** `20M`
    *   **Keep Rotations:** `5`
2.  Click "Save Retention Policy".
3.  **Verification:**
    *   **UI:** Values should be updated.
    *   **System File:** `/etc/logrotate.d/fwanalyzer-hosts` should reflect these new values (still targeting `/var/log/fwanalyzer-hosts/*.log`).
    *   Test rotation behavior as above; it will now apply to all `*.log` files in the directory with the new settings.

### D. Disabling Log Retention

1.  Uncheck the "Enabled" box in the UI.
2.  Click "Save Retention Policy".
3.  **Verification:**
    *   **UI:** "Enabled" should be unchecked.
    *   **System File:** The file `/etc/logrotate.d/fwanalyzer-hosts` should be **deleted**. Check with `ls /etc/logrotate.d/fwanalyzer-hosts`.

### E. Testing Invalid Log Retention Input

1.  Try entering invalid data for "Max Size" (e.g., "100X", "abc").
2.  Click "Save Retention Policy".
3.  **Verification:**
    *   **UI:** An error message should be displayed detailing the invalid format for "Max Size". The policy should not be saved with invalid data.
    *   **System File:** The logrotate configuration file should not change if the form submission failed.

## V. General Error Handling

1.  **Script Execution Failure:** If the `apply_sys_config.py` script fails for any reason (e.g., `sudo` permissions are incorrect, script has a bug not caught in dry run), the UI should display a comprehensive error message including `stdout` and `stderr` from the script.
    *   You could simulate this by temporarily breaking the `sudoers` rule or introducing a syntax error into the Python script (do this in a safe test environment only and revert immediately).
2.  Verify that even if the script application fails, the database changes (e.g., new IP added to DB) are either rolled back or the UI provides clear indication of the partial success/failure. (Note: The current implementation saves to DB first, then tries to apply. There's no automatic DB rollback on script failure).

Please report any issues, unexpected behavior, or unclear parts of these instructions.
Happy Testing!Okay, I have created the `USER_TESTING_INSTRUCTIONS.md` file with detailed steps for the user to test the new rsyslog and logrotate configuration features. This includes prerequisites, navigation, specific test cases for adding/deleting IPs, changing log retention policies, and verifying the changes on the system and through log processing. It also covers testing invalid inputs and error handling.

All pre-testing checks and the preparation of testing instructions are now complete.
