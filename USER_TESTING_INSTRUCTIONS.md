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
    *   **System File:** Open `/etc/rsyslog.d/fortigate.conf` on your server (requires sudo).
        *   Look for the block managed by FWAnalyzer:
            ```
            # BEGIN FWANALYZER MANAGED HOSTS
            if ($fromhost-ip == '192.168.1.100') then { # Or your IP, or multiple IPs
                action(
                    type="omfile"
                    file="/var/log/fortigate.log"
                    template="FortiGateRaw"
                )
                stop
            }
            # END FWANALYZER MANAGED HOSTS
            ```
        *   Confirm your new IP is present in the `if (...)` condition.
    *   **Rsyslog Service:** The script attempts to reload rsyslog. Check its status: `sudo systemctl status rsyslog`. Look for recent reload messages.
    *   **Log Processing:** Send a test syslog message from the whitelisted IP.
        Example using `logger` (run from the machine with the whitelisted IP, assuming it can reach the rsyslog server):
        ```bash
        logger -n <your_rsyslog_server_ip> -P 514 -T "This is a test log from 192.168.1.100" 
        ```
        Then, check the `/var/log/fortigate.log` file on your rsyslog server:
        ```bash
        sudo tail -f /var/log/fortigate.log 
        ```
        You should see your test message.

### B. Adding Another Whitelisted IP

1.  Add a second IP address (e.g., `192.168.1.101`) following the same steps as above.
2.  **Verification:**
    *   **UI:** Both IPs should now be listed.
    *   **System File:** `/etc/rsyslog.d/fortigate.conf` should now include both IPs in the condition:
        ```
        if ($fromhost-ip == '192.168.1.100' or $fromhost-ip == '192.168.1.101') then { ... }
        ```
    *   **Log Processing:** Send test logs from both IPs and verify they appear in `/var/log/fortigate.log`.

### C. Deleting a Whitelisted IP

1.  In the "Current Hosts" list, find one of the IPs you added (e.g., `192.168.1.100`).
2.  Click the "Delete" button next to it. Confirm if prompted.
3.  **Verification:**
    *   **UI:** The IP should be removed from the list. The other IP (`192.168.1.101`) should remain.
    *   **System File:** `/etc/rsyslog.d/fortigate.conf` should be updated to only include the remaining IP:
        ```
        if ($fromhost-ip == '192.168.1.101') then { ... }
        ```
    *   **Log Processing:**
        *   Send a test log from the remaining IP (`192.168.1.101`). It **should** appear in `/var/log/fortigate.log`.
        *   Send a test log from the deleted IP (`192.168.1.100`). It **should NOT** appear in `/var/log/fortigate.log`.

### D. Deleting All Whitelisted IPs

1.  Delete the last remaining IP from the list.
2.  **Verification:**
    *   **UI:** The "Current Hosts" list should indicate no hosts are configured.
    *   **System File:** `/etc/rsyslog.d/fortigate.conf` should now contain a condition that is effectively always false:
        ```
        if ($fromhost-ip == '255.255.255.255' and $fromhost-ip == '255.255.255.254') then { ... }
        ```
    *   **Log Processing:** Send test logs from any of the previously whitelisted IPs. None should appear in `/var/log/fortigate.log`.

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
    *   **System File:** Check the content of `/etc/logrotate.d/fwanalyzer-fortigate` (this is the filename defined in `scripts/apply_sys_config.py`). It should look like this:
        ```
        /var/log/fortigate.log {
            daily
            size 10M
            rotate 3
            missingok
            notifempty
            compress
            delaycompress
        }
        ```

### B. Testing Log Rotation (Requires Generating Logs and Time)

This is the most complex part to test immediately as logrotate typically runs on a daily cron schedule.

1.  **Generate Logs:** Ensure enough logs are being sent to `/var/log/fortigate.log` to exceed the `10M` size limit. If you don't have live FortiGate traffic, you might need to script sending a large volume of test messages.
    ```bash
    # Example: send many logs (be careful with this on a shared system)
    # You might need to run this from a whitelisted IP if rsyslog rules are active
    for i in $(seq 1 200000); do logger -n <your_rsyslog_server_ip> -P 514 -T "Large volume test log entry $i"; done 
    ```
    Check the size of `/var/log/fortigate.log`: `ls -lh /var/log/fortigate.log`.

2.  **Force Logrotate (Option 1):**
    *   To test the rotation without waiting for the cron job, you can force logrotate to run:
        ```bash
        sudo logrotate -f /etc/logrotate.d/fwanalyzer-fortigate 
        # or sudo logrotate -f /etc/logrotate.conf (if you want to run all logrotate jobs)
        ```
    *   After running, check the `/var/log/` directory:
        ```bash
        ls -l /var/log/fortigate*
        ```
        You should see rotated files like `fortigate.log.1`, `fortigate.log.2.gz`, etc., depending on how many times it has rotated and your `keep_rotations` setting. The current `fortigate.log` should be smaller if it was rotated due_to size.

3.  **Wait for Scheduled Rotation (Option 2):**
    *   Simply wait for the system's daily cron job that runs logrotate (usually early morning).
    *   Check the logs the next day.

4.  **Verify Rotation Count:** Over a few days (or by forcing rotation multiple times and adjusting file timestamps if you're very advanced), verify that no more than 3 rotated logs (`fortigate.log.1`, `fortigate.log.2.gz`, `fortigate.log.3.gz`) are kept, plus the active `fortigate.log`.

### C. Changing Log Retention Policy

1.  Change the policy:
    *   **Max Size:** `20M`
    *   **Keep Rotations:** `5`
2.  Click "Save Retention Policy".
3.  **Verification:**
    *   **UI:** Values should be updated.
    *   **System File:** `/etc/logrotate.d/fwanalyzer-fortigate` should reflect these new values.
    *   Testing the actual rotation behavior will again require generating logs and waiting/forcing rotation.

### D. Disabling Log Retention

1.  Uncheck the "Enabled" box.
2.  Click "Save Retention Policy".
3.  **Verification:**
    *   **UI:** "Enabled" should be unchecked.
    *   **System File:** The file `/etc/logrotate.d/fwanalyzer-fortigate` should be **deleted**. Check with `ls /etc/logrotate.d/fwanalyzer-fortigate`.

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
