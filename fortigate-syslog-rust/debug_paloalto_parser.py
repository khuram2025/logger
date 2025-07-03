#!/usr/bin/env python3
import re

# Sample log captured from tcpdump
sample_log = "<14>Jul  3 14:21:27 SMO-RUH-MU04-F09R14-DC-FW1.smo.sa 1,2025/07/03 14:21:27,025201005457,TRAFFIC,end,2817,2025/07/03 14:21:27,10.10.200.21,10.10.108.20,0.0.0.0,0.0.0.0,From_Users_Or_Servers_To_LDAP,smo\\ra.almasoud,,incomplete,vsys1,SMO-WIFI-EMPLOYEE,SERVER,ae1.201,ae3.108,H_SMO_LFP,2025/07/03 14:21:27,4319108,1,59781,389,0,0,0x1b,tcp,allow,388,190,198,6,2025/07/03 14:21:11,0,any,,7502587801701290874,0x8000000000000000,10.0.0.0-10.255.255.255,10.0.0.0-10.255.255.255,,3,3,tcp-rst-from-server,210,70,0,0,,SMO-RUH-MU04-F09R14-DC-FW1,from-policy,,,0,,0,,N/A,0,0,0,0,5f5c3012-7352-4dce-8e5b-ef5d82150ec3,0,0,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,2025-07-03T14:21:27.945+03:00,,,unknown,unknown,unknown,1,,,incomplete,no,no,0,NonProxyTraffic,"

# Strip syslog header
if sample_log.startswith('<'):
    end_pos = sample_log.find('>')
    if end_pos > 0:
        log_without_priority = sample_log[end_pos + 1:]
        print(f"Log without priority: {log_without_priority[:100]}...")
        
        # Find where CSV data starts (after hostname)
        csv_start = log_without_priority.find('1,')
        if csv_start > 0:
            csv_part = log_without_priority[csv_start:]
            print(f"\nCSV part: {csv_part[:100]}...")
            
            # Split CSV fields
            fields = csv_part.split(',')
            print(f"\nNumber of fields: {len(fields)}")
            
            # Print important fields
            print("\nImportant fields:")
            print(f"Field 0 (FUTURE_USE): {fields[0] if len(fields) > 0 else 'N/A'}")
            print(f"Field 1 (receive_time): {fields[1] if len(fields) > 1 else 'N/A'}")
            print(f"Field 2 (serial_number): {fields[2] if len(fields) > 2 else 'N/A'}")
            print(f"Field 3 (type): {fields[3] if len(fields) > 3 else 'N/A'}")
            print(f"Field 7 (src_ip): {fields[7] if len(fields) > 7 else 'N/A'}")
            print(f"Field 8 (dst_ip): {fields[8] if len(fields) > 8 else 'N/A'}")
            print(f"Field 11 (rule_name): {fields[11] if len(fields) > 11 else 'N/A'}")
            print(f"Field 24 (src_port): {fields[24] if len(fields) > 24 else 'N/A'}")
            print(f"Field 25 (dst_port): {fields[25] if len(fields) > 25 else 'N/A'}")
            print(f"Field 30 (action): {fields[30] if len(fields) > 30 else 'N/A'}")
            
            # Check if it's a TRAFFIC log
            if len(fields) > 3 and fields[3] == 'TRAFFIC':
                print("\n✓ This is a valid TRAFFIC log")
                
                # Check IPs
                if len(fields) > 8:
                    src_ip = fields[7]
                    dst_ip = fields[8]
                    print(f"\nSource IP: {src_ip} (valid: {src_ip != '0.0.0.0' and src_ip != ''})")
                    print(f"Dest IP: {dst_ip} (valid: {dst_ip != '0.0.0.0' and dst_ip != ''})")