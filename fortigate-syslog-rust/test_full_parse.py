#!/usr/bin/env python3

# Raw log from tcpdump - with syslog priority
raw_log = "<14>Jul  3 15:11:17 SMO-RUH-MU04-F09R14-DC-FW1.smo.sa 1,2025/07/03 15:11:17,025201005457,TRAFFIC,end,2817,2025/07/03 15:11:17,10.10.200.15,103.235.46.102,0.0.0.0,0.0.0.0,Allow Internet Trrafic,smo\\a.alhejaili,,ping,vsys1,SMO-WIFI-EMPLOYEE,HQ_DC_CORE,ae1.201,ae1.2004,H_SMO_LFP,2025/07/03 15:11:17,646044,1,0,0,0,0,0x100019,icmp,allow,110,110,0,1,2025/07/03 15:11:09,0,any,,7502587801702064241,0x8000000000000000,10.0.0.0-10.255.255.255,Hong Kong,,1,0,aged-out,210,70,0,0,,SMO-RUH-MU04-F09R14-DC-FW1,from-policy,,,0,,0,,N/A,0,0,0,0,ce9269f2-931f-47b0-8553-a7bc9ed91e93,0,0,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,2025-07-03T15:11:17.571+03:00,,,internet-utility,general-internet,network-protocol,2,\"has-known-vulnerability,tunnel-other-application,pervasive-use\",,untunneled,no,no,0,NonProxyTraffic,"

print("Original log length:", len(raw_log))
print("First 100 chars:", raw_log[:100])

# Strip syslog priority (what strip_syslog_priority does)
if raw_log.startswith('<'):
    end_pos = raw_log.find('>')
    if end_pos > 0 and end_pos < 10:
        clean_message = raw_log[end_pos + 1:]
        print("\nAfter stripping priority:")
        print("First 100 chars:", clean_message[:100])
        
        # What the Palo Alto parser looks for
        csv_start = clean_message.find("1,")
        if csv_start >= 0:
            print(f"\nFound CSV start at position {csv_start}")
            csv_part = clean_message[csv_start:]
            print("CSV part first 100 chars:", csv_part[:100])
            
            # Count fields
            fields = csv_part.split(',')
            print(f"\nNumber of fields: {len(fields)}")
            
            # Check key fields
            if len(fields) > 30:
                print("\n✓ Has enough fields for Palo Alto TRAFFIC log")
                print(f"Type field (3): {fields[3]}")
                print(f"Src IP (7): {fields[7]}")
                print(f"Dst IP (8): {fields[8]}")
                print(f"Action (30): {fields[30]}")
        else:
            print("\n✗ Could not find '1,' pattern for CSV start")