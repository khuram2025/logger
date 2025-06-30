#!/usr/bin/env python3

import socket
import time

def send_test_paloalto_log():
    # Sample Palo Alto traffic log in CSV format
    test_log = '1,2024/06/30 15:15:00,012345678901,TRAFFIC,end,2049,2024/06/30 15:15:00,192.168.1.100,8.8.8.8,192.168.1.100,8.8.8.8,Allow-DNS,user1,,dns,vsys1,trust,untrust,ethernet1/1,ethernet1/2,Forward,2024/06/30 15:15:00,12345,1,53123,53,53123,53,0x400000,tcp,allow,200,100,100,2,2024/06/30 15:14:57,3,any,0,123456,0x0,US,US,0,1,1,aged-out,1,2,3,4,vsys1,PaloAlto-FW01,from-policy,,,,,,,,none,,,,rule-uuid'
    
    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        # Send to localhost:5514 from the registered Palo Alto IP
        server_address = ('127.0.0.1', 5514)
        
        # Add syslog priority prefix
        syslog_message = f'<134>{test_log}'
        
        print(f"Sending test Palo Alto log to {server_address[0]}:{server_address[1]}")
        print(f"Log content: {syslog_message[:200]}...")
        
        # Send the log
        sock.sendto(syslog_message.encode('utf-8'), server_address)
        print("Test log sent successfully!")
        
        # Wait a moment
        time.sleep(2)
        
    except Exception as e:
        print(f"Error sending test log: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    send_test_paloalto_log()