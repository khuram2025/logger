#!/usr/bin/env python3

import socket
import time

def send_test_fortigate_log():
    # Test FortiGate format log but from Palo Alto IP
    test_log = 'date=2024-06-30 time=15:20:00 devname="PaloAlto-FW01" devid="PA123456" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" eventtime=1719758400 srcip=192.168.1.200 srcport=45678 srcintf="ethernet1/1" srcintfrole="trust" dstip=8.8.4.4 dstport=53 dstintf="ethernet1/2" dstintfrole="untrust" proto=17 action="accept" policyid=1 service="DNS" duration=123 sentbyte=64 rcvdbyte=128 sentpkt=1 rcvdpkt=1'
    
    # Create UDP socket and bind to Palo Alto IP
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        # Bind to a local address (simulate coming from Palo Alto IP)
        # Note: This won't actually change the source IP but will test the parsing
        server_address = ('127.0.0.1', 5514)
        
        # Add syslog priority prefix
        syslog_message = f'<134>{test_log}'
        
        print(f"Sending test FortiGate-format log to {server_address[0]}:{server_address[1]}")
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
    send_test_fortigate_log()