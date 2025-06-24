#!/usr/bin/env python3
"""
URL Parser Watchdog
Monitors the PaloAlto URL parser and restarts it when it gets stuck
"""

import time
import subprocess
import logging
from datetime import datetime
from clickhouse_driver import Client

# Configuration
CHECK_INTERVAL = 60  # Check every minute
STUCK_THRESHOLD = 300  # Consider stuck if no data for 5 minutes
CH_PASSWORD = 'Read@123'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s [URL-Watchdog] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/tmp/url_parser_watchdog.log')
    ]
)

def check_recent_data():
    """Check if URL parser has inserted data recently"""
    try:
        client = Client(host='localhost', port=9000, user='default', password=CH_PASSWORD, database='network_logs')
        
        query = """
            SELECT COUNT(*) as count, MAX(timestamp) as latest 
            FROM pa_urls_optimized 
            WHERE timestamp >= now() - INTERVAL 5 MINUTE
        """
        
        result = client.execute(query)
        if result and len(result) > 0:
            count, latest = result[0]
            logging.info(f"Found {count} records, latest: {latest}")
            return count > 0
        return False
        
    except Exception as e:
        logging.error(f"Error checking data: {e}")
        return False

def restart_service():
    """Restart the URL parser service"""
    try:
        logging.warning("Restarting stuck URL parser service...")
        
        # Kill the service process
        result = subprocess.run(['pkill', '-f', 'paloalto_url_parser.py'], 
                              capture_output=True, text=True)
        time.sleep(5)
        
        # Let systemd restart it automatically
        logging.info("Service should auto-restart via systemd")
        return True
        
    except Exception as e:
        logging.error(f"Error restarting service: {e}")
        return False

def main():
    """Main watchdog loop"""
    logging.info("Starting URL Parser Watchdog")
    last_data_time = time.time()
    
    while True:
        try:
            has_recent_data = check_recent_data()
            current_time = time.time()
            
            if has_recent_data:
                last_data_time = current_time
                logging.debug("URL parser is working normally")
            else:
                time_since_data = current_time - last_data_time
                if time_since_data > STUCK_THRESHOLD:
                    logging.warning(f"No data for {time_since_data:.0f} seconds - restarting parser")
                    if restart_service():
                        last_data_time = current_time  # Reset timer after restart
                
            time.sleep(CHECK_INTERVAL)
            
        except KeyboardInterrupt:
            logging.info("Watchdog stopped by user")
            break
        except Exception as e:
            logging.error(f"Watchdog error: {e}")
            time.sleep(CHECK_INTERVAL)

if __name__ == '__main__':
    main()