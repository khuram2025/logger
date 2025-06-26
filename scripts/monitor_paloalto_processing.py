#!/usr/bin/env python3
"""
Monitor PaloAlto log processing health and performance
"""

import os
import time
import logging
from datetime import datetime, timedelta
from clickhouse_driver import Client

# Configuration
CH_HOST = 'localhost'
CH_PORT = 9000
CH_USER = 'default'
CH_PASSWORD = 'Read@123'
CH_DB = 'network_logs'
LOG_FILE = '/var/log/paloalto-1004.log'

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s [MONITOR] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/tmp/paloalto-monitor.log')
    ]
)

def check_processing_health():
    """Check the health of PaloAlto log processing"""
    try:
        client = Client(
            host=CH_HOST,
            port=CH_PORT,
            user=CH_USER,
            password=CH_PASSWORD,
            database=CH_DB
        )
        
        # Check recent URL processing
        now = datetime.now()
        hour_ago = now - timedelta(hours=1)
        
        url_count = client.execute("""
            SELECT count(*) FROM pa_urls_optimized 
            WHERE timestamp >= %(hour_ago)s
        """, {'hour_ago': hour_ago})[0][0]
        
        traffic_count = client.execute("""
            SELECT count(*) FROM paloalto_traffic 
            WHERE timestamp >= %(hour_ago)s
        """, {'hour_ago': hour_ago})[0][0]
        
        # Check log file status
        log_size = os.path.getsize(LOG_FILE) if os.path.exists(LOG_FILE) else 0
        log_size_mb = log_size / (1024 * 1024)
        
        # Get latest records
        latest_url = client.execute("""
            SELECT max(timestamp) FROM pa_urls_optimized
        """)[0][0]
        
        latest_traffic = client.execute("""
            SELECT max(timestamp) FROM paloalto_traffic
        """)[0][0]
        
        # Calculate processing lag
        url_lag = (now - latest_url).total_seconds() / 60 if latest_url else 999
        traffic_lag = (now - latest_traffic).total_seconds() / 60 if latest_traffic else 999
        
        # Report status
        status = {
            'timestamp': now,
            'url_records_last_hour': url_count,
            'traffic_records_last_hour': traffic_count,
            'log_file_size_mb': log_size_mb,
            'url_processing_lag_minutes': url_lag,
            'traffic_processing_lag_minutes': traffic_lag,
            'latest_url_record': latest_url,
            'latest_traffic_record': latest_traffic
        }
        
        logging.info(f"Health Check Results:")
        logging.info(f"  URL records (last hour): {url_count}")
        logging.info(f"  Traffic records (last hour): {traffic_count}")
        logging.info(f"  Log file size: {log_size_mb:.1f} MB")
        logging.info(f"  URL processing lag: {url_lag:.1f} minutes")
        logging.info(f"  Traffic processing lag: {traffic_lag:.1f} minutes")
        
        # Check for issues
        issues = []
        if url_count == 0 and url_lag > 30:
            issues.append(f"No URL records processed in last hour (lag: {url_lag:.1f} min)")
        if traffic_count == 0 and traffic_lag > 30:
            issues.append(f"No traffic records processed in last hour (lag: {traffic_lag:.1f} min)")
        if log_size_mb > 1000:
            issues.append(f"Log file is very large ({log_size_mb:.1f} MB)")
        
        if issues:
            logging.warning("Issues detected:")
            for issue in issues:
                logging.warning(f"  - {issue}")
        else:
            logging.info("✅ All systems healthy")
            
        return status
        
    except Exception as e:
        logging.error(f"Health check failed: {e}")
        return None

def check_processing_rate():
    """Check processing rates over different time periods"""
    try:
        client = Client(
            host=CH_HOST,
            port=CH_PORT,
            user=CH_USER,
            password=CH_PASSWORD,
            database=CH_DB
        )
        
        # Check rates for different periods
        periods = [
            ('1 hour', 1),
            ('6 hours', 6),
            ('24 hours', 24)
        ]
        
        logging.info("Processing rates:")
        for period_name, hours in periods:
            start_time = datetime.now() - timedelta(hours=hours)
            
            url_rate = client.execute("""
                SELECT count(*) FROM pa_urls_optimized 
                WHERE timestamp >= %(start_time)s
            """, {'start_time': start_time})[0][0]
            
            traffic_rate = client.execute("""
                SELECT count(*) FROM paloalto_traffic 
                WHERE timestamp >= %(start_time)s
            """, {'start_time': start_time})[0][0]
            
            logging.info(f"  {period_name}: {url_rate} URLs, {traffic_rate} traffic")
            
    except Exception as e:
        logging.error(f"Rate check failed: {e}")

def main():
    """Main monitoring function"""
    logging.info("Starting PaloAlto processing monitor...")
    
    while True:
        try:
            check_processing_health()
            check_processing_rate()
            logging.info("---")
            time.sleep(300)  # Check every 5 minutes
            
        except KeyboardInterrupt:
            logging.info("Monitor stopped by user")
            break
        except Exception as e:
            logging.error(f"Monitor error: {e}")
            time.sleep(60)  # Wait a minute before retrying

if __name__ == '__main__':
    main()