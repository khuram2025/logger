#!/usr/bin/env python3
"""
ClickHouse Data Cleanup Script

This script manages data retention for ClickHouse tables based on 
configured retention policies.
"""

import os
import sys
import json
import logging
from datetime import datetime, timedelta
from clickhouse_driver import Client

# Add the project directory to Python path
sys.path.append('/home/net/analyzer')

def setup_logging():
    """Setup logging configuration"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('/home/net/analyzer/logs/clickhouse_cleanup.log'),
            logging.StreamHandler()
        ]
    )

def load_config():
    """Load storage configuration"""
    config_file = '/home/net/analyzer/config/clickhouse_storage.json'
    default_config = {
        'data_retention_days': 90,
        'enable_auto_cleanup': True
    }
    
    try:
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                config = json.load(f)
                return {
                    'retention_days': config.get('data_retention_days', 90),
                    'enabled': config.get('enable_auto_cleanup', True)
                }
    except Exception as e:
        logging.error(f"Failed to load config: {e}")
    
    return {
        'retention_days': default_config['data_retention_days'],
        'enabled': default_config['enable_auto_cleanup']
    }

def get_clickhouse_client():
    """Get ClickHouse client connection"""
    try:
        return Client(
            host='localhost',
            port=9000,
            user='default',
            password='Read@123'
        )
    except Exception as e:
        logging.error(f"Failed to connect to ClickHouse: {e}")
        return None

def cleanup_table_data(client, table_name, retention_days, dry_run=False):
    """Clean up old data from a specific table"""
    try:
        # Calculate cutoff date
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        cutoff_str = cutoff_date.strftime('%Y-%m-%d')
        
        # Check if table has date column
        columns_query = f"DESCRIBE TABLE network_logs.{table_name}"
        columns = client.execute(columns_query)
        
        date_column = None
        for col in columns:
            col_name = col[0].lower()
            if 'date' in col_name or 'time' in col_name:
                date_column = col[0]
                break
        
        if not date_column:
            logging.warning(f"No date column found in table {table_name}")
            return 0
        
        # Count records to be deleted
        count_query = f"""
        SELECT count() FROM network_logs.{table_name} 
        WHERE toDate({date_column}) < '{cutoff_str}'
        """
        
        try:
            count_result = client.execute(count_query)
            records_to_delete = count_result[0][0] if count_result else 0
        except Exception as e:
            logging.warning(f"Could not count records in {table_name}: {e}")
            return 0
        
        if records_to_delete == 0:
            logging.info(f"No old records to delete in {table_name}")
            return 0
        
        if dry_run:
            logging.info(f"DRY RUN: Would delete {records_to_delete} records from {table_name} older than {cutoff_str}")
            return records_to_delete
        
        # Delete old records
        delete_query = f"""
        ALTER TABLE network_logs.{table_name} 
        DELETE WHERE toDate({date_column}) < '{cutoff_str}'
        """
        
        logging.info(f"Deleting {records_to_delete} records from {table_name} older than {cutoff_str}")
        client.execute(delete_query)
        
        return records_to_delete
        
    except Exception as e:
        logging.error(f"Error cleaning up table {table_name}: {e}")
        return 0

def get_table_info(client):
    """Get information about tables and their sizes"""
    try:
        query = """
        SELECT 
            table,
            sum(rows) as total_rows,
            formatReadableSize(sum(bytes_on_disk)) as size_on_disk,
            min(min_date) as oldest_date,
            max(max_date) as newest_date
        FROM system.parts 
        WHERE database = 'network_logs' AND active
        GROUP BY table
        ORDER BY sum(bytes_on_disk) DESC
        """
        
        return client.execute(query)
    except Exception as e:
        logging.error(f"Error getting table info: {e}")
        return []

def main():
    """Main cleanup function"""
    setup_logging()
    
    # Load configuration
    config = load_config()
    
    if not config['enabled']:
        logging.info("Auto cleanup is disabled")
        return
    
    retention_days = config['retention_days']
    logging.info(f"Starting data cleanup with {retention_days} days retention")
    
    # Get ClickHouse client
    client = get_clickhouse_client()
    if not client:
        logging.error("Could not connect to ClickHouse")
        return
    
    try:
        # Get table information
        tables_info = get_table_info(client)
        
        if not tables_info:
            logging.warning("No tables found or could not get table info")
            return
        
        total_deleted = 0
        
        for table_info in tables_info:
            table_name = table_info[0]
            total_rows = table_info[1]
            size_on_disk = table_info[2]
            
            logging.info(f"Processing table {table_name} ({total_rows} rows, {size_on_disk})")
            
            # Clean up the table
            deleted_count = cleanup_table_data(client, table_name, retention_days)
            total_deleted += deleted_count
            
            if deleted_count > 0:
                logging.info(f"Deleted {deleted_count} records from {table_name}")
        
        logging.info(f"Cleanup completed. Total records deleted: {total_deleted}")
        
        # Update cleanup log
        log_cleanup_run(total_deleted, retention_days)
        
    except Exception as e:
        logging.error(f"Error during cleanup: {e}")
    finally:
        try:
            client.disconnect()
        except:
            pass

def log_cleanup_run(deleted_count, retention_days):
    """Log cleanup run information"""
    log_file = '/home/net/analyzer/config/clickhouse_cleanup_log.json'
    
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'records_deleted': deleted_count,
        'retention_days': retention_days,
        'status': 'completed'
    }
    
    try:
        # Load existing log
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                log_data = json.load(f)
        else:
            log_data = {'cleanup_runs': []}
        
        # Add new entry
        if 'cleanup_runs' not in log_data:
            log_data['cleanup_runs'] = []
        
        log_data['cleanup_runs'].append(log_entry)
        
        # Keep only last 50 entries
        log_data['cleanup_runs'] = log_data['cleanup_runs'][-50:]
        
        # Update summary
        log_data['last_run'] = log_entry
        log_data['total_runs'] = len(log_data['cleanup_runs'])
        
        # Save log
        with open(log_file, 'w') as f:
            json.dump(log_data, f, indent=2)
            
    except Exception as e:
        logging.error(f"Failed to update cleanup log: {e}")

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='ClickHouse Data Cleanup')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be deleted without actually deleting')
    parser.add_argument('--retention-days', type=int, help='Override retention days from config')
    
    args = parser.parse_args()
    
    if args.dry_run:
        logging.info("Running in DRY RUN mode - no data will be deleted")
    
    main()