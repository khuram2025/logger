import os
from clickhouse_driver import Client # Assume this can be imported

CH_HOST = os.environ.get('CH_HOST', 'localhost')
CH_PORT = int(os.environ.get('CH_PORT', 9000)) # clickhouse_driver expects int
CH_USER = os.environ.get('CH_USER', 'default')
CH_PASSWORD = os.environ.get('CH_PASSWORD', '') # Default to empty if not set
CH_DB = os.environ.get('CH_DB', 'network_logs')

def get_clickhouse_client():
    try:
        client = Client(
            host=CH_HOST,
            port=CH_PORT,
            user=CH_USER,
            password=CH_PASSWORD,
            database=CH_DB,
            # Adding a timeout for connection attempts
            connect_timeout=10, # seconds
            send_receive_timeout=30 # seconds for query execution
        )
        # Test connection (optional, but good for immediate feedback)
        # client.execute('SELECT 1') 
        # print("Successfully connected to ClickHouse.") # For debugging
        return client
    except Exception as e:
        print(f"Error connecting to ClickHouse: {e}") # Or use logging
        return None
