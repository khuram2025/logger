from clickhouse_driver import Client
from dashboard.constants import CH_HOST, CH_PORT, CH_USER, CH_PASSWORD, CH_DB

def get_clickhouse_client():
    """Get a ClickHouse client instance"""
    return Client(
        host=CH_HOST,
        port=CH_PORT,
        user=CH_USER,
        password=CH_PASSWORD,
        database=CH_DB
    )