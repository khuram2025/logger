import ipaddress

def get_ip_filter_clause(ip_filter, ip_field_name):
    """Generate SQL WHERE clause for IP filtering"""
    if not ip_filter:
        return None
    
    if ip_filter == 'external_only':
        return f"""
            NOT (
                {ip_field_name} LIKE '10.%' OR 
                {ip_field_name} LIKE '192.168.%' OR 
                {ip_field_name} LIKE '172.16.%' OR {ip_field_name} LIKE '172.17.%' OR {ip_field_name} LIKE '172.18.%' OR {ip_field_name} LIKE '172.19.%' OR
                {ip_field_name} LIKE '172.20.%' OR {ip_field_name} LIKE '172.21.%' OR {ip_field_name} LIKE '172.22.%' OR {ip_field_name} LIKE '172.23.%' OR
                {ip_field_name} LIKE '172.24.%' OR {ip_field_name} LIKE '172.25.%' OR {ip_field_name} LIKE '172.26.%' OR {ip_field_name} LIKE '172.27.%' OR
                {ip_field_name} LIKE '172.28.%' OR {ip_field_name} LIKE '172.29.%' OR {ip_field_name} LIKE '172.30.%' OR {ip_field_name} LIKE '172.31.%' OR
                {ip_field_name} = '127.0.0.1' OR {ip_field_name} LIKE '169.254.%'
            )
        """.strip()
    
    try:
        # Check if it's a CIDR notation
        network = ipaddress.ip_network(ip_filter, strict=False)
        if network.num_addresses == 1:
            # It's a single IP, treat as exact match
            return f"{ip_field_name} = '{str(network.network_address)}'"
        else:
            # It's a subnet, use range check for broader compatibility
            start_ip = str(network.network_address)
            end_ip = str(network.broadcast_address)
            return f"IPv4StringToNum({ip_field_name}) BETWEEN IPv4StringToNum('{start_ip}') AND IPv4StringToNum('{end_ip}')"
    except ValueError:
        # Not a valid CIDR, treat as partial IP match
        return f"{ip_field_name} LIKE '{ip_filter}%'"