#!/usr/bin/env python3
"""
Script to update the existing parsers to use the enhanced IP validator.
This will show the changes needed to integrate better IP validation.
"""

print("""
To integrate the enhanced IP validator into your parsers:

1. Add the import at the top of both parser files:
   from enhanced_ip_validator import IPValidator

2. In enhanced_fortigate_to_clickhouse.py, replace the IP validation logic (lines 121-147) with:
   
   # Handle IP fields with enhanced validation
   for field in IP_FIELDS:
       if field in data:
           data[field] = IPValidator.validate_and_fix_ip(data[field], field)
       else:
           data[field] = '0.0.0.0'

3. In enhanced_paloalto_to_clickhouse.py, update the parse_traffic_log function:
   
   # Replace lines 118-122 with:
   data['srcip'] = IPValidator.validate_and_fix_ip(fields[7] if len(fields) > 7 else '', 'srcip')
   data['dstip'] = IPValidator.validate_and_fix_ip(fields[8] if len(fields) > 8 else '', 'dstip')

4. Also update the validation in process_batch (lines 498-512):
   
   # Validate traffic record
   srcip = record.get('srcip', '0.0.0.0')
   dstip = record.get('dstip', '0.0.0.0')
   
   # No need for additional validation as IPValidator already ensures valid IPs
   row = [record[field] for field in ALL_FIELDS]
   traffic_rows.append(row)

5. For debugging, you can enable detailed logging:
   
   # Add this near the top of your parsers after imports:
   import sys
   sys.path.append('/home/net/analyzer/scripts')
   from enhanced_ip_validator import IPValidator
   
   # Set logging level for IP validation debugging
   logging.getLogger().setLevel(logging.DEBUG)  # Change to INFO in production

Benefits:
- Automatically fixes truncated IPs (10.1 -> 10.1.0.0)
- Handles IPs with ports or subnets
- Provides detailed logging for troubleshooting
- Consistent validation across all parsers
""")