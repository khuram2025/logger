#!/usr/bin/env python3
"""
Test script for the optimized URL parser
"""
import os
import sys

# Set environment variables for testing
os.environ['PROCESS_FROM_BEGINNING'] = 'true'
os.environ['LOG_LEVEL'] = 'INFO'

# Add the scripts directory to the path
sys.path.append('/home/net/analyzer/scripts')

# Import and run the parser
from paloalto_url_clickhouse import main

if __name__ == '__main__':
    print("🧪 Testing optimized URL parser with PROCESS_FROM_BEGINNING=true")
    main()