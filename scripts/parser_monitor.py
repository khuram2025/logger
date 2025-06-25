#!/usr/bin/env python3
"""
Parser Health Monitoring Script
Monitors FortiGate and PaloAlto parsers for issues and sends alerts.
"""

import os
import time
import psutil
import subprocess
from datetime import datetime, timedelta
from clickhouse_driver import Client
import logging
import json

# Configuration
CH_HOST = os.getenv('CH_HOST', 'localhost')
CH_PORT = int(os.getenv('CH_PORT', '9000'))
CH_USER = os.getenv('CH_USER', 'default')
CH_PASSWORD = os.getenv('CH_PASSWORD', 'Read@123')
CH_DB = os.getenv('CH_DB', 'network_logs')

# Thresholds
MAX_LAG_MINUTES = 5
MAX_CPU_PERCENT = 80
MAX_MEMORY_MB = 500
MIN_RECORDS_PER_MINUTE = 10
MAX_LOG_SIZE_GB = 1

# Log files
LOG_FILES = {
    'fortigate': '/var/log/fortigate.log',
    'paloalto': '/var/log/paloalto-1004.log'
}

PARSER_LOGS = {
    'fortigate': '/tmp/fortigate_enhanced.log',
    'paloalto': '/tmp/paloalto_enhanced.log'
}

class ParserMonitor:
    def __init__(self):
        self.client = Client(
            host=CH_HOST,
            port=CH_PORT,
            user=CH_USER,
            password=CH_PASSWORD,
            database=CH_DB
        )
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/tmp/parser_monitor.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def check_parser_processes(self):
        """Check if parser processes are running"""
        issues = []
        
        parsers = {
            'fortigate': 'enhanced_fortigate_to_clickhouse',
            'paloalto': 'enhanced_paloalto_to_clickhouse'
        }
        
        for name, script_name in parsers.items():
            found = False
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if script_name in ' '.join(proc.info['cmdline'] or []):
                        found = True
                        # Check CPU and memory
                        cpu_percent = proc.cpu_percent(interval=1)
                        memory_mb = proc.memory_info().rss / 1024 / 1024
                        
                        if cpu_percent > MAX_CPU_PERCENT:
                            issues.append(f"{name} parser high CPU: {cpu_percent:.1f}%")
                        if memory_mb > MAX_MEMORY_MB:
                            issues.append(f"{name} parser high memory: {memory_mb:.1f}MB")
                        
                        self.logger.info(f"{name} parser: PID={proc.pid}, CPU={cpu_percent:.1f}%, Memory={memory_mb:.1f}MB")
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            if not found:
                issues.append(f"{name} parser is NOT running!")
        
        return issues
    
    def check_data_lag(self):
        """Check if data ingestion is lagging"""
        issues = []
        
        tables = {
            'fortigate': 'fortigate_traffic',
            'paloalto': 'paloalto_traffic'
        }
        
        for name, table in tables.items():
            try:
                query = f"""
                SELECT 
                    MAX(timestamp) as last_record,
                    COUNT(*) as recent_count
                FROM {CH_DB}.{table}
                WHERE timestamp > now() - INTERVAL 5 MINUTE
                """
                result = self.client.execute(query)
                
                if result:
                    last_record, recent_count = result[0]
                    lag_minutes = (datetime.now() - last_record).total_seconds() / 60
                    
                    if lag_minutes > MAX_LAG_MINUTES:
                        issues.append(f"{name} data lag: {lag_minutes:.1f} minutes behind")
                    
                    if recent_count < MIN_RECORDS_PER_MINUTE * 5:
                        issues.append(f"{name} low ingestion rate: {recent_count} records in 5 min")
                    
                    self.logger.info(f"{name}: Last record {lag_minutes:.1f} min ago, {recent_count} recent records")
            except Exception as e:
                issues.append(f"{name} query error: {str(e)}")
        
        return issues
    
    def check_log_files(self):
        """Check log file sizes and growth"""
        issues = []
        
        for name, path in LOG_FILES.items():
            try:
                if os.path.exists(path):
                    size_gb = os.path.getsize(path) / 1024 / 1024 / 1024
                    
                    if size_gb > MAX_LOG_SIZE_GB:
                        issues.append(f"{name} log file too large: {size_gb:.2f}GB")
                    
                    # Check if file is growing
                    mtime = os.path.getmtime(path)
                    age_minutes = (time.time() - mtime) / 60
                    
                    if age_minutes > 10:
                        issues.append(f"{name} log file not updated for {age_minutes:.1f} minutes")
                    
                    self.logger.info(f"{name} log: {size_gb:.2f}GB, last modified {age_minutes:.1f} min ago")
                else:
                    issues.append(f"{name} log file missing: {path}")
            except Exception as e:
                issues.append(f"{name} log check error: {str(e)}")
        
        return issues
    
    def check_parser_errors(self):
        """Check parser logs for recent errors"""
        issues = []
        
        for name, log_path in PARSER_LOGS.items():
            try:
                if os.path.exists(log_path):
                    # Check last 100 lines for errors
                    result = subprocess.run(
                        ['tail', '-100', log_path],
                        capture_output=True,
                        text=True
                    )
                    
                    error_count = result.stdout.count('ERROR')
                    warning_count = result.stdout.count('WARNING')
                    
                    if error_count > 5:
                        issues.append(f"{name} parser has {error_count} errors in recent logs")
                    
                    self.logger.info(f"{name} parser log: {error_count} errors, {warning_count} warnings")
            except Exception as e:
                self.logger.warning(f"Could not check {name} parser log: {str(e)}")
        
        return issues
    
    def generate_status_report(self):
        """Generate comprehensive status report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'checks': {
                'processes': self.check_parser_processes(),
                'data_lag': self.check_data_lag(),
                'log_files': self.check_log_files(),
                'parser_errors': self.check_parser_errors()
            }
        }
        
        all_issues = []
        for check, issues in report['checks'].items():
            all_issues.extend(issues)
        
        report['healthy'] = len(all_issues) == 0
        report['issue_count'] = len(all_issues)
        report['issues'] = all_issues
        
        return report
    
    def save_report(self, report):
        """Save report to file"""
        report_path = '/tmp/parser_status.json'
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Also save a human-readable summary
        summary_path = '/tmp/parser_status.txt'
        with open(summary_path, 'w') as f:
            f.write(f"Parser Status Report - {report['timestamp']}\n")
            f.write("=" * 50 + "\n\n")
            
            if report['healthy']:
                f.write("✅ All systems operational\n")
            else:
                f.write(f"⚠️  {report['issue_count']} issues detected:\n\n")
                for issue in report['issues']:
                    f.write(f"  - {issue}\n")
            
            f.write("\nDetailed checks:\n")
            for check, issues in report['checks'].items():
                f.write(f"\n{check.upper()}:\n")
                if issues:
                    for issue in issues:
                        f.write(f"  ❌ {issue}\n")
                else:
                    f.write("  ✅ OK\n")

def main():
    monitor = ParserMonitor()
    
    # Run once or continuously
    if '--continuous' in os.sys.argv:
        monitor.logger.info("Starting continuous monitoring...")
        while True:
            report = monitor.generate_status_report()
            monitor.save_report(report)
            
            if not report['healthy']:
                monitor.logger.warning(f"Issues detected: {report['issues']}")
            
            time.sleep(300)  # Check every 5 minutes
    else:
        report = monitor.generate_status_report()
        monitor.save_report(report)
        
        print(f"\nStatus: {'✅ Healthy' if report['healthy'] else '⚠️  Issues detected'}")
        if report['issues']:
            print("\nIssues:")
            for issue in report['issues']:
                print(f"  - {issue}")
        
        print(f"\nFull report saved to: /tmp/parser_status.txt")

if __name__ == "__main__":
    main()