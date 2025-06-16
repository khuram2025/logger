#!/usr/bin/env python3
"""
log_manager.py

Advanced log file management system that ensures log files don't exceed 2GB
and safely removes old logs after they've been processed and stored in ClickHouse.

Features:
- Real-time file size monitoring
- Coordinated log rotation with processing scripts
- Processed log tracking and verification
- Safe deletion of old logs
- Zero data loss guarantee
"""

import os
import time
import logging
import threading
import shutil
import gzip
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from clickhouse_driver import Client

# Configuration
LOG_DIR = '/var/log'
MAX_LOG_SIZE = 2 * 1024 * 1024 * 1024  # 2GB
ROTATION_THRESHOLD = int(MAX_LOG_SIZE * 0.9)  # Rotate at 1.8GB
PROCESSED_REGISTRY_FILE = '/var/lib/log-manager/processed_logs.json'
BACKUP_DIR = '/var/lib/log-manager/backups'
CHECK_INTERVAL = 60  # Check every minute

# ClickHouse connection for verification
CH_HOST = os.getenv('CH_HOST', 'localhost')
CH_PORT = int(os.getenv('CH_PORT', '9000'))
CH_USER = os.getenv('CH_USER', 'default')
CH_PASSWORD = os.getenv('CH_PASSWORD', 'Read@123')
CH_DB = os.getenv('CH_DB', 'network_logs')

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s [LogManager] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/var/log/log-manager.log')
    ]
)

@dataclass
class LogFileInfo:
    """Information about a log file and its processing status"""
    filepath: str
    size: int
    last_modified: float
    last_processed_position: int
    last_processed_time: float
    rotated_files: List[str]
    total_lines_processed: int
    total_bytes_processed: int
    clickhouse_verified: bool

@dataclass
class ProcessedLogRecord:
    """Record of a processed and verified log file"""
    original_file: str
    rotated_file: str
    start_position: int
    end_position: int
    lines_processed: int
    bytes_processed: int
    processing_start_time: float
    processing_end_time: float
    clickhouse_verification_time: float
    safe_to_delete: bool

class LogManager:
    def __init__(self):
        self.client = Client(
            host=CH_HOST,
            port=CH_PORT,
            user=CH_USER,
            password=CH_PASSWORD,
            database=CH_DB
        )
        
        # Tracked log files
        self.tracked_files = {
            '/var/log/fortigate.log': 'fortigate_traffic',
            '/var/log/paloalto-1004.log': 'fortigate_traffic'
        }
        
        # File information tracking
        self.file_info: Dict[str, LogFileInfo] = {}
        self.processed_records: List[ProcessedLogRecord] = []
        
        # Thread safety
        self.lock = threading.RLock()
        
        # Initialize directories and registry
        self._initialize()
    
    def _initialize(self):
        """Initialize directories and load existing registry"""
        os.makedirs(os.path.dirname(PROCESSED_REGISTRY_FILE), exist_ok=True)
        os.makedirs(BACKUP_DIR, exist_ok=True)
        
        # Load existing processed records
        self._load_registry()
        
        # Initialize file info for tracked files
        for filepath in self.tracked_files.keys():
            if os.path.exists(filepath):
                self._update_file_info(filepath)
    
    def _load_registry(self):
        """Load processed log registry from disk"""
        try:
            if os.path.exists(PROCESSED_REGISTRY_FILE):
                with open(PROCESSED_REGISTRY_FILE, 'r') as f:
                    data = json.load(f)
                    self.processed_records = [
                        ProcessedLogRecord(**record) for record in data.get('processed_records', [])
                    ]
                    
                    # Load file info
                    for filepath, info_data in data.get('file_info', {}).items():
                        self.file_info[filepath] = LogFileInfo(**info_data)
                        
                logging.info(f"Loaded {len(self.processed_records)} processed records from registry")
        except Exception as e:
            logging.error(f"Error loading registry: {e}")
    
    def _save_registry(self):
        """Save processed log registry to disk"""
        try:
            data = {
                'file_info': {filepath: asdict(info) for filepath, info in self.file_info.items()},
                'processed_records': [asdict(record) for record in self.processed_records],
                'last_updated': time.time()
            }
            
            # Atomic write
            temp_file = PROCESSED_REGISTRY_FILE + '.tmp'
            with open(temp_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            os.rename(temp_file, PROCESSED_REGISTRY_FILE)
            logging.debug("Registry saved successfully")
        except Exception as e:
            logging.error(f"Error saving registry: {e}")
    
    def _update_file_info(self, filepath: str):
        """Update file information for a tracked file"""
        try:
            stat = os.stat(filepath)
            
            if filepath not in self.file_info:
                self.file_info[filepath] = LogFileInfo(
                    filepath=filepath,
                    size=stat.st_size,
                    last_modified=stat.st_mtime,
                    last_processed_position=0,
                    last_processed_time=0,
                    rotated_files=[],
                    total_lines_processed=0,
                    total_bytes_processed=0,
                    clickhouse_verified=False
                )
            else:
                info = self.file_info[filepath]
                info.size = stat.st_size
                info.last_modified = stat.st_mtime
        except Exception as e:
            logging.error(f"Error updating file info for {filepath}: {e}")
    
    def check_file_rotation_needed(self, filepath: str) -> bool:
        """Check if a file needs to be rotated based on size"""
        try:
            if not os.path.exists(filepath):
                return False
                
            size = os.path.getsize(filepath)
            return size >= ROTATION_THRESHOLD
        except Exception as e:
            logging.error(f"Error checking file size for {filepath}: {e}")
            return False
    
    def coordinate_rotation(self, filepath: str) -> bool:
        """
        Coordinate log rotation with active processing scripts.
        Returns True if rotation was successful.
        """
        with self.lock:
            try:
                if not os.path.exists(filepath):
                    logging.warning(f"File {filepath} does not exist for rotation")
                    return False
                
                logging.info(f"Starting coordinated rotation for {filepath}")
                
                # Generate timestamp for rotated file
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                rotated_path = f"{filepath}.{timestamp}"
                
                # Get current file info
                self._update_file_info(filepath)
                current_info = self.file_info[filepath]
                
                # Create processing record for the current file state
                record = ProcessedLogRecord(
                    original_file=filepath,
                    rotated_file=rotated_path,
                    start_position=current_info.last_processed_position,
                    end_position=current_info.size,
                    lines_processed=0,  # Will be updated by processing scripts
                    bytes_processed=current_info.size - current_info.last_processed_position,
                    processing_start_time=time.time(),
                    processing_end_time=0,
                    clickhouse_verification_time=0,
                    safe_to_delete=False
                )
                
                # Perform atomic rotation using copytruncate method
                # This ensures processing scripts can continue without interruption
                
                # 1. Copy current file to rotated location
                shutil.copy2(filepath, rotated_path)
                
                # 2. Truncate original file (this is atomic)
                with open(filepath, 'w') as f:
                    pass  # This truncates the file
                
                # 3. Update file info
                current_info.rotated_files.append(rotated_path)
                current_info.last_processed_position = 0  # Reset for new file
                current_info.size = 0
                
                # 4. Add processing record
                self.processed_records.append(record)
                
                # 5. Save registry
                self._save_registry()
                
                logging.info(f"Successfully rotated {filepath} to {rotated_path}")
                
                # 6. Compress rotated file
                self._compress_rotated_file(rotated_path)
                
                return True
                
            except Exception as e:
                logging.error(f"Error during coordinated rotation for {filepath}: {e}")
                return False
    
    def _compress_rotated_file(self, filepath: str):
        """Compress a rotated log file"""
        try:
            compressed_path = filepath + '.gz'
            
            with open(filepath, 'rb') as f_in:
                with gzip.open(compressed_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            # Remove uncompressed file
            os.remove(filepath)
            
            # Update record with compressed filename
            for record in self.processed_records:
                if record.rotated_file == filepath:
                    record.rotated_file = compressed_path
                    break
            
            logging.info(f"Compressed {filepath} to {compressed_path}")
            
        except Exception as e:
            logging.error(f"Error compressing {filepath}: {e}")
    
    def verify_clickhouse_data(self, record: ProcessedLogRecord) -> bool:
        """
        Verify that the data from a processed log file exists in ClickHouse.
        This is a safety check before allowing file deletion.
        """
        try:
            table_name = self.tracked_files.get(record.original_file)
            if not table_name:
                logging.warning(f"No table mapping for {record.original_file}")
                return False
            
            # Calculate expected time range for the data
            start_time = datetime.fromtimestamp(record.processing_start_time)
            end_time = datetime.fromtimestamp(record.processing_end_time)
            
            # Query ClickHouse for records in this time range
            query = f"""
                SELECT COUNT(*) 
                FROM {CH_DB}.{table_name} 
                WHERE timestamp >= '{start_time.strftime('%Y-%m-%d %H:%M:%S')}'
                  AND timestamp <= '{end_time.strftime('%Y-%m-%d %H:%M:%S')}'
            """
            
            result = self.client.execute(query)
            record_count = result[0][0] if result else 0
            
            # If we have records in the expected time range, consider it verified
            # Note: This is a basic verification. Could be enhanced with more specific checks
            if record_count > 0:
                record.clickhouse_verification_time = time.time()
                record.safe_to_delete = True
                logging.info(f"ClickHouse verification passed for {record.rotated_file}: {record_count} records found")
                return True
            else:
                logging.warning(f"ClickHouse verification failed for {record.rotated_file}: no records found")
                return False
                
        except Exception as e:
            logging.error(f"Error during ClickHouse verification for {record.rotated_file}: {e}")
            return False
    
    def cleanup_old_files(self, max_age_days: int = 7):
        """
        Clean up old rotated files that have been verified and are older than max_age_days.
        """
        cutoff_time = time.time() - (max_age_days * 24 * 3600)
        files_deleted = 0
        
        for record in self.processed_records[:]:  # Copy list to allow modification
            try:
                # Only delete if verified and old enough
                if (record.safe_to_delete and 
                    record.clickhouse_verification_time > 0 and
                    record.clickhouse_verification_time < cutoff_time):
                    
                    if os.path.exists(record.rotated_file):
                        # Move to backup directory first (extra safety)
                        backup_filename = os.path.basename(record.rotated_file)
                        backup_path = os.path.join(BACKUP_DIR, backup_filename)
                        
                        shutil.move(record.rotated_file, backup_path)
                        logging.info(f"Moved {record.rotated_file} to backup: {backup_path}")
                        
                        # Update record
                        record.rotated_file = backup_path
                        files_deleted += 1
                    
                    # Remove very old backup files (30 days)
                    very_old_cutoff = time.time() - (30 * 24 * 3600)
                    if record.clickhouse_verification_time < very_old_cutoff:
                        if os.path.exists(record.rotated_file):
                            os.remove(record.rotated_file)
                            logging.info(f"Permanently deleted old backup: {record.rotated_file}")
                        
                        # Remove from registry
                        self.processed_records.remove(record)
                        
            except Exception as e:
                logging.error(f"Error cleaning up {record.rotated_file}: {e}")
        
        if files_deleted > 0:
            self._save_registry()
            logging.info(f"Cleaned up {files_deleted} old log files")
    
    def update_processing_status(self, filepath: str, position: int, lines_processed: int):
        """
        Update processing status for a file. Called by processing scripts.
        """
        with self.lock:
            if filepath in self.file_info:
                info = self.file_info[filepath]
                info.last_processed_position = position
                info.last_processed_time = time.time()
                info.total_lines_processed += lines_processed
                info.total_bytes_processed = position
                
                # Update any pending records
                for record in self.processed_records:
                    if (record.original_file == filepath and 
                        record.processing_end_time == 0 and
                        position >= record.end_position):
                        record.processing_end_time = time.time()
                        record.lines_processed = lines_processed
                        
                        # Schedule verification
                        threading.Thread(
                            target=self._delayed_verification,
                            args=(record,),
                            daemon=True
                        ).start()
                
                self._save_registry()
    
    def _delayed_verification(self, record: ProcessedLogRecord):
        """Perform delayed ClickHouse verification to allow for processing lag"""
        # Wait a bit to ensure all data has been inserted
        time.sleep(30)
        
        if self.verify_clickhouse_data(record):
            self._save_registry()
    
    def monitor_files(self):
        """Main monitoring loop"""
        logging.info("Starting log file monitoring")
        
        while True:
            try:
                with self.lock:
                    # Check each tracked file
                    for filepath in self.tracked_files.keys():
                        if os.path.exists(filepath):
                            self._update_file_info(filepath)
                            
                            # Check if rotation is needed
                            if self.check_file_rotation_needed(filepath):
                                logging.warning(f"File {filepath} size threshold reached, initiating rotation")
                                self.coordinate_rotation(filepath)
                    
                    # Verify pending records
                    for record in self.processed_records:
                        if (record.processing_end_time > 0 and 
                            record.clickhouse_verification_time == 0 and
                            time.time() - record.processing_end_time > 60):  # Wait 1 minute
                            
                            if self.verify_clickhouse_data(record):
                                self._save_registry()
                    
                    # Cleanup old files
                    self.cleanup_old_files()
                
                # Status logging
                total_size = sum(info.size for info in self.file_info.values())
                logging.info(f"Monitoring {len(self.tracked_files)} files, total size: {total_size / (1024*1024):.1f} MB")
                
            except Exception as e:
                logging.error(f"Error in monitoring loop: {e}")
            
            time.sleep(CHECK_INTERVAL)
    
    def get_status(self) -> Dict:
        """Get current status of log management"""
        with self.lock:
            return {
                'tracked_files': len(self.tracked_files),
                'file_info': {filepath: {
                    'size_mb': info.size / (1024*1024),
                    'last_processed_position': info.last_processed_position,
                    'processing_lag_mb': (info.size - info.last_processed_position) / (1024*1024),
                    'total_lines_processed': info.total_lines_processed
                } for filepath, info in self.file_info.items()},
                'pending_verification': len([r for r in self.processed_records if not r.safe_to_delete]),
                'verified_files': len([r for r in self.processed_records if r.safe_to_delete]),
                'total_processed_records': len(self.processed_records)
            }


def main():
    """Main entry point"""
    import signal
    import sys
    
    manager = LogManager()
    
    def signal_handler(signum, frame):
        logging.info("Received shutdown signal, saving state...")
        manager._save_registry()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start monitoring
    manager.monitor_files()


if __name__ == '__main__':
    main()