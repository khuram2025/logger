#!/usr/bin/env python3
"""
log_manager_optimized.py

Optimized log file management system with async compression and better performance.
"""

import os
import time
import logging
import threading
import shutil
import gzip
import json
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from clickhouse_driver import Client
from concurrent.futures import ThreadPoolExecutor
import queue

# Configuration
LOG_DIR = '/var/log'
MAX_LOG_SIZE = 2 * 1024 * 1024 * 1024  # 2GB
ROTATION_THRESHOLD = int(MAX_LOG_SIZE * 0.9)  # Rotate at 1.8GB
PROCESSED_REGISTRY_FILE = '/var/lib/log-manager/processed_logs.json'
BACKUP_DIR = '/var/lib/log-manager/backups'
CHECK_INTERVAL = 60  # Check every minute
COMPRESSION_WORKERS = 2  # Number of compression threads

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
    compression_status: str  # 'pending', 'in_progress', 'completed', 'failed'

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
        
        # Compression queue and thread pool
        self.compression_queue = queue.Queue()
        self.compression_executor = ThreadPoolExecutor(max_workers=COMPRESSION_WORKERS)
        
        # Initialize directories and registry
        self._initialize()
        
        # Start compression workers
        self._start_compression_workers()
    
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
                    self.processed_records = []
                    for record_data in data.get('processed_records', []):
                        # Add compression_status field if not present (for backward compatibility)
                        if 'compression_status' not in record_data:
                            record_data['compression_status'] = 'completed'
                        self.processed_records.append(ProcessedLogRecord(**record_data))
                    
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
                    safe_to_delete=False,
                    compression_status='pending'
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
                
                # 6. Queue file for async compression
                self.compression_queue.put(record)
                
                return True
                
            except Exception as e:
                logging.error(f"Error during coordinated rotation for {filepath}: {e}")
                return False
    
    def _start_compression_workers(self):
        """Start background threads for compression"""
        for i in range(COMPRESSION_WORKERS):
            thread = threading.Thread(
                target=self._compression_worker,
                name=f"CompressionWorker-{i}",
                daemon=True
            )
            thread.start()
    
    def _compression_worker(self):
        """Worker thread for compressing rotated files"""
        while True:
            try:
                # Get record from queue (blocks until available)
                record = self.compression_queue.get()
                
                if record is None:  # Shutdown signal
                    break
                
                self._compress_rotated_file_async(record)
                
            except Exception as e:
                logging.error(f"Error in compression worker: {e}")
            finally:
                self.compression_queue.task_done()
    
    def _compress_rotated_file_async(self, record: ProcessedLogRecord):
        """Compress a rotated log file asynchronously"""
        try:
            filepath = record.rotated_file
            compressed_path = filepath + '.gz'
            
            # Update status
            with self.lock:
                record.compression_status = 'in_progress'
                self._save_registry()
            
            logging.info(f"Starting compression of {filepath} (size: {os.path.getsize(filepath) / (1024*1024*1024):.1f} GB)")
            start_time = time.time()
            
            # Use pigz for parallel compression if available, otherwise use gzip
            if shutil.which('pigz'):
                # Use pigz with 4 threads for faster compression
                cmd = ['pigz', '-4', '-k', filepath]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    # Remove original file after successful compression
                    os.remove(filepath)
                    logging.info(f"Compressed {filepath} using pigz in {time.time() - start_time:.1f}s")
                else:
                    raise Exception(f"pigz compression failed: {result.stderr}")
            else:
                # Fall back to Python gzip
                with open(filepath, 'rb') as f_in:
                    with gzip.open(compressed_path, 'wb', compresslevel=6) as f_out:
                        # Use larger buffer for better performance
                        shutil.copyfileobj(f_in, f_out, length=1024*1024)
                
                # Remove uncompressed file
                os.remove(filepath)
                logging.info(f"Compressed {filepath} using gzip in {time.time() - start_time:.1f}s")
            
            # Update record with compressed filename
            with self.lock:
                record.rotated_file = compressed_path
                record.compression_status = 'completed'
                self._save_registry()
            
        except Exception as e:
            logging.error(f"Error compressing {record.rotated_file}: {e}")
            with self.lock:
                record.compression_status = 'failed'
                self._save_registry()
    
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
                # Only delete if verified, compressed, and old enough
                if (record.safe_to_delete and 
                    record.compression_status == 'completed' and
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
    
    def monitor_files(self):
        """Main monitoring loop"""
        logging.info("Starting optimized log file monitoring")
        
        while True:
            try:
                rotation_needed = []
                
                with self.lock:
                    # Check each tracked file
                    for filepath in self.tracked_files.keys():
                        if os.path.exists(filepath):
                            self._update_file_info(filepath)
                            
                            # Check if rotation is needed
                            if self.check_file_rotation_needed(filepath):
                                rotation_needed.append(filepath)
                    
                    # Rotate files that need it
                    for filepath in rotation_needed:
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
                pending_compression = sum(1 for r in self.processed_records if r.compression_status == 'pending')
                in_progress_compression = sum(1 for r in self.processed_records if r.compression_status == 'in_progress')
                
                logging.info(f"Monitoring {len(self.tracked_files)} files, total size: {total_size / (1024*1024):.1f} MB, "
                           f"pending compression: {pending_compression}, in progress: {in_progress_compression}")
                
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
                'total_processed_records': len(self.processed_records),
                'compression_status': {
                    'pending': len([r for r in self.processed_records if r.compression_status == 'pending']),
                    'in_progress': len([r for r in self.processed_records if r.compression_status == 'in_progress']),
                    'completed': len([r for r in self.processed_records if r.compression_status == 'completed']),
                    'failed': len([r for r in self.processed_records if r.compression_status == 'failed'])
                }
            }
    
    def shutdown(self):
        """Gracefully shutdown the log manager"""
        logging.info("Shutting down log manager...")
        
        # Stop compression workers
        for _ in range(COMPRESSION_WORKERS):
            self.compression_queue.put(None)
        
        # Wait for compression queue to empty
        self.compression_queue.join()
        
        # Shutdown executor
        self.compression_executor.shutdown(wait=True)
        
        # Save final state
        self._save_registry()


def main():
    """Main entry point"""
    import signal
    import sys
    
    manager = LogManager()
    
    def signal_handler(signum, frame):
        logging.info("Received shutdown signal, saving state...")
        manager.shutdown()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start monitoring
    manager.monitor_files()


if __name__ == '__main__':
    main()