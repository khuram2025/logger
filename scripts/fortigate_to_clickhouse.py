#!/usr/bin/env python3
"""
fortigate_to_clickhouse.py

Continuously tails /var/log/fortigate.log and inserts each entry into
the ClickHouse table `network_logs.fortigate_traffic`.

Requirements:
    pip3 install clickhouse-driver

Configurable via environment variables:
    CH_HOST        ClickHouse host        (default: localhost)
    CH_PORT        ClickHouse port        (default: 9000)
    CH_USER        ClickHouse user        (default: default)
    CH_PASSWORD    ClickHouse password    (default: empty)
    CH_DB          ClickHouse database    (default: network_logs)
"""

import os
import time
import re
import logging
from datetime import datetime
from clickhouse_driver import Client
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading
import signal
import sys

# ── Configuration ─────────────────────────────────────────────────────────────
CH_HOST     = os.getenv('CH_HOST',     'localhost')
CH_PORT     = int(os.getenv('CH_PORT',     '9000'))
CH_USER     = os.getenv('CH_USER',     'default')
CH_PASSWORD = os.getenv('CH_PASSWORD', 'Read@123')
CH_DB       = os.getenv('CH_DB',       'network_logs')

LOG_FILE    = '/var/log/fortigate.log'

# ── Logging Setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[logging.StreamHandler()]
)

# ── ClickHouse Client ─────────────────────────────────────────────────────────
CLIENT = Client(
    host=CH_HOST,
    port=CH_PORT,
    user=CH_USER,
    password=CH_PASSWORD,
    database=CH_DB
)

# ── Parsing Logic ─────────────────────────────────────────────────────────────
KV_PATTERN = re.compile(r'(\w+)=(".*?"|\S+)')

NUMERIC_FIELDS = {
    'eventtime', 'srcport', 'dstport', 'sessionid', 'proto', 'policyid',
    'duration', 'sentbyte', 'rcvdbyte', 'sentpkt', 'rcvdpkt',
    'sentdelta', 'rcvddelta', 'durationdelta', 'sentpktdelta', 'rcvdpktdelta'
}

ALL_FIELDS = [
    'timestamp', 'raw_message', 'devname', 'devid', 'eventtime', 'tz',
    'logid', 'type', 'subtype', 'level', 'vd', 'srcip', 'srcport',
    'srcintf', 'srcintfrole', 'dstip', 'dstport', 'dstintf', 'dstintfrole',
    'srccountry', 'dstcountry', 'sessionid', 'proto', 'action', 'policyid',
    'policytype', 'poluuid', 'policyname', 'service', 'trandisp', 'appcat',
    'duration', 'sentbyte', 'rcvdbyte', 'sentpkt', 'rcvdpkt', 'sentdelta',
    'rcvddelta', 'durationdelta', 'sentpktdelta', 'rcvdpktdelta', 'vpntype'
]

def parse_line(line: str) -> dict:
    """
    Parse a FortiGate syslog line into a dict of all expected fields.
    Missing numeric fields default to 0; others to empty string.
    """
    data = {}
    for key, val in KV_PATTERN.findall(line):
        data[key] = val.strip('"')

    # Build timestamp & raw_message
    date = data.get('date', '')
    t    = data.get('time', '')
    timestamp_str = f"{date} {t}"
    try:
        data['timestamp'] = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S") if date and t else None
    except Exception:
        data['timestamp'] = None
    data['raw_message'] = line.rstrip('\n')

    # Ensure all numeric fields are integers
    for field in NUMERIC_FIELDS:
        val = data.get(field, 0)
        try:
            data[field] = int(val)
        except Exception:
            data[field] = 0

    # Assign defaults
    for field in ALL_FIELDS:
        if field not in data:
            data[field] = 0 if field in NUMERIC_FIELDS else ''

    # Remove intermediate date/time keys
    data.pop('date', None)
    data.pop('time', None)
    return data

# ── Log Handler for Watchdog ────────────────────────────────────────────────
BATCH_SIZE = 500
BATCH_FLUSH_INTERVAL = 2  # seconds

class LogHandler(FileSystemEventHandler):
    def __init__(self, filepath, buffer, buffer_lock, process_batch_func):
        self.filepath = filepath
        self.buffer = buffer
        self.buffer_lock = buffer_lock
        self.process_batch_func = process_batch_func
        self._fp = open(self.filepath, 'r')
        self._fp.seek(0, os.SEEK_END)  # Only process new lines

    def on_modified(self, event):
        if event.src_path != self.filepath:
            return
        while True:
            line = self._fp.readline()
            if not line:
                break
            with self.buffer_lock:
                self.buffer.append(line)
                if len(self.buffer) >= BATCH_SIZE:
                    self.process_batch_func()

    def on_moved(self, event):
        if event.src_path == self.filepath:
            self._fp.close()
            self._fp = open(self.filepath, 'r')
            self._fp.seek(0, os.SEEK_END)


# ── Main Ingestion Loop ──────────────────────────────────────────────────────
def main():
    insert_query = f"""
        INSERT INTO {CH_DB}.fortigate_traffic ({', '.join(ALL_FIELDS)}) VALUES
    """
    logging.info("Starting FortiGate → ClickHouse ingestion with batch size %d", BATCH_SIZE)

    buffer = []
    buffer_lock = threading.Lock()
    stop_event = threading.Event()

    def process_batch():
        with buffer_lock:
            if not buffer:
                return
            batch = buffer[:]
            buffer.clear()
        rows = []
        for line in batch:
            try:
                rec = parse_line(line)
                row = [rec[field] for field in ALL_FIELDS]
                rows.append(row)
            except Exception as e:
                logging.error(f"Parse error: {e} | line: {line.strip()}")
        if rows:
            try:
                CLIENT.execute(insert_query, rows)
                logging.info(f"Inserted {len(rows)} rows to ClickHouse.")
            except Exception as e:
                logging.error(f"Batch insert error: {e}")

    handler = LogHandler(LOG_FILE, buffer, buffer_lock, process_batch)
    observer = Observer()
    observer.schedule(handler, path=os.path.dirname(LOG_FILE) or '.', recursive=False)
    observer.start()

    def flush_and_exit(signum, frame):
        logging.info("Shutting down. Flushing remaining logs...")
        process_batch()
        observer.stop()
        observer.join()
        sys.exit(0)

    signal.signal(signal.SIGINT, flush_and_exit)
    signal.signal(signal.SIGTERM, flush_and_exit)

    # Periodically flush buffer in case of low log volume
    try:
        while True:
            time.sleep(BATCH_FLUSH_INTERVAL)
            process_batch()
    except KeyboardInterrupt:
        flush_and_exit(None, None)

if __name__ == '__main__':
    main()
