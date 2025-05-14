#!/usr/bin/env python3
import re, time, queue, threading
from datetime import datetime
from elasticsearch import Elasticsearch, helpers
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

LOG_PATH          = "/var/log/fortigate.log"
INDEX_NAME        = "fortigate-simple"
BULK_CHUNK_SIZE   = 500
BULK_MAX_RETRIES  = 3
BULK_RETRY_BACKOFF= 2
NUM_WORKERS       = 4
LINE_PATTERN = re.compile(
    r'date=(\d{4}-\d{2}-\d{2}) '
    r'time=(\d{2}:\d{2}:\d{2}).*?'
    r'srcip=([\d.]+).*?'
    r'dstip=([\d.]+).*?'
    r'eventtime=(\d+)'
)  # Now also captures eventtime

es = Elasticsearch("http://localhost:9200")
line_q = queue.Queue(maxsize=10000)
buffer = []
buffer_lock = threading.Lock()

def bulk_index(docs):
    helpers.bulk(
        es,
        docs,
        index=INDEX_NAME,
        chunk_size=BULK_CHUNK_SIZE,
        max_retries=BULK_MAX_RETRIES,
        initial_backoff=BULK_RETRY_BACKOFF
    )

def parser_worker():
    kv_pattern = re.compile(r'(\w+)=(("[^"]*")|([^\s]+))')
    while True:
        line = line_q.get()
        if line is None:
            break
        # Extract all key-value pairs
        fields = [(k, v.strip('"')) for k, v, *_ in kv_pattern.findall(line)]
        # Find indices for 'date' and 'rcvdpkt'
        keys = [k for k, v in fields]
        try:
            start_idx = keys.index('date')
            end_idx = keys.index('rcvdpkt')
            # Only keep fields from 'date' to 'rcvdpkt' (inclusive)
            selected = fields[start_idx:end_idx+1]
        except ValueError:
            selected = fields  # fallback: keep all if not found
        doc = dict(selected)
        # Handle eventtime for @timestamp
        eventtime = doc.get("eventtime")
        if eventtime:
            try:
                eventtime_int = int(eventtime)
                dt = datetime.utcfromtimestamp(eventtime_int / 1_000_000)
                doc["@timestamp"] = dt.isoformat() + "Z"
            except Exception:
                pass
        with buffer_lock:
            buffer.append({"_source": doc})
            if len(buffer) >= BULK_CHUNK_SIZE:
                bulk_index(buffer.copy())
                buffer.clear()
        line_q.task_done()

class LogHandler(FileSystemEventHandler):
    def __init__(self, path):
        self.path = path
        self._fp = open(self.path, 'r')
    # self._fp.seek(0, 2)  # Start from beginning for full reindex
    def on_modified(self, event):
        if event.src_path != self.path: return
        for line in self._fp:
            line_q.put(line)
    def on_moved(self, event):
        if event.src_path == self.path:
            self._fp.close()
            self._fp = open(self.path, 'r')
            self._fp.seek(0, 2)

def main():
    # start parser threads
    workers = []
    for _ in range(NUM_WORKERS):
        t = threading.Thread(target=parser_worker, daemon=True)
        t.start()
        workers.append(t)

    # watch log file
    handler  = LogHandler(LOG_PATH)
    observer = Observer()
    observer.schedule(handler, path=LOG_PATH.rsplit('/',1)[0], recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        # flush remaining docs
        with buffer_lock:
            if buffer: bulk_index(buffer)
        # stop workers
        for _ in workers: line_q.put(None)
        for t in workers: t.join()
        observer.stop()
        observer.join()

if __name__ == "__main__":
    main()
