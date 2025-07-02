import multiprocessing
import os

# Server socket
bind = "127.0.0.1:8000"
backlog = 2048

# Worker processes
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "sync"
worker_connections = 1000
timeout = 120
keepalive = 2

# Restart workers after this many requests, to prevent memory leaks
max_requests = 1000
max_requests_jitter = 50

# Logging
accesslog = "/home/net/analyzer/logs/gunicorn_access.log"
errorlog = "/home/net/analyzer/logs/gunicorn_error.log"
loglevel = "info"

# Process naming
proc_name = "analyzer_gunicorn"

# Daemon mode
daemon = False
pidfile = "/home/net/analyzer/gunicorn.pid"

# Security
user = "net"
group = "net"

# Preload app for better performance
preload_app = True

# Graceful timeout
graceful_timeout = 30

def when_ready(server):
    server.log.info("Server is ready. Spawning workers")

def worker_int(worker):
    worker.log.info("worker received INT or QUIT signal")

def pre_fork(server, worker):
    server.log.info("Worker spawned (pid: %s)", worker.pid)

def post_fork(server, worker):
    server.log.info("Worker spawned (pid: %s)", worker.pid)