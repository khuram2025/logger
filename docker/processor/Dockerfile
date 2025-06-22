# Log Processor Dockerfile
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy and install Python requirements
COPY requirements-processor.txt /app/
RUN pip install --no-cache-dir -r requirements-processor.txt

# Copy scripts
COPY scripts/ /app/scripts/

# Create directories
RUN mkdir -p /app/state /app/logs /var/log/supervisor

# Copy supervisor configuration
COPY docker/processor/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Create non-root user
RUN useradd -m -u 1000 processor && chown -R processor:processor /app
USER processor

# Health check
HEALTHCHECK --interval=60s --timeout=10s --start-period=30s \
    CMD python -c "import os; exit(0 if os.path.exists('/app/state/processor.pid') else 1)"

# Run supervisor
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]