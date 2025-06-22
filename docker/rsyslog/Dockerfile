# rsyslog Server Dockerfile
FROM ubuntu:22.04

# Install rsyslog and dependencies
RUN apt-get update && apt-get install -y \
    rsyslog \
    rsyslog-relp \
    rsyslog-gnutls \
    rsyslog-mysql \
    rsyslog-pgsql \
    rsyslog-elasticsearch \
    rsyslog-mmjsonparse \
    rsyslog-imptcp \
    rsyslog-mmnormalize \
    curl \
    netcat \
    && rm -rf /var/lib/apt/lists/*

# Create log directories
RUN mkdir -p /var/log/rsyslog /var/spool/rsyslog

# Copy rsyslog configuration
COPY rsyslog/rsyslog.conf /etc/rsyslog.conf
COPY rsyslog/conf.d/ /etc/rsyslog.d/

# Create rsyslog user if not exists
RUN useradd -r -s /bin/false rsyslog || true

# Set permissions
RUN chown -R rsyslog:rsyslog /var/log/rsyslog /var/spool/rsyslog

# Expose syslog ports
EXPOSE 514/udp
EXPOSE 514/tcp
EXPOSE 6514/tcp

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
    CMD nc -z localhost 514 || exit 1

# Run rsyslog in foreground
CMD ["rsyslogd", "-n", "-f", "/etc/rsyslog.conf"]