# Docker Deployment Guide for Log Analyzer

## Overview

This guide provides complete instructions for deploying the Log Analyzer system using Docker containers. The containerized deployment includes all components: Django web application, ClickHouse database, rsyslog server, log processors, and Nginx reverse proxy.

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│ Network Devices │────▶│  rsyslog:514     │────▶│   ClickHouse    │
│  (FortiGate,    │     │   (Container)    │     │  (Container)    │
│   PaloAlto)     │     └──────────────────┘     └─────────────────┘
└─────────────────┘              │                         ▲
                                 ▼                         │
                        ┌──────────────────┐              │
                        │  Log Processors  │──────────────┘
                        │  (Container)     │
                        └──────────────────┘
                                 ▲
                                 │
                        ┌──────────────────┐
                        │  Django + Celery │
                        │   (Container)    │
                        └──────────────────┘
                                 ▲
                                 │
                        ┌──────────────────┐
                        │  Nginx (Port 80) │
                        │   (Container)    │
                        └──────────────────┘
```

## Prerequisites

1. **Docker Engine** (version 20.10 or higher)
2. **Docker Compose** (version 2.0 or higher)
3. **System Requirements**:
   - CPU: 4+ cores recommended
   - RAM: 8GB minimum, 16GB recommended
   - Storage: 100GB+ for log storage
   - OS: Linux (Ubuntu 20.04+ recommended)

## Quick Start

1. **Clone or download the repository**:
   ```bash
   git clone <repository-url>
   cd analyzer
   ```

2. **Run the deployment script**:
   ```bash
   ./deploy.sh
   ```

3. **Access the application**:
   - Web Interface: http://localhost
   - Django Admin: http://localhost/admin
   - ClickHouse UI: http://localhost:8123

## Container Services

### Core Services

1. **clickhouse**: ClickHouse database for log storage
   - Port: 8123 (HTTP), 9000 (Native)
   - Volume: clickhouse-data

2. **rsyslog**: Syslog receiver
   - Ports: 514/udp, 514/tcp, 6514/tcp (TLS)
   - Volume: rsyslog-logs

3. **django**: Django web application
   - Port: 8000 (internal)
   - Volumes: static-files, media-files

4. **nginx**: Web server and reverse proxy
   - Ports: 80, 443
   - Volumes: static-files, media-files

5. **log-processor**: Log parsing and processing
   - Volumes: rsyslog-logs, processor-state

### Supporting Services

6. **celery**: Async task processing
7. **redis**: Message broker for Celery
8. **management**: Periodic management tasks

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```env
# ClickHouse Configuration
CH_HOST=clickhouse
CH_PORT=9000
CH_USER=default
CH_PASSWORD=Read@123
CH_DB=network_logs

# Django Configuration
DJANGO_SECRET_KEY=your-secret-key-here
DJANGO_DEBUG=False
DJANGO_ALLOWED_HOSTS=localhost,your-domain.com

# Email Configuration (optional)
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-password
```

### Syslog Configuration

Configure your network devices to send logs to the Docker host:
- Protocol: UDP or TCP
- Port: 514
- Format: Standard syslog

Example FortiGate configuration:
```
config log syslogd setting
    set status enable
    set server "your-docker-host-ip"
    set port 514
end
```

## Management Commands

Use the `manage.sh` script for common operations:

```bash
# Start all services
./manage.sh start

# Stop all services
./manage.sh stop

# View logs
./manage.sh logs [service-name]

# Get shell access
./manage.sh shell django

# Backup data
./manage.sh backup

# Show status
./manage.sh status
```

## Data Persistence

The following volumes persist data between container restarts:

- `clickhouse-data`: ClickHouse database files
- `rsyslog-logs`: Raw syslog files
- `processor-state`: Processing state and checkpoints
- `static-files`: Django static files
- `media-files`: Uploaded media files

## Scaling and Performance

### Horizontal Scaling

1. **Log Processors**: Scale by increasing replicas
   ```yaml
   deploy:
     replicas: 3
   ```

2. **Django Workers**: Adjust Gunicorn workers
   ```yaml
   command: gunicorn --workers 8
   ```

### Performance Tuning

1. **ClickHouse**: Edit `clickhouse/config.xml`
   - Increase `max_memory_usage`
   - Adjust `max_concurrent_queries`

2. **rsyslog**: Edit `rsyslog/rsyslog.conf`
   - Increase `queue.size`
   - Adjust `queue.workerthreads`

## Monitoring

### Built-in Monitoring

- Django Admin: `/admin/`
- ClickHouse metrics: `http://localhost:8123/metrics`
- Container stats: `docker stats`

### Log Files

- Application logs: `./logs/django/`
- Syslog files: `./logs/rsyslog/`
- Processor logs: `./logs/processor/`

## Backup and Recovery

### Automated Backup

```bash
# Create backup
./manage.sh backup

# Backups are stored in ./backups/
```

### Manual Backup

1. **ClickHouse data**:
   ```bash
   docker-compose exec clickhouse clickhouse-backup create
   ```

2. **Django data**:
   ```bash
   docker-compose exec django python manage.py dumpdata > backup.json
   ```

### Recovery

1. Stop services: `./manage.sh stop`
2. Restore volumes from backup
3. Start services: `./manage.sh start`

## Troubleshooting

### Common Issues

1. **Port conflicts**:
   - Check if ports 80, 514, 8123 are available
   - Modify ports in `docker-compose.yml` if needed

2. **Permission errors**:
   ```bash
   sudo chown -R $USER:$USER .
   chmod +x *.sh
   ```

3. **Container not starting**:
   ```bash
   # Check logs
   docker-compose logs [service-name]
   
   # Rebuild container
   docker-compose build --no-cache [service-name]
   ```

4. **Database connection errors**:
   - Ensure ClickHouse is running: `docker-compose ps clickhouse`
   - Check connectivity: `docker-compose exec django nc -zv clickhouse 9000`

### Debug Mode

Enable debug mode for troubleshooting:
```bash
# Edit .env file
DJANGO_DEBUG=True

# Restart Django
docker-compose restart django
```

## Security Considerations

1. **Change default passwords** in:
   - `clickhouse/users.xml`
   - `.env` file

2. **Enable HTTPS**:
   - Add SSL certificates to `nginx/ssl/`
   - Update `nginx/conf.d/default.conf`

3. **Firewall rules**:
   ```bash
   # Allow only necessary ports
   sudo ufw allow 80/tcp
   sudo ufw allow 443/tcp
   sudo ufw allow 514/udp
   sudo ufw allow 514/tcp
   ```

4. **Regular updates**:
   ```bash
   ./manage.sh update
   ```

## Production Deployment

For production environments:

1. **Use Docker Swarm or Kubernetes** for orchestration
2. **Enable SSL/TLS** for all services
3. **Configure log rotation** and retention policies
4. **Set up monitoring** (Prometheus, Grafana)
5. **Implement backup automation**
6. **Use external Redis** for better performance

## Support and Maintenance

- Check logs: `./manage.sh logs`
- Update services: `./manage.sh update`
- Clean unused resources: `docker system prune`

For issues or questions, please refer to the project documentation or create an issue in the repository.