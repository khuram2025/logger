#!/bin/bash

# Log Analyzer Docker Management Script
# This script provides easy management commands for the Docker stack

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Function to print usage
usage() {
    echo "Log Analyzer Docker Management Script"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  start       - Start all services"
    echo "  stop        - Stop all services"
    echo "  restart     - Restart all services"
    echo "  status      - Show service status"
    echo "  logs        - Show logs (optionally specify service)"
    echo "  shell       - Get shell access to a service"
    echo "  backup      - Backup data and configuration"
    echo "  restore     - Restore from backup"
    echo "  update      - Update and rebuild services"
    echo "  clean       - Clean up containers and volumes"
    echo ""
    echo "Examples:"
    echo "  $0 start"
    echo "  $0 logs django"
    echo "  $0 shell clickhouse"
}

# Start services
start_services() {
    echo -e "${GREEN}[+]${NC} Starting services..."
    docker-compose up -d
    echo -e "${GREEN}[+]${NC} Services started successfully"
}

# Stop services
stop_services() {
    echo -e "${YELLOW}[*]${NC} Stopping services..."
    docker-compose down
    echo -e "${GREEN}[+]${NC} Services stopped successfully"
}

# Restart services
restart_services() {
    echo -e "${YELLOW}[*]${NC} Restarting services..."
    docker-compose restart
    echo -e "${GREEN}[+]${NC} Services restarted successfully"
}

# Show status
show_status() {
    echo -e "${GREEN}[+]${NC} Service Status:"
    docker-compose ps
    echo ""
    echo -e "${GREEN}[+]${NC} Resource Usage:"
    docker stats --no-stream
}

# Show logs
show_logs() {
    if [ -z "$1" ]; then
        docker-compose logs -f --tail=100
    else
        docker-compose logs -f --tail=100 "$1"
    fi
}

# Get shell access
get_shell() {
    if [ -z "$1" ]; then
        echo -e "${RED}[!]${NC} Please specify a service name"
        echo "Available services: django, clickhouse, rsyslog, nginx, log-processor, celery"
        exit 1
    fi
    
    case "$1" in
        django|celery|management)
            docker-compose exec "$1" /bin/bash
            ;;
        clickhouse)
            docker-compose exec "$1" clickhouse-client
            ;;
        *)
            docker-compose exec "$1" /bin/sh
            ;;
    esac
}

# Backup data
backup_data() {
    BACKUP_DIR="backups/$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    
    echo -e "${GREEN}[+]${NC} Creating backup in $BACKUP_DIR..."
    
    # Backup ClickHouse data
    echo -e "${YELLOW}[*]${NC} Backing up ClickHouse data..."
    docker-compose exec clickhouse clickhouse-backup create
    docker cp "$(docker-compose ps -q clickhouse):/var/lib/clickhouse/backup" "$BACKUP_DIR/clickhouse"
    
    # Backup Django database
    echo -e "${YELLOW}[*]${NC} Backing up Django database..."
    docker-compose exec django python manage.py dumpdata > "$BACKUP_DIR/django_data.json"
    
    # Backup configuration files
    echo -e "${YELLOW}[*]${NC} Backing up configuration..."
    cp -r nginx "$BACKUP_DIR/"
    cp -r rsyslog "$BACKUP_DIR/"
    cp docker-compose.yml "$BACKUP_DIR/"
    
    # Create backup info
    echo "{
        \"date\": \"$(date)\",
        \"version\": \"$(git rev-parse HEAD 2>/dev/null || echo 'unknown')\",
        \"services\": $(docker-compose ps --services | jq -R -s -c 'split(\"\n\")[:-1]')
    }" > "$BACKUP_DIR/backup_info.json"
    
    echo -e "${GREEN}[+]${NC} Backup completed: $BACKUP_DIR"
}

# Update services
update_services() {
    echo -e "${GREEN}[+]${NC} Updating services..."
    
    # Pull latest changes
    git pull origin main 2>/dev/null || echo "Not a git repository"
    
    # Rebuild images
    docker-compose build --no-cache
    
    # Run migrations
    docker-compose run --rm django python manage.py migrate
    
    # Restart services
    docker-compose up -d
    
    echo -e "${GREEN}[+]${NC} Update completed successfully"
}

# Clean up
cleanup() {
    echo -e "${YELLOW}[*]${NC} This will remove all containers and volumes. Are you sure? (y/n)"
    read -r confirm
    if [[ $confirm == "y" ]]; then
        docker-compose down -v
        docker system prune -af
        echo -e "${GREEN}[+]${NC} Cleanup completed"
    else
        echo -e "${YELLOW}[*]${NC} Cleanup cancelled"
    fi
}

# Main script logic
case "$1" in
    start)
        start_services
        ;;
    stop)
        stop_services
        ;;
    restart)
        restart_services
        ;;
    status)
        show_status
        ;;
    logs)
        show_logs "$2"
        ;;
    shell)
        get_shell "$2"
        ;;
    backup)
        backup_data
        ;;
    update)
        update_services
        ;;
    clean)
        cleanup
        ;;
    *)
        usage
        exit 1
        ;;
esac