#!/bin/bash

# Log Analyzer Docker Deployment Script
# This script deploys the complete log analyzer stack using Docker Compose

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[*]${NC} $1"
}

# Check if Docker is installed
check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    print_status "Docker and Docker Compose are installed"
}

# Create necessary directories
create_directories() {
    print_status "Creating necessary directories..."
    
    mkdir -p nginx/conf.d
    mkdir -p clickhouse
    mkdir -p rsyslog/conf.d
    mkdir -p logs/{django,rsyslog,nginx,processor}
    mkdir -p data/{clickhouse,postgres}
    
    print_status "Directories created successfully"
}

# Set proper permissions
set_permissions() {
    print_status "Setting permissions..."
    
    # Make scripts executable
    chmod +x scripts/*.py 2>/dev/null || true
    chmod +x deploy.sh
    chmod +x manage.sh
    
    print_status "Permissions set successfully"
}

# Build Docker images
build_images() {
    print_status "Building Docker images..."
    
    docker-compose build --no-cache
    
    print_status "Docker images built successfully"
}

# Initialize database
init_database() {
    print_status "Initializing database..."
    
    # Start only ClickHouse first
    docker-compose up -d clickhouse
    
    # Wait for ClickHouse to be ready
    print_status "Waiting for ClickHouse to be ready..."
    sleep 10
    
    # Run Django migrations
    docker-compose run --rm django python manage.py migrate
    
    # Create superuser (optional)
    print_warning "Would you like to create a Django superuser? (y/n)"
    read -r create_superuser
    if [[ $create_superuser == "y" ]]; then
        docker-compose run --rm django python manage.py createsuperuser
    fi
    
    print_status "Database initialized successfully"
}

# Start services
start_services() {
    print_status "Starting all services..."
    
    docker-compose up -d
    
    print_status "All services started successfully"
}

# Show service status
show_status() {
    print_status "Service Status:"
    docker-compose ps
    
    echo ""
    print_status "Service URLs:"
    echo "  - Web Interface: http://localhost"
    echo "  - Django Admin: http://localhost/admin"
    echo "  - ClickHouse UI: http://localhost:8123"
    echo "  - Syslog UDP: localhost:514"
    echo "  - Syslog TCP: localhost:514"
}

# Main deployment flow
main() {
    echo "========================================="
    echo "Log Analyzer Docker Deployment"
    echo "========================================="
    echo ""
    
    check_docker
    create_directories
    set_permissions
    
    # Check if this is first deployment
    if [ ! -f ".deployed" ]; then
        print_warning "This appears to be the first deployment."
        build_images
        init_database
    else
        print_warning "Previous deployment detected. Rebuild images? (y/n)"
        read -r rebuild
        if [[ $rebuild == "y" ]]; then
            build_images
        fi
    fi
    
    start_services
    
    # Mark as deployed
    touch .deployed
    
    echo ""
    show_status
    
    echo ""
    print_status "Deployment completed successfully!"
    print_warning "To view logs: docker-compose logs -f [service_name]"
    print_warning "To stop services: docker-compose down"
}

# Run main function
main "$@"