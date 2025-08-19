#!/bin/bash
# PQC-VPN Production Startup Script
# Fixes common issues and provides proper initialization

set -e

echo "=== PQC-VPN Production Startup ==="
echo "Initializing PQC-VPN enterprise deployment..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're in the correct directory
check_directory() {
    log_info "Checking project directory structure..."
    
    if [[ ! -d "docker" || ! -d "tools" || ! -d "web" || ! -f "requirements.txt" ]]; then
        log_error "Not in PQC-VPN project root directory!"
        log_info "Please run this script from the main PQC-VPN directory containing:"
        echo "  📁 docker/"
        echo "  📁 tools/"
        echo "  📁 web/"
        echo "  📄 requirements.txt"
        exit 1
    fi
    
    log_success "Directory structure verified"
}

# Clean up any existing containers
cleanup_containers() {
    log_info "Cleaning up existing containers..."
    
    # Stop all PQC-VPN related containers
    docker-compose -f docker/docker-compose.production-fixed.yml down 2>/dev/null || true
    docker-compose -f docker/docker-compose.production.yml down 2>/dev/null || true
    docker-compose -f docker/docker-compose.yml down 2>/dev/null || true
    
    # Remove orphaned containers
    docker container prune -f
    
    log_success "Container cleanup completed"
}

# Setup environment configuration
setup_environment() {
    log_info "Setting up environment configuration..."
    
    if [[ ! -f ".env" ]]; then
        if [[ -f ".env.example" ]]; then
            log_info "Creating .env from .env.example..."
            cp .env.example .env
            log_warning "Please edit .env file with your specific configuration!"
            log_warning "Important: Change default passwords and set your HUB_IP!"
        else
            log_error ".env.example not found! Creating minimal .env..."
            cat > .env << 'EOF'
# Minimal PQC-VPN Configuration
HUB_IP=192.168.1.100
HUB_DOMAIN=pqc-hub.demo.local
ORGANIZATION=DemoOrganization
COUNTRY=US
STATE=California
LOCALITY=Demo

# Security (CHANGE THESE!)
ADMIN_PASSWORD=ChangeMe123!
SECRET_KEY=demo-secret-key-change-in-production
PQC_KEM_ALGORITHM=kyber1024
PQC_SIG_ALGORITHM=dilithium5

# Database
POSTGRES_PASSWORD=SecurePostgres123!
POSTGRES_USER=pqc_admin
POSTGRES_DB=pqc_vpn_enterprise

# Cache
REDIS_PASSWORD=SecureRedis123!

# Monitoring
GRAFANA_PASSWORD=SecureGrafana123!
GRAFANA_SECRET_KEY=grafana-secret-key-demo

# Ports (using non-conflicting defaults)
POSTGRES_EXTERNAL_PORT=15432
REDIS_EXTERNAL_PORT=16379
GRAFANA_EXTERNAL_PORT=13000
PROMETHEUS_EXTERNAL_PORT=19090

# Features
ENTERPRISE_MODE=true
ENABLE_MONITORING=true
LOG_LEVEL=INFO
EOF
        fi
        
        log_warning "Created .env file with default values"
        log_warning "IMPORTANT: Edit .env file before proceeding!"
        echo ""
        echo "Key settings to update:"
        echo "  - HUB_IP: Set to your server's IP address"
        echo "  - ADMIN_PASSWORD: Change from default"
        echo "  - All other passwords: Use secure values"
        echo ""
        read -p "Press Enter after updating .env file, or Ctrl+C to exit..."
    else
        log_success "Environment file .env already exists"
    fi
}

# Create required directories
create_directories() {
    log_info "Creating required directories..."
    
    # Create missing configuration directories
    mkdir -p configs/{prometheus,grafana,nginx}
    mkdir -p data/{postgres,redis,pqc-vpn}
    mkdir -p logs
    
    log_success "Directory structure created"
}

# Create basic Prometheus configuration if missing
create_prometheus_config() {
    if [[ ! -f "configs/prometheus/prometheus.yml" ]]; then
        log_info "Creating basic Prometheus configuration..."
        mkdir -p configs/prometheus
        cat > configs/prometheus/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  # - "first_rules.yml"

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'pqc-vpn-hub'
    static_configs:
      - targets: ['pqc-vpn-hub:9100']
    scrape_interval: 30s
    metrics_path: '/metrics'

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres:5432']
    scrape_interval: 60s

  - job_name: 'redis'
    static_configs:
      - targets: ['redis:6379']
    scrape_interval: 60s
EOF
        log_success "Prometheus configuration created"
    fi
}

# Check Docker and Docker Compose
check_docker() {
    log_info "Checking Docker installation..."
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed!"
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running!"
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed!"
        exit 1
    fi
    
    log_success "Docker environment verified"
}

# Build the application
build_application() {
    log_info "Building PQC-VPN application..."
    
    # Source environment variables
    set -a
    source .env
    set +a
    
    # Build the main hub container
    log_info "Building pqc-vpn-hub container..."
    docker-compose -f docker/docker-compose.production-fixed.yml build pqc-vpn-hub
    
    log_success "Application built successfully"
}

# Start core services
start_core_services() {
    log_info "Starting core services (PostgreSQL and Redis)..."
    
    docker-compose -f docker/docker-compose.production-fixed.yml up -d postgres redis
    
    # Wait for databases to be ready
    log_info "Waiting for databases to initialize..."
    sleep 15
    
    # Check database health
    local retries=0
    while ! docker exec pqc-postgres pg_isready -U pqc_admin -d pqc_vpn_enterprise 2>/dev/null; do
        retries=$((retries + 1))
        if [ $retries -gt 12 ]; then
            log_error "PostgreSQL failed to start properly"
            exit 1
        fi
        log_info "Waiting for PostgreSQL... (attempt $retries/12)"
        sleep 5
    done
    
    log_success "Core services started successfully"
}

# Start main application
start_application() {
    log_info "Starting PQC-VPN Hub..."
    
    docker-compose -f docker/docker-compose.production-fixed.yml up -d pqc-vpn-hub
    
    # Wait for application to start
    log_info "Waiting for application to initialize..."
    sleep 30
    
    log_success "PQC-VPN Hub started"
}

# Start monitoring (optional)
start_monitoring() {
    if [[ "${1:-}" == "--with-monitoring" ]]; then
        log_info "Starting monitoring services..."
        
        create_prometheus_config
        docker-compose -f docker/docker-compose.production-fixed.yml --profile monitoring up -d
        
        log_success "Monitoring services started"
        echo ""
        echo "Monitoring URLs:"
        echo "  Grafana: http://localhost:${GRAFANA_EXTERNAL_PORT:-13000}"
        echo "  Prometheus: http://localhost:${PROMETHEUS_EXTERNAL_PORT:-19090}"
    fi
}

# Verify deployment
verify_deployment() {
    log_info "Verifying deployment..."
    
    # Check container status
    echo ""
    echo "Container Status:"
    docker-compose -f docker/docker-compose.production-fixed.yml ps
    
    # Check key services
    echo ""
    log_info "Testing key services..."
    
    # Test database connection
    if docker exec pqc-postgres pg_isready -U pqc_admin -d pqc_vpn_enterprise &>/dev/null; then
        log_success "PostgreSQL is healthy"
    else
        log_warning "PostgreSQL may not be fully ready"
    fi
    
    # Test Redis connection
    if docker exec pqc-redis redis-cli ping &>/dev/null; then
        log_success "Redis is healthy"
    else
        log_warning "Redis may not be fully ready"
    fi
    
    # Test web interface
    if curl -k -f https://localhost:8443/health &>/dev/null; then
        log_success "Web interface is responding"
    else
        log_warning "Web interface may still be initializing"
    fi
    
    echo ""
    log_success "Deployment verification completed"
}

# Show access information
show_access_info() {
    echo ""
    echo "=== PQC-VPN Access Information ==="
    echo ""
    echo "🌐 Web Interface: https://localhost:8443"
    echo "🔐 Admin Login: admin / ${ADMIN_PASSWORD:-ChangeMe123!}"
    echo ""
    echo "📊 API Endpoint: https://localhost:9090"
    echo "📈 Metrics: http://localhost:9100"
    echo ""
    echo "🗄️  Database (PostgreSQL): localhost:${POSTGRES_EXTERNAL_PORT:-15432}"
    echo "⚡ Cache (Redis): localhost:${REDIS_EXTERNAL_PORT:-16379}"
    echo ""
    
    if [[ "${1:-}" == "--with-monitoring" ]]; then
        echo "📈 Grafana: http://localhost:${GRAFANA_EXTERNAL_PORT:-13000}"
        echo "📊 Prometheus: http://localhost:${PROMETHEUS_EXTERNAL_PORT:-19090}"
        echo ""
    fi
    
    echo "📋 View logs: docker-compose -f docker/docker-compose.production-fixed.yml logs -f"
    echo "🛑 Stop all: docker-compose -f docker/docker-compose.production-fixed.yml down"
    echo ""
}

# Main execution
main() {
    local with_monitoring=""
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --with-monitoring)
                with_monitoring="--with-monitoring"
                shift
                ;;
            --help|-h)
                echo "Usage: $0 [--with-monitoring] [--help]"
                echo ""
                echo "Options:"
                echo "  --with-monitoring    Start with Grafana and Prometheus"
                echo "  --help              Show this help message"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Run startup sequence
    check_directory
    check_docker
    cleanup_containers
    setup_environment
    create_directories
    build_application
    start_core_services
    start_application
    start_monitoring "$with_monitoring"
    
    # Wait a moment for services to stabilize
    sleep 10
    
    verify_deployment
    show_access_info "$with_monitoring"
    
    log_success "PQC-VPN deployment completed successfully!"
}

# Run main function with all arguments
main "$@"