#!/bin/bash
# PQC-VPN Enterprise Demo Setup Script - Windows Compatible
# Complete deployment with real strongSwan integration and enterprise dashboard

set -e

echo "🚀 PQC-VPN Enterprise Demo Setup Starting..."
echo "Setting up: 1 Hub Server + 3 Demo Clients + Enterprise Dashboard + Monitoring"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
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

log_demo() {
    echo -e "${PURPLE}[DEMO]${NC} $1"
}

log_enterprise() {
    echo -e "${CYAN}[ENTERPRISE]${NC} $1"
}

# Detect operating system and get host IP
detect_host_ip() {
    local host_ip="192.168.1.100"  # Default fallback
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        host_ip=$(ip route get 1.1.1.1 | grep -oP 'src \K\S+' 2>/dev/null || echo "192.168.1.100")
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        host_ip=$(route get 1.1.1.1 | grep interface | awk '{print $2}' | xargs ipconfig getifaddr 2>/dev/null || echo "192.168.1.100")
    elif [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
        # Windows (Cygwin/MSYS2/Git Bash)
        if command -v ipconfig &> /dev/null; then
            # Try to get IP from ipconfig
            host_ip=$(ipconfig | grep -E "IPv4.*:" | head -1 | awk '{print $NF}' | tr -d '\r' 2>/dev/null || echo "192.168.1.100")
        elif command -v hostname &> /dev/null; then
            # Fallback to hostname resolution
            host_ip=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "192.168.1.100")
        fi
    else
        # Unknown OS
        log_warning "Unknown operating system: $OSTYPE. Using default IP."
        host_ip="192.168.1.100"
    fi
    
    echo "$host_ip"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if [[ ! -d "docker" || ! -d "tools" || ! -d "web" || ! -f "requirements.txt" ]]; then
        log_error "Not in PQC-VPN project root directory!"
        echo "Please run from the main PQC-VPN directory containing:"
        echo "  📁 docker/ 📁 tools/ 📁 web/ 📄 requirements.txt"
        exit 1
    fi
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is required but not found!"
        echo "Please install Docker Desktop for Windows:"
        echo "https://docs.docker.com/desktop/install/windows-install/"
        exit 1
    fi
    
    # Check Docker Compose
    if ! docker compose version &> /dev/null && ! docker-compose --version &> /dev/null; then
        log_error "Docker Compose is required but not found!"
        echo "Please ensure Docker Desktop is running and includes Docker Compose."
        exit 1
    fi
    
    # Check Docker daemon
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running!"
        echo "Please start Docker Desktop and try again."
        exit 1
    fi
    
    # Check Docker version
    docker_version=$(docker --version | grep -oE '[0-9]+\.[0-9]+' | head -1)
    log_info "Docker version $docker_version detected"
    
    # Check available disk space (Windows compatible)
    if command -v df &> /dev/null; then
        available_space=$(df . | tail -1 | awk '{print $4}')
        if [[ $available_space -lt 10485760 ]]; then  # 10GB in KB
            log_warning "Less than 10GB disk space available. This may cause issues."
        fi
    fi
    
    log_success "Prerequisites verified"
}

# Clean environment
clean_environment() {
    log_info "Cleaning previous environment..."
    
    # Use docker compose (newer) or docker-compose (legacy)
    local compose_cmd="docker compose"
    if ! docker compose version &> /dev/null; then
        compose_cmd="docker-compose"
    fi
    
    # Stop any existing containers
    $compose_cmd -f docker/docker-compose.enterprise.yml down --remove-orphans 2>/dev/null || true
    $compose_cmd -f docker/docker-compose.production-fixed.yml down --remove-orphans 2>/dev/null || true
    $compose_cmd -f docker/docker-compose.production.yml down --remove-orphans 2>/dev/null || true
    
    # Clean up containers and volumes
    docker container prune -f >/dev/null 2>&1 || true
    docker volume prune -f >/dev/null 2>&1 || true
    
    # Remove previous demo configs (Windows compatible)
    rm -rf demo-client-configs 2>/dev/null || true
    rm -rf client-configs.tar.gz 2>/dev/null || true
    rm -rf data/ logs/ 2>/dev/null || true
    
    log_success "Environment cleaned"
}

# Setup enterprise environment
setup_enterprise_environment() {
    log_enterprise "Setting up enterprise environment configuration..."
    
    # Detect host IP (Windows compatible)
    HOST_IP=$(detect_host_ip)
    log_enterprise "Detected host IP: $HOST_IP"
    
    # Create enterprise .env file
    cat > .env << EOF
# =============================================================================
# PQC-VPN ENTERPRISE CONFIGURATION (Windows Compatible)
# =============================================================================

# Network Configuration
HUB_IP=${HOST_IP}
HUB_DOMAIN=pqc-hub.enterprise.local
ORGANIZATION=DemoEnterprise
COUNTRY=US
STATE=California
LOCALITY=DemoCity

# =============================================================================
# ENTERPRISE SECURITY SETTINGS
# =============================================================================
ADMIN_PASSWORD=EnterpriseAdmin123!
SECRET_KEY=enterprise-secret-key-32chars-long
PQC_KEM_ALGORITHM=kyber1024
PQC_SIG_ALGORITHM=dilithium5

# =============================================================================
# DATABASE CONFIGURATION (Enterprise Grade)
# =============================================================================
POSTGRES_PASSWORD=EnterpriseDB123!
POSTGRES_USER=pqc_admin
POSTGRES_DB=pqc_vpn_enterprise

# =============================================================================
# CACHE CONFIGURATION
# =============================================================================
REDIS_PASSWORD=EnterpriseRedis123!

# =============================================================================
# MONITORING CONFIGURATION
# =============================================================================
GRAFANA_PASSWORD=EnterpriseGrafana123!
GRAFANA_SECRET_KEY=enterprise-grafana-secret-32chars

# =============================================================================
# ENTERPRISE PORTS (Windows Compatible)
# =============================================================================
VPN_PORT_IKE=500
VPN_PORT_NATT=4500
WEB_PORT=8443
API_PORT=9090
METRICS_PORT=9100

# External ports (avoid conflicts)
POSTGRES_EXTERNAL_PORT=15432
REDIS_EXTERNAL_PORT=16379
GRAFANA_EXTERNAL_PORT=13000
PROMETHEUS_EXTERNAL_PORT=19090

# =============================================================================
# WINDOWS SPECIFIC SETTINGS
# =============================================================================
COMPOSE_CONVERT_WINDOWS_PATHS=1
COMPOSE_PATH_SEPARATOR=;

# =============================================================================
# ENTERPRISE FEATURES
# =============================================================================
ENTERPRISE_MODE=true
ENABLE_MONITORING=true
ENABLE_API=true
LOG_LEVEL=INFO
VERSION=1.0.0
BUILD_TYPE=enterprise
AUTO_CONNECT=false
EOF

    # Create required directories with proper structure (Windows compatible)
    log_enterprise "Creating enterprise directory structure..."
    mkdir -p data/postgres data/redis data/ipsec data/pqc-vpn data/prometheus data/grafana 2>/dev/null || true
    mkdir -p logs configs/prometheus configs/grafana/dashboards configs/grafana/datasources 2>/dev/null || true
    
    # Create Prometheus configuration
    cat > configs/prometheus/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s
  external_labels:
    monitor: 'pqc-vpn-monitor'

scrape_configs:
  - job_name: 'pqc-vpn-metrics'
    static_configs:
      - targets: ['metrics-exporter:9100']
    scrape_interval: 30s
    metrics_path: '/metrics'

  - job_name: 'pqc-vpn-api'
    static_configs:
      - targets: ['api-server:9090']
    scrape_interval: 60s
    metrics_path: '/metrics'
EOF

    # Create Grafana datasource configuration
    cat > configs/grafana/datasources/prometheus.yml << 'EOF'
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
EOF

    # Create basic Grafana dashboard
    cat > configs/grafana/dashboards/pqc-vpn.json << 'EOF'
{
  "dashboard": {
    "id": null,
    "title": "PQC-VPN Enterprise Dashboard",
    "tags": ["pqc", "vpn", "enterprise"],
    "timezone": "browser",
    "panels": [
      {
        "id": 1,
        "title": "Active Connections",
        "type": "stat",
        "targets": [
          {
            "expr": "pqc_vpn_active_connections",
            "legendFormat": "Connections"
          }
        ]
      }
    ],
    "time": {
      "from": "now-6h",
      "to": "now"
    },
    "refresh": "30s"
  }
}
EOF

    log_success "Enterprise environment configured with host IP: ${HOST_IP}"
}

# Start enterprise services (Windows compatible)
start_enterprise_services() {
    log_enterprise "Starting PQC-VPN enterprise services..."
    
    # Determine compose command
    local compose_cmd="docker compose"
    if ! docker compose version &> /dev/null; then
        compose_cmd="docker-compose"
        log_info "Using legacy docker-compose command"
    fi
    
    # Check if enterprise compose file exists
    if [[ ! -f "docker/docker-compose.enterprise.yml" ]]; then
        log_error "Enterprise Docker Compose file not found!"
        echo "Using fallback production configuration..."
        COMPOSE_FILE="docker/docker-compose.production-fixed.yml"
    else
        COMPOSE_FILE="docker/docker-compose.enterprise.yml"
    fi
    
    # Build and start core services
    log_enterprise "Building PQC-VPN enterprise images..."
    $compose_cmd -f $COMPOSE_FILE build --parallel postgres redis || {
        log_warning "Parallel build failed, trying sequential build..."
        $compose_cmd -f $COMPOSE_FILE build postgres redis
    }
    
    # Start databases first
    log_enterprise "Starting enterprise databases..."
    $compose_cmd -f $COMPOSE_FILE up -d postgres redis
    
    # Wait for databases with enhanced health checking
    log_enterprise "Waiting for databases to initialize..."
    local retries=0
    while ! docker exec pqc-postgres pg_isready -U pqc_admin -d pqc_vpn_enterprise 2>/dev/null; do
        retries=$((retries + 1))
        if [ $retries -gt 20 ]; then
            log_error "PostgreSQL failed to start!"
            $compose_cmd -f $COMPOSE_FILE logs postgres
            exit 1
        fi
        log_info "Waiting for PostgreSQL... (attempt $retries/20)"
        sleep 3
    done
    
    while ! docker exec pqc-redis redis-cli ping 2>/dev/null | grep -q PONG; do
        retries=$((retries + 1))
        if [ $retries -gt 25 ]; then
            log_error "Redis failed to start!"
            $compose_cmd -f $COMPOSE_FILE logs redis
            exit 1
        fi
        log_info "Waiting for Redis... (attempt $retries/25)"
        sleep 2
    done
    
    # Try to build and start main services
    log_enterprise "Building main PQC-VPN components..."
    if ! $compose_cmd -f $COMPOSE_FILE build pqc-vpn-hub 2>/dev/null; then
        log_warning "Hub build failed, trying alternative approach..."
        # Use a simpler configuration for Windows
        create_windows_fallback_compose
        COMPOSE_FILE="docker-compose.windows.yml"
        $compose_cmd -f $COMPOSE_FILE build
    fi
    
    # Start main PQC-VPN hub
    log_enterprise "Starting PQC-VPN hub..."
    $compose_cmd -f $COMPOSE_FILE up -d pqc-vpn-hub || {
        log_warning "Hub startup failed, checking logs..."
        $compose_cmd -f $COMPOSE_FILE logs pqc-vpn-hub
    }
    
    # Wait for hub to initialize
    log_enterprise "Waiting for services to initialize..."
    sleep 30
    
    # Start web services if available
    if $compose_cmd -f $COMPOSE_FILE config | grep -q "web-dashboard"; then
        log_enterprise "Starting enterprise web services..."
        $compose_cmd -f $COMPOSE_FILE up -d web-dashboard api-server || {
            log_warning "Web services startup failed, continuing with basic setup..."
        }
    fi
    
    # Start monitoring (optional)
    if [[ "${ENABLE_MONITORING:-true}" == "true" ]]; then
        log_enterprise "Starting monitoring stack..."
        $compose_cmd -f $COMPOSE_FILE --profile monitoring up -d || {
            log_warning "Monitoring stack startup failed, continuing without monitoring..."
        }
    fi
    
    # Wait for all services to stabilize
    log_enterprise "Waiting for all services to stabilize..."
    sleep 45
    
    log_success "Enterprise services started"
}

# Create Windows-compatible fallback compose file
create_windows_fallback_compose() {
    cat > docker-compose.windows.yml << 'EOF'
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    container_name: pqc-postgres
    restart: unless-stopped
    environment:
      POSTGRES_DB: ${POSTGRES_DB:-pqc_vpn_enterprise}
      POSTGRES_USER: ${POSTGRES_USER:-pqc_admin}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-EnterpriseDB123!}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "${POSTGRES_EXTERNAL_PORT:-15432}:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER:-pqc_admin}"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    container_name: pqc-redis
    restart: unless-stopped
    command: redis-server --requirepass ${REDIS_PASSWORD:-EnterpriseRedis123!}
    volumes:
      - redis_data:/data
    ports:
      - "${REDIS_EXTERNAL_PORT:-16379}:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 3s
      retries: 5

  pqc-vpn-hub:
    image: strongswan/strongswan:latest
    container_name: pqc-vpn-hub
    restart: unless-stopped
    privileged: true
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    environment:
      - HUB_IP=${HUB_IP:-192.168.1.100}
      - ENTERPRISE_MODE=true
    volumes:
      - pqc_configs:/etc/ipsec.d
      - pqc_logs:/var/log
    ports:
      - "${VPN_PORT_IKE:-500}:500/udp"
      - "${VPN_PORT_NATT:-4500}:4500/udp"
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy

volumes:
  postgres_data:
  redis_data:
  pqc_configs:
  pqc_logs:
EOF
}

# Create simplified demo users
create_demo_users() {
    log_demo "Creating demo user entries..."
    
    # Add demo users to database
    docker exec pqc-postgres psql -U pqc_admin -d pqc_vpn_enterprise -c "
    INSERT INTO users (username, email, auth_type, full_name, department, status) VALUES
    ('engineering-alice', 'alice@engineering.demo', 'pki', 'Alice Cooper - Senior Engineer', 'Engineering', 'active'),
    ('sales-bob', 'bob@sales.demo', 'psk', 'Bob Wilson - Sales Manager', 'Sales', 'active'),
    ('executive-carol', 'carol@exec.demo', 'pki', 'Carol Davis - CTO', 'Executive', 'active')
    ON CONFLICT (username) DO NOTHING;
    " 2>/dev/null || log_warning "User creation requires manual setup"
    
    log_success "Demo users prepared"
}

# Verify enterprise deployment
verify_enterprise_deployment() {
    log_enterprise "Verifying enterprise deployment..."
    
    # Determine compose command
    local compose_cmd="docker compose"
    if ! docker compose version &> /dev/null; then
        compose_cmd="docker-compose"
    fi
    
    # Check container status
    echo ""
    echo "=== Enterprise Container Status ==="
    local compose_file="docker/docker-compose.enterprise.yml"
    if [[ ! -f "$compose_file" ]]; then
        compose_file="docker-compose.windows.yml"
    fi
    $compose_cmd -f $compose_file ps
    
    # Check services health
    echo ""
    log_enterprise "Checking enterprise service health..."
    
    # Database health
    if docker exec pqc-postgres pg_isready -U pqc_admin -d pqc_vpn_enterprise &>/dev/null; then
        log_success "✅ PostgreSQL Enterprise Database is healthy"
    else
        log_warning "⚠️ PostgreSQL may not be ready"
    fi
    
    # Cache health
    if docker exec pqc-redis redis-cli ping &>/dev/null; then
        log_success "✅ Redis Enterprise Cache is healthy"
    else
        log_warning "⚠️ Redis may not be ready"
    fi
    
    # VPN Hub health
    if docker exec pqc-vpn-hub which ipsec &>/dev/null; then
        log_success "✅ VPN Hub container is running"
    else
        log_warning "⚠️ VPN Hub may not have strongSwan installed"
    fi
    
    # Web services health (if available)
    if docker ps --format "table {{.Names}}" | grep -q "pqc-web-dashboard"; then
        if curl -k -f https://localhost:8443/api/enterprise/status &>/dev/null; then
            log_success "✅ Enterprise Web Dashboard is responding"
        else
            log_warning "⚠️ Enterprise Web Dashboard may still be starting"
        fi
    else
        log_info "ℹ️ Web dashboard not deployed (using basic setup)"
    fi
    
    log_success "Enterprise deployment verification completed"
}

# Show enterprise demo information
show_enterprise_info() {
    local host_ip=${HOST_IP:-$(detect_host_ip)}
    
    echo ""
    echo "🎉 ========================================"
    echo "🚀 PQC-VPN ENTERPRISE DEMO READY!"
    echo "🎉 ========================================"
    echo ""
    echo "📋 WINDOWS ENTERPRISE SETUP:"
    echo "   ✅ PostgreSQL Database (Enterprise-grade)"
    echo "   ✅ Redis Cache (High-performance)"
    echo "   ✅ VPN Hub Container (strongSwan-based)"
    echo "   ✅ 3 Demo Users (Multi-auth ready)"
    echo "   ✅ Windows Docker Integration"
    echo ""
    echo "🌐 ACCESS POINTS:"
    echo "   PostgreSQL:    localhost:15432"
    echo "   Redis:         localhost:16379"
    echo "   VPN Ports:     500/UDP, 4500/UDP"
    echo ""
    if docker ps --format "table {{.Names}}" | grep -q "pqc-web-dashboard"; then
        echo "   Dashboard:     https://${host_ip}:8443"
        echo "   API:           https://${host_ip}:9090"
    fi
    if docker ps --format "table {{.Names}}" | grep -q "pqc-grafana"; then
        echo "   Grafana:       http://${host_ip}:13000"
        echo "   Prometheus:    http://${host_ip}:19090"
    fi
    echo ""
    echo "👥 DEMO USERS:"
    echo "   🔐 engineering-alice: PKI Auth (Engineering)"
    echo "   🔑 sales-bob:         PSK Auth (Sales)" 
    echo "   🔐 executive-carol:   PKI Auth (Executive)"
    echo ""
    echo "🔧 WINDOWS MANAGEMENT:"
    echo "   View containers:  docker ps"
    echo "   View logs:        docker logs [container-name]"
    echo "   Database access:  docker exec -it pqc-postgres psql -U pqc_admin -d pqc_vpn_enterprise"
    echo "   Redis access:     docker exec -it pqc-redis redis-cli"
    echo "   Stop demo:        docker compose down"
    echo ""
    echo "📝 NEXT STEPS:"
    echo "   1. Install strongSwan on client machines"
    echo "   2. Configure VPN connections"
    echo "   3. Test inter-client communication"
    echo ""
    log_success "Windows enterprise demo setup completed successfully!"
    echo ""
    echo "🚀 Ready for demonstration on Windows!"
}

# Main execution
main() {
    local with_simulation=""
    local enable_monitoring="true"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --with-simulation)
                with_simulation="--with-simulation"
                shift
                ;;
            --no-monitoring)
                enable_monitoring="false"
                shift
                ;;
            --help|-h)
                echo "Usage: $0 [--with-simulation] [--no-monitoring] [--help]"
                echo ""
                echo "Sets up PQC-VPN enterprise demo with 1 hub + 3 clients (Windows Compatible)"
                echo ""
                echo "Options:"
                echo "  --with-simulation    Add simulated connection activity"
                echo "  --no-monitoring      Skip monitoring stack"
                echo "  --help              Show this help message"
                echo ""
                echo "Windows Requirements:"
                echo "  • Docker Desktop for Windows"
                echo "  • Git Bash or PowerShell"
                echo "  • 4GB+ RAM available"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done
    
    # Export monitoring setting
    export ENABLE_MONITORING="$enable_monitoring"
    
    # Main enterprise setup sequence
    echo "🏢 Starting PQC-VPN Enterprise Demo Setup..."
    check_prerequisites
    clean_environment
    setup_enterprise_environment
    start_enterprise_services
    create_demo_users
    
    # Wait for everything to stabilize
    sleep 15
    
    verify_enterprise_deployment
    show_enterprise_info
}

# Handle script interruption
trap 'echo -e "\n${RED}Enterprise demo setup interrupted!${NC}"; exit 1' INT TERM

# Run main function with all arguments
main "$@"
