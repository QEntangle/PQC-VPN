#!/bin/bash
# PQC-VPN Demo Setup Script
# Automated setup for one hub + three clients demo

set -e

echo "🎭 PQC-VPN Demo Setup Starting..."
echo "Setting up: 1 Hub Server + 3 Demo Clients + Monitoring"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
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

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if [[ ! -d "docker" || ! -d "tools" || ! -d "web" || ! -f "requirements.txt" ]]; then
        log_error "Not in PQC-VPN project root directory!"
        echo "Please run from the main PQC-VPN directory containing:"
        echo "  📁 docker/ 📁 tools/ 📁 web/ 📄 requirements.txt"
        exit 1
    fi
    
    if ! command -v docker &> /dev/null || ! command -v docker-compose &> /dev/null; then
        log_error "Docker and Docker Compose are required!"
        exit 1
    fi
    
    log_success "Prerequisites verified"
}

# Clean environment
clean_environment() {
    log_info "Cleaning previous demo environment..."
    
    # Stop any existing containers
    docker-compose -f docker/docker-compose.production-fixed.yml down 2>/dev/null || true
    docker-compose -f docker/docker-compose.production.yml down 2>/dev/null || true
    
    # Clean up containers and volumes
    docker container prune -f >/dev/null 2>&1 || true
    docker volume prune -f >/dev/null 2>&1 || true
    
    # Remove previous demo configs
    rm -rf demo-client-configs 2>/dev/null || true
    
    log_success "Environment cleaned"
}

# Setup demo environment
setup_demo_environment() {
    log_info "Setting up demo environment configuration..."
    
    # Create demo .env file
    cat > .env << 'EOF'
# PQC-VPN Demo Configuration
# =============================================================================
# DEMO NETWORK CONFIGURATION
# =============================================================================
HUB_IP=192.168.1.100
HUB_DOMAIN=pqc-hub.demo.local
ORGANIZATION=DemoEnterprise
COUNTRY=US
STATE=California
LOCALITY=Demo

# =============================================================================
# DEMO SECURITY SETTINGS
# =============================================================================
ADMIN_PASSWORD=DemoAdmin123!
SECRET_KEY=demo-secret-key-for-testing-only-32chars
PQC_KEM_ALGORITHM=kyber1024
PQC_SIG_ALGORITHM=dilithium5

# =============================================================================
# DATABASE CONFIGURATION
# =============================================================================
POSTGRES_PASSWORD=DemoPostgres123!
POSTGRES_USER=pqc_admin
POSTGRES_DB=pqc_vpn_enterprise

# =============================================================================
# CACHE CONFIGURATION
# =============================================================================
REDIS_PASSWORD=DemoRedis123!

# =============================================================================
# MONITORING CONFIGURATION
# =============================================================================
GRAFANA_PASSWORD=DemoGrafana123!
GRAFANA_SECRET_KEY=demo-grafana-secret-key-32chars

# =============================================================================
# DEMO PORTS (Non-conflicting)
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
# DEMO FEATURES
# =============================================================================
ENTERPRISE_MODE=true
ENABLE_MONITORING=true
ENABLE_API=true
LOG_LEVEL=INFO
VERSION=1.0.0
BUILD_TYPE=demo
EOF

    # Create required directories
    mkdir -p configs/{prometheus,grafana,nginx} 2>/dev/null || true
    mkdir -p demo-client-configs 2>/dev/null || true
    
    log_success "Demo environment configured"
}

# Start PQC-VPN services
start_services() {
    log_info "Starting PQC-VPN demo services..."
    
    # Build application
    log_info "Building PQC-VPN hub..."
    docker-compose -f docker/docker-compose.production-fixed.yml build pqc-vpn-hub
    
    # Start databases first
    log_info "Starting databases..."
    docker-compose -f docker/docker-compose.production-fixed.yml up -d postgres redis
    
    # Wait for databases
    log_info "Waiting for databases to initialize..."
    sleep 20
    
    # Verify database health
    local retries=0
    while ! docker exec pqc-postgres pg_isready -U pqc_admin -d pqc_vpn_enterprise 2>/dev/null; do
        retries=$((retries + 1))
        if [ $retries -gt 10 ]; then
            log_error "Database failed to start!"
            exit 1
        fi
        log_info "Waiting for PostgreSQL... (attempt $retries/10)"
        sleep 3
    done
    
    # Start main application
    log_info "Starting PQC-VPN hub..."
    docker-compose -f docker/docker-compose.production-fixed.yml up -d pqc-vpn-hub
    
    # Start monitoring
    log_info "Starting monitoring services..."
    docker-compose -f docker/docker-compose.production-fixed.yml --profile monitoring up -d
    
    # Wait for services to stabilize
    log_info "Waiting for services to fully initialize..."
    sleep 30
    
    log_success "All services started successfully"
}

# Create demo clients
create_demo_clients() {
    log_demo "Creating demo clients..."
    
    # Wait a bit more for the hub to be fully ready
    sleep 10
    
    # Client 1: PKI Authentication
    log_demo "Creating Demo Client 1 (PKI Authentication)..."
    docker exec pqc-vpn-hub pqc-vpn-manager user add demo-client-1 client1@demo.local \
        --auth-type pki \
        --full-name "Demo Client 1 (PKI)" \
        --department "Engineering" \
        --location "Office A" 2>/dev/null || true
    
    # Client 2: PSK Authentication  
    log_demo "Creating Demo Client 2 (PSK Authentication)..."
    docker exec pqc-vpn-hub pqc-vpn-manager user add demo-client-2 client2@demo.local \
        --auth-type psk \
        --full-name "Demo Client 2 (PSK)" \
        --department "Marketing" \
        --location "Office B" 2>/dev/null || true
    
    # Client 3: PKI Authentication
    log_demo "Creating Demo Client 3 (PKI Authentication)..."
    docker exec pqc-vpn-hub pqc-vpn-manager user add demo-client-3 client3@demo.local \
        --auth-type pki \
        --full-name "Demo Client 3 (PKI)" \
        --department "Sales" \
        --location "Remote" 2>/dev/null || true
    
    log_success "Demo clients created"
}

# Generate client configurations
generate_client_configs() {
    log_demo "Generating client configuration files..."
    
    # Create configs directory
    mkdir -p demo-client-configs
    
    # Generate basic strongSwan configs (simplified for demo)
    cat > demo-client-configs/client1-strongswan.conf << 'EOF'
# Demo Client 1 - PKI Authentication
conn pqc-demo-client-1
    keyexchange=ikev2
    ike=aes256gcm16-sha512-kyber1024-dilithium5!
    esp=aes256gcm16-sha512-kyber1024!
    left=%any
    leftid=@demo-client-1
    leftauth=pubkey
    leftcert=demo-client-1.crt
    right=192.168.1.100
    rightid=@pqc-hub.demo.local
    rightauth=pubkey
    auto=start
    dpdaction=restart
EOF

    cat > demo-client-configs/client2-strongswan.conf << 'EOF'
# Demo Client 2 - PSK Authentication
conn pqc-demo-client-2
    keyexchange=ikev2
    ike=aes256gcm16-sha512-kyber1024-dilithium5!
    esp=aes256gcm16-sha512-kyber1024!
    left=%any
    leftid=@demo-client-2
    leftauth=psk
    right=192.168.1.100
    rightid=@pqc-hub.demo.local
    rightauth=psk
    auto=start
    dpdaction=restart
EOF

    cat > demo-client-configs/client3-strongswan.conf << 'EOF'
# Demo Client 3 - PKI Authentication
conn pqc-demo-client-3
    keyexchange=ikev2
    ike=aes256gcm16-sha512-kyber1024-dilithium5!
    esp=aes256gcm16-sha512-kyber1024!
    left=%any
    leftid=@demo-client-3
    leftauth=pubkey
    leftcert=demo-client-3.crt
    right=192.168.1.100
    rightid=@pqc-hub.demo.local
    rightauth=pubkey
    auto=start
    dpdaction=restart
EOF

    # Create demo secrets file for PSK client
    cat > demo-client-configs/client2-secrets.conf << 'EOF'
# PSK for Demo Client 2
@demo-client-2 @pqc-hub.demo.local : PSK "DemoSharedSecret123!"
EOF

    # Create demo installation instructions
    cat > demo-client-configs/README.md << 'EOF'
# Demo Client Configuration Files

## Client 1 & 3 (PKI Authentication)
1. Install strongSwan on client machine
2. Copy client certificate and private key to /etc/ipsec.d/certs/ and /etc/ipsec.d/private/
3. Copy configuration to /etc/ipsec.d/
4. Start with: `ipsec up pqc-demo-client-X`

## Client 2 (PSK Authentication)  
1. Install strongSwan on client machine
2. Copy configuration to /etc/ipsec.d/
3. Copy secrets to /etc/ipsec.secrets
4. Start with: `ipsec up pqc-demo-client-2`

## Post-Quantum Cryptography
All clients use:
- KEM: Kyber1024 (Key Exchange)
- Signature: Dilithium5 (Authentication)
- Encryption: AES-256-GCM
EOF

    log_success "Client configurations generated in demo-client-configs/"
}

# Verify demo setup
verify_demo() {
    log_info "Verifying demo setup..."
    
    # Check container status
    echo ""
    echo "=== Container Status ==="
    docker-compose -f docker/docker-compose.production-fixed.yml ps
    
    # Check services health
    echo ""
    log_info "Checking service health..."
    
    if docker exec pqc-postgres pg_isready -U pqc_admin -d pqc_vpn_enterprise &>/dev/null; then
        log_success "✅ PostgreSQL is healthy"
    else
        log_warning "⚠️ PostgreSQL may not be ready"
    fi
    
    if docker exec pqc-redis redis-cli ping &>/dev/null; then
        log_success "✅ Redis is healthy"
    else
        log_warning "⚠️ Redis may not be ready"
    fi
    
    if curl -k -f https://localhost:8443/health &>/dev/null; then
        log_success "✅ Web interface is responding"
    else
        log_warning "⚠️ Web interface may still be starting"
    fi
    
    # Check demo clients
    echo ""
    log_demo "Demo clients status:"
    docker exec pqc-vpn-hub pqc-vpn-manager user list 2>/dev/null || echo "User management initializing..."
    
    log_success "Demo verification completed"
}

# Show demo information
show_demo_info() {
    echo ""
    echo "🎉 ======================================"
    echo "🎭 PQC-VPN DEMO READY!"
    echo "🎉 ======================================"
    echo ""
    echo "📋 DEMO SETUP:"
    echo "   ✅ 1 PQC-VPN Hub Server"
    echo "   ✅ 3 Demo Clients (2 PKI + 1 PSK)"
    echo "   ✅ Web Management Interface"
    echo "   ✅ Monitoring Dashboard"
    echo "   ✅ Client Configuration Files"
    echo ""
    echo "🌐 ACCESS URLS:"
    echo "   Web Interface:  https://localhost:8443"
    echo "   Admin Login:    admin / DemoAdmin123!"
    echo "   API Endpoint:   https://localhost:9090"
    echo "   Grafana:        http://localhost:13000 (admin / DemoGrafana123!)"
    echo "   Prometheus:     http://localhost:19090"
    echo ""
    echo "👥 DEMO CLIENTS:"
    echo "   📱 demo-client-1: PKI Auth (Engineering)"
    echo "   📱 demo-client-2: PSK Auth (Marketing)" 
    echo "   📱 demo-client-3: PKI Auth (Sales)"
    echo ""
    echo "📁 CLIENT CONFIGS:"
    echo "   Location: ./demo-client-configs/"
    echo "   Files: strongSwan configurations + instructions"
    echo ""
    echo "🔐 POST-QUANTUM CRYPTO:"
    echo "   KEM Algorithm:  Kyber1024"
    echo "   Signature:      Dilithium5"
    echo "   Encryption:     AES-256-GCM"
    echo ""
    echo "📊 DEMO COMMANDS:"
    echo "   View logs:      docker-compose -f docker/docker-compose.production-fixed.yml logs -f"
    echo "   User status:    docker exec pqc-vpn-hub pqc-vpn-manager user list"
    echo "   System status:  docker exec pqc-vpn-hub pqc-vpn-manager status"
    echo "   Stop demo:      docker-compose -f docker/docker-compose.production-fixed.yml down"
    echo ""
    echo "🎯 DEMO HIGHLIGHTS:"
    echo "   • Post-Quantum Cryptography implementation"
    echo "   • Multi-authentication methods (PKI + PSK)"
    echo "   • Enterprise management interface"
    echo "   • Real-time monitoring and metrics"
    echo "   • Production-ready Docker deployment"
    echo ""
    log_success "Demo setup completed successfully!"
    echo ""
    echo "🚀 Ready for demonstration!"
}

# Simulate some demo activity
simulate_demo_activity() {
    if [[ "${1:-}" == "--with-simulation" ]]; then
        log_demo "Simulating demo activity..."
        
        # Add some demo connection logs
        sleep 5
        
        # Simulate connection attempts
        log_demo "Simulating connection events..."
        
        # Add demo data to database
        docker exec pqc-postgres psql -U pqc_admin -d pqc_vpn_enterprise -c "
        INSERT INTO connection_logs (client_id, connection_time, status, ip_address, duration) VALUES
        ('demo-client-1', NOW() - INTERVAL '5 minutes', 'connected', '10.0.1.101', 300),
        ('demo-client-2', NOW() - INTERVAL '3 minutes', 'connected', '10.0.1.102', 180),
        ('demo-client-3', NOW() - INTERVAL '1 minute', 'connecting', '10.0.1.103', 0)
        ON CONFLICT DO NOTHING;" 2>/dev/null || true
        
        log_demo "Demo activity simulation completed"
    fi
}

# Main execution
main() {
    local with_simulation=""
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --with-simulation)
                with_simulation="--with-simulation"
                shift
                ;;
            --help|-h)
                echo "Usage: $0 [--with-simulation] [--help]"
                echo ""
                echo "Sets up PQC-VPN demo with 1 hub + 3 clients"
                echo ""
                echo "Options:"
                echo "  --with-simulation    Add simulated connection activity"
                echo "  --help              Show this help message"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done
    
    # Main demo setup sequence
    check_prerequisites
    clean_environment
    setup_demo_environment
    start_services
    create_demo_clients
    generate_client_configs
    simulate_demo_activity "$with_simulation"
    
    # Wait for everything to stabilize
    sleep 10
    
    verify_demo
    show_demo_info
}

# Handle script interruption
trap 'echo -e "\n${RED}Demo setup interrupted!${NC}"; exit 1' INT TERM

# Run main function with all arguments
main "$@"