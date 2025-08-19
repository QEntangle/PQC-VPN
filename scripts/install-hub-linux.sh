#!/bin/bash

# PQC-VPN Hub Installation Script for Linux (Enhanced)
# Supports Ubuntu 20.04+, CentOS 8+, Debian 11+, RHEL 8+, Rocky Linux 8+
# Version: 2.0.0

set -euo pipefail

# Script configuration
SCRIPT_VERSION="2.0.0"
SCRIPT_NAME="PQC-VPN Hub Installer"
LOG_FILE="/var/log/pqc-vpn-install.log"
CONFIG_DIR="/etc/pqc-vpn"
BACKUP_DIR="/var/backups/pqc-vpn"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Installation options (can be overridden via environment variables)
HUB_IP="${HUB_IP:-$(hostname -I | awk '{print $1}')}"
ENABLE_HA="${ENABLE_HA:-false}"
ENABLE_MONITORING="${ENABLE_MONITORING:-true}"
ENABLE_WEB_INTERFACE="${ENABLE_WEB_INTERFACE:-true}"
STRONGSWAN_VERSION="${STRONGSWAN_VERSION:-5.9.14}"
AUTH_METHODS="${AUTH_METHODS:-pki,psk,hybrid}"
PQC_ALGORITHMS="${PQC_ALGORITHMS:-kyber1024,kyber768,dilithium5,dilithium3}"
INSTALL_MODE="${INSTALL_MODE:-production}"  # production, development, testing

# Function definitions
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "${LOG_FILE}"
}

info() {
    log "INFO" "${BLUE}[INFO]${NC} $*"
}

warn() {
    log "WARN" "${YELLOW}[WARN]${NC} $*"
}

error() {
    log "ERROR" "${RED}[ERROR]${NC} $*"
}

success() {
    log "SUCCESS" "${GREEN}[SUCCESS]${NC} $*"
}

debug() {
    if [[ "${DEBUG:-false}" == "true" ]]; then
        log "DEBUG" "${PURPLE}[DEBUG]${NC} $*"
    fi
}

# Cleanup function
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        error "Installation failed with exit code $exit_code"
        error "Check the log file: $LOG_FILE"
    fi
    exit $exit_code
}

trap cleanup EXIT

print_banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
╔═══════════════════════════════════════════════════════════════╗
║                    PQC-VPN Hub Installer                     ║
║                 Post-Quantum Cryptography VPN                ║
║                        Version 2.0.0                        ║
╚═══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS_ID="$ID"
        OS_VERSION="$VERSION_ID"
        OS_NAME="$PRETTY_NAME"
    elif [[ -f /etc/redhat-release ]]; then
        OS_ID="rhel"
        OS_VERSION=$(cat /etc/redhat-release | sed 's/.*release \([0-9]\+\).*/\1/')
        OS_NAME=$(cat /etc/redhat-release)
    else
        error "Unsupported operating system"
        exit 1
    fi
    
    info "Detected OS: $OS_NAME"
    debug "OS ID: $OS_ID, Version: $OS_VERSION"
}

check_requirements() {
    info "Checking system requirements..."
    
    # Check CPU architecture
    local arch=$(uname -m)
    if [[ "$arch" != "x86_64" && "$arch" != "aarch64" ]]; then
        error "Unsupported architecture: $arch"
        exit 1
    fi
    
    # Check available memory (minimum 2GB)
    local mem_gb=$(free -g | awk '/^Mem:/{print $2}')
    if [[ $mem_gb -lt 2 ]]; then
        warn "System has less than 2GB RAM. PQC-VPN may not perform optimally."
    fi
    
    # Check disk space (minimum 10GB)
    local disk_gb=$(df / | awk 'NR==2{printf "%.0f", $4/1024/1024}')
    if [[ $disk_gb -lt 10 ]]; then
        error "Insufficient disk space. At least 10GB required."
        exit 1
    fi
    
    # Check kernel version for IPsec support
    local kernel_version=$(uname -r | cut -d. -f1-2)
    local kernel_major=$(echo $kernel_version | cut -d. -f1)
    local kernel_minor=$(echo $kernel_version | cut -d. -f2)
    
    if [[ $kernel_major -lt 4 || ($kernel_major -eq 4 && $kernel_minor -lt 15) ]]; then
        warn "Kernel version $kernel_version may not support all PQC features"
    fi
    
    success "System requirements check passed"
}

setup_logging() {
    # Create log directory
    mkdir -p "$(dirname "$LOG_FILE")"
    
    # Start logging
    info "Starting $SCRIPT_NAME v$SCRIPT_VERSION"
    info "Installation mode: $INSTALL_MODE"
    info "Hub IP: $HUB_IP"
    info "Authentication methods: $AUTH_METHODS"
    info "PQC algorithms: $PQC_ALGORITHMS"
}

create_directories() {
    info "Creating directory structure..."
    
    local dirs=(
        "$CONFIG_DIR"
        "$BACKUP_DIR"
        "/etc/ipsec.d/certs"
        "/etc/ipsec.d/private"
        "/etc/ipsec.d/cacerts"
        "/etc/ipsec.d/crls"
        "/etc/ipsec.d/conf.d"
        "/etc/ipsec.d/secrets"
        "/var/log/strongswan"
        "/var/log/pqc-vpn"
        "/usr/local/share/pqc-vpn"
        "/usr/local/bin/pqc-vpn"
    )
    
    for dir in "${dirs[@]}"; do
        mkdir -p "$dir"
        debug "Created directory: $dir"
    done
    
    # Set proper permissions
    chmod 700 /etc/ipsec.d/private
    chmod 755 /etc/ipsec.d/certs
    chmod 755 /etc/ipsec.d/cacerts
    
    success "Directory structure created"
}

install_dependencies() {
    info "Installing system dependencies..."
    
    case "$OS_ID" in
        ubuntu|debian)
            # Update package list
            apt-get update -qq
            
            # Install dependencies
            local packages=(
                "build-essential"
                "libssl-dev"
                "libcurl4-openssl-dev"
                "libgmp-dev"
                "libtspi-dev"
                "libldap2-dev"
                "libsystemd-dev"
                "pkg-config"
                "libnl-3-dev"
                "libnl-route-3-dev"
                "iptables-dev"
                "python3"
                "python3-pip"
                "python3-dev"
                "git"
                "wget"
                "curl"
                "jq"
                "openssl"
                "strongswan"
                "strongswan-pki"
                "strongswan-swanctl"
                "ipsec-tools"
                "docker.io"
                "docker-compose"
            )
            
            if [[ "$ENABLE_MONITORING" == "true" ]]; then
                packages+=("prometheus" "grafana")
            fi
            
            DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}"
            ;;
            
        centos|rhel|rocky|almalinux)
            # Enable EPEL repository
            if ! rpm -q epel-release > /dev/null 2>&1; then
                yum install -y epel-release
            fi
            
            # Install dependencies
            local packages=(
                "gcc"
                "gcc-c++"
                "make"
                "openssl-devel"
                "libcurl-devel"
                "gmp-devel"
                "systemd-devel"
                "pkgconfig"
                "libnl3-devel"
                "iptables-devel"
                "python3"
                "python3-pip"
                "python3-devel"
                "git"
                "wget"
                "curl"
                "jq"
                "openssl"
                "strongswan"
                "docker"
                "docker-compose"
            )
            
            yum install -y "${packages[@]}"
            ;;
            
        *)
            error "Unsupported operating system: $OS_ID"
            exit 1
            ;;
    esac
    
    success "System dependencies installed"
}

install_pqc_libraries() {
    info "Installing Post-Quantum Cryptography libraries..."
    
    # Create temporary build directory
    local build_dir="/tmp/pqc-build-$$"
    mkdir -p "$build_dir"
    cd "$build_dir"
    
    # Install liboqs (Open Quantum Safe)
    info "Building liboqs..."
    git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs.git
    cd liboqs
    mkdir build && cd build
    cmake -DCMAKE_INSTALL_PREFIX=/usr/local \
          -DOQS_USE_OPENSSL=ON \
          -DOQS_BUILD_ONLY_LIB=ON \
          -DOQS_ENABLE_KEM_KYBER=ON \
          -DOQS_ENABLE_SIG_DILITHIUM=ON \
          -DOQS_ENABLE_SIG_FALCON=ON \
          -DOQS_ENABLE_SIG_SPHINCS=ON \
          ..
    make -j$(nproc)
    make install
    ldconfig
    
    # Install OQS-OpenSSL provider
    cd "$build_dir"
    info "Building OQS-OpenSSL provider..."
    git clone --depth 1 --branch main https://github.com/open-quantum-safe/oqs-provider.git
    cd oqs-provider
    cmake -DCMAKE_INSTALL_PREFIX=/usr/local -S . -B _build
    cmake --build _build
    cmake --install _build
    
    # Configure OpenSSL to use the OQS provider
    local openssl_config="/etc/ssl/openssl.cnf"
    if ! grep -q "oqsprovider" "$openssl_config" 2>/dev/null; then
        cat >> "$openssl_config" << 'EOF'

# OQS Provider Configuration
[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[oqsprovider_sect]
activate = 1
module = /usr/local/lib/ossl-modules/oqsprovider.so
EOF
    fi
    
    # Cleanup
    cd /
    rm -rf "$build_dir"
    
    success "PQC libraries installed"
}

configure_strongswan() {
    info "Configuring strongSwan with PQC support..."
    
    # Backup existing configuration
    if [[ -f /etc/ipsec.conf ]]; then
        cp /etc/ipsec.conf "$BACKUP_DIR/ipsec.conf.backup.$(date +%Y%m%d_%H%M%S)"
    fi
    
    if [[ -f /etc/ipsec.secrets ]]; then
        cp /etc/ipsec.secrets "$BACKUP_DIR/ipsec.secrets.backup.$(date +%Y%m%d_%H%M%S)"
    fi
    
    if [[ -f /etc/strongswan.conf ]]; then
        cp /etc/strongswan.conf "$BACKUP_DIR/strongswan.conf.backup.$(date +%Y%m%d_%H%M%S)"
    fi
    
    # Copy enhanced configuration files from the repository
    local repo_dir="${REPO_DIR:-/opt/PQC-VPN}"
    if [[ -d "$repo_dir/configs/hub" ]]; then
        cp "$repo_dir/configs/hub/ipsec.conf" /etc/ipsec.conf
        cp "$repo_dir/configs/hub/ipsec.secrets" /etc/ipsec.secrets
        cp "$repo_dir/configs/hub/strongswan.conf" /etc/strongswan.conf
    else
        # Download from GitHub if repository not found locally
        warn "Local repository not found, downloading configuration from GitHub..."
        wget -O /etc/ipsec.conf "https://raw.githubusercontent.com/QEntangle/PQC-VPN/main/configs/hub/ipsec.conf"
        wget -O /etc/ipsec.secrets "https://raw.githubusercontent.com/QEntangle/PQC-VPN/main/configs/hub/ipsec.secrets"
        wget -O /etc/strongswan.conf "https://raw.githubusercontent.com/QEntangle/PQC-VPN/main/configs/hub/strongswan.conf"
    fi
    
    # Replace template variables
    sed -i "s/{HUB_IP}/$HUB_IP/g" /etc/ipsec.conf
    sed -i "s/{HUB_IP}/$HUB_IP/g" /etc/ipsec.secrets
    
    # Set proper permissions
    chmod 644 /etc/ipsec.conf
    chmod 600 /etc/ipsec.secrets
    chmod 644 /etc/strongswan.conf
    
    success "strongSwan configuration updated"
}

generate_certificates() {
    info "Generating PQC certificates..."
    
    # Use the enhanced certificate generation script
    local cert_script="${REPO_DIR:-/opt/PQC-VPN}/tools/pqc-keygen.py"
    if [[ -f "$cert_script" ]]; then
        python3 "$cert_script" ca
        python3 "$cert_script" hub "$HUB_IP"
    else
        # Fallback to basic certificate generation
        warn "PQC certificate generator not found, using basic OpenSSL certificates"
        
        # Generate CA certificate
        openssl req -x509 -newkey rsa:4096 -keyout /etc/ipsec.d/private/ca-key.pem \
                    -out /etc/ipsec.d/cacerts/ca-cert.pem -days 3650 -nodes \
                    -subj "/C=US/O=PQC-VPN/CN=PQC-VPN CA"
        
        # Generate hub certificate
        openssl req -newkey rsa:4096 -keyout /etc/ipsec.d/private/hub-key.pem \
                    -out /tmp/hub-req.pem -nodes \
                    -subj "/C=US/O=PQC-VPN/CN=hub.pqc-vpn.local"
        
        openssl x509 -req -in /tmp/hub-req.pem -CA /etc/ipsec.d/cacerts/ca-cert.pem \
                     -CAkey /etc/ipsec.d/private/ca-key.pem -CAcreateserial \
                     -out /etc/ipsec.d/certs/hub-cert.pem -days 365
        
        rm /tmp/hub-req.pem
    fi
    
    # Set proper permissions
    chmod 600 /etc/ipsec.d/private/*
    chmod 644 /etc/ipsec.d/certs/*
    chmod 644 /etc/ipsec.d/cacerts/*
    
    success "Certificates generated"
}

setup_firewall() {
    info "Configuring firewall..."
    
    # Detect firewall system
    if command -v ufw > /dev/null; then
        # Ubuntu/Debian UFW
        ufw --force enable
        ufw allow 500/udp
        ufw allow 4500/udp
        ufw allow ssh
        
        if [[ "$ENABLE_WEB_INTERFACE" == "true" ]]; then
            ufw allow 8443
        fi
        
        if [[ "$ENABLE_MONITORING" == "true" ]]; then
            ufw allow 3000  # Grafana
            ufw allow 9090  # Prometheus
        fi
        
    elif command -v firewall-cmd > /dev/null; then
        # CentOS/RHEL firewalld
        systemctl enable firewalld
        systemctl start firewalld
        
        firewall-cmd --permanent --add-service=ipsec
        firewall-cmd --permanent --add-port=500/udp
        firewall-cmd --permanent --add-port=4500/udp
        
        if [[ "$ENABLE_WEB_INTERFACE" == "true" ]]; then
            firewall-cmd --permanent --add-port=8443/tcp
        fi
        
        if [[ "$ENABLE_MONITORING" == "true" ]]; then
            firewall-cmd --permanent --add-port=3000/tcp
            firewall-cmd --permanent --add-port=9090/tcp
        fi
        
        firewall-cmd --reload
        
    elif command -v iptables > /dev/null; then
        # Direct iptables
        iptables -A INPUT -p udp --dport 500 -j ACCEPT
        iptables -A INPUT -p udp --dport 4500 -j ACCEPT
        iptables -A INPUT -p tcp --dport 22 -j ACCEPT
        
        if [[ "$ENABLE_WEB_INTERFACE" == "true" ]]; then
            iptables -A INPUT -p tcp --dport 8443 -j ACCEPT
        fi
        
        # Save iptables rules
        if command -v iptables-save > /dev/null; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        fi
    fi
    
    success "Firewall configured"
}

configure_networking() {
    info "Configuring network settings..."
    
    # Enable IP forwarding
    echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-pqc-vpn.conf
    echo 'net.ipv6.conf.all.forwarding = 1' >> /etc/sysctl.d/99-pqc-vpn.conf
    
    # Optimize for VPN performance
    cat >> /etc/sysctl.d/99-pqc-vpn.conf << 'EOF'
# PQC-VPN Network Optimizations
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.route.flush = 1
EOF
    
    # Apply sysctl settings
    sysctl -p /etc/sysctl.d/99-pqc-vpn.conf
    
    success "Network settings configured"
}

install_python_tools() {
    info "Installing Python management tools..."
    
    # Install Python dependencies
    pip3 install --upgrade pip
    
    local pip_packages=(
        "psutil>=5.9.0"
        "pyyaml>=6.0"
        "cryptography>=41.0.0"
        "requests>=2.28.0"
        "click>=8.1.0"
        "tabulate>=0.9.0"
        "colorama>=0.4.6"
        "flask>=2.3.0"
        "flask-cors>=4.0.0"
        "jinja2>=3.1.0"
        "jsonschema>=4.0.0"
        "schedule>=1.2.0"
    )
    
    pip3 install "${pip_packages[@]}"
    
    # Install PQC-VPN tools
    local tools_dir="${REPO_DIR:-/opt/PQC-VPN}/tools"
    if [[ -d "$tools_dir" ]]; then
        cp "$tools_dir"/*.py /usr/local/bin/pqc-vpn/
        chmod +x /usr/local/bin/pqc-vpn/*.py
        
        # Create symlinks
        ln -sf /usr/local/bin/pqc-vpn/vpn-manager.py /usr/local/bin/pqc-vpn-manager
        ln -sf /usr/local/bin/pqc-vpn/connection-monitor.py /usr/local/bin/pqc-connection-monitor
        ln -sf /usr/local/bin/pqc-vpn/pqc-keygen.py /usr/local/bin/pqc-keygen
    fi
    
    success "Python tools installed"
}

setup_web_interface() {
    if [[ "$ENABLE_WEB_INTERFACE" != "true" ]]; then
        return 0
    fi
    
    info "Setting up web management interface..."
    
    # Install web interface files
    local web_dir="${REPO_DIR:-/opt/PQC-VPN}/web"
    if [[ -d "$web_dir" ]]; then
        mkdir -p /var/www/pqc-vpn
        cp -r "$web_dir"/* /var/www/pqc-vpn/
        
        # Create systemd service for web API
        cat > /etc/systemd/system/pqc-vpn-web.service << 'EOF'
[Unit]
Description=PQC-VPN Web Management Interface
After=network.target strongswan.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/var/www/pqc-vpn
ExecStart=/usr/bin/python3 /var/www/pqc-vpn/api_server.py
Restart=always
RestartSec=10
Environment=PYTHONPATH=/usr/local/bin/pqc-vpn

[Install]
WantedBy=multi-user.target
EOF
        
        systemctl daemon-reload
        systemctl enable pqc-vpn-web
    fi
    
    success "Web interface configured"
}

setup_monitoring() {
    if [[ "$ENABLE_MONITORING" != "true" ]]; then
        return 0
    fi
    
    info "Setting up monitoring..."
    
    # Create monitoring configuration
    mkdir -p /etc/pqc-vpn/monitoring
    
    # Prometheus configuration
    cat > /etc/pqc-vpn/monitoring/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'pqc-vpn-hub'
    static_configs:
      - targets: ['localhost:8443']
    metrics_path: '/api/metrics'
    
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['localhost:9100']
EOF
    
    # Node exporter for system metrics
    if ! command -v node_exporter > /dev/null; then
        local node_exporter_version="1.7.0"
        wget -O /tmp/node_exporter.tar.gz \
            "https://github.com/prometheus/node_exporter/releases/download/v${node_exporter_version}/node_exporter-${node_exporter_version}.linux-amd64.tar.gz"
        tar -xzf /tmp/node_exporter.tar.gz -C /tmp
        mv "/tmp/node_exporter-${node_exporter_version}.linux-amd64/node_exporter" /usr/local/bin/
        rm -rf /tmp/node_exporter*
        
        # Create systemd service
        cat > /etc/systemd/system/node-exporter.service << 'EOF'
[Unit]
Description=Node Exporter
After=network.target

[Service]
Type=simple
User=nobody
Group=nobody
ExecStart=/usr/local/bin/node_exporter
Restart=always

[Install]
WantedBy=multi-user.target
EOF
        
        systemctl daemon-reload
        systemctl enable node-exporter
        systemctl start node-exporter
    fi
    
    success "Monitoring configured"
}

setup_systemd_services() {
    info "Configuring systemd services..."
    
    # Ensure strongSwan is enabled and started
    systemctl enable strongswan
    
    # Create PQC-VPN specific service
    cat > /etc/systemd/system/pqc-vpn.service << 'EOF'
[Unit]
Description=PQC-VPN Hub Service
After=network.target strongswan.service
Requires=strongswan.service

[Service]
Type=forking
ExecStart=/usr/sbin/ipsec start --nofork
ExecReload=/usr/sbin/ipsec reload
ExecStop=/usr/sbin/ipsec stop
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    # Create maintenance service
    cat > /etc/systemd/system/pqc-vpn-maintenance.service << 'EOF'
[Unit]
Description=PQC-VPN Maintenance Tasks
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/pqc-vpn-maintenance.sh

[Install]
WantedBy=multi-user.target
EOF
    
    # Create maintenance timer
    cat > /etc/systemd/system/pqc-vpn-maintenance.timer << 'EOF'
[Unit]
Description=Run PQC-VPN maintenance tasks daily
Requires=pqc-vpn-maintenance.service

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF
    
    # Create maintenance script
    cat > /usr/local/bin/pqc-vpn-maintenance.sh << 'EOF'
#!/bin/bash
# PQC-VPN Maintenance Script

# Rotate logs
find /var/log/strongswan -name "*.log" -mtime +30 -delete
find /var/log/pqc-vpn -name "*.log" -mtime +30 -delete

# Check certificate expiry
if command -v pqc-connection-monitor > /dev/null; then
    pqc-connection-monitor certificates --check-expiry
fi

# Backup configuration
if [[ -d /var/backups/pqc-vpn ]]; then
    tar -czf "/var/backups/pqc-vpn/config-backup-$(date +%Y%m%d).tar.gz" \
        /etc/ipsec.conf /etc/ipsec.secrets /etc/strongswan.conf \
        /etc/ipsec.d/certs /etc/ipsec.d/cacerts 2>/dev/null || true
    
    # Keep only last 7 days of backups
    find /var/backups/pqc-vpn -name "config-backup-*.tar.gz" -mtime +7 -delete
fi
EOF
    
    chmod +x /usr/local/bin/pqc-vpn-maintenance.sh
    
    # Reload systemd and enable services
    systemctl daemon-reload
    systemctl enable pqc-vpn
    systemctl enable pqc-vpn-maintenance.timer
    
    success "Systemd services configured"
}

start_services() {
    info "Starting services..."
    
    # Start strongSwan
    systemctl start strongswan
    
    # Start PQC-VPN service
    systemctl start pqc-vpn
    
    # Start web interface if enabled
    if [[ "$ENABLE_WEB_INTERFACE" == "true" ]]; then
        systemctl start pqc-vpn-web
    fi
    
    # Start maintenance timer
    systemctl start pqc-vpn-maintenance.timer
    
    # Verify services are running
    sleep 5
    
    if systemctl is-active --quiet strongswan; then
        success "strongSwan service is running"
    else
        error "strongSwan service failed to start"
        systemctl status strongswan
    fi
    
    if systemctl is-active --quiet pqc-vpn; then
        success "PQC-VPN service is running"
    else
        warn "PQC-VPN service status check failed"
    fi
    
    success "Services started"
}

perform_post_install_checks() {
    info "Performing post-installation checks..."
    
    # Check IPsec status
    if ipsec status > /dev/null 2>&1; then
        success "IPsec is functioning correctly"
    else
        warn "IPsec status check failed"
    fi
    
    # Check certificate validity
    if [[ -f /etc/ipsec.d/certs/hub-cert.pem ]]; then
        local cert_expiry=$(openssl x509 -in /etc/ipsec.d/certs/hub-cert.pem -noout -enddate | cut -d= -f2)
        info "Hub certificate expires: $cert_expiry"
    fi
    
    # Check PQC library availability
    if openssl list -providers | grep -q oqsprovider; then
        success "OpenSSL OQS provider is available"
    else
        warn "OpenSSL OQS provider not detected"
    fi
    
    # Check network connectivity
    if ping -c 1 8.8.8.8 > /dev/null 2>&1; then
        success "Internet connectivity verified"
    else
        warn "Internet connectivity check failed"
    fi
    
    # Performance check
    local cpu_cores=$(nproc)
    local mem_gb=$(free -g | awk '/^Mem:/{print $2}')
    info "System resources: $cpu_cores CPU cores, ${mem_gb}GB RAM"
    
    success "Post-installation checks completed"
}

print_installation_summary() {
    echo -e "\n${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                   INSTALLATION COMPLETE                      ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}\n"
    
    echo -e "${CYAN}🎉 PQC-VPN Hub has been successfully installed!${NC}\n"
    
    echo -e "${BLUE}📊 Installation Summary:${NC}"
    echo -e "   • Hub IP Address: ${YELLOW}$HUB_IP${NC}"
    echo -e "   • Authentication Methods: ${YELLOW}$AUTH_METHODS${NC}"
    echo -e "   • PQC Algorithms: ${YELLOW}$PQC_ALGORITHMS${NC}"
    echo -e "   • Web Interface: ${YELLOW}$([ "$ENABLE_WEB_INTERFACE" == "true" ] && echo "Enabled" || echo "Disabled")${NC}"
    echo -e "   • Monitoring: ${YELLOW}$([ "$ENABLE_MONITORING" == "true" ] && echo "Enabled" || echo "Disabled")${NC}"
    echo -e "   • High Availability: ${YELLOW}$([ "$ENABLE_HA" == "true" ] && echo "Enabled" || echo "Disabled")${NC}"
    
    echo -e "\n${BLUE}🔗 Access Points:${NC}"
    if [[ "$ENABLE_WEB_INTERFACE" == "true" ]]; then
        echo -e "   • Web Dashboard: ${YELLOW}https://$HUB_IP:8443${NC}"
    fi
    if [[ "$ENABLE_MONITORING" == "true" ]]; then
        echo -e "   • Grafana: ${YELLOW}http://$HUB_IP:3000${NC} (admin/admin)"
        echo -e "   • Prometheus: ${YELLOW}http://$HUB_IP:9090${NC}"
    fi
    
    echo -e "\n${BLUE}📁 Important Files:${NC}"
    echo -e "   • Configuration: ${YELLOW}/etc/ipsec.conf${NC}"
    echo -e "   • Secrets: ${YELLOW}/etc/ipsec.secrets${NC}"
    echo -e "   • Certificates: ${YELLOW}/etc/ipsec.d/certs/${NC}"
    echo -e "   • Logs: ${YELLOW}/var/log/strongswan/${NC}"
    echo -e "   • Installation Log: ${YELLOW}$LOG_FILE${NC}"
    
    echo -e "\n${BLUE}🔧 Next Steps:${NC}"
    echo -e "   1. Add spoke users: ${YELLOW}pqc-vpn-manager user add <username> --email <email>${NC}"
    echo -e "   2. Monitor connections: ${YELLOW}pqc-connection-monitor status${NC}"
    echo -e "   3. View logs: ${YELLOW}journalctl -u strongswan -f${NC}"
    echo -e "   4. Check status: ${YELLOW}ipsec status${NC}"
    
    echo -e "\n${BLUE}📚 Documentation:${NC}"
    echo -e "   • GitHub: ${YELLOW}https://github.com/QEntangle/PQC-VPN${NC}"
    echo -e "   • Docs: ${YELLOW}https://github.com/QEntangle/PQC-VPN/tree/main/docs${NC}"
    
    echo -e "\n${GREEN}✅ Installation completed successfully!${NC}"
    echo -e "   ${CYAN}Thank you for choosing PQC-VPN for quantum-safe networking.${NC}\n"
}

# Main installation function
main() {
    print_banner
    check_root
    detect_os
    setup_logging
    check_requirements
    create_directories
    install_dependencies
    install_pqc_libraries
    configure_strongswan
    generate_certificates
    setup_firewall
    configure_networking
    install_python_tools
    setup_web_interface
    setup_monitoring
    setup_systemd_services
    start_services
    perform_post_install_checks
    print_installation_summary
}

# Handle command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --hub-ip)
            HUB_IP="$2"
            shift 2
            ;;
        --enable-ha)
            ENABLE_HA="true"
            shift
            ;;
        --disable-web)
            ENABLE_WEB_INTERFACE="false"
            shift
            ;;
        --disable-monitoring)
            ENABLE_MONITORING="false"
            shift
            ;;
        --install-mode)
            INSTALL_MODE="$2"
            shift 2
            ;;
        --auth-methods)
            AUTH_METHODS="$2"
            shift 2
            ;;
        --pqc-algorithms)
            PQC_ALGORITHMS="$2"
            shift 2
            ;;
        --debug)
            DEBUG="true"
            shift
            ;;
        --help|-h)
            echo "PQC-VPN Hub Installer v$SCRIPT_VERSION"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --hub-ip IP               Set hub IP address"
            echo "  --enable-ha               Enable high availability"
            echo "  --disable-web             Disable web interface"
            echo "  --disable-monitoring      Disable monitoring"
            echo "  --install-mode MODE       Set install mode (production/development/testing)"
            echo "  --auth-methods METHODS    Set authentication methods (pki,psk,hybrid)"
            echo "  --pqc-algorithms ALGOS    Set PQC algorithms (kyber1024,dilithium5,etc)"
            echo "  --debug                   Enable debug output"
            echo "  --help, -h                Show this help message"
            echo ""
            echo "Environment Variables:"
            echo "  HUB_IP                    Hub IP address"
            echo "  ENABLE_HA                 Enable high availability (true/false)"
            echo "  ENABLE_MONITORING         Enable monitoring (true/false)"
            echo "  ENABLE_WEB_INTERFACE      Enable web interface (true/false)"
            echo "  REPO_DIR                  Local repository directory"
            echo ""
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Run main installation
main "$@"
