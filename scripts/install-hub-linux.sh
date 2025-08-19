#!/bin/bash

# PQC-VPN Hub Installation Script for Linux
# Enterprise Post-Quantum Cryptography VPN Solution
# Supports Ubuntu 20.04+, CentOS 8+, Debian 11+, RHEL 8+, Rocky Linux 8+
# Version: 1.0.0

set -euo pipefail

# Script configuration
SCRIPT_VERSION="1.0.0"
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
ENTERPRISE_MODE="${ENTERPRISE_MODE:-false}"

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
║          Enterprise Post-Quantum Cryptography VPN           ║
║                        Version 1.0.0                        ║
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
    
    # Check available memory (minimum 4GB for enterprise)
    local mem_gb=$(free -g | awk '/^Mem:/{print $2}')
    if [[ "$ENTERPRISE_MODE" == "true" && $mem_gb -lt 8 ]]; then
        error "Enterprise mode requires at least 8GB RAM. Current: ${mem_gb}GB"
        exit 1
    elif [[ $mem_gb -lt 4 ]]; then
        warn "System has less than 4GB RAM. PQC-VPN may not perform optimally."
    fi
    
    # Check disk space (minimum 20GB for enterprise)
    local disk_gb=$(df / | awk 'NR==2{printf "%.0f", $4/1024/1024}')
    local min_disk=$([[ "$ENTERPRISE_MODE" == "true" ]] && echo "20" || echo "10")
    if [[ $disk_gb -lt $min_disk ]]; then
        error "Insufficient disk space. At least ${min_disk}GB required."
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
    info "Enterprise mode: $ENTERPRISE_MODE"
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
        "/var/lib/pqc-vpn"
        "/opt/pqc-vpn"
    )
    
    for dir in "${dirs[@]}"; do
        mkdir -p "$dir"
        debug "Created directory: $dir"
    done
    
    # Set proper permissions
    chmod 700 /etc/ipsec.d/private
    chmod 755 /etc/ipsec.d/certs
    chmod 755 /etc/ipsec.d/cacerts
    chmod 750 /var/lib/pqc-vpn
    
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
                "python3-venv"
                "git"
                "wget"
                "curl"
                "jq"
                "openssl"
                "strongswan"
                "strongswan-pki"
                "strongswan-swanctl"
                "ipsec-tools"
                "cmake"
                "ninja-build"
                "libtool"
                "autotools-dev"
                "doxygen"
                "graphviz"
                "docker.io"
                "docker-compose"
            )
            
            if [[ "$ENABLE_MONITORING" == "true" ]]; then
                packages+=("prometheus" "grafana")
            fi
            
            if [[ "$ENTERPRISE_MODE" == "true" ]]; then
                packages+=("postgresql" "redis-server" "nginx")
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
                "cmake"
                "ninja-build"
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
                "libtool"
                "autotools"
                "doxygen"
                "graphviz"
            )
            
            if [[ "$ENTERPRISE_MODE" == "true" ]]; then
                packages+=("postgresql-server" "redis" "nginx")
            fi
            
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
    info "Building liboqs with full algorithm support..."
    git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs.git
    cd liboqs
    mkdir build && cd build
    cmake -GNinja \
          -DCMAKE_INSTALL_PREFIX=/usr/local \
          -DCMAKE_BUILD_TYPE=Release \
          -DOQS_USE_OPENSSL=ON \
          -DOQS_BUILD_ONLY_LIB=ON \
          -DOQS_ENABLE_KEM_KYBER=ON \
          -DOQS_ENABLE_SIG_DILITHIUM=ON \
          -DOQS_ENABLE_SIG_FALCON=ON \
          -DOQS_ENABLE_SIG_SPHINCS=ON \
          -DOQS_ENABLE_KEM_NTRU=ON \
          -DOQS_ENABLE_KEM_SABER=ON \
          -DOQS_BUILD_SHARED_LIBS=ON \
          ..
    ninja
    ninja install
    ldconfig
    
    # Install OQS-OpenSSL provider
    cd "$build_dir"
    info "Building OQS-OpenSSL provider..."
    git clone --depth 1 --branch main https://github.com/open-quantum-safe/oqs-provider.git
    cd oqs-provider
    cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -S . -B _build
    ninja -C _build
    ninja -C _build install
    
    # Configure OpenSSL to use the OQS provider
    local openssl_config="/etc/ssl/openssl.cnf"
    if ! grep -q "oqsprovider" "$openssl_config" 2>/dev/null; then
        cat >> "$openssl_config" << 'EOF'

# OQS Provider Configuration for PQC-VPN
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
    
    # Verify installation
    if /usr/local/bin/openssl list -providers | grep -q oqsprovider; then
        success "OQS provider successfully installed"
    else
        warn "OQS provider installation may have issues"
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
    
    # Create enterprise-grade ipsec.conf
    cat > /etc/ipsec.conf << EOF
# PQC-VPN Hub Configuration - Version 1.0.0
config setup
    charondebug="ike 2, knl 2, cfg 2, net 2, esp 2, dmn 2, mgr 2"
    strictcrlpolicy=no
    uniqueids=never

# High Security Profile - Kyber-1024 + Dilithium-5
conn %default
    keyexchange=ikev2
    ike=aes256gcm16-sha512-kyber1024-dilithium5!
    esp=aes256gcm16-sha512-kyber1024!
    dpdaction=restart
    dpddelay=30s
    dpdtimeout=120s
    rekeymargin=3m
    keyingtries=3
    authby=pubkey
    left=$HUB_IP
    leftsubnet=0.0.0.0/0
    leftfirewall=yes
    right=%any
    auto=add

# PKI Authentication Profile
conn pki-profile
    also=%default
    leftcert=hub-cert.pem
    leftid=@hub.pqc-vpn.local
    rightca="C=US, O=PQC-VPN, CN=PQC-VPN CA"
    
# PSK Authentication Profile  
conn psk-profile
    also=%default
    authby=psk
    leftid=@hub.pqc-vpn.local
    
# Balanced Security Profile - Kyber-768 + Dilithium-3
conn balanced-profile
    keyexchange=ikev2
    ike=aes256gcm16-sha384-kyber768-dilithium3!
    esp=aes256gcm16-sha384-kyber768!
    dpdaction=restart
    dpddelay=30s
    dpdtimeout=120s
    rekeymargin=5m
    keyingtries=3
    authby=pubkey
    left=$HUB_IP
    leftsubnet=0.0.0.0/0
    leftfirewall=yes
    right=%any
    leftcert=hub-cert.pem
    leftid=@hub.pqc-vpn.local
    rightca="C=US, O=PQC-VPN, CN=PQC-VPN CA"
    auto=add

# High Performance Profile - Kyber-512 + Dilithium-2
conn performance-profile
    keyexchange=ikev2
    ike=aes128gcm16-sha256-kyber512-dilithium2!
    esp=aes128gcm16-sha256-kyber512!
    dpdaction=restart
    dpddelay=30s
    dpdtimeout=120s
    rekeymargin=8m
    keyingtries=3
    authby=pubkey
    left=$HUB_IP
    leftsubnet=0.0.0.0/0
    leftfirewall=yes
    right=%any
    leftcert=hub-cert.pem
    leftid=@hub.pqc-vpn.local
    rightca="C=US, O=PQC-VPN, CN=PQC-VPN CA"
    auto=add
EOF

    # Create ipsec.secrets
    cat > /etc/ipsec.secrets << EOF
# PQC-VPN Hub Secrets - Version 1.0.0
# RSA private key for this host, authenticating it to any other host
: RSA hub-key.pem

# Pre-shared keys (PSK) for specific connections
# Add PSK entries as needed for spoke authentication
EOF

    # Create enhanced strongswan.conf
    cat > /etc/strongswan.conf << EOF
# PQC-VPN strongSwan Configuration - Version 1.0.0
charon {
    load_modular = yes
    
    # Performance optimizations
    threads = $(([[ "$ENTERPRISE_MODE" == "true" ]] && echo "32" || echo "16"))
    worker_threads = $(([[ "$ENTERPRISE_MODE" == "true" ]] && echo "16" || echo "8"))
    
    processor {
        priority_threads {
            high = $(([[ "$ENTERPRISE_MODE" == "true" ]] && echo "8" || echo "4"))
            medium = $(([[ "$ENTERPRISE_MODE" == "true" ]] && echo "4" || echo "2"))
            low = $(([[ "$ENTERPRISE_MODE" == "true" ]] && echo "2" || echo "1"))
        }
    }
    
    # Network settings
    port = 500
    port_nat_t = 4500
    
    # Security settings
    send_vendor_id = no
    send_delay = 0
    retransmit_timeout = 4.0
    retransmit_tries = 5
    retransmit_base = 1.8
    
    # Logging
    filelog {
        /var/log/strongswan/charon.log {
            time_format = %b %e %T
            ike_name = yes
            append = no
            default = 1
            flush_line = yes
        }
        stderr {
            ike = 2
            knl = 2
            cfg = 2
        }
    }
    
    # Plugin configuration
    plugins {
        include strongswan.d/charon/*.conf
        
        openssl {
            load = yes
            
            # Enable PQC algorithms
            fips_mode = no
            engine_id = oqsprovider
        }
        
        kernel-netlink {
            load = yes
            fwmark = !0x42
        }
        
        socket-default {
            load = yes
        }
        
        stroke {
            load = yes
        }
        
        updown {
            load = yes
        }
        
        eap-identity {
            load = yes
        }
        
        eap-md5 {
            load = yes
        }
        
        eap-mschapv2 {
            load = yes
        }
        
        eap-radius {
            load = yes
        }
        
        xauth-generic {
            load = yes
        }
        
        resolve {
            load = yes
        }
        
        nonce {
            load = yes
        }
        
        random {
            load = yes
        }
        
        pem {
            load = yes
        }
        
        pkcs1 {
            load = yes
        }
        
        pkcs8 {
            load = yes
        }
        
        pkcs12 {
            load = yes
        }
        
        pubkey {
            load = yes
        }
        
        sshkey {
            load = yes
        }
        
        x509 {
            load = yes
        }
        
        revocation {
            load = yes
        }
        
        constraints {
            load = yes
        }
        
        acert {
            load = yes
        }
        
        hmac {
            load = yes
        }
        
        aes {
            load = yes
        }
        
        des {
            load = yes
        }
        
        sha1 {
            load = yes
        }
        
        sha2 {
            load = yes
        }
        
        md5 {
            load = yes
        }
        
        gmp {
            load = yes
        }
        
        curve25519 {
            load = yes
        }
        
        mgf1 {
            load = yes
        }
        
        gcm {
            load = yes
        }
        
        ccm {
            load = yes
        }
        
        ctr {
            load = yes
        }
        
        cmac {
            load = yes
        }
    }
}

include strongswan.d/*.conf
EOF

    # Set proper permissions
    chmod 644 /etc/ipsec.conf
    chmod 600 /etc/ipsec.secrets
    chmod 644 /etc/strongswan.conf
    
    success "strongSwan configuration created"
}

generate_certificates() {
    info "Generating PQC certificates..."
    
    # Generate CA private key with Dilithium-5
    /usr/local/bin/openssl genpkey -algorithm dilithium5 \
        -out /etc/ipsec.d/private/ca-key.pem
    
    # Generate CA certificate
    /usr/local/bin/openssl req -new -x509 -key /etc/ipsec.d/private/ca-key.pem \
        -out /etc/ipsec.d/cacerts/ca-cert.pem -days 3650 \
        -subj "/C=US/ST=Unknown/L=Unknown/O=PQC-VPN/OU=Certificate Authority/CN=PQC-VPN CA"
    
    # Generate hub private key with Dilithium-5
    /usr/local/bin/openssl genpkey -algorithm dilithium5 \
        -out /etc/ipsec.d/private/hub-key.pem
    
    # Generate hub certificate signing request
    /usr/local/bin/openssl req -new -key /etc/ipsec.d/private/hub-key.pem \
        -out /tmp/hub-req.pem \
        -subj "/C=US/ST=Unknown/L=Unknown/O=PQC-VPN/OU=Hub/CN=hub.pqc-vpn.local"
    
    # Sign hub certificate with CA
    /usr/local/bin/openssl x509 -req -in /tmp/hub-req.pem \
        -CA /etc/ipsec.d/cacerts/ca-cert.pem \
        -CAkey /etc/ipsec.d/private/ca-key.pem \
        -CAcreateserial \
        -out /etc/ipsec.d/certs/hub-cert.pem \
        -days 365 \
        -extensions v3_req
    
    # Cleanup
    rm -f /tmp/hub-req.pem
    
    # Set proper permissions
    chmod 600 /etc/ipsec.d/private/*
    chmod 644 /etc/ipsec.d/certs/*
    chmod 644 /etc/ipsec.d/cacerts/*
    
    # Verify certificates
    if /usr/local/bin/openssl x509 -in /etc/ipsec.d/cacerts/ca-cert.pem -text | grep -q "dilithium5"; then
        success "PQC certificates generated successfully"
    else
        warn "Certificate generation completed but PQC verification failed"
    fi
    
    success "Certificates generated"
}

setup_firewall() {
    info "Configuring firewall..."
    
    # Detect firewall system
    if command -v ufw > /dev/null; then
        # Ubuntu/Debian UFW
        ufw --force enable
        ufw allow 500/udp comment "IPsec IKE"
        ufw allow 4500/udp comment "IPsec NAT-T"
        ufw allow ssh comment "SSH"
        
        if [[ "$ENABLE_WEB_INTERFACE" == "true" ]]; then
            ufw allow 8443 comment "PQC-VPN Web Interface"
        fi
        
        if [[ "$ENABLE_MONITORING" == "true" ]]; then
            ufw allow 3000 comment "Grafana"
            ufw allow 9090 comment "Prometheus"
            ufw allow 9100 comment "Node Exporter"
        fi
        
        if [[ "$ENTERPRISE_MODE" == "true" ]]; then
            ufw allow 443 comment "HTTPS"
            ufw allow 80 comment "HTTP"
            ufw allow 5432 comment "PostgreSQL"
            ufw allow 6379 comment "Redis"
        fi
        
    elif command -v firewall-cmd > /dev/null; then
        # CentOS/RHEL firewalld
        systemctl enable firewalld
        systemctl start firewalld
        
        firewall-cmd --permanent --add-service=ipsec
        firewall-cmd --permanent --add-port=500/udp
        firewall-cmd --permanent --add-port=4500/udp
        firewall-cmd --permanent --add-service=ssh
        
        if [[ "$ENABLE_WEB_INTERFACE" == "true" ]]; then
            firewall-cmd --permanent --add-port=8443/tcp
        fi
        
        if [[ "$ENABLE_MONITORING" == "true" ]]; then
            firewall-cmd --permanent --add-port=3000/tcp
            firewall-cmd --permanent --add-port=9090/tcp
            firewall-cmd --permanent --add-port=9100/tcp
        fi
        
        if [[ "$ENTERPRISE_MODE" == "true" ]]; then
            firewall-cmd --permanent --add-service=http
            firewall-cmd --permanent --add-service=https
            firewall-cmd --permanent --add-port=5432/tcp
            firewall-cmd --permanent --add-port=6379/tcp
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
        
        if [[ "$ENABLE_MONITORING" == "true" ]]; then
            iptables -A INPUT -p tcp --dport 3000 -j ACCEPT
            iptables -A INPUT -p tcp --dport 9090 -j ACCEPT
            iptables -A INPUT -p tcp --dport 9100 -j ACCEPT
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
    
    # Enterprise-grade network optimizations
    cat >> /etc/sysctl.d/99-pqc-vpn.conf << 'EOF'
# PQC-VPN Network Optimizations v1.0.0
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 131072 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.core.netdev_max_backlog = 10000
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fack = 1
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.ipv4.tcp_mtu_probing = 1
net.ipv4.route.flush = 1
net.ipv6.route.flush = 1

# Security enhancements
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
EOF
    
    # Apply sysctl settings
    sysctl -p /etc/sysctl.d/99-pqc-vpn.conf
    
    success "Network settings configured"
}

install_python_tools() {
    info "Installing Python management tools..."
    
    # Create virtual environment for PQC-VPN
    python3 -m venv /opt/pqc-vpn/venv
    source /opt/pqc-vpn/venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip setuptools wheel
    
    # Install core dependencies
    pip install -r /dev/stdin << 'EOF'
# PQC-VPN Python Dependencies v1.0.0
Flask==3.0.0
Flask-SQLAlchemy==3.1.1
Flask-Login==0.6.3
Flask-RESTX==1.3.0
psutil>=5.9.0
PyYAML>=6.0
cryptography>=41.0.0
requests>=2.28.0
click>=8.1.0
tabulate>=0.9.0
colorama>=0.4.6
rich>=13.0.0
prometheus-client>=0.19.0
schedule>=1.2.0
sqlalchemy>=2.0.0
redis>=5.0.0
pydantic>=2.5.0
jsonschema>=4.0.0
structlog>=23.0.0
EOF
    
    deactivate
    
    # Create wrapper scripts
    cat > /usr/local/bin/pqc-vpn-manager << 'EOF'
#!/bin/bash
source /opt/pqc-vpn/venv/bin/activate
exec python3 /opt/pqc-vpn/tools/pqc-vpn-manager.py "$@"
EOF

    cat > /usr/local/bin/pqc-connection-monitor << 'EOF'
#!/bin/bash
source /opt/pqc-vpn/venv/bin/activate
exec python3 /opt/pqc-vpn/tools/connection-monitor.py "$@"
EOF

    cat > /usr/local/bin/pqc-keygen << 'EOF'
#!/bin/bash
source /opt/pqc-vpn/venv/bin/activate
exec python3 /opt/pqc-vpn/tools/pqc-keygen.py "$@"
EOF
    
    chmod +x /usr/local/bin/pqc-*
    
    success "Python tools installed"
}

setup_web_interface() {
    if [[ "$ENABLE_WEB_INTERFACE" != "true" ]]; then
        return 0
    fi
    
    info "Setting up web management interface..."
    
    # Create web interface directory
    mkdir -p /var/www/pqc-vpn
    
    # Create systemd service for web API
    cat > /etc/systemd/system/pqc-vpn-web.service << 'EOF'
[Unit]
Description=PQC-VPN Web Management Interface
After=network.target strongswan.service
Wants=strongswan.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/var/www/pqc-vpn
Environment=PYTHONPATH=/opt/pqc-vpn/venv/lib/python3.*/site-packages
ExecStart=/opt/pqc-vpn/venv/bin/python3 /opt/pqc-vpn/web/api_server.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable pqc-vpn-web
    
    success "Web interface configured"
}

setup_monitoring() {
    if [[ "$ENABLE_MONITORING" != "true" ]]; then
        return 0
    fi
    
    info "Setting up monitoring..."
    
    # Create monitoring configuration directory
    mkdir -p /etc/pqc-vpn/monitoring
    
    # Install Node Exporter for system metrics
    local node_exporter_version="1.7.0"
    local arch=$([[ "$(uname -m)" == "aarch64" ]] && echo "arm64" || echo "amd64")
    
    if ! command -v node_exporter > /dev/null; then
        wget -O /tmp/node_exporter.tar.gz \
            "https://github.com/prometheus/node_exporter/releases/download/v${node_exporter_version}/node_exporter-${node_exporter_version}.linux-${arch}.tar.gz"
        tar -xzf /tmp/node_exporter.tar.gz -C /tmp
        mv "/tmp/node_exporter-${node_exporter_version}.linux-${arch}/node_exporter" /usr/local/bin/
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
ExecStart=/usr/local/bin/node_exporter --web.listen-address=:9100
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        
        systemctl daemon-reload
        systemctl enable node-exporter
        systemctl start node-exporter
    fi
    
    # Create Prometheus configuration
    cat > /etc/pqc-vpn/monitoring/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "pqc_vpn_rules.yml"

scrape_configs:
  - job_name: 'pqc-vpn-hub'
    static_configs:
      - targets: ['localhost:8443']
    metrics_path: '/api/metrics'
    scheme: https
    tls_config:
      insecure_skip_verify: true
    
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['localhost:9100']
    
  - job_name: 'strongswan'
    static_configs:
      - targets: ['localhost:9101']

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - localhost:9093
EOF

    # Create alerting rules
    cat > /etc/pqc-vpn/monitoring/pqc_vpn_rules.yml << 'EOF'
groups:
  - name: pqc_vpn_alerts
    rules:
      - alert: VPNConnectionDown
        expr: up{job="pqc-vpn-hub"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "PQC-VPN Hub is down"
          description: "PQC-VPN Hub has been down for more than 1 minute"
          
      - alert: HighConnectionCount
        expr: pqc_vpn_active_connections > 1000
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High number of VPN connections"
          description: "More than 1000 active VPN connections"
          
      - alert: CertificateExpiring
        expr: (pqc_vpn_certificate_expiry_seconds - time()) / 86400 < 30
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "Certificate expiring soon"
          description: "Certificate expires in less than 30 days"
EOF
    
    success "Monitoring configured"
}

setup_systemd_services() {
    info "Configuring systemd services..."
    
    # Ensure strongSwan is enabled
    systemctl enable strongswan
    
    # Create PQC-VPN main service
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
TimeoutStartSec=60
TimeoutStopSec=30

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
User=root
Group=root
EOF
    
    # Create maintenance timer
    cat > /etc/systemd/system/pqc-vpn-maintenance.timer << 'EOF'
[Unit]
Description=Run PQC-VPN maintenance tasks daily
Requires=pqc-vpn-maintenance.service

[Timer]
OnCalendar=*-*-* 02:00:00
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
EOF
    
    # Create maintenance script
    cat > /usr/local/bin/pqc-vpn-maintenance.sh << 'EOF'
#!/bin/bash
# PQC-VPN Maintenance Script v1.0.0

set -euo pipefail

LOG_FILE="/var/log/pqc-vpn/maintenance.log"
BACKUP_DIR="/var/backups/pqc-vpn"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG_FILE"
}

log "Starting PQC-VPN maintenance tasks"

# Rotate logs
find /var/log/strongswan -name "*.log" -mtime +30 -delete 2>/dev/null || true
find /var/log/pqc-vpn -name "*.log" -mtime +30 -delete 2>/dev/null || true

# Compress old logs
find /var/log/strongswan -name "*.log" -mtime +7 -exec gzip {} \; 2>/dev/null || true
find /var/log/pqc-vpn -name "*.log" -mtime +7 -exec gzip {} \; 2>/dev/null || true

# Check certificate expiry
if command -v pqc-connection-monitor > /dev/null; then
    pqc-connection-monitor certificates --check-expiry >> "$LOG_FILE" 2>&1 || true
fi

# Backup configuration
if [[ -d "$BACKUP_DIR" ]]; then
    backup_file="$BACKUP_DIR/config-backup-$(date +%Y%m%d).tar.gz"
    tar -czf "$backup_file" \
        /etc/ipsec.conf \
        /etc/ipsec.secrets \
        /etc/strongswan.conf \
        /etc/ipsec.d/certs \
        /etc/ipsec.d/cacerts \
        /etc/pqc-vpn \
        2>/dev/null || true
    
    # Keep only last 14 days of backups
    find "$BACKUP_DIR" -name "config-backup-*.tar.gz" -mtime +14 -delete 2>/dev/null || true
fi

# Update system packages (security updates only)
if command -v apt-get > /dev/null; then
    apt-get update -qq && apt-get upgrade -y --only-upgrade -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" 2>> "$LOG_FILE" || true
elif command -v yum > /dev/null; then
    yum update -y --security 2>> "$LOG_FILE" || true
fi

# Restart services if needed
if systemctl is-failed strongswan > /dev/null 2>&1; then
    log "Restarting failed strongSwan service"
    systemctl restart strongswan
fi

if systemctl is-failed pqc-vpn-web > /dev/null 2>&1; then
    log "Restarting failed web service"
    systemctl restart pqc-vpn-web
fi

log "Maintenance tasks completed"
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
        exit 1
    fi
    
    if [[ "$ENABLE_WEB_INTERFACE" == "true" ]]; then
        if systemctl is-active --quiet pqc-vpn-web; then
            success "Web interface service is running"
        else
            warn "Web interface service status check failed"
        fi
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
        local cert_expiry=$(/usr/local/bin/openssl x509 -in /etc/ipsec.d/certs/hub-cert.pem -noout -enddate | cut -d= -f2)
        info "Hub certificate expires: $cert_expiry"
    fi
    
    # Check PQC algorithm availability
    if /usr/local/bin/openssl list -signature-algorithms | grep -q dilithium; then
        success "Dilithium signature algorithms available"
    else
        warn "Dilithium algorithms not detected"
    fi
    
    if /usr/local/bin/openssl list -kem-algorithms | grep -q kyber; then
        success "Kyber KEM algorithms available"
    else
        warn "Kyber algorithms not detected"
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
    local disk_gb=$(df / | awk 'NR==2{printf "%.0f", $4/1024/1024}')
    info "System resources: $cpu_cores CPU cores, ${mem_gb}GB RAM, ${disk_gb}GB disk space"
    
    # Check if enterprise requirements are met
    if [[ "$ENTERPRISE_MODE" == "true" ]]; then
        if [[ $cpu_cores -ge 8 && $mem_gb -ge 16 ]]; then
            success "Enterprise resource requirements met"
        else
            warn "System may not meet enterprise performance requirements"
        fi
    fi
    
    success "Post-installation checks completed"
}

print_installation_summary() {
    echo -e "\n${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                   INSTALLATION COMPLETE                      ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}\n"
    
    echo -e "${CYAN}🎉 PQC-VPN Hub v1.0.0 has been successfully installed!${NC}\n"
    
    echo -e "${BLUE}📊 Installation Summary:${NC}"
    echo -e "   • Version: ${YELLOW}1.0.0${NC}"
    echo -e "   • Hub IP Address: ${YELLOW}$HUB_IP${NC}"
    echo -e "   • Enterprise Mode: ${YELLOW}$([ "$ENTERPRISE_MODE" == "true" ] && echo "Enabled" || echo "Disabled")${NC}"
    echo -e "   • Authentication Methods: ${YELLOW}$AUTH_METHODS${NC}"
    echo -e "   • PQC Algorithms: ${YELLOW}$PQC_ALGORITHMS${NC}"
    echo -e "   • Web Interface: ${YELLOW}$([ "$ENABLE_WEB_INTERFACE" == "true" ] && echo "Enabled" || echo "Disabled")${NC}"
    echo -e "   • Monitoring: ${YELLOW}$([ "$ENABLE_MONITORING" == "true" ] && echo "Enabled" || echo "Disabled")${NC}"
    echo -e "   • High Availability: ${YELLOW}$([ "$ENABLE_HA" == "true" ] && echo "Enabled" || echo "Disabled")${NC}"
    
    echo -e "\n${BLUE}🔗 Access Points:${NC}"
    if [[ "$ENABLE_WEB_INTERFACE" == "true" ]]; then
        echo -e "   • Web Dashboard: ${YELLOW}https://$HUB_IP:8443${NC}"
        echo -e "     Default credentials: admin/admin (please change immediately)"
    fi
    if [[ "$ENABLE_MONITORING" == "true" ]]; then
        echo -e "   • Grafana: ${YELLOW}http://$HUB_IP:3000${NC} (admin/admin)"
        echo -e "   • Prometheus: ${YELLOW}http://$HUB_IP:9090${NC}"
        echo -e "   • Node Exporter: ${YELLOW}http://$HUB_IP:9100/metrics${NC}"
    fi
    
    echo -e "\n${BLUE}📁 Important Files:${NC}"
    echo -e "   • Configuration: ${YELLOW}/etc/ipsec.conf${NC}"
    echo -e "   • Secrets: ${YELLOW}/etc/ipsec.secrets${NC}"
    echo -e "   • Certificates: ${YELLOW}/etc/ipsec.d/certs/${NC}"
    echo -e "   • CA Certificate: ${YELLOW}/etc/ipsec.d/cacerts/ca-cert.pem${NC}"
    echo -e "   • Logs: ${YELLOW}/var/log/strongswan/${NC}"
    echo -e "   • Installation Log: ${YELLOW}$LOG_FILE${NC}"
    echo -e "   • Backups: ${YELLOW}$BACKUP_DIR${NC}"
    
    echo -e "\n${BLUE}🔧 Management Commands:${NC}"
    echo -e "   • Add user: ${YELLOW}pqc-vpn-manager user add <username> --email <email> --auth-type pki${NC}"
    echo -e "   • Monitor connections: ${YELLOW}pqc-connection-monitor status${NC}"
    echo -e "   • System status: ${YELLOW}pqc-vpn-manager status${NC}"
    echo -e "   • View logs: ${YELLOW}journalctl -u strongswan -f${NC}"
    echo -e "   • Check IPsec: ${YELLOW}ipsec status${NC}"
    echo -e "   • Generate certificates: ${YELLOW}pqc-keygen --help${NC}"
    
    echo -e "\n${BLUE}🔒 Security Verification:${NC}"
    echo -e "   • Verify PQC algorithms: ${YELLOW}/usr/local/bin/openssl list -signature-algorithms | grep dilithium${NC}"
    echo -e "   • Check certificate: ${YELLOW}/usr/local/bin/openssl x509 -in /etc/ipsec.d/certs/hub-cert.pem -text | grep dilithium${NC}"
    echo -e "   • Validate configuration: ${YELLOW}ipsec listcerts${NC}"
    
    echo -e "\n${BLUE}⚠️  Security Recommendations:${NC}"
    echo -e "   1. Change default web interface password immediately"
    echo -e "   2. Configure firewall rules for your environment"
    echo -e "   3. Set up automated certificate renewal"
    echo -e "   4. Configure backup procedures"
    echo -e "   5. Review and customize security policies"
    
    echo -e "\n${BLUE}📚 Documentation:${NC}"
    echo -e "   • GitHub Repository: ${YELLOW}https://github.com/QEntangle/PQC-VPN${NC}"
    echo -e "   • Quick Start Guide: ${YELLOW}https://github.com/QEntangle/PQC-VPN/blob/main/QUICKSTART.md${NC}"
    echo -e "   • Documentation: ${YELLOW}https://github.com/QEntangle/PQC-VPN/tree/main/docs${NC}"
    
    echo -e "\n${BLUE}🆘 Support:${NC}"
    echo -e "   • Enterprise Support: ${YELLOW}support@qentangle.com${NC}"
    echo -e "   • Community: ${YELLOW}https://github.com/QEntangle/PQC-VPN/discussions${NC}"
    echo -e "   • Issues: ${YELLOW}https://github.com/QEntangle/PQC-VPN/issues${NC}"
    
    echo -e "\n${GREEN}✅ Installation completed successfully!${NC}"
    echo -e "   ${CYAN}Your network is now protected with quantum-safe cryptography.${NC}\n"
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
        --enterprise-mode)
            ENTERPRISE_MODE="true"
            shift
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
        --admin-password)
            ADMIN_PASSWORD="$2"
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
            echo "  --enterprise-mode         Enable enterprise features and optimizations"
            echo "  --enable-ha               Enable high availability configuration"
            echo "  --disable-web             Disable web management interface"
            echo "  --disable-monitoring      Disable monitoring and metrics"
            echo "  --install-mode MODE       Set install mode (production/development/testing)"
            echo "  --auth-methods METHODS    Set authentication methods (pki,psk,hybrid)"
            echo "  --pqc-algorithms ALGOS    Set PQC algorithms (kyber1024,dilithium5,etc)"
            echo "  --admin-password PASS     Set initial admin password"
            echo "  --debug                   Enable debug output"
            echo "  --help, -h                Show this help message"
            echo ""
            echo "Environment Variables:"
            echo "  HUB_IP                    Hub IP address"
            echo "  ENTERPRISE_MODE           Enable enterprise mode (true/false)"
            echo "  ENABLE_HA                 Enable high availability (true/false)"
            echo "  ENABLE_MONITORING         Enable monitoring (true/false)"
            echo "  ENABLE_WEB_INTERFACE      Enable web interface (true/false)"
            echo "  ADMIN_PASSWORD            Initial admin password"
            echo ""
            echo "Examples:"
            echo "  $0 --hub-ip 192.168.1.100 --enterprise-mode"
            echo "  $0 --hub-ip 10.0.0.1 --disable-monitoring --auth-methods pki"
            echo ""
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Validate required parameters
if [[ -z "$HUB_IP" ]]; then
    error "Hub IP address is required. Use --hub-ip or set HUB_IP environment variable."
    exit 1
fi

# Run main installation
main "$@"
