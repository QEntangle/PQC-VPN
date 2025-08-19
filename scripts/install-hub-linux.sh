#!/bin/bash

# PQC-VPN Hub Installation Script for Linux
# This script installs and configures strongSwan with Post-Quantum Cryptography support
# Supports Ubuntu 20.04+, Debian 11+, CentOS 8+, Rocky Linux 8+

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VPN_USER="vpn"
VPN_GROUP="vpn"
HUB_IP="10.10.0.1"
HUB_SUBNET="10.10.0.0/16"

# Logging function
log() { echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"; }
error() { echo -e "${RED}[ERROR] $1${NC}" >&2; }
warning() { echo -e "${YELLOW}[WARNING] $1${NC}"; }
success() { echo -e "${GREEN}[SUCCESS] $1${NC}"; }

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

# Detect Linux distribution
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    else
        error "Cannot detect Linux distribution"
        exit 1
    fi
    log "Detected OS: $OS $VER"
}

# Install dependencies
install_dependencies() {
    log "Installing dependencies..."
    case "$OS" in
        "Ubuntu"|"Debian"*)
            apt-get update
            apt-get install -y build-essential libssl-dev libgmp-dev libcurl4-openssl-dev \
                libsystemd-dev pkg-config git wget curl unzip iptables iptables-persistent \
                strongswan strongswan-pki strongswan-libcharon-extra-plugins \
                libcharon-extra-plugins python3 python3-pip openssl cmake
            ;;
        "CentOS"*|"Rocky"*|"Red Hat"*|"Fedora"*)
            if command -v dnf &> /dev/null; then
                dnf update -y
                dnf install -y gcc gcc-c++ make openssl-devel gmp-devel libcurl-devel \
                    systemd-devel pkgconfig git wget curl unzip iptables iptables-services \
                    strongswan python3 python3-pip openssl cmake
            else
                yum update -y
                yum install -y gcc gcc-c++ make openssl-devel gmp-devel libcurl-devel \
                    systemd-devel pkgconfig git wget curl unzip iptables iptables-services \
                    strongswan python3 python3-pip openssl cmake
            fi
            ;;
        *)
            error "Unsupported operating system: $OS"
            exit 1
            ;;
    esac
    success "Dependencies installed successfully"
}

# Install PQC libraries
install_pqc_libraries() {
    log "Installing Post-Quantum Cryptography libraries..."
    cd /tmp
    if [[ ! -d "liboqs" ]]; then
        git clone --branch main https://github.com/open-quantum-safe/liboqs.git
    fi
    cd liboqs
    mkdir -p build && cd build
    cmake -DCMAKE_INSTALL_PREFIX=/usr/local \
          -DOQS_BUILD_ONLY_LIB=ON \
          -DOQS_MINIMAL_BUILD="KEM_kyber_1024;SIG_dilithium_5" ..
    make -j$(nproc) && make install && ldconfig
    success "PQC libraries installed successfully"
}

# Create VPN user
create_vpn_user() {
    log "Creating VPN user and group..."
    if ! getent group "$VPN_GROUP" > /dev/null 2>&1; then
        groupadd "$VPN_GROUP"
    fi
    if ! getent passwd "$VPN_USER" > /dev/null 2>&1; then
        useradd -r -g "$VPN_GROUP" -s /bin/false -M "$VPN_USER"
    fi
    success "VPN user created successfully"
}

# Configure system
configure_system() {
    log "Configuring system settings..."
    echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf
    echo 'net.ipv6.conf.all.forwarding = 1' >> /etc/sysctl.conf
    echo 'net.ipv4.conf.all.accept_redirects = 0' >> /etc/sysctl.conf
    echo 'net.ipv4.conf.all.send_redirects = 0' >> /etc/sysctl.conf
    sysctl -p
    success "System configured successfully"
}

# Setup directories
setup_directories() {
    log "Setting up directories..."
    mkdir -p /etc/ipsec.d/{cacerts,certs,private,secrets}
    mkdir -p /var/log/strongswan
    mkdir -p /etc/pqc-vpn/{certs,configs,scripts}
    mkdir -p /var/lib/pqc-vpn
    chmod 700 /etc/ipsec.d/private /etc/ipsec.d/secrets /etc/pqc-vpn/certs
    chmod 755 /etc/pqc-vpn
    chown -R root:root /etc/ipsec.d
    chown -R "$VPN_USER":"$VPN_GROUP" /var/lib/pqc-vpn
    success "Directories created successfully"
}

# Install strongSwan config
install_strongswan_config() {
    log "Installing strongSwan configuration..."
    # Backup existing files
    for file in ipsec.conf ipsec.secrets strongswan.conf; do
        [[ -f /etc/$file ]] && cp /etc/$file /etc/$file.backup.$(date +%Y%m%d_%H%M%S)
    done
    # Install new configs
    cp "$PROJECT_ROOT/configs/hub/ipsec.conf" /etc/ipsec.conf
    cp "$PROJECT_ROOT/configs/hub/ipsec.secrets" /etc/ipsec.secrets
    cp "$PROJECT_ROOT/configs/hub/strongswan.conf" /etc/strongswan.conf
    chmod 644 /etc/ipsec.conf /etc/strongswan.conf
    chmod 600 /etc/ipsec.secrets
    success "strongSwan configuration installed"
}

# Configure firewall
configure_firewall() {
    log "Configuring firewall..."
    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    iptables -A INPUT -p udp --dport 500 -j ACCEPT
    iptables -A INPUT -p udp --dport 4500 -j ACCEPT
    iptables -A INPUT -p esp -j ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -t nat -A POSTROUTING -s $HUB_SUBNET -o $INTERFACE -j MASQUERADE
    iptables -A FORWARD -s $HUB_SUBNET -j ACCEPT
    iptables -A FORWARD -d $HUB_SUBNET -j ACCEPT
    case "$OS" in
        "Ubuntu"|"Debian"*) iptables-save > /etc/iptables/rules.v4 ;;
        *) iptables-save > /etc/sysconfig/iptables; systemctl enable iptables ;;
    esac
    success "Firewall configured successfully"
}

# Configure services
configure_services() {
    log "Configuring services..."
    systemctl enable strongswan
    systemctl start strongswan
    success "Services configured successfully"
}

# Final setup
final_setup() {
    log "Performing final setup..."
    PUBLIC_IP=$(curl -s ifconfig.me || echo "unknown")
    cat > /etc/pqc-vpn/hub-info.txt << EOF
PQC VPN Hub Configuration
========================

Hub Public IP: $PUBLIC_IP
Hub Internal IP: $HUB_IP
Hub Subnet: $HUB_SUBNET

To add a new spoke user:
sudo bash $PROJECT_ROOT/scripts/add-spoke-user.sh <username>

To monitor connections:
sudo bash $PROJECT_ROOT/scripts/monitor-vpn.sh

Log files:
- strongSwan: /var/log/strongswan.log
- System: journalctl -u strongswan
EOF
    success "Hub installation completed!"
    warning "Run certificate generation: bash $PROJECT_ROOT/scripts/generate-pqc-certs.sh --ca"
    log "Configuration summary saved to: /etc/pqc-vpn/hub-info.txt"
}

# Main function
main() {
    log "Starting PQC VPN Hub installation..."
    check_root
    detect_os
    install_dependencies
    install_pqc_libraries
    create_vpn_user
    configure_system
    setup_directories
    install_strongswan_config
    configure_firewall
    configure_services
    final_setup
    success "PQC VPN Hub installation completed successfully!"
}

# Run main function
main "$@"