#!/bin/bash
#
# PQC-VPN Spoke Installation Script for Linux
# Supports Ubuntu 20.04+, CentOS 8+, Debian 11+
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
    log_success "Root privileges confirmed"
}

# Detect OS
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    else
        log_error "Cannot detect OS. Supported: Ubuntu 20.04+, CentOS 8+, Debian 11+"
        exit 1
    fi
    
    log_info "Detected OS: $OS $VER"
}

# Install dependencies based on OS
install_dependencies() {
    log_info "Installing dependencies..."
    
    case "$OS" in
        "Ubuntu"|"Debian"*)
            apt update
            apt install -y build-essential libssl-dev libgmp-dev libtspi-dev \
                libldap2-dev libcurl4-openssl-dev libxml2-dev libsystemd-dev \
                libpcsclite-dev pkg-config gettext flex bison autoconf automake \
                libtool git wget curl iptables python3 python3-pip cmake ninja-build
            ;;
        "CentOS"*|"Red Hat"*|"Rocky"*|"AlmaLinux"*)
            yum groupinstall -y "Development Tools"
            yum install -y openssl-devel gmp-devel trousers-devel openldap-devel \
                libcurl-devel libxml2-devel systemd-devel pcsc-lite-devel \
                pkgconfig gettext flex bison autoconf automake libtool \
                git wget curl iptables python3 python3-pip cmake ninja-build
            ;;
        *)
            log_error "Unsupported OS: $OS"
            exit 1
            ;;
    esac
    
    log_success "Dependencies installed"
}

# Install liboqs for PQC support
install_liboqs() {
    log_info "Installing liboqs for Post-Quantum Cryptography support..."
    
    cd /tmp
    rm -rf liboqs
    git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs.git
    cd liboqs
    
    mkdir -p build && cd build
    cmake -G Ninja -DCMAKE_INSTALL_PREFIX=/usr/local \
          -DOQS_BUILD_ONLY_LIB=ON \
          -DOQS_MINIMAL_BUILD="KEM_kyber_512;KEM_kyber_768;KEM_kyber_1024;SIG_dilithium_2;SIG_dilithium_3;SIG_dilithium_5" \
          ..
    ninja
    ninja install
    ldconfig
    
    log_success "liboqs installed with PQC algorithms"
}

# Install strongSwan with PQC support
install_strongswan() {
    log_info "Installing strongSwan with Post-Quantum Cryptography support..."
    
    cd /tmp
    rm -rf strongswan
    git clone https://github.com/strongswan/strongswan.git
    cd strongswan
    git checkout 5.9.14
    
    ./autogen.sh
    ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
        --libexecdir=/usr/lib --enable-openssl --enable-python-eggs \
        --enable-cmd --enable-conf --enable-connmark --enable-dhcp \
        --enable-eap-aka --enable-eap-gtc --enable-eap-identity \
        --enable-eap-md5 --enable-eap-mschapv2 --enable-eap-radius \
        --enable-eap-tls --enable-farp --enable-files --enable-gcrypt \
        --enable-gmp --enable-ldap --enable-mysql --enable-sqlite \
        --enable-stroke --enable-updown --enable-unity --enable-xauth-eap \
        --enable-xauth-pam --enable-chapoly --enable-curl --enable-systemd \
        --disable-des --enable-oqs --with-ipseclibdir=/usr/lib/ipsec
    
    make -j$(nproc)
    make install
    
    # Create systemd service if not exists
    if [[ ! -f /etc/systemd/system/strongswan.service ]]; then
        cat > /etc/systemd/system/strongswan.service << 'EOF'
[Unit]
Description=strongSwan IPsec IKEv1/IKEv2 daemon using ipsec.conf
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/sbin/ipsec start --nofork
ExecReload=/usr/sbin/ipsec reload
Restart=on-abnormal
KillMode=mixed

[Install]
WantedBy=multi-user.target
EOF
    fi
    
    systemctl daemon-reload
    systemctl enable strongswan
    
    log_success "strongSwan with PQC support installed"
}

# Get hub configuration
get_hub_config() {
    log_info "Configuring spoke connection..."
    
    read -p "Enter Hub IP address: " HUB_IP
    read -p "Enter spoke username: " SPOKE_USER
    read -p "Enter hub admin IP (for cert exchange): " HUB_ADMIN_IP
    
    if [[ -z "$HUB_IP" || -z "$SPOKE_USER" ]]; then
        log_error "Hub IP and spoke username are required"
        exit 1
    fi
    
    log_info "Hub IP: $HUB_IP"
    log_info "Spoke User: $SPOKE_USER"
}

# Create directories
create_directories() {
    log_info "Creating directories..."
    
    mkdir -p /etc/ipsec.d/{cacerts,certs,private}
    mkdir -p /var/log/pqc-vpn
    mkdir -p /opt/pqc-vpn/{scripts,certs}
    
    log_success "Directories created"
}

# Generate spoke certificates
generate_certificates() {
    log_info "Generating PQC certificates for spoke: $SPOKE_USER"
    
    cd /opt/pqc-vpn/certs
    
    # Generate spoke private key using Dilithium
    openssl genpkey -algorithm dilithium5 -out ${SPOKE_USER}-key.pem
    
    # Generate certificate request
    openssl req -new -key ${SPOKE_USER}-key.pem -out ${SPOKE_USER}.csr \
        -subj "/C=US/ST=CA/L=SF/O=PQC-VPN/OU=Spoke/CN=${SPOKE_USER}"
    
    log_success "Certificate request generated: ${SPOKE_USER}.csr"
    log_warning "Please send ${SPOKE_USER}.csr to the hub administrator to get it signed"
    log_warning "You will need the signed certificate and CA certificate to complete setup"
}

# Configure strongSwan
configure_strongswan() {
    log_info "Configuring strongSwan for spoke..."
    
    # Copy template configuration
    cp "$(dirname "$0")/../configs/spoke/strongswan.conf" /etc/strongswan.conf
    
    # Create ipsec.conf from template
    sed -e "s/%HUB_IP%/${HUB_IP}/g" \
        -e "s/%SPOKE_USER%/${SPOKE_USER}/g" \
        "$(dirname "$0")/../configs/spoke/ipsec.conf.template" > /etc/ipsec.conf
    
    # Create ipsec.secrets from template  
    sed -e "s/%SPOKE_USER%/${SPOKE_USER}/g" \
        "$(dirname "$0")/../configs/spoke/ipsec.secrets.template" > /etc/ipsec.secrets
    
    chmod 600 /etc/ipsec.secrets
    
    log_success "strongSwan configuration completed"
}

# Configure firewall
configure_firewall() {
    log_info "Configuring firewall..."
    
    # Allow strongSwan ports
    if command -v ufw >/dev/null 2>&1; then
        ufw allow 500/udp
        ufw allow 4500/udp
        ufw allow out 500/udp
        ufw allow out 4500/udp
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port=500/udp
        firewall-cmd --permanent --add-port=4500/udp
        firewall-cmd --reload
    else
        # Use iptables directly
        iptables -A INPUT -p udp --dport 500 -j ACCEPT
        iptables -A INPUT -p udp --dport 4500 -j ACCEPT
        iptables -A OUTPUT -p udp --dport 500 -j ACCEPT
        iptables -A OUTPUT -p udp --dport 4500 -j ACCEPT
        
        # Save iptables rules
        if command -v iptables-save >/dev/null 2>&1; then
            iptables-save > /etc/iptables.rules
        fi
    fi
    
    log_success "Firewall configured"
}

# Create management scripts
create_management_scripts() {
    log_info "Creating management scripts..."
    
    # Create connect script
    cat > /opt/pqc-vpn/scripts/connect.sh << EOF
#!/bin/bash
echo "Connecting to PQC-VPN Hub..."
systemctl start strongswan
ipsec up pqc-vpn
echo "Connection status:"
ipsec status
EOF

    # Create disconnect script
    cat > /opt/pqc-vpn/scripts/disconnect.sh << EOF
#!/bin/bash
echo "Disconnecting from PQC-VPN Hub..."
ipsec down pqc-vpn
systemctl stop strongswan
echo "Disconnected."
EOF

    # Create status script
    cat > /opt/pqc-vpn/scripts/status.sh << EOF
#!/bin/bash
echo "PQC-VPN Status:"
echo "==============="
systemctl status strongswan --no-pager
echo ""
echo "IPsec Status:"
ipsec status
echo ""
echo "Active Tunnels:"
ip route show table 220 2>/dev/null || echo "No active tunnels"
EOF

    # Create certificate installation script
    cat > /opt/pqc-vpn/scripts/install-certs.sh << 'EOF'
#!/bin/bash
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

if [[ -z "$1" || -z "$2" ]]; then
    echo "Usage: $0 <spoke-cert.pem> <ca-cert.pem>"
    echo "Example: $0 alice-cert.pem ca-cert.pem"
    exit 1
fi

SPOKE_CERT="$1"
CA_CERT="$2"

if [[ ! -f "$SPOKE_CERT" || ! -f "$CA_CERT" ]]; then
    echo "Certificate files not found"
    exit 1
fi

echo "Installing certificates..."
cp "$SPOKE_CERT" /etc/ipsec.d/certs/
cp "$CA_CERT" /etc/ipsec.d/cacerts/

echo "Certificates installed successfully"
echo "You can now connect using: /opt/pqc-vpn/scripts/connect.sh"
EOF

    chmod +x /opt/pqc-vpn/scripts/*.sh
    
    # Create symbolic links for easy access
    ln -sf /opt/pqc-vpn/scripts/connect.sh /usr/local/bin/pqc-connect
    ln -sf /opt/pqc-vpn/scripts/disconnect.sh /usr/local/bin/pqc-disconnect
    ln -sf /opt/pqc-vpn/scripts/status.sh /usr/local/bin/pqc-status
    
    log_success "Management scripts created"
}

# Main installation function
main() {
    log_info "Starting PQC-VPN Spoke installation for Linux..."
    
    check_root
    detect_os
    install_dependencies
    install_liboqs
    install_strongswan
    get_hub_config
    create_directories
    generate_certificates
    configure_strongswan
    configure_firewall
    create_management_scripts
    
    log_success "PQC-VPN Spoke installation completed!"
    echo ""
    log_info "Next steps:"
    log_info "1. Send the certificate request to hub admin: /opt/pqc-vpn/certs/${SPOKE_USER}.csr"
    log_info "2. Get signed certificate and CA certificate from hub admin"
    log_info "3. Install certificates: sudo /opt/pqc-vpn/scripts/install-certs.sh <your-cert.pem> <ca-cert.pem>"
    log_info "4. Connect to VPN: pqc-connect"
    log_info "5. Check status: pqc-status"
    log_info "6. Disconnect: pqc-disconnect"
    echo ""
    log_info "Certificate request location: /opt/pqc-vpn/certs/${SPOKE_USER}.csr"
    log_info "Hub IP configured: $HUB_IP"
    log_info "Spoke username: $SPOKE_USER"
    echo ""
    log_success "Installation complete!"
}

# Run main function
main "$@"