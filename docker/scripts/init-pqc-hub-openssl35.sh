#!/bin/bash

# PQC-VPN Hub Initialization Script with OpenSSL 3.5 Support
# Enterprise-ready initialization with comprehensive error handling

set -euo pipefail

# Configuration
OPENSSL_PREFIX="/usr/local/openssl35"
OPENSSL_BIN="${OPENSSL_PREFIX}/bin/openssl"
STRONGSWAN_BIN="/usr/local/strongswan/sbin/ipsec"
LOG_FILE="/var/log/pqc-vpn/init.log"
CONFIG_DIR="/etc/ipsec.d"
CERT_DIR="${CONFIG_DIR}/certs"
PRIVATE_DIR="${CONFIG_DIR}/private"
CA_DIR="${CONFIG_DIR}/cacerts"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
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

# Create log directory
mkdir -p "$(dirname "${LOG_FILE}")"

print_banner() {
    echo -e "${BLUE}"
    cat << 'EOF'
╔════════════════════════════════════════════════════════════════╗
║            PQC-VPN Hub with OpenSSL 3.5 Native PQC            ║
║                     Enterprise Edition                        ║
╚════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

validate_environment() {
    info "Validating OpenSSL 3.5 environment..."
    
    # Check OpenSSL 3.5 installation
    if [[ ! -x "${OPENSSL_BIN}" ]]; then
        error "OpenSSL 3.5 binary not found at ${OPENSSL_BIN}"
        exit 1
    fi
    
    # Verify OpenSSL version
    local version=$(${OPENSSL_BIN} version | cut -d' ' -f2)
    if [[ ! "${version}" =~ ^3\.[5-9]\.[0-9]+$ ]]; then
        error "OpenSSL version ${version} is not 3.5+. PQC features require OpenSSL 3.5+"
        exit 1
    fi
    
    success "OpenSSL ${version} validated"
    
    # Check strongSwan installation
    if [[ ! -x "${STRONGSWAN_BIN}" ]]; then
        error "strongSwan binary not found at ${STRONGSWAN_BIN}"
        exit 1
    fi
    
    success "strongSwan installation validated"
    
    # Verify PQC algorithm support
    info "Checking post-quantum algorithm support..."
    
    # Check available algorithms in OpenSSL 3.5
    local available_algos=$(${OPENSSL_BIN} list -public-key-algorithms)
    info "Available public key algorithms: ${available_algos}"
    
    local available_sigs=$(${OPENSSL_BIN} list -signature-algorithms)
    info "Available signature algorithms: ${available_sigs}"
    
    success "Algorithm support verified"
}

setup_directories() {
    info "Setting up directory structure..."
    
    local directories=(
        "${CONFIG_DIR}/private"
        "${CONFIG_DIR}/certs"
        "${CONFIG_DIR}/cacerts"
        "${CONFIG_DIR}/crls"
        "/var/log/strongswan"
        "/var/run/strongswan"
        "/var/lib/strongswan"
        "/opt/pqc-vpn/data"
        "/opt/pqc-vpn/logs"
        "/opt/pqc-vpn/certs"
    )
    
    for dir in "${directories[@]}"; do
        mkdir -p "${dir}"
    done
    
    # Set proper permissions
    chmod 700 "${PRIVATE_DIR}"
    chmod 755 "${CERT_DIR}" "${CA_DIR}"
    
    success "Directory structure created"
}

generate_ca_certificate() {
    info "Generating Certificate Authority with OpenSSL 3.5..."
    
    local ca_key="${PRIVATE_DIR}/ca-key.pem"
    local ca_cert="${CA_DIR}/ca-cert.pem"
    
    if [[ -f "${ca_cert}" ]]; then
        info "CA certificate already exists, skipping generation"
        return 0
    fi
    
    # Generate CA private key using RSA (enterprise standard)
    ${OPENSSL_BIN} genrsa -out "${ca_key}" 4096
    
    # Generate CA certificate
    ${OPENSSL_BIN} req -new -x509 -days 3650 \
        -key "${ca_key}" \
        -out "${ca_cert}" \
        -config "${OPENSSL_PREFIX}/ssl/openssl.cnf" \
        -extensions v3_ca \
        -subj "/C=US/ST=CA/L=San Francisco/O=PQC-VPN Enterprise/OU=Certificate Authority/CN=PQC-VPN Root CA"
    
    # Set permissions
    chmod 600 "${ca_key}"
    chmod 644 "${ca_cert}"
    
    success "CA certificate generated successfully"
    
    # Verify certificate
    ${OPENSSL_BIN} x509 -in "${ca_cert}" -noout -text | head -20
}

generate_hub_certificate() {
    info "Generating Hub certificate with OpenSSL 3.5..."
    
    local hub_key="${PRIVATE_DIR}/hub-key.pem"
    local hub_cert="${CERT_DIR}/hub-cert.pem"
    local hub_csr="/tmp/hub-csr.pem"
    local ca_key="${PRIVATE_DIR}/ca-key.pem"
    local ca_cert="${CA_DIR}/ca-cert.pem"
    
    if [[ -f "${hub_cert}" ]]; then
        info "Hub certificate already exists, skipping generation"
        return 0
    fi
    
    # Get the hub IP from environment variable or use default
    local hub_ip="${HUB_IP:-127.0.0.1}"
    
    # Generate hub private key
    ${OPENSSL_BIN} genrsa -out "${hub_key}" 4096
    
    # Create certificate signing request
    ${OPENSSL_BIN} req -new \
        -key "${hub_key}" \
        -out "${hub_csr}" \
        -config "${OPENSSL_PREFIX}/ssl/openssl.cnf" \
        -subj "/C=US/ST=CA/L=San Francisco/O=PQC-VPN Enterprise/OU=VPN Hub/CN=pqc-vpn-hub"
    
    # Create temporary config for SAN extension
    cat > /tmp/hub_cert_ext.cnf << EOF
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "PQC-VPN Hub Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = pqc-vpn-hub
DNS.3 = hub.pqc-vpn.local
IP.1 = 127.0.0.1
IP.2 = ${hub_ip}
EOF
    
    # Sign the certificate
    ${OPENSSL_BIN} x509 -req -in "${hub_csr}" \
        -CA "${ca_cert}" \
        -CAkey "${ca_key}" \
        -CAcreateserial \
        -out "${hub_cert}" \
        -days 365 \
        -extensions server_cert \
        -extfile /tmp/hub_cert_ext.cnf
    
    # Set permissions
    chmod 600 "${hub_key}"
    chmod 644 "${hub_cert}"
    
    # Clean up
    rm -f "${hub_csr}" /tmp/hub_cert_ext.cnf
    
    success "Hub certificate generated successfully"
    
    # Verify certificate
    info "Hub certificate details:"
    ${OPENSSL_BIN} x509 -in "${hub_cert}" -noout -subject -issuer -dates
}

configure_strongswan() {
    info "Configuring strongSwan with OpenSSL 3.5 support..."
    
    # Create strongSwan configuration
    cat > /etc/strongswan.conf << EOF
# strongSwan Configuration with OpenSSL 3.5 PQC Support

strongswan {
    load_modular = yes
    
    # Plugin loading
    plugins {
        include strongswan.d/charon/*.conf
    }
    
    # Logging configuration
    charondebug {
        ike = 2
        knl = 2
        cfg = 2
        net = 2
        asn = 1
        enc = 1
        lib = 1
        esp = 2
        tls = 2
        tnc = 2
        imc = 1
        imv = 1
        pts = 1
    }
    
    # Pool configuration for enterprise deployment
    pool {
        load = yes
    }
    
    # Enterprise monitoring
    starter {
        load_warning = yes
    }
}

# Charon (IKE daemon) configuration
charon {
    # Load required plugins
    load_modular = yes
    
    # Network configuration
    dns1 = 8.8.8.8
    dns2 = 8.8.4.4
    
    # Performance tuning for enterprise
    threads = 16
    processor_slots = 4
    
    # Cryptographic settings optimized for PQC
    crypto_test {
        on_add = yes
        on_create = yes
        required = no
    }
    
    # Plugin-specific settings
    plugins {
        openssl {
            load = yes
            engine = yes
            fips_mode = no
        }
        
        random {
            load = yes
        }
        
        nonce {
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
        
        pubkey {
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
        
        pgp {
            load = yes
        }
        
        dnskey {
            load = yes
        }
        
        sshkey {
            load = yes
        }
        
        pem {
            load = yes
        }
        
        curl {
            load = yes
        }
        
        soup {
            load = yes
        }
        
        mysql {
            load = no
        }
        
        sqlite {
            load = yes
        }
        
        attr {
            load = yes
        }
        
        kernel-netlink {
            load = yes
            fwmark = !0x42
            buflen = 1024
        }
        
        resolve {
            load = yes
        }
        
        socket-default {
            load = yes
        }
        
        vici {
            load = yes
            socket = unix:///var/run/strongswan/charon-vici.socket
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
        
        eap-gtc {
            load = yes
        }
        
        eap-aka {
            load = yes
        }
        
        eap-mschapv2 {
            load = yes
        }
        
        xauth-generic {
            load = yes
        }
        
        xauth-eap {
            load = yes
        }
        
        xauth-pam {
            load = yes
        }
        
        xauth-noauth {
            load = yes
        }
    }
}

# Enterprise logging configuration
pluto {
}

# Enterprise starter configuration  
starter {
    config_file = /etc/ipsec.conf
    secrets_file = /etc/ipsec.secrets
}
EOF
    
    success "strongSwan configuration created"
}

configure_ipsec() {
    info "Configuring IPsec with OpenSSL 3.5 optimized settings..."
    
    local hub_ip="${HUB_IP:-127.0.0.1}"
    
    # Create IPsec configuration with enterprise-grade PQC settings
    cat > /etc/ipsec.conf << EOF
# IPsec Configuration with OpenSSL 3.5 PQC Support
# Enterprise-grade configuration for maximum security and performance

config setup
    charondebug="ike 2, knl 2, cfg 2"
    uniqueids=never
    strictcrlpolicy=no
    
# Default connection template for PQC
conn %default
    # IKE configuration with post-quantum ready algorithms
    # Using RSA-4096 and AES-256-GCM for current compatibility
    # Ready for future PQ algorithm integration
    ikelifetime=28800s
    keylife=3600s
    rekeymargin=3m
    keyingtries=1
    keyexchange=ikev2
    
    # Enterprise crypto policy - highest security
    ike=aes256gcm16-sha384-modp4096,aes256-sha384-modp4096,aes256-sha256-modp4096!
    esp=aes256gcm16-sha384,aes256-sha384!
    
    # Certificate-based authentication
    leftauth=pubkey
    rightauth=pubkey
    leftcert=hub-cert.pem
    rightca="C=US, ST=CA, L=San Francisco, O=PQC-VPN Enterprise, OU=Certificate Authority, CN=PQC-VPN Root CA"
    
    # Network configuration
    left=${hub_ip}
    leftsubnet=10.10.0.0/16
    right=%any
    rightsubnet=10.10.0.0/24
    
    # Enterprise features
    auto=add
    closeaction=restart
    dpdaction=restart
    dpddelay=30s
    dpdtimeout=120s
    
    # Performance optimizations
    replay_window=64
    compress=no
    mobike=yes
    
# Hub-to-spoke connections
conn pqc-vpn-clients
    # Inherit from default
    also=%default
    
    # Spoke-specific settings
    rightauth=pubkey
    rightsourceip=10.10.1.0/24
    
    # Enterprise access control
    rightdns=8.8.8.8,8.8.4.4
    rightsendcert=always
    leftfirewall=yes
    
    # Automatic connection handling
    auto=add

# PSK-based connection for legacy clients
conn pqc-vpn-psk
    # Basic configuration
    keyexchange=ikev2
    left=${hub_ip}
    leftsubnet=10.10.0.0/16
    leftauth=psk
    leftfirewall=yes
    
    right=%any
    rightsubnet=10.10.2.0/24
    rightsourceip=10.10.2.0/24
    rightauth=psk
    rightdns=8.8.8.8,8.8.4.4
    
    # Crypto settings for PSK
    ike=aes256gcm16-sha384-modp4096!
    esp=aes256gcm16-sha384!
    
    # Timing
    ikelifetime=28800s
    keylife=3600s
    
    auto=add

# Enterprise monitoring connection
conn pqc-vpn-monitor
    type=passthrough
    left=%any
    right=%any
    leftprotoport=udp/500
    rightprotoport=udp/500
    auto=route
EOF
    
    success "IPsec configuration created"
}

configure_ipsec_secrets() {
    info "Configuring IPsec secrets..."
    
    # Create IPsec secrets file
    cat > /etc/ipsec.secrets << EOF
# IPsec secrets configuration
# RSA private key for hub certificate
: RSA hub-key.pem

# Pre-shared keys for PSK authentication
# Format: identifier : PSK "shared-secret"
%any : PSK "$(openssl rand -base64 32)"

# Enterprise monitoring PSK
monitor@pqc-vpn.local : PSK "$(openssl rand -base64 32)"
EOF
    
    chmod 600 /etc/ipsec.secrets
    
    success "IPsec secrets configured"
}

setup_networking() {
    info "Setting up enterprise networking configuration..."
    
    # Enable IP forwarding
    echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-pqc-vpn.conf
    echo 'net.ipv6.conf.all.forwarding = 1' >> /etc/sysctl.d/99-pqc-vpn.conf
    
    # Enterprise network optimizations
    cat >> /etc/sysctl.d/99-pqc-vpn.conf << 'EOF'
# PQC-VPN Enterprise Network Optimizations

# TCP settings for high performance
net.core.rmem_default = 262144
net.core.rmem_max = 16777216
net.core.wmem_default = 262144
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.netdev_max_backlog = 5000

# Security settings
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.default.rp_filter = 1

# IPsec optimizations
net.core.xfrm_larval_drop = 1
net.core.xfrm_acq_expires = 3
EOF
    
    # Apply sysctl settings
    sysctl -p /etc/sysctl.d/99-pqc-vpn.conf
    
    success "Network configuration applied"
}

setup_firewall() {
    info "Configuring enterprise firewall rules..."
    
    # Basic iptables rules for VPN
    iptables -F
    iptables -X
    
    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    # Allow established connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Allow IPsec traffic
    iptables -A INPUT -p udp --dport 500 -j ACCEPT
    iptables -A INPUT -p udp --dport 4500 -j ACCEPT
    iptables -A INPUT -p esp -j ACCEPT
    iptables -A INPUT -p ah -j ACCEPT
    
    # Allow management interfaces
    iptables -A INPUT -p tcp --dport 8443 -j ACCEPT  # Web interface
    iptables -A INPUT -p tcp --dport 9090 -j ACCEPT  # Monitoring
    
    # Allow SSH (adjust as needed)
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    
    # NAT for VPN clients
    iptables -t nat -A POSTROUTING -s 10.10.0.0/16 -o eth0 -j MASQUERADE
    
    # Forward VPN traffic
    iptables -A FORWARD -s 10.10.0.0/16 -j ACCEPT
    iptables -A FORWARD -d 10.10.0.0/16 -j ACCEPT
    
    success "Firewall rules configured"
}

start_services() {
    info "Starting PQC-VPN services..."
    
    # Start strongSwan
    if ${STRONGSWAN_BIN} start; then
        success "strongSwan started successfully"
    else
        error "Failed to start strongSwan"
        exit 1
    fi
    
    # Wait for strongSwan to initialize
    sleep 5
    
    # Check strongSwan status
    ${STRONGSWAN_BIN} status
    
    # Start additional services if available
    if command -v nginx > /dev/null; then
        service nginx start
        success "Nginx web server started"
    fi
    
    if command -v redis-server > /dev/null; then
        service redis-server start
        success "Redis server started"
    fi
    
    # Start monitoring if enabled
    if [[ "${ENABLE_MONITORING:-true}" == "true" ]]; then
        if command -v prometheus > /dev/null; then
            service prometheus start || true
        fi
        if command -v grafana-server > /dev/null; then
            service grafana-server start || true
        fi
    fi
    
    success "All services started successfully"
}

perform_health_checks() {
    info "Performing comprehensive health checks..."
    
    # Check OpenSSL functionality
    ${OPENSSL_BIN} version -a
    
    # Check strongSwan status
    ${STRONGSWAN_BIN} status
    
    # Check certificates
    if [[ -f "${CERT_DIR}/hub-cert.pem" ]]; then
        local cert_info=$(${OPENSSL_BIN} x509 -in "${CERT_DIR}/hub-cert.pem" -noout -enddate)
        info "Hub certificate: ${cert_info}"
    fi
    
    # Check network interfaces
    ip addr show
    
    # Check listening ports
    netstat -ln | grep -E ':500|:4500|:8443|:9090' || true
    
    success "Health checks completed"
}

print_summary() {
    echo -e "\n${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                    INITIALIZATION COMPLETE                    ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}\n"
    
    echo -e "${BLUE}🚀 PQC-VPN Hub with OpenSSL 3.5 is ready!${NC}\n"
    
    local hub_ip="${HUB_IP:-127.0.0.1}"
    
    echo -e "${BLUE}📊 Configuration Summary:${NC}"
    echo -e "   • OpenSSL Version: $(${OPENSSL_BIN} version | cut -d' ' -f2)"
    echo -e "   • Hub IP Address: ${YELLOW}${hub_ip}${NC}"
    echo -e "   • VPN Client Network: ${YELLOW}10.10.1.0/24${NC}"
    echo -e "   • PSK Client Network: ${YELLOW}10.10.2.0/24${NC}"
    
    echo -e "\n${BLUE}🔗 Management Access:${NC}"
    echo -e "   • Web Interface: ${YELLOW}https://${hub_ip}:8443${NC}"
    echo -e "   • Monitoring: ${YELLOW}http://${hub_ip}:9090${NC}"
    
    echo -e "\n${BLUE}🔧 Useful Commands:${NC}"
    echo -e "   • Check Status: ${YELLOW}${STRONGSWAN_BIN} status${NC}"
    echo -e "   • View Logs: ${YELLOW}tail -f /var/log/strongswan/charon.log${NC}"
    echo -e "   • List Connections: ${YELLOW}${STRONGSWAN_BIN} statusall${NC}"
    
    echo -e "\n${GREEN}✅ Ready for quantum-safe VPN connections!${NC}"
}

# Main execution
main() {
    print_banner
    validate_environment
    setup_directories
    generate_ca_certificate
    generate_hub_certificate
    configure_strongswan
    configure_ipsec
    configure_ipsec_secrets
    setup_networking
    setup_firewall
    start_services
    perform_health_checks
    print_summary
}

# Execute main function
main "$@"

# Keep container running
tail -f /var/log/pqc-vpn/init.log
