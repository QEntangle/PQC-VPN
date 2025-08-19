#!/bin/bash
# PQC-VPN Hub Entrypoint Script
# Initializes and starts the PQC-VPN hub services

set -euo pipefail

# Configuration
SCRIPT_DIR="/opt/pqc-vpn/scripts"
DATA_DIR="/opt/pqc-vpn/data"
CONFIG_DIR="/etc/pqc-vpn"
LOG_DIR="/var/log/pqc-vpn"
VENV_PATH="/opt/pqc-vpn/venv"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging function
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $*" | tee -a "${LOG_DIR}/hub.log"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $*" | tee -a "${LOG_DIR}/hub.log"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARN:${NC} $*" | tee -a "${LOG_DIR}/hub.log"
}

# Create necessary directories
init_directories() {
    log "Creating directories..."
    mkdir -p "${DATA_DIR}" "${CONFIG_DIR}" "${LOG_DIR}"
    mkdir -p /etc/ipsec.d/{certs,private,cacerts,crls}
    chmod 700 /etc/ipsec.d/private
    chmod 755 /etc/ipsec.d/{certs,cacerts,crls}
}

# Verify PQC support
verify_pqc_support() {
    log "Verifying Post-Quantum Cryptography support..."
    
    # Test OpenSSL with OQS provider
    if ! /usr/local/ssl/bin/openssl list -providers | grep -q "oqsprovider"; then
        error "OQS provider not loaded in OpenSSL"
        return 1
    fi
    
    # Test available PQC algorithms
    if ! /usr/local/ssl/bin/openssl list -signature-algorithms | grep -q "dilithium"; then
        error "Dilithium signature algorithms not available"
        return 1
    fi
    
    if ! /usr/local/ssl/bin/openssl list -kem-algorithms | grep -q "kyber"; then
        error "Kyber KEM algorithms not available"
        return 1
    fi
    
    log "✅ PQC support verified: Dilithium and Kyber algorithms available"
    return 0
}

# Initialize CA and certificates
init_certificates() {
    log "Initializing PQC certificates..."
    
    local ca_cert="/etc/ipsec.d/cacerts/ca-cert.pem"
    local ca_key="/etc/ipsec.d/private/ca-key.pem"
    local hub_cert="/etc/ipsec.d/certs/hub-cert.pem"
    local hub_key="/etc/ipsec.d/private/hub-key.pem"
    
    # Get configuration from environment
    local org="${ORGANIZATION:-PQC-VPN-Enterprise}"
    local country="${COUNTRY:-US}"
    local state="${STATE:-California}"
    local locality="${LOCALITY:-San Francisco}"
    local hub_ip="${HUB_IP:-127.0.0.1}"
    local hub_domain="${HUB_DOMAIN:-pqc-hub.local}"
    
    # Generate CA certificate if it doesn't exist
    if [[ ! -f "$ca_cert" || ! -f "$ca_key" ]]; then
        log "Generating PQC CA certificate..."
        
        # Generate CA private key with Dilithium-5
        /usr/local/ssl/bin/openssl genpkey \
            -algorithm dilithium5 \
            -out "$ca_key"
        
        chmod 600 "$ca_key"
        
        # Generate CA certificate
        /usr/local/ssl/bin/openssl req -new -x509 \
            -key "$ca_key" \
            -out "$ca_cert" \
            -days 3650 \
            -subj "/C=$country/ST=$state/L=$locality/O=$org/OU=Certificate Authority/CN=$org Root CA"
        
        log "✅ CA certificate generated with Dilithium-5"
    else
        log "CA certificate already exists"
    fi
    
    # Generate hub certificate if it doesn't exist
    if [[ ! -f "$hub_cert" || ! -f "$hub_key" ]]; then
        log "Generating PQC hub certificate..."
        
        # Generate hub private key
        /usr/local/ssl/bin/openssl genpkey \
            -algorithm dilithium5 \
            -out "$hub_key"
        
        chmod 600 "$hub_key"
        
        # Generate certificate signing request
        local csr_file="/tmp/hub.csr"
        /usr/local/ssl/bin/openssl req -new \
            -key "$hub_key" \
            -out "$csr_file" \
            -subj "/C=$country/ST=$state/L=$locality/O=$org/OU=VPN Hub/CN=$hub_domain"
        
        # Create extensions file
        local ext_file="/tmp/hub_ext.conf"
        cat > "$ext_file" << EOF
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $hub_domain
DNS.2 = localhost
IP.1 = $hub_ip
IP.2 = 127.0.0.1
EOF
        
        # Sign the certificate
        /usr/local/ssl/bin/openssl x509 -req \
            -in "$csr_file" \
            -CA "$ca_cert" \
            -CAkey "$ca_key" \
            -CAcreateserial \
            -out "$hub_cert" \
            -days 365 \
            -extensions v3_req \
            -extfile "$ext_file"
        
        # Clean up temporary files
        rm -f "$csr_file" "$ext_file"
        
        log "✅ Hub certificate generated with Dilithium-5"
    else
        log "Hub certificate already exists"
    fi
    
    # Verify certificate signatures
    if /usr/local/ssl/bin/openssl x509 -in "$hub_cert" -text | grep -q "dilithium5"; then
        log "✅ Hub certificate uses Dilithium-5 signature"
    else
        warn "Hub certificate may not be using PQC signature algorithm"
    fi
}

# Configure strongSwan
configure_strongswan() {
    log "Configuring strongSwan with PQC support..."
    
    local hub_ip="${HUB_IP:-127.0.0.1}"
    local hub_domain="${HUB_DOMAIN:-pqc-hub.local}"
    local pqc_kem="${PQC_KEM_ALGORITHM:-kyber1024}"
    local pqc_sig="${PQC_SIG_ALGORITHM:-dilithium5}"
    
    # Create ipsec.conf with PQC configuration
    cat > /etc/ipsec.conf << EOF
# PQC-VPN strongSwan Configuration
# Generated: $(date)

config setup
    charondebug="ike 2, knl 2, cfg 2, net 2, esp 2, dmn 2, mgr 2"
    strictcrlpolicy=no
    uniqueids=never

# Default connection template with PQC
conn %default
    keyexchange=ikev2
    ike=aes256gcm16-sha512-${pqc_kem}-${pqc_sig}!
    esp=aes256gcm16-sha512-${pqc_kem}!
    dpdaction=restart
    dpddelay=30s
    dpdtimeout=120s
    rekeymargin=3m
    keyingtries=3
    left=$hub_ip
    leftsubnet=0.0.0.0/0
    leftfirewall=yes
    right=%any
    auto=add

# PKI-based connections
conn pqc-pki
    also=%default
    authby=pubkey
    leftcert=hub-cert.pem
    leftid=@$hub_domain
    rightca="C=US, O=PQC-VPN-Enterprise, CN=PQC-VPN-Enterprise Root CA"

# PSK-based connections  
conn pqc-psk
    also=%default
    authby=psk
    leftid=@$hub_domain

# High performance profile (Kyber-512 + Dilithium-2)
conn pqc-performance
    keyexchange=ikev2
    ike=aes128gcm16-sha256-kyber512-dilithium2!
    esp=aes128gcm16-sha256-kyber512!
    authby=pubkey
    left=$hub_ip
    leftsubnet=0.0.0.0/0
    leftfirewall=yes
    right=%any
    leftcert=hub-cert.pem
    leftid=@$hub_domain
    rightca="C=US, O=PQC-VPN-Enterprise, CN=PQC-VPN-Enterprise Root CA"
    auto=add
EOF

    # Create ipsec.secrets
    cat > /etc/ipsec.secrets << EOF
# PQC-VPN Secrets Configuration
# Generated: $(date)

# RSA/PQC private key for this host
: RSA hub-key.pem

# Pre-shared keys will be added by management system
# Format: username : PSK "secret-key"
EOF

    chmod 600 /etc/ipsec.secrets

    # Create strongswan.conf with PQC optimization
    cat > /etc/strongswan.conf << EOF
# strongSwan Configuration for PQC-VPN
# Generated: $(date)

charon {
    load_modular = yes
    
    # Performance optimization for PQC
    threads = 16
    worker_threads = 8
    
    processor {
        priority_threads {
            high = 4
            medium = 2
            low = 1
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
        ${LOG_DIR}/charon.log {
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
            fips_mode = no
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
        
        resolve {
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
        
        xauth-generic {
            load = yes
        }
        
        pem {
            load = yes
        }
        
        pkcs1 {
            load = yes
        }
        
        x509 {
            load = yes
        }
        
        pubkey {
            load = yes
        }
        
        hmac {
            load = yes
        }
        
        aes {
            load = yes
        }
        
        sha1 {
            load = yes
        }
        
        sha2 {
            load = yes
        }
        
        gmp {
            load = yes
        }
        
        random {
            load = yes
        }
        
        nonce {
            load = yes
        }
        
        gcm {
            load = yes
        }
    }
}

include strongswan.d/*.conf
EOF

    log "✅ strongSwan configured with PQC algorithms"
}

# Configure networking
configure_networking() {
    log "Configuring network settings..."
    
    # Enable IP forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
    
    # Configure iptables for VPN
    iptables -t nat -A POSTROUTING -s 10.10.0.0/16 -o eth0 -j MASQUERADE
    iptables -A FORWARD -s 10.10.0.0/16 -j ACCEPT
    iptables -A FORWARD -d 10.10.0.0/16 -j ACCEPT
    
    # Allow VPN ports
    iptables -A INPUT -p udp --dport 500 -j ACCEPT
    iptables -A INPUT -p udp --dport 4500 -j ACCEPT
    iptables -A INPUT -p tcp --dport 8443 -j ACCEPT
    iptables -A INPUT -p tcp --dport 9090 -j ACCEPT
    
    log "✅ Network configuration applied"
}

# Initialize database
init_database() {
    log "Initializing PQC-VPN database..."
    
    # Activate virtual environment and run database initialization
    source "$VENV_PATH/bin/activate"
    
    # Run the management tool to initialize database
    python3 /opt/pqc-vpn/tools/pqc-vpn-manager.py --config-path "$DATA_DIR" user list > /dev/null 2>&1 || true
    
    log "✅ Database initialized"
}

# Start web dashboard
start_web_dashboard() {
    if [[ "${ENABLE_WEB_INTERFACE:-true}" == "true" ]]; then
        log "Starting web management dashboard..."
        
        source "$VENV_PATH/bin/activate"
        
        # Start the web dashboard in background
        python3 /opt/pqc-vpn/web/dashboard.py \
            --host 0.0.0.0 \
            --port 8443 \
            --config-path "$DATA_DIR" \
            > "${LOG_DIR}/dashboard.log" 2>&1 &
        
        local dashboard_pid=$!
        echo $dashboard_pid > /var/run/pqc-dashboard.pid
        
        log "✅ Web dashboard started (PID: $dashboard_pid)"
    fi
}

# Start monitoring
start_monitoring() {
    if [[ "${ENABLE_MONITORING:-true}" == "true" ]]; then
        log "Starting monitoring services..."
        
        source "$VENV_PATH/bin/activate"
        
        # Start connection monitor
        python3 /opt/pqc-vpn/tools/connection-monitor.py \
            --daemon \
            --config-path "$DATA_DIR" \
            > "${LOG_DIR}/monitor.log" 2>&1 &
        
        local monitor_pid=$!
        echo $monitor_pid > /var/run/pqc-monitor.pid
        
        log "✅ Monitoring started (PID: $monitor_pid)"
    fi
}

# Start strongSwan
start_strongswan() {
    log "Starting strongSwan IPsec..."
    
    # Start strongSwan
    /usr/local/strongswan/sbin/ipsec start --nofork &
    local strongswan_pid=$!
    echo $strongswan_pid > /var/run/strongswan.pid
    
    # Wait a moment for startup
    sleep 5
    
    # Verify strongSwan is running
    if /usr/local/strongswan/sbin/ipsec status > /dev/null 2>&1; then
        log "✅ strongSwan started successfully (PID: $strongswan_pid)"
        
        # Display available connections
        log "Available VPN connections:"
        /usr/local/strongswan/sbin/ipsec statusall | grep -E "(conn|Security)" || true
    else
        error "Failed to start strongSwan"
        return 1
    fi
}

# Health check function
health_check() {
    local errors=0
    
    # Check strongSwan
    if ! /usr/local/strongswan/sbin/ipsec status > /dev/null 2>&1; then
        error "strongSwan is not running"
        ((errors++))
    fi
    
    # Check certificates
    if [[ ! -f "/etc/ipsec.d/cacerts/ca-cert.pem" ]]; then
        error "CA certificate missing"
        ((errors++))
    fi
    
    # Check PQC algorithms
    if ! /usr/local/ssl/bin/openssl list -signature-algorithms | grep -q "dilithium"; then
        error "Dilithium algorithms not available"
        ((errors++))
    fi
    
    if [[ $errors -eq 0 ]]; then
        log "✅ Health check passed"
        return 0
    else
        error "Health check failed with $errors errors"
        return 1
    fi
}

# Signal handlers for graceful shutdown
shutdown_services() {
    log "Shutting down PQC-VPN services..."
    
    # Stop strongSwan
    if [[ -f /var/run/strongswan.pid ]]; then
        local pid=$(cat /var/run/strongswan.pid)
        if kill -0 "$pid" 2>/dev/null; then
            log "Stopping strongSwan (PID: $pid)"
            /usr/local/strongswan/sbin/ipsec stop
        fi
        rm -f /var/run/strongswan.pid
    fi
    
    # Stop web dashboard
    if [[ -f /var/run/pqc-dashboard.pid ]]; then
        local pid=$(cat /var/run/pqc-dashboard.pid)
        if kill -0 "$pid" 2>/dev/null; then
            log "Stopping web dashboard (PID: $pid)"
            kill -TERM "$pid"
        fi
        rm -f /var/run/pqc-dashboard.pid
    fi
    
    # Stop monitoring
    if [[ -f /var/run/pqc-monitor.pid ]]; then
        local pid=$(cat /var/run/pqc-monitor.pid)
        if kill -0 "$pid" 2>/dev/null; then
            log "Stopping monitoring (PID: $pid)"
            kill -TERM "$pid"
        fi
        rm -f /var/run/pqc-monitor.pid
    fi
    
    log "PQC-VPN services stopped"
    exit 0
}

# Set up signal handlers
trap shutdown_services SIGTERM SIGINT

# Main initialization sequence
main() {
    log "🔐 Starting PQC-VPN Hub v1.0.0"
    log "Configuration: Hub IP=${HUB_IP:-auto}, Domain=${HUB_DOMAIN:-auto}"
    
    # Initialize components
    init_directories
    verify_pqc_support
    init_certificates
    configure_strongswan
    configure_networking
    init_database
    
    # Start services
    start_web_dashboard
    start_monitoring
    start_strongswan
    
    # Initial health check
    if health_check; then
        log "🎉 PQC-VPN Hub started successfully"
        log "   - VPN endpoint: ${HUB_IP:-auto}:500/4500"
        log "   - Web dashboard: https://${HUB_IP:-localhost}:8443"
        log "   - API endpoint: http://${HUB_IP:-localhost}:9090"
    else
        error "PQC-VPN Hub startup completed with warnings"
    fi
    
    # Keep container running and perform periodic health checks
    while true; do
        sleep 300  # 5 minutes
        if ! health_check; then
            warn "Health check failed, but continuing..."
        fi
    done
}

# Handle different commands
case "${1:-hub}" in
    hub)
        main
        ;;
    health)
        health_check
        ;;
    test-pqc)
        verify_pqc_support
        ;;
    bash)
        exec /bin/bash
        ;;
    *)
        error "Unknown command: $1"
        echo "Available commands: hub, health, test-pqc, bash"
        exit 1
        ;;
esac
