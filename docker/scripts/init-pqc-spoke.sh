#!/bin/bash
#
# Real PQC-VPN Spoke Client Initialization Script
# This script sets up actual Post-Quantum Cryptography VPN client
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Environment variables
HUB_IP=${HUB_IP:-192.168.1.100}
CLIENT_NAME=${CLIENT_NAME:-client}
AUTH_TYPE=${AUTH_TYPE:-pki}
ORGANIZATION=${ORGANIZATION:-PQC-VPN-Enterprise}
COUNTRY=${COUNTRY:-US}
STATE=${STATE:-CA}
LOCALITY=${LOCALITY:-San Francisco}

# PQC Algorithm configuration
PQC_KEM_ALGORITHM=${PQC_KEM_ALGORITHM:-kyber1024}
PQC_SIG_ALGORITHM=${PQC_SIG_ALGORITHM:-dilithium5}

log_info "🚀 Initializing Real PQC-VPN Spoke Client: $CLIENT_NAME"
log_info "Hub IP: $HUB_IP"
log_info "Authentication Type: $AUTH_TYPE"
log_info "PQC KEM Algorithm: $PQC_KEM_ALGORITHM"
log_info "PQC Signature Algorithm: $PQC_SIG_ALGORITHM"

# Create necessary directories
mkdir -p /etc/ipsec.d/{private,certs,cacerts,crls,ocspcerts}
mkdir -p /var/log/strongswan
mkdir -p /opt/pqc-client/{data,logs,certs}

# Set proper permissions
chmod 700 /etc/ipsec.d/private
chmod 755 /etc/ipsec.d/{certs,cacerts,crls,ocspcerts}
chmod 755 /opt/pqc-client/{data,logs,certs}

# Test PQC availability
log_info "🔍 Testing Post-Quantum Cryptography availability..."

# Test OQS provider
if /usr/local/oqs-openssl/bin/openssl list -providers | grep -q "oqsprovider"; then
    log_success "✅ OQS Provider detected"
    PQC_AVAILABLE=true
else
    log_error "❌ OQS Provider not found"
    PQC_AVAILABLE=false
    exit 1
fi

# Generate or fetch client certificates based on auth type
log_info "🔐 Setting up $AUTH_TYPE authentication..."

case "$AUTH_TYPE" in
    "pki")
        setup_pki_auth
        ;;
    "psk")
        setup_psk_auth
        ;;
    "hybrid")
        setup_hybrid_auth
        ;;
    *)
        log_error "Unknown authentication type: $AUTH_TYPE"
        exit 1
        ;;
esac

setup_pki_auth() {
    log_info "Setting up PKI authentication with PQC certificates..."
    
    # Wait for hub to be ready and fetch CA certificate
    log_info "Waiting for hub to be ready..."
    until ping -c 1 $HUB_IP > /dev/null 2>&1; do
        log_info "Waiting for hub connectivity..."
        sleep 5
    done
    
    # Fetch CA certificate from hub (in production, this would be done securely)
    log_info "Fetching CA certificate from hub..."
    max_attempts=10
    attempt=0
    while [ $attempt -lt $max_attempts ]; do
        if curl -k -s https://$HUB_IP:8443/api/ca-cert -o /etc/ipsec.d/cacerts/ca-cert.pem 2>/dev/null; then
            log_success "✅ CA certificate downloaded"
            break
        else
            log_info "Attempt $((attempt + 1))/$max_attempts: Waiting for hub CA..."
            sleep 10
            attempt=$((attempt + 1))
        fi
    done
    
    if [ $attempt -eq $max_attempts ]; then
        log_warning "Could not fetch CA certificate from hub, generating self-signed..."
        # In production, this would fail - for demo, we'll generate a temporary cert
        generate_temp_client_cert
    fi
    
    # Generate client private key
    if [ ! -f /etc/ipsec.d/private/${CLIENT_NAME}-key.pem ]; then
        log_info "Generating PQC client private key..."
        /usr/local/oqs-openssl/bin/openssl genpkey \
            -algorithm $PQC_SIG_ALGORITHM \
            -out /etc/ipsec.d/private/${CLIENT_NAME}-key.pem
        chmod 600 /etc/ipsec.d/private/${CLIENT_NAME}-key.pem
        
        # Generate certificate request
        log_info "Generating certificate signing request..."
        /usr/local/oqs-openssl/bin/openssl req -new \
            -key /etc/ipsec.d/private/${CLIENT_NAME}-key.pem \
            -out /tmp/${CLIENT_NAME}.csr \
            -subj "/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORGANIZATION/OU=VPN Client/CN=$CLIENT_NAME"
        
        # Submit CSR to hub for signing (in production)
        log_info "Submitting CSR to hub for signing..."
        if curl -k -X POST -F "csr=@/tmp/${CLIENT_NAME}.csr" \
                https://$HUB_IP:8443/api/sign-csr \
                -o /etc/ipsec.d/certs/${CLIENT_NAME}-cert.pem 2>/dev/null; then
            log_success "✅ Client certificate signed by hub"
        else
            log_warning "Could not get certificate signed by hub, using self-signed"
            generate_temp_client_cert
        fi
        
        rm -f /tmp/${CLIENT_NAME}.csr
    fi
}

setup_psk_auth() {
    log_info "Setting up PSK authentication..."
    
    # Generate or use provided PSK
    PSK_KEY=${PSK_KEY:-$(openssl rand -hex 32)}
    
    # Register PSK with hub (in production, done through management interface)
    log_info "Registering PSK with hub..."
    curl -k -X POST -H "Content-Type: application/json" \
         -d "{\"client_name\":\"$CLIENT_NAME\",\"psk_key\":\"$PSK_KEY\",\"auth_type\":\"psk\"}" \
         https://$HUB_IP:8443/api/register-client 2>/dev/null || log_warning "Could not register with hub"
    
    log_success "✅ PSK configured: $PSK_KEY"
}

setup_hybrid_auth() {
    log_info "Setting up Hybrid PKI+PSK authentication..."
    setup_pki_auth
    setup_psk_auth
}

generate_temp_client_cert() {
    log_info "Generating temporary self-signed client certificate..."
    /usr/local/oqs-openssl/bin/openssl req -new -x509 \
        -key /etc/ipsec.d/private/${CLIENT_NAME}-key.pem \
        -out /etc/ipsec.d/certs/${CLIENT_NAME}-cert.pem \
        -days 365 \
        -subj "/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORGANIZATION/OU=VPN Client/CN=$CLIENT_NAME"
}

# Create real strongSwan configuration for spoke
log_info "📝 Creating Real PQC strongSwan Configuration..."

create_strongswan_config() {
    cat > /etc/ipsec.conf << EOF
# Real Post-Quantum Cryptography strongSwan Client Configuration
# Client: $CLIENT_NAME
# Generated: $(date)

config setup
    charondebug="cfg 2, dmn 2, ike 2, net 2, esp 2"
    uniqueids=yes
    cachecrls=no
    strictcrlpolicy=no

# Default connection parameters
conn %default
    keyexchange=ikev2
    dpdaction=restart
    dpddelay=30s
    rekey=no
    left=%any
    right=$HUB_IP
    rightsubnet=0.0.0.0/0
    auto=start
    
# Real PQC connection to hub
conn hub-$AUTH_TYPE
    auto=start
    type=tunnel
EOF

    case "$AUTH_TYPE" in
        "pki")
            cat >> /etc/ipsec.conf << EOF
    leftauth=pubkey
    rightauth=pubkey
    leftcert=${CLIENT_NAME}-cert.pem
    leftid="C=$COUNTRY, O=$ORGANIZATION, CN=$CLIENT_NAME"
    rightid=%any
    # Real PQC algorithms - ML-KEM + ML-DSA
    ike=aes256gcm16-sha512-$PQC_KEM_ALGORITHM-$PQC_SIG_ALGORITHM!
    esp=aes256gcm16-sha512-$PQC_KEM_ALGORITHM!
EOF
            ;;
        "psk")
            cat >> /etc/ipsec.conf << EOF
    leftauth=psk
    rightauth=psk
    leftid=$CLIENT_NAME
    rightid=%any
    # Real PQC algorithms with PSK
    ike=aes256gcm16-sha512-$PQC_KEM_ALGORITHM!
    esp=aes256gcm16-sha512-$PQC_KEM_ALGORITHM!
EOF
            ;;
        "hybrid")
            cat >> /etc/ipsec.conf << EOF
    leftauth=pubkey
    rightauth=psk
    leftcert=${CLIENT_NAME}-cert.pem
    leftid="C=$COUNTRY, O=$ORGANIZATION, CN=$CLIENT_NAME"
    rightid=%any
    # Hybrid PKI+PSK with PQC
    ike=aes256gcm16-sha512-$PQC_KEM_ALGORITHM-$PQC_SIG_ALGORITHM!
    esp=aes256gcm16-sha512-$PQC_KEM_ALGORITHM!
EOF
            ;;
    esac
}

create_strongswan_config

# Create IPsec secrets
log_info "🔑 Creating IPsec secrets..."

cat > /etc/ipsec.secrets << EOF
# Real PQC-VPN Client Secrets
# Client: $CLIENT_NAME
# Generated: $(date)

EOF

case "$AUTH_TYPE" in
    "pki")
        echo ": RSA ${CLIENT_NAME}-key.pem" >> /etc/ipsec.secrets
        ;;
    "psk")
        echo "$CLIENT_NAME : PSK \"$PSK_KEY\"" >> /etc/ipsec.secrets
        ;;
    "hybrid")
        echo ": RSA ${CLIENT_NAME}-key.pem" >> /etc/ipsec.secrets
        echo "$CLIENT_NAME : PSK \"$PSK_KEY\"" >> /etc/ipsec.secrets
        ;;
esac

chmod 600 /etc/ipsec.secrets

# Configure strongSwan daemon
cat > /etc/strongswan.conf << EOF
# Real PQC strongSwan Client Configuration

charon {
    load_modular = yes
    
    # Enable debugging
    filelog {
        /var/log/strongswan/charon.log {
            time_format = %b %e %T
            ike_name = yes
            append = no
            default = 2
            flush_line = yes
        }
    }
    
    # Crypto plugins
    plugins {
        include strongswan.d/charon/*.conf
        
        # PQC support
        openssl {
            load = yes
            fips_mode = 0
        }
        
        # Enable VICI for monitoring
        vici {
            load = yes
        }
    }
    
    # Client-specific settings
    port = 500
    port_nat_t = 4500
    
    # Performance settings
    threads = 8
    
    # Security settings
    integrity_test = yes
    crypto_test = yes
}

include strongswan.d/*.conf
EOF

# Start client monitoring
log_info "📊 Starting Client Monitoring..."

cat > /opt/pqc-client/tools/client_monitor.py << 'EOF'
#!/usr/bin/env python3
"""
Real PQC-VPN Client Monitoring
"""

import time
import json
import subprocess
import psutil
import socket
from datetime import datetime

class PQCClientMonitor:
    def __init__(self, client_name):
        self.client_name = client_name
        self.strongswan_bin = '/usr/local/strongswan/sbin/ipsec'
    
    def get_connection_status(self):
        """Get real connection status"""
        try:
            result = subprocess.run([self.strongswan_bin, 'status'], 
                                  capture_output=True, text=True, timeout=10)
            return {
                'connected': 'ESTABLISHED' in result.stdout,
                'status_output': result.stdout,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'connected': False, 'error': str(e)}
    
    def get_system_metrics(self):
        """Get client system metrics"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            network = psutil.net_io_counters()
            
            return {
                'cpu_usage': round(cpu_percent, 2),
                'memory_percent': round(memory.percent, 2),
                'network_bytes_sent': network.bytes_sent,
                'network_bytes_recv': network.bytes_recv,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def log_status(self):
        """Log current status"""
        conn_status = self.get_connection_status()
        sys_metrics = self.get_system_metrics()
        
        status = {
            'client_name': self.client_name,
            'connection': conn_status,
            'system': sys_metrics
        }
        
        print(f"[{datetime.now()}] {self.client_name} - Connected: {conn_status.get('connected', False)}")
        return status
    
    def run(self):
        """Run continuous monitoring"""
        print(f"🔧 Starting PQC-VPN Client Monitor for {self.client_name}...")
        while True:
            try:
                self.log_status()
                time.sleep(60)  # Update every minute
            except Exception as e:
                print(f"❌ Monitor error: {e}")
                time.sleep(60)

if __name__ == "__main__":
    import sys
    client_name = sys.argv[1] if len(sys.argv) > 1 else "unknown"
    monitor = PQCClientMonitor(client_name)
    monitor.run()
EOF

chmod +x /opt/pqc-client/tools/client_monitor.py

# Enable IP forwarding
echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-ip-forward.conf
sysctl -p /etc/sysctl.d/99-ip-forward.conf

# Start strongSwan
log_info "🔐 Starting Real PQC strongSwan Client..."
/usr/local/strongswan/sbin/ipsec start

# Wait for strongSwan to initialize
sleep 5

# Start connection
log_info "🔗 Establishing VPN Connection..."
/usr/local/strongswan/sbin/ipsec up hub-$AUTH_TYPE

# Start monitoring
nohup python3 /opt/pqc-client/tools/client_monitor.py $CLIENT_NAME > /var/log/pqc-client-monitor.log 2>&1 &

# Verify connection
sleep 10
if /usr/local/strongswan/sbin/ipsec status | grep -q "ESTABLISHED"; then
    log_success "🎉 Real PQC-VPN Client Successfully Connected!"
    log_info "📊 Client: $CLIENT_NAME"
    log_info "🔐 Hub: $HUB_IP"
    log_info "🔑 Auth: $AUTH_TYPE"
    log_info "🧮 PQC KEM: $PQC_KEM_ALGORITHM"
    log_info "🔏 PQC SIG: $PQC_SIG_ALGORITHM"
else
    log_warning "⚠️  Connection not established yet, check logs"
fi

# Keep container running and show status
while true; do
    echo -e "\n${GREEN}$(date)${NC} - PQC Client $CLIENT_NAME Status:"
    /usr/local/strongswan/sbin/ipsec status
    
    # Test connectivity to hub
    if ping -c 1 $HUB_IP > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Hub connectivity: OK${NC}"
    else
        echo -e "${RED}❌ Hub connectivity: FAILED${NC}"
    fi
    
    sleep 300  # Show status every 5 minutes
done
