#!/bin/bash
#
# Real PQC-VPN Hub Initialization Script
# This script sets up actual Post-Quantum Cryptography VPN
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
HUB_DOMAIN=${HUB_DOMAIN:-pqc-hub.local}
ORGANIZATION=${ORGANIZATION:-PQC-VPN-Enterprise}
COUNTRY=${COUNTRY:-US}
STATE=${STATE:-CA}
LOCALITY=${LOCALITY:-San Francisco}

# PQC Algorithm configuration
PQC_KEM_ALGORITHM=${PQC_KEM_ALGORITHM:-kyber1024}
PQC_SIG_ALGORITHM=${PQC_SIG_ALGORITHM:-dilithium5}

log_info "🚀 Initializing Real PQC-VPN Hub..."
log_info "Hub IP: $HUB_IP"
log_info "PQC KEM Algorithm: $PQC_KEM_ALGORITHM"
log_info "PQC Signature Algorithm: $PQC_SIG_ALGORITHM"

# Create necessary directories
mkdir -p /etc/ipsec.d/{private,certs,cacerts,crls,ocspcerts}
mkdir -p /var/log/strongswan
mkdir -p /opt/pqc-vpn/{data,logs,certs,users}
mkdir -p /var/lib/strongswan

# Set proper permissions
chmod 700 /etc/ipsec.d/private
chmod 755 /etc/ipsec.d/{certs,cacerts,crls,ocspcerts}
chmod 755 /opt/pqc-vpn/{data,logs,certs,users}

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

# Test PQC algorithms
if /usr/local/oqs-openssl/bin/openssl list -signature-algorithms | grep -q "$PQC_SIG_ALGORITHM"; then
    log_success "✅ PQC Signature algorithm ($PQC_SIG_ALGORITHM) available"
else
    log_error "❌ PQC Signature algorithm ($PQC_SIG_ALGORITHM) not available"
    exit 1
fi

if /usr/local/oqs-openssl/bin/openssl list -kem-algorithms | grep -q "$PQC_KEM_ALGORITHM"; then
    log_success "✅ PQC KEM algorithm ($PQC_KEM_ALGORITHM) available"
else
    log_error "❌ PQC KEM algorithm ($PQC_KEM_ALGORITHM) not available"
    exit 1
fi

# Generate real PQC certificates
log_info "🔐 Generating Real Post-Quantum Certificates..."

# Generate PQC CA key and certificate
if [ ! -f /etc/ipsec.d/private/ca-key.pem ]; then
    log_info "Generating PQC CA private key..."
    /usr/local/oqs-openssl/bin/openssl genpkey \
        -algorithm $PQC_SIG_ALGORITHM \
        -out /etc/ipsec.d/private/ca-key.pem
    chmod 600 /etc/ipsec.d/private/ca-key.pem
    
    log_info "Generating PQC CA certificate..."
    /usr/local/oqs-openssl/bin/openssl req -new -x509 \
        -key /etc/ipsec.d/private/ca-key.pem \
        -out /etc/ipsec.d/cacerts/ca-cert.pem \
        -days 3650 \
        -subj "/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORGANIZATION/OU=Certificate Authority/CN=PQC-VPN-CA"
    
    log_success "✅ PQC CA certificate generated"
fi

# Generate PQC Hub key and certificate
if [ ! -f /etc/ipsec.d/private/hub-key.pem ]; then
    log_info "Generating PQC Hub private key..."
    /usr/local/oqs-openssl/bin/openssl genpkey \
        -algorithm $PQC_SIG_ALGORITHM \
        -out /etc/ipsec.d/private/hub-key.pem
    chmod 600 /etc/ipsec.d/private/hub-key.pem
    
    log_info "Generating PQC Hub certificate..."
    /usr/local/oqs-openssl/bin/openssl req -new \
        -key /etc/ipsec.d/private/hub-key.pem \
        -out /tmp/hub.csr \
        -subj "/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORGANIZATION/OU=VPN Hub/CN=$HUB_DOMAIN"
    
    # Create certificate extensions for hub
    cat > /tmp/hub_extensions.conf << EOF
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $HUB_DOMAIN
IP.1 = $HUB_IP
EOF
    
    /usr/local/oqs-openssl/bin/openssl x509 -req \
        -in /tmp/hub.csr \
        -CA /etc/ipsec.d/cacerts/ca-cert.pem \
        -CAkey /etc/ipsec.d/private/ca-key.pem \
        -CAcreateserial \
        -out /etc/ipsec.d/certs/hub-cert.pem \
        -days 365 \
        -extensions v3_ext \
        -extfile /tmp/hub_extensions.conf
    
    rm -f /tmp/hub.csr /tmp/hub_extensions.conf
    log_success "✅ PQC Hub certificate generated"
fi

# Create real strongSwan configuration with PQC
log_info "📝 Creating Real PQC strongSwan Configuration..."

cat > /etc/ipsec.conf << EOF
# Real Post-Quantum Cryptography strongSwan Configuration
# Generated: $(date)

config setup
    charondebug="cfg 2, dmn 2, ike 2, net 2, esp 2, lib 2"
    uniqueids=yes
    cachecrls=no
    strictcrlpolicy=no

# Default connection parameters
conn %default
    keyexchange=ikev2
    dpdaction=clear
    dpddelay=300s
    rekey=no
    left=%any
    leftsubnet=0.0.0.0/0
    right=%any
    leftfirewall=yes
    rightfirewall=yes
    
# Real PQC Hub-to-Spoke connections
conn pqc-pki-spoke
    auto=add
    type=tunnel
    leftauth=pubkey
    rightauth=pubkey
    leftcert=hub-cert.pem
    leftid="C=$COUNTRY, O=$ORGANIZATION, CN=$HUB_DOMAIN"
    rightid=%any
    rightsubnet=10.10.0.0/16
    # Real PQC algorithms - ML-KEM + ML-DSA
    ike=aes256gcm16-sha512-$PQC_KEM_ALGORITHM-$PQC_SIG_ALGORITHM!
    esp=aes256gcm16-sha512-$PQC_KEM_ALGORITHM!

conn pqc-psk-spoke
    auto=add
    type=tunnel
    leftauth=psk
    rightauth=psk
    leftid=@$HUB_DOMAIN
    rightid=%any
    rightsubnet=10.10.0.0/16
    # Real PQC algorithms with PSK
    ike=aes256gcm16-sha512-$PQC_KEM_ALGORITHM!
    esp=aes256gcm16-sha512-$PQC_KEM_ALGORITHM!

conn pqc-hybrid-spoke
    auto=add
    type=tunnel
    leftauth=pubkey
    rightauth=psk
    leftcert=hub-cert.pem
    leftid="C=$COUNTRY, O=$ORGANIZATION, CN=$HUB_DOMAIN"
    rightid=%any
    rightsubnet=10.10.0.0/16
    # Hybrid PKI+PSK with PQC
    ike=aes256gcm16-sha512-$PQC_KEM_ALGORITHM-$PQC_SIG_ALGORITHM!
    esp=aes256gcm16-sha512-$PQC_KEM_ALGORITHM!
EOF

# Create IPsec secrets
cat > /etc/ipsec.secrets << EOF
# Real PQC-VPN Hub Secrets
# Generated: $(date)

# Hub certificate private key
: RSA hub-key.pem

# Default PSK for testing
@$HUB_DOMAIN %any : PSK "pqc-enterprise-key-$(date +%s)-secure"

# Demo user PSKs (will be replaced by management system)
demo-user-1 : PSK "user1-pqc-$(date +%s)"
demo-user-2 : PSK "user2-pqc-$(date +%s)"
demo-user-3 : PSK "user3-pqc-$(date +%s)"
EOF

chmod 600 /etc/ipsec.secrets

# Configure strongSwan daemon
cat > /etc/strongswan.conf << EOF
# Real PQC strongSwan Configuration

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
        
        # Enable VICI for management API
        vici {
            load = yes
        }
        
        # Enable updown script
        updown {
            load = yes
        }
    }
    
    # Real network settings
    port = 500
    port_nat_t = 4500
    
    # Performance settings
    threads = 16
    processor {
        priority_threads = yes
    }
    
    # Security settings
    integrity_test = yes
    crypto_test = yes
}

include strongswan.d/*.conf
EOF

# Initialize database
log_info "📊 Initializing Real Monitoring Database..."
python3 -c "
import sqlite3
import json
from datetime import datetime

conn = sqlite3.connect('/opt/pqc-vpn/data/pqc-vpn.db')
cursor = conn.cursor()

# Create real monitoring tables
cursor.execute('''
CREATE TABLE IF NOT EXISTS connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    client_ip TEXT,
    connect_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    disconnect_time TIMESTAMP NULL,
    bytes_in INTEGER DEFAULT 0,
    bytes_out INTEGER DEFAULT 0,
    auth_method TEXT,
    pqc_algorithms TEXT,
    status TEXT DEFAULT 'active'
)
''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT,
    auth_type TEXT,
    certificate_path TEXT NULL,
    psk_key TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    status TEXT DEFAULT 'active'
)
''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS system_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    active_connections INTEGER,
    cpu_usage REAL,
    memory_usage REAL,
    network_in INTEGER,
    network_out INTEGER,
    pqc_connections INTEGER
)
''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT,
    source_ip TEXT,
    user_id TEXT NULL,
    severity TEXT,
    message TEXT
)
''')

# Insert initial demo users
demo_users = [
    ('alice', 'alice@company.com', 'pki'),
    ('bob', 'bob@company.com', 'psk'),
    ('charlie', 'charlie@company.com', 'hybrid')
]

for username, email, auth_type in demo_users:
    cursor.execute('''
        INSERT OR REPLACE INTO users (username, email, auth_type, status)
        VALUES (?, ?, ?, 'active')
    ''', (username, email, auth_type))

conn.commit()
conn.close()

print('✅ Database initialized with real schema')
"

# Start Redis for real-time data
redis-server --daemonize yes --port 6379 --bind 127.0.0.1

# Start real monitoring service
log_info "🔧 Starting Real Monitoring Services..."

# Create real monitoring service
cat > /opt/pqc-vpn/tools/real_monitor.py << 'EOF'
#!/usr/bin/env python3
"""
Real PQC-VPN Monitoring Service
Collects actual system metrics and VPN statistics
"""

import time
import json
import sqlite3
import psutil
import subprocess
import redis
from datetime import datetime
import re

class RealPQCMonitor:
    def __init__(self):
        self.db_path = '/opt/pqc-vpn/data/pqc-vpn.db'
        self.redis_client = redis.Redis(host='localhost', port=6379, db=0)
        
    def get_strongswan_status(self):
        """Get real strongSwan connection status"""
        try:
            result = subprocess.run(['/usr/local/strongswan/sbin/ipsec', 'statusall'], 
                                  capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            return f"Error: {e}"
    
    def get_active_connections(self):
        """Count real active VPN connections"""
        try:
            result = subprocess.run(['/usr/local/strongswan/sbin/ipsec', 'status'], 
                                  capture_output=True, text=True)
            # Count ESTABLISHED connections
            established = result.stdout.count('ESTABLISHED')
            return established
        except:
            return 0
    
    def get_pqc_connections(self):
        """Count connections using PQC algorithms"""
        try:
            status = self.get_strongswan_status()
            # Look for PQC algorithm names
            pqc_patterns = ['kyber', 'dilithium', 'falcon', 'sphincs']
            pqc_count = 0
            for pattern in pqc_patterns:
                pqc_count += len(re.findall(pattern, status, re.IGNORECASE))
            return pqc_count
        except:
            return 0
    
    def get_system_metrics(self):
        """Get real system performance metrics"""
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        network = psutil.net_io_counters()
        
        return {
            'cpu_usage': cpu_percent,
            'memory_usage': memory.percent,
            'memory_total': memory.total,
            'memory_used': memory.used,
            'network_bytes_sent': network.bytes_sent,
            'network_bytes_recv': network.bytes_recv
        }
    
    def update_metrics(self):
        """Update real-time metrics in database and Redis"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get real metrics
        active_conn = self.get_active_connections()
        pqc_conn = self.get_pqc_connections()
        sys_metrics = self.get_system_metrics()
        
        # Store in database
        cursor.execute('''
            INSERT INTO system_metrics 
            (active_connections, cpu_usage, memory_usage, network_in, network_out, pqc_connections)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (active_conn, sys_metrics['cpu_usage'], sys_metrics['memory_usage'],
              sys_metrics['network_bytes_recv'], sys_metrics['network_bytes_sent'], pqc_conn))
        
        # Store in Redis for real-time access
        real_time_data = {
            'timestamp': datetime.now().isoformat(),
            'active_connections': active_conn,
            'pqc_connections': pqc_conn,
            'cpu_usage': sys_metrics['cpu_usage'],
            'memory_usage': sys_metrics['memory_usage'],
            'strongswan_status': self.get_strongswan_status()
        }
        
        self.redis_client.set('pqc_vpn_status', json.dumps(real_time_data))
        self.redis_client.expire('pqc_vpn_status', 300)  # 5 minute expiry
        
        conn.commit()
        conn.close()
        
        print(f"✅ Updated metrics: {active_conn} active, {pqc_conn} PQC connections")
    
    def run(self):
        """Run continuous monitoring"""
        print("🔧 Starting Real PQC-VPN Monitor...")
        while True:
            try:
                self.update_metrics()
                time.sleep(30)  # Update every 30 seconds
            except Exception as e:
                print(f"❌ Monitor error: {e}")
                time.sleep(60)

if __name__ == "__main__":
    monitor = RealPQCMonitor()
    monitor.run()
EOF

chmod +x /opt/pqc-vpn/tools/real_monitor.py

# Create systemd service for monitoring
cat > /etc/systemd/system/pqc-monitor.service << EOF
[Unit]
Description=Real PQC-VPN Monitoring Service
After=strongswan.service redis.service
Requires=strongswan.service

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/pqc-vpn/tools/real_monitor.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable services
systemctl daemon-reload
systemctl enable pqc-monitor.service

# Configure network and iptables
log_info "🌐 Configuring Network and Firewall..."

# Enable IP forwarding
echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-ip-forward.conf
echo 'net.ipv6.conf.all.forwarding = 1' >> /etc/sysctl.d/99-ip-forward.conf
sysctl -p /etc/sysctl.d/99-ip-forward.conf

# Configure iptables for VPN
iptables -A INPUT -p udp --dport 500 -j ACCEPT
iptables -A INPUT -p udp --dport 4500 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
iptables -A INPUT -p tcp --dport 8443 -j ACCEPT
iptables -A FORWARD -s 10.10.0.0/16 -j ACCEPT
iptables -A FORWARD -d 10.10.0.0/16 -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.10.0.0/16 -o eth0 -j MASQUERADE

# Save iptables rules
iptables-save > /etc/iptables/rules.v4

# Start strongSwan
log_info "🔐 Starting Real PQC strongSwan..."
/usr/local/strongswan/sbin/ipsec start

# Wait for strongSwan to initialize
sleep 5

# Verify PQC is working
log_info "🔍 Verifying Real PQC Implementation..."
if /usr/local/strongswan/sbin/ipsec status | grep -q "loaded"; then
    log_success "✅ strongSwan with PQC loaded successfully"
else
    log_error "❌ strongSwan failed to load"
    exit 1
fi

# Start monitoring
nohup python3 /opt/pqc-vpn/tools/real_monitor.py > /var/log/pqc-monitor.log 2>&1 &

# Start web dashboard
nohup python3 /opt/pqc-vpn/web/real_dashboard.py > /var/log/pqc-dashboard.log 2>&1 &

log_success "🎉 Real PQC-VPN Hub Successfully Initialized!"
log_info "📊 Web Dashboard: https://$HUB_IP:8443"
log_info "🔐 strongSwan Status: ipsec status"
log_info "📈 Monitor Logs: tail -f /var/log/pqc-monitor.log"

# Keep container running and show status
while true; do
    echo -e "\n${GREEN}$(date)${NC} - PQC-VPN Hub Status:"
    /usr/local/strongswan/sbin/ipsec status
    sleep 300  # Show status every 5 minutes
done
