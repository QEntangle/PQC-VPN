# 🔐 PQC-VPN Windows Demo Guide
## 1 Server + 3 Clients Setup

This guide provides a complete step-by-step process to demonstrate PQC-VPN with one server (hub) and three clients (spokes) running on Windows with separate terminals.

## 🎯 Demo Overview

- **Hub Server**: 1 instance (Terminal 1)
- **Client 1 (Alice)**: Kyber-1024 + PKI auth (Terminal 2)
- **Client 2 (Bob)**: Kyber-768 + PSK auth (Terminal 3)
- **Client 3 (Charlie)**: Kyber-512 + Hybrid auth (Terminal 4)
- **Dashboard**: Real-time monitoring (Terminal 5)

## 📋 Prerequisites

### Required Software
- **Windows 10/11** with WSL2 or **Windows with Docker Desktop**
- **Git for Windows**
- **PowerShell or Command Prompt**
- **Python 3.8+**
- **Docker Desktop** (recommended for easy setup)

### Network Setup
- All instances will run on localhost with different ports
- Hub: `10.10.0.1` (simulated)
- Alice: `10.10.1.50`
- Bob: `10.10.1.51` 
- Charlie: `10.10.1.52`

## 🚀 Step 1: Initial Setup

### 1.1 Clone and Prepare Repository
```powershell
# Open PowerShell as Administrator
cd C:\
git clone https://github.com/QEntangle/PQC-VPN.git
cd PQC-VPN

# Create demo directories
mkdir demo-setup
mkdir demo-setup\hub
mkdir demo-setup\client-alice
mkdir demo-setup\client-bob  
mkdir demo-setup\client-charlie
mkdir demo-setup\logs
```

### 1.2 Install Dependencies
```powershell
# Install Python packages
pip install flask flask-cors psutil pyyaml

# Install Docker Desktop if not already installed
# Download from: https://www.docker.com/products/docker-desktop
```

## 🏗️ Step 2: Generate Certificates and Keys

### 2.1 Setup Certificate Infrastructure
```powershell
# Open Terminal 1 (Certificate Generation)
cd C:\PQC-VPN

# Run certificate generation script
python tools\pqc_keygen.py --setup-demo

# This creates:
# - CA certificate with PQC algorithms
# - Hub server certificate 
# - Client certificates for Alice, Bob, Charlie
# - PSK keys for PSK/Hybrid authentication
```

### 2.2 Verify Certificate Generation
```powershell
# Check generated files
dir demo-setup\hub\certs\
dir demo-setup\client-alice\certs\
dir demo-setup\client-bob\certs\
dir demo-setup\client-charlie\certs\

# You should see:
# - ca-cert.pem (CA certificate)
# - hub-cert.pem (Hub certificate) 
# - alice-cert.pem, bob-cert.pem, charlie-cert.pem (Client certificates)
# - Private keys and PSK files
```

## 🖥️ Step 3: Configure Hub Server

### 3.1 Open Terminal 1 - Hub Server
```powershell
# New PowerShell window - Terminal 1
cd C:\PQC-VPN
title "PQC-VPN Hub Server"

# Copy hub configuration
copy configs\hub-config-template.conf demo-setup\hub\ipsec.conf
copy configs\hub-secrets-template demo-setup\hub\ipsec.secrets
```

### 3.2 Configure Hub Settings
Edit `demo-setup\hub\ipsec.conf`:
```bash
# Hub configuration for demo
config setup
    charondebug="ike 2, knl 2, cfg 2"
    strictcrlpolicy=no

conn %default
    keyexchange=ikev2
    ike=aes256-sha256-x25519,aes256-sha256-kyber1024!
    esp=aes256-sha256-x25519,aes256-sha256-kyber1024!
    dpdaction=clear
    dpddelay=300s
    rekey=no
    left=10.10.0.1
    leftsubnet=10.10.0.0/16
    leftcert=hub-cert.pem
    leftid="C=US, O=PQC-VPN Demo, CN=hub.pqc-demo.local"

# Connection for Alice (PKI)
conn alice-pki
    auto=add
    right=10.10.1.50
    rightsubnet=10.10.1.50/32
    rightid="C=US, O=PQC-VPN Demo, CN=alice.pqc-demo.local"
    rightcert=alice-cert.pem
    
# Connection for Bob (PSK)  
conn bob-psk
    auto=add
    right=10.10.1.51
    rightsubnet=10.10.1.51/32
    rightid=bob
    authby=secret
    ike=aes256-sha256-kyber768!
    esp=aes256-sha256-kyber768!
    
# Connection for Charlie (Hybrid)
conn charlie-hybrid
    auto=add  
    right=10.10.1.52
    rightsubnet=10.10.1.52/32
    rightid="C=US, O=PQC-VPN Demo, CN=charlie.pqc-demo.local"
    rightcert=charlie-cert.pem
    authby=secret
    ike=aes256-sha256-kyber512!
    esp=aes256-sha256-kyber512!
```

## 👥 Step 4: Configure Clients

### 4.1 Terminal 2 - Client Alice (PKI Authentication)
```powershell
# New PowerShell window - Terminal 2
cd C:\PQC-VPN\demo-setup\client-alice
title "PQC-VPN Client - Alice (PKI)"

# Create Alice's configuration
echo 'config setup
    charondebug="ike 2, knl 2, cfg 2"
    strictcrlpolicy=no

conn %default
    keyexchange=ikev2
    ike=aes256-sha256-kyber1024!
    esp=aes256-sha256-kyber1024!
    dpdaction=restart
    dpddelay=300s
    rekey=no
    right=10.10.0.1
    rightsubnet=10.10.0.0/16
    rightid="C=US, O=PQC-VPN Demo, CN=hub.pqc-demo.local"
    left=10.10.1.50
    leftsubnet=10.10.1.50/32
    leftcert=alice-cert.pem
    leftid="C=US, O=PQC-VPN Demo, CN=alice.pqc-demo.local"
    auto=start

conn hub
    rightcert=hub-cert.pem' > ipsec.conf
```

### 4.2 Terminal 3 - Client Bob (PSK Authentication)
```powershell
# New PowerShell window - Terminal 3  
cd C:\PQC-VPN\demo-setup\client-bob
title "PQC-VPN Client - Bob (PSK)"

# Create Bob's configuration
echo 'config setup
    charondebug="ike 2, knl 2, cfg 2"
    strictcrlpolicy=no

conn %default
    keyexchange=ikev2
    ike=aes256-sha256-kyber768!
    esp=aes256-sha256-kyber768!
    dpdaction=restart
    dpddelay=300s
    rekey=no
    right=10.10.0.1
    rightsubnet=10.10.0.0/16
    rightid=hub
    left=10.10.1.51
    leftsubnet=10.10.1.51/32
    leftid=bob
    authby=secret
    auto=start

conn hub' > ipsec.conf

# Create PSK secrets file
echo 'bob hub : PSK "demo-psk-key-bob-2025"' > ipsec.secrets
```

### 4.3 Terminal 4 - Client Charlie (Hybrid Authentication)
```powershell
# New PowerShell window - Terminal 4
cd C:\PQC-VPN\demo-setup\client-charlie  
title "PQC-VPN Client - Charlie (Hybrid)"

# Create Charlie's configuration
echo 'config setup
    charondebug="ike 2, knl 2, cfg 2"
    strictcrlpolicy=no

conn %default
    keyexchange=ikev2
    ike=aes256-sha256-kyber512!
    esp=aes256-sha256-kyber512!
    dpdaction=restart
    dpddelay=300s
    rekey=no
    right=10.10.0.1
    rightsubnet=10.10.0.0/16
    rightid="C=US, O=PQC-VPN Demo, CN=hub.pqc-demo.local"
    left=10.10.1.52
    leftsubnet=10.10.1.52/32
    leftcert=charlie-cert.pem
    leftid="C=US, O=PQC-VPN Demo, CN=charlie.pqc-demo.local"
    authby=secret
    auto=start

conn hub
    rightcert=hub-cert.pem' > ipsec.conf

# Create hybrid secrets
echo 'charlie hub : PSK "demo-psk-key-charlie-2025"' > ipsec.secrets
```

## 🚀 Step 5: Start Services

### 5.1 Start Hub Server (Terminal 1)
```powershell
# In Terminal 1 (Hub)
cd C:\PQC-VPN\demo-setup\hub

# Start hub with Docker (recommended)
docker run -it --rm --name pqc-vpn-hub \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  -v ${PWD}:/etc/ipsec.d \
  -p 500:500/udp \
  -p 4500:4500/udp \
  pqc-vpn:latest \
  /start-hub.sh

# Alternative: Direct execution (if strongSwan installed locally)
# ipsec start --nofork
```

### 5.2 Start Client Alice (Terminal 2)
```powershell
# In Terminal 2 (Alice)
cd C:\PQC-VPN\demo-setup\client-alice

# Wait 10 seconds after hub starts
timeout /t 10

# Start Alice's client
docker run -it --rm --name pqc-vpn-alice \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  -v ${PWD}:/etc/ipsec.d \
  pqc-vpn:latest \
  /start-client.sh alice

echo "Alice (PKI with Kyber-1024) connecting..."
```

### 5.3 Start Client Bob (Terminal 3)
```powershell
# In Terminal 3 (Bob)
cd C:\PQC-VPN\demo-setup\client-bob

# Wait 5 seconds
timeout /t 5

# Start Bob's client
docker run -it --rm --name pqc-vpn-bob \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  -v ${PWD}:/etc/ipsec.d \
  pqc-vpn:latest \
  /start-client.sh bob

echo "Bob (PSK with Kyber-768) connecting..."
```

### 5.4 Start Client Charlie (Terminal 4)
```powershell
# In Terminal 4 (Charlie)
cd C:\PQC-VPN\demo-setup\client-charlie

# Wait 5 seconds
timeout /t 5

# Start Charlie's client
docker run -it --rm --name pqc-vpn-charlie \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  -v ${PWD}:/etc/ipsec.d \
  pqc-vpn:latest \
  /start-client.sh charlie

echo "Charlie (Hybrid with Kyber-512) connecting..."
```

## 📊 Step 6: Start Real-Time Dashboard

### 6.1 Open Terminal 5 - Dashboard
```powershell
# New PowerShell window - Terminal 5
cd C:\PQC-VPN
title "PQC-VPN Dashboard"

# Start the corrected dashboard
.\start-dashboard.sh

# Or manually:
cd web
python api_server.py
```

### 6.2 Access Dashboard
- Open browser: `https://localhost:8443`
- Login: `admin` / `pqc-admin-2025`
- You should see real-time data showing:
  - 3 active connections
  - Different PQC algorithms in use
  - Real system metrics

## 🧪 Step 7: Demo Test Scenarios

### 7.1 Connection Verification
```powershell
# In each terminal, verify connections:

# Terminal 1 (Hub) - Check status
docker exec pqc-vpn-hub ipsec status
# Should show: alice-pki[1], bob-psk[2], charlie-hybrid[3] ESTABLISHED

# Terminal 2 (Alice) - Test connectivity  
docker exec pqc-vpn-alice ping 10.10.0.1
docker exec pqc-vpn-alice ping 10.10.1.51  # Bob
docker exec pqc-vpn-alice ping 10.10.1.52  # Charlie

# Terminal 3 (Bob) - Test connectivity
docker exec pqc-vpn-bob ping 10.10.0.1
docker exec pqc-vpn-bob ping 10.10.1.50   # Alice
docker exec pqc-vpn-bob ping 10.10.1.52   # Charlie

# Terminal 4 (Charlie) - Test connectivity
docker exec pqc-vpn-charlie ping 10.10.0.1
docker exec pqc-vpn-charlie ping 10.10.1.50  # Alice
docker exec pqc-vpn-charlie ping 10.10.1.51  # Bob
```

### 7.2 Algorithm Verification
```powershell
# Check which PQC algorithms are in use
# Terminal 1 (Hub)
docker exec pqc-vpn-hub ipsec statusall

# Look for:
# alice-pki: IKE...kyber1024...ESP...kyber1024
# bob-psk: IKE...kyber768...ESP...kyber768  
# charlie-hybrid: IKE...kyber512...ESP...kyber512
```

### 7.3 Dashboard Monitoring
In the dashboard (`https://localhost:8443`):

1. **Active Connections**: Should show 3
2. **PQC Tunnels**: Should show 3
3. **Algorithm Usage**: 
   - Kyber-1024: 1 (Alice)
   - Kyber-768: 1 (Bob) 
   - Kyber-512: 1 (Charlie)
4. **Authentication Types**:
   - PKI: 1 (Alice)
   - PSK: 1 (Bob)
   - Hybrid: 1 (Charlie)

### 7.4 Disconnect/Reconnect Demo
```powershell
# Demonstrate disconnection and reconnection

# Disconnect Alice (Terminal 2)
docker exec pqc-vpn-alice ipsec down hub
# Dashboard should show 2 active connections

# Reconnect Alice
docker exec pqc-vpn-alice ipsec up hub  
# Dashboard should show 3 active connections again

# Try disconnecting from dashboard
# Click disconnect button next to Alice's connection
```

## 🎬 Step 8: Demo Script

### 8.1 Demonstration Flow
```powershell
# Complete demo presentation script

echo "=== PQC-VPN Live Demo ==="
echo "1. Starting Hub Server..."
# Start Terminal 1

echo "2. Connecting Alice with PKI + Kyber-1024..."
# Start Terminal 2, show connection

echo "3. Connecting Bob with PSK + Kyber-768..."  
# Start Terminal 3, show connection

echo "4. Connecting Charlie with Hybrid + Kyber-512..."
# Start Terminal 4, show connection

echo "5. Opening Real-Time Dashboard..."
# Start Terminal 5, show dashboard

echo "6. Demonstrating connectivity..."
# Run ping tests

echo "7. Showing PQC algorithm usage..."
# Show ipsec statusall output

echo "8. Dashboard real-time updates..."
# Refresh dashboard, show live data

echo "9. Connection management..."
# Disconnect/reconnect clients

echo "Demo complete! ✅"
```

## 🔧 Troubleshooting

### Common Issues

1. **Docker Permission Denied**
   ```powershell
   # Run PowerShell as Administrator
   # Enable WSL2 integration in Docker Desktop
   ```

2. **Port Conflicts**
   ```powershell
   # Check if ports 500/4500 are in use
   netstat -an | findstr :500
   netstat -an | findstr :4500
   ```

3. **Connection Failures**
   ```powershell
   # Check logs in each terminal
   # Verify certificates are in correct locations
   # Ensure time synchronization between containers
   ```

4. **Dashboard Not Loading**
   ```powershell
   # Check if Flask is running
   # Verify port 8443 is available
   # Check Python dependencies are installed
   ```

## 📝 Demo Notes

### Key Points to Highlight

1. **Real PQC Algorithms**: Each client uses different Kyber variants
2. **Multiple Auth Methods**: PKI, PSK, and Hybrid authentication  
3. **Live Monitoring**: Dashboard shows real-time connection data
4. **Scalability**: Easy to add more clients with different configurations
5. **Security**: Post-quantum cryptography protects against quantum threats

### Performance Metrics

- **Connection Time**: ~5-10 seconds per client
- **Throughput**: Varies by algorithm (Kyber-1024 > 768 > 512)
- **CPU Usage**: Monitor via dashboard
- **Memory Usage**: Track resource consumption

This complete demo showcases a fully functional PQC-VPN system with real-time monitoring and multiple client configurations! 🚀
