# 🐧 PQC-VPN Git Bash Demo Guide
## 1 Server + 3 Clients Setup for Git Bash on Windows

This guide provides a complete step-by-step process using **Git Bash** to demonstrate PQC-VPN with one server (hub) and three clients (spokes) on Windows.

## 🎯 Demo Overview

- **Hub Server**: 1 instance (Git Bash Terminal 1)
- **Client 1 (Alice)**: Kyber-1024 + PKI auth (Git Bash Terminal 2)
- **Client 2 (Bob)**: Kyber-768 + PSK auth (Git Bash Terminal 3)
- **Client 3 (Charlie)**: Kyber-512 + Hybrid auth (Git Bash Terminal 4)
- **Dashboard**: Real-time monitoring (Git Bash Terminal 5)

## 📋 Prerequisites

### Required Software
- **Git for Windows** (includes Git Bash)
- **Docker Desktop** for Windows
- **Python 3.8+** 
- **Windows 10/11**

### Check Prerequisites in Git Bash
```bash
# Open Git Bash and verify installations
git --version
docker --version
python --version
winpty docker ps  # Test Docker with winpty
```

## 🚀 Step 1: Initial Setup in Git Bash

### 1.1 Clone Repository
```bash
# Open Git Bash
cd /c/
git clone https://github.com/QEntangle/PQC-VPN.git
cd PQC-VPN

# Create demo directories
mkdir -p demo-setup/{hub,client-alice,client-bob,client-charlie,logs}
```

### 1.2 Install Python Dependencies
```bash
# Install required packages
pip install flask flask-cors psutil pyyaml

# Verify installation
python -c "import flask, psutil; print('Dependencies OK')"
```

## 🏗️ Step 2: Generate Configurations

### 2.1 Create Hub Configuration
```bash
# Create hub ipsec.conf
cat > demo-setup/hub/ipsec.conf << 'EOF'
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
EOF

# Create hub secrets
cat > demo-setup/hub/ipsec.secrets << 'EOF'
# Hub secrets for demo
: RSA hub-key.pem
bob : PSK "demo-psk-key-bob-2025"
charlie : PSK "demo-psk-key-charlie-2025"
EOF
```

### 2.2 Create Client Configurations
```bash
# Alice configuration (PKI)
cat > demo-setup/client-alice/ipsec.conf << 'EOF'
config setup
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
    rightcert=hub-cert.pem
EOF

echo ": RSA alice-key.pem" > demo-setup/client-alice/ipsec.secrets

# Bob configuration (PSK)
cat > demo-setup/client-bob/ipsec.conf << 'EOF'
config setup
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

conn hub
EOF

echo 'bob hub : PSK "demo-psk-key-bob-2025"' > demo-setup/client-bob/ipsec.secrets

# Charlie configuration (Hybrid)
cat > demo-setup/client-charlie/ipsec.conf << 'EOF'
config setup
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
    rightcert=hub-cert.pem
EOF

cat > demo-setup/client-charlie/ipsec.secrets << 'EOF'
: RSA charlie-key.pem
charlie hub : PSK "demo-psk-key-charlie-2025"
EOF
```

## 🚀 Step 3: Create Git Bash Launcher Scripts

### 3.1 Hub Server Script
```bash
# Create hub startup script
cat > demo-setup/start-hub.sh << 'EOF'
#!/bin/bash
echo "🔐 Starting PQC-VPN Hub Server..."
echo "=================================="
echo ""
echo "Hub Configuration:"
echo "  • Network: 10.10.0.0/16"
echo "  • Algorithms: Kyber-1024, Kyber-768, Kyber-512"
echo "  • Auth: PKI + PSK + Hybrid"
echo ""

cd "$(dirname "$0")/hub"

# Convert Windows path to Unix-style for Docker
WIN_PATH=$(pwd -W)
UNIX_PATH="/$(echo $WIN_PATH | sed 's/://' | sed 's/\\/\//g')"

echo "Starting Docker container..."
winpty docker run -it --rm --name pqc-vpn-hub \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  -v "$UNIX_PATH":/etc/ipsec.d \
  -p 500:500/udp \
  -p 4500:4500/udp \
  strongswan/strongswan:latest \
  /bin/bash -c "ipsec start --nofork"
EOF

chmod +x demo-setup/start-hub.sh
```

### 3.2 Client Scripts
```bash
# Alice startup script
cat > demo-setup/start-alice.sh << 'EOF'
#!/bin/bash
echo "👩 Starting Alice - PKI Authentication with Kyber-1024..."
echo "======================================================="
echo ""
echo "Alice Configuration:"
echo "  • IP: 10.10.1.50"
echo "  • Auth: PKI (Certificate-based)"
echo "  • Algorithm: Kyber-1024"
echo ""

# Wait for hub to be ready
echo "Waiting 15 seconds for hub to initialize..."
sleep 15

cd "$(dirname "$0")/client-alice"
WIN_PATH=$(pwd -W)
UNIX_PATH="/$(echo $WIN_PATH | sed 's/://' | sed 's/\\/\//g')"

echo "Connecting to hub..."
winpty docker run -it --rm --name pqc-vpn-alice \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  -v "$UNIX_PATH":/etc/ipsec.d \
  strongswan/strongswan:latest \
  /bin/bash -c "ipsec start --nofork"
EOF

chmod +x demo-setup/start-alice.sh

# Bob startup script
cat > demo-setup/start-bob.sh << 'EOF'
#!/bin/bash
echo "👨 Starting Bob - PSK Authentication with Kyber-768..."
echo "===================================================="
echo ""
echo "Bob Configuration:"
echo "  • IP: 10.10.1.51"
echo "  • Auth: PSK (Pre-shared Key)"
echo "  • Algorithm: Kyber-768"
echo ""

echo "Waiting 20 seconds for hub to initialize..."
sleep 20

cd "$(dirname "$0")/client-bob"
WIN_PATH=$(pwd -W)
UNIX_PATH="/$(echo $WIN_PATH | sed 's/://' | sed 's/\\/\//g')"

echo "Connecting to hub..."
winpty docker run -it --rm --name pqc-vpn-bob \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  -v "$UNIX_PATH":/etc/ipsec.d \
  strongswan/strongswan:latest \
  /bin/bash -c "ipsec start --nofork"
EOF

chmod +x demo-setup/start-bob.sh

# Charlie startup script
cat > demo-setup/start-charlie.sh << 'EOF'
#!/bin/bash
echo "🧑 Starting Charlie - Hybrid Authentication with Kyber-512..."
echo "==========================================================="
echo ""
echo "Charlie Configuration:"
echo "  • IP: 10.10.1.52"
echo "  • Auth: Hybrid (PKI + PSK)"
echo "  • Algorithm: Kyber-512"
echo ""

echo "Waiting 25 seconds for hub to initialize..."
sleep 25

cd "$(dirname "$0")/client-charlie"
WIN_PATH=$(pwd -W)
UNIX_PATH="/$(echo $WIN_PATH | sed 's/://' | sed 's/\\/\//g')"

echo "Connecting to hub..."
winpty docker run -it --rm --name pqc-vpn-charlie \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  -v "$UNIX_PATH":/etc/ipsec.d \
  strongswan/strongswan:latest \
  /bin/bash -c "ipsec start --nofork"
EOF

chmod +x demo-setup/start-charlie.sh
```

### 3.3 Dashboard Script
```bash
# Dashboard startup script
cat > demo-setup/start-dashboard.sh << 'EOF'
#!/bin/bash
echo "📊 Starting PQC-VPN Real-Time Dashboard..."
echo "=========================================="
echo ""
echo "Dashboard Features:"
echo "  • Real-time connection monitoring"
echo "  • Live system metrics"
echo "  • PQC algorithm usage tracking"
echo "  • Interactive user management"
echo ""
echo "Dashboard Access:"
echo "  • URL: https://localhost:8443"
echo "  • Username: admin"
echo "  • Password: pqc-admin-2025"
echo ""

sleep 5

cd ../web
export PYTHONIOENCODING=utf-8
export ADMIN_PASSWORD="${ADMIN_PASSWORD:-pqc-admin-2025}"
export API_PORT="${API_PORT:-8443}"

echo "Starting dashboard server..."
python api_server.py
EOF

chmod +x demo-setup/start-dashboard.sh
```

### 3.4 Main Demo Launcher
```bash
# Create main demo menu
cat > demo-setup/run-demo.sh << 'EOF'
#!/bin/bash

# Colors for Git Bash
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

clear
echo -e "${BLUE}🔐 PQC-VPN Git Bash Demo Launcher${NC}"
echo "=================================="
echo ""
echo "Select component to start:"
echo ""
echo -e "${GREEN}1)${NC} Hub Server (start first)"
echo -e "${GREEN}2)${NC} Alice Client (PKI + Kyber-1024)"
echo -e "${GREEN}3)${NC} Bob Client (PSK + Kyber-768)"
echo -e "${GREEN}4)${NC} Charlie Client (Hybrid + Kyber-512)"
echo -e "${GREEN}5)${NC} Dashboard (Real-time monitoring)"
echo -e "${GREEN}6)${NC} Start All (automatic sequence)"
echo -e "${GREEN}7)${NC} Test Connections"
echo -e "${GREEN}8)${NC} View Logs"
echo -e "${GREEN}9)${NC} Exit"
echo ""

read -p "Enter choice [1-9]: " choice
echo ""

case $choice in
    1)
        echo -e "${BLUE}Starting Hub Server...${NC}"
        ./start-hub.sh
        ;;
    2)
        echo -e "${BLUE}Starting Alice Client...${NC}"
        ./start-alice.sh
        ;;
    3)
        echo -e "${BLUE}Starting Bob Client...${NC}"
        ./start-bob.sh
        ;;
    4)
        echo -e "${BLUE}Starting Charlie Client...${NC}"
        ./start-charlie.sh
        ;;
    5)
        echo -e "${BLUE}Starting Dashboard...${NC}"
        ./start-dashboard.sh
        ;;
    6)
        echo -e "${GREEN}🚀 Starting complete demo sequence...${NC}"
        echo ""
        
        echo "1. Starting Hub Server..."
        (./start-hub.sh) &
        HUB_PID=$!
        sleep 5
        
        echo "2. Starting Dashboard..."
        (./start-dashboard.sh) &
        DASH_PID=$!
        sleep 3
        
        echo "3. Starting Alice..."
        (./start-alice.sh) &
        ALICE_PID=$!
        sleep 3
        
        echo "4. Starting Bob..."
        (./start-bob.sh) &
        BOB_PID=$!
        sleep 3
        
        echo "5. Starting Charlie..."
        (./start-charlie.sh) &
        CHARLIE_PID=$!
        
        echo ""
        echo -e "${GREEN}✅ All components started!${NC}"
        echo ""
        echo -e "${YELLOW}📊 Access Dashboard: https://localhost:8443${NC}"
        echo -e "${YELLOW}🔑 Login: admin / pqc-admin-2025${NC}"
        echo ""
        echo "Press Ctrl+C to stop all services"
        
        # Cleanup function
        cleanup() {
            echo -e "\n${YELLOW}🛑 Stopping services...${NC}"
            kill $HUB_PID $DASH_PID $ALICE_PID $BOB_PID $CHARLIE_PID 2>/dev/null
            winpty docker stop pqc-vpn-hub pqc-vpn-alice pqc-vpn-bob pqc-vpn-charlie 2>/dev/null
            exit 0
        }
        
        trap cleanup INT TERM
        wait
        ;;
    7)
        echo -e "${BLUE}Testing Connections...${NC}"
        echo ""
        echo "Hub Status:"
        winpty docker exec pqc-vpn-hub ipsec status
        echo ""
        echo "Testing Alice connectivity:"
        winpty docker exec pqc-vpn-alice ping -c 3 10.10.0.1
        echo ""
        echo "Testing Bob connectivity:"
        winpty docker exec pqc-vpn-bob ping -c 3 10.10.0.1
        echo ""
        echo "Testing Charlie connectivity:"
        winpty docker exec pqc-vpn-charlie ping -c 3 10.10.0.1
        read -p "Press Enter to continue..."
        ;;
    8)
        echo -e "${BLUE}Viewing Container Logs...${NC}"
        echo ""
        echo "=== Hub Logs ==="
        winpty docker logs pqc-vpn-hub | tail -20
        echo ""
        echo "=== Alice Logs ==="
        winpty docker logs pqc-vpn-alice | tail -20
        echo ""
        echo "=== Bob Logs ==="
        winpty docker logs pqc-vpn-bob | tail -20
        echo ""
        echo "=== Charlie Logs ==="
        winpty docker logs pqc-vpn-charlie | tail -20
        read -p "Press Enter to continue..."
        ;;
    9)
        echo -e "${GREEN}Goodbye!${NC}"
        exit 0
        ;;
    *)
        echo -e "${RED}Invalid choice. Please try again.${NC}"
        sleep 2
        exec $0
        ;;
esac
EOF

chmod +x demo-setup/run-demo.sh
```

## 🎬 Step 4: Running the Demo in Git Bash

### 4.1 Open Multiple Git Bash Terminals

#### Method 1: Manual Terminal Opening
```bash
# Terminal 1 - Hub Server
cd /c/PQC-VPN/demo-setup
./run-demo.sh
# Choose option 1

# Terminal 2 - Alice Client (new Git Bash window)
cd /c/PQC-VPN/demo-setup  
./run-demo.sh
# Choose option 2

# Terminal 3 - Bob Client (new Git Bash window)
cd /c/PQC-VPN/demo-setup
./run-demo.sh
# Choose option 3

# Terminal 4 - Charlie Client (new Git Bash window)
cd /c/PQC-VPN/demo-setup
./run-demo.sh
# Choose option 4

# Terminal 5 - Dashboard (new Git Bash window)
cd /c/PQC-VPN/demo-setup
./run-demo.sh
# Choose option 5
```

#### Method 2: Automatic All-in-One
```bash
# Single terminal - starts all components
cd /c/PQC-VPN/demo-setup
./run-demo.sh
# Choose option 6 (Start All)
```

### 4.2 Testing in Git Bash
```bash
# Check Docker containers
winpty docker ps

# Test connections
winpty docker exec pqc-vpn-hub ipsec status

# Check algorithms in use
winpty docker exec pqc-vpn-hub ipsec statusall

# Test inter-client connectivity
winpty docker exec pqc-vpn-alice ping -c 3 10.10.1.51  # Ping Bob
winpty docker exec pqc-vpn-bob ping -c 3 10.10.1.52    # Ping Charlie
```

## 🔧 Git Bash Specific Tips

### 4.1 Docker Commands in Git Bash
```bash
# Always use winpty for interactive Docker commands
winpty docker run -it ...
winpty docker exec -it ...

# For non-interactive commands, winpty is optional
docker ps
docker logs container_name
```

### 4.2 Path Conversion
```bash
# Git Bash automatically converts paths, but for Docker volumes:
# Current directory in Windows format
WIN_PATH=$(pwd -W)
# Convert to Unix format for Docker
UNIX_PATH="/$(echo $WIN_PATH | sed 's/://' | sed 's/\\/\//g')"
```

### 4.3 Script Permissions
```bash
# Make scripts executable
chmod +x demo-setup/*.sh

# Check permissions
ls -la demo-setup/*.sh
```

## 📊 Expected Results

After running the demo, you should see:

### Dashboard (https://localhost:8443)
- **Active Connections**: 3
- **PQC Tunnels**: 3
- **Algorithms**: Kyber-1024, Kyber-768, Kyber-512
- **Auth Types**: PKI, PSK, Hybrid

### Git Bash Terminal Output
```bash
# Hub terminal shows
Security Associations (1 up, 0 connecting):
alice-pki[1]: ESTABLISHED 10 seconds ago
bob-psk[2]: ESTABLISHED 5 seconds ago  
charlie-hybrid[3]: ESTABLISHED 2 seconds ago

# Each client terminal shows
connection 'hub' established successfully
```

## 🛠️ Troubleshooting Git Bash Issues

### Common Git Bash Problems

1. **winpty Issues**
   ```bash
   # If winpty fails, try:
   alias docker='winpty docker'
   ```

2. **Path Problems**
   ```bash
   # Check current path format
   pwd      # Unix style: /c/PQC-VPN
   pwd -W   # Windows style: C:\PQC-VPN
   ```

3. **Permission Denied**
   ```bash
   # Fix script permissions
   chmod +x demo-setup/*.sh
   ```

4. **Docker Volume Mount Issues**
   ```bash
   # Verify path conversion
   echo "Windows: $(pwd -W)"
   echo "Unix: /$(echo $(pwd -W) | sed 's/://' | sed 's/\\/\//g')"
   ```

## 🎯 Git Bash Demo Advantages

- **Unix-like environment** on Windows
- **Better script support** than Windows CMD
- **Familiar commands** for Linux users
- **Integrated with Git** for version control
- **Color support** for better visualization
- **Tab completion** for easier navigation

Your PQC-VPN demo is now fully configured for Git Bash! 🐧🔐
EOF