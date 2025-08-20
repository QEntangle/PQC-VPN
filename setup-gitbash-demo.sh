#!/bin/bash
# PQC-VPN Git Bash Demo Setup Script
# Automates the setup of 1 server + 3 clients demo for Git Bash

set -e

# Colors for Git Bash
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

clear
echo -e "${BLUE}🐧 PQC-VPN Git Bash Demo Setup${NC}"
echo "=================================="

# Check if running in Git Bash
if [[ ! "$TERM_PROGRAM" =~ "mintty" ]] && [[ ! "$MSYSTEM" ]]; then
    echo -e "${YELLOW}⚠️  Warning: This script is optimized for Git Bash${NC}"
    echo "For best results, run this in Git Bash terminal"
    echo ""
fi

# Set base directory
BASE_DIR="$(pwd)"
DEMO_DIR="$BASE_DIR/demo-setup"

echo -e "${BLUE}📂 Setting up demo directories...${NC}"
mkdir -p "$DEMO_DIR"/{hub,client-alice,client-bob,client-charlie,logs}

# Check requirements
echo -e "${BLUE}🔍 Checking requirements...${NC}"

# Check Git
if command -v git >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Git found: $(git --version)${NC}"
else
    echo -e "${RED}❌ Git not found${NC}"
    exit 1
fi

# Check Docker
if command -v docker >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Docker found: $(docker --version)${NC}"
    
    # Test Docker with winpty
    if winpty docker ps >/dev/null 2>&1; then
        echo -e "${GREEN}✅ Docker + winpty working${NC}"
    else
        echo -e "${YELLOW}⚠️  Docker requires winpty in Git Bash${NC}"
        echo "Commands will use 'winpty docker' prefix"
    fi
else
    echo -e "${RED}❌ Docker not found${NC}"
    echo "Please install Docker Desktop: https://www.docker.com/products/docker-desktop"
    exit 1
fi

# Check Python
if command -v python >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Python found: $(python --version)${NC}"
elif command -v python3 >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Python3 found: $(python3 --version)${NC}"
    alias python=python3
else
    echo -e "${RED}❌ Python not found${NC}"
    echo "Please install Python 3.8+: https://www.python.org/downloads/"
    exit 1
fi

# Install Python dependencies
echo -e "${BLUE}📦 Installing Python dependencies...${NC}"
if pip install flask flask-cors psutil pyyaml >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Python packages installed${NC}"
else
    echo -e "${YELLOW}⚠️  Warning: Some packages may have failed to install${NC}"
fi

# Generate demo configurations
echo -e "${BLUE}⚙️  Generating demo configurations...${NC}"

# Hub configuration
echo -e "${CYAN}Creating hub configuration...${NC}"
cat > "$DEMO_DIR/hub/ipsec.conf" << 'EOF'
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

# Hub secrets
cat > "$DEMO_DIR/hub/ipsec.secrets" << 'EOF'
# Hub secrets for demo
: RSA hub-key.pem
bob : PSK "demo-psk-key-bob-2025"
charlie : PSK "demo-psk-key-charlie-2025"
EOF

# Alice configuration (PKI)
echo -e "${CYAN}Creating Alice (PKI) configuration...${NC}"
cat > "$DEMO_DIR/client-alice/ipsec.conf" << 'EOF'
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

echo ": RSA alice-key.pem" > "$DEMO_DIR/client-alice/ipsec.secrets"

# Bob configuration (PSK)
echo -e "${CYAN}Creating Bob (PSK) configuration...${NC}"
cat > "$DEMO_DIR/client-bob/ipsec.conf" << 'EOF'
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

echo 'bob hub : PSK "demo-psk-key-bob-2025"' > "$DEMO_DIR/client-bob/ipsec.secrets"

# Charlie configuration (Hybrid)
echo -e "${CYAN}Creating Charlie (Hybrid) configuration...${NC}"
cat > "$DEMO_DIR/client-charlie/ipsec.conf" << 'EOF'
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

cat > "$DEMO_DIR/client-charlie/ipsec.secrets" << 'EOF'
: RSA charlie-key.pem
charlie hub : PSK "demo-psk-key-charlie-2025"
EOF

# Create startup scripts
echo -e "${BLUE}📝 Creating Git Bash startup scripts...${NC}"

# Hub launcher
cat > "$DEMO_DIR/start-hub.sh" << 'EOF'
#!/bin/bash
echo -e "\033[0;34m🔐 Starting PQC-VPN Hub Server...\033[0m"
echo "=================================="
echo ""
echo -e "\033[0;32mHub Configuration:\033[0m"
echo "  • Network: 10.10.0.0/16"
echo "  • Algorithms: Kyber-1024, Kyber-768, Kyber-512"
echo "  • Auth: PKI + PSK + Hybrid"
echo ""

cd "$(dirname "$0")/hub"

# Convert Windows path to Unix-style for Docker
WIN_PATH=$(pwd -W 2>/dev/null || pwd)
UNIX_PATH="/$(echo $WIN_PATH | sed 's/://' | sed 's/\\/\//g')"

echo "Starting Docker container with path: $UNIX_PATH"
winpty docker run -it --rm --name pqc-vpn-hub \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  -v "$UNIX_PATH":/etc/ipsec.d \
  -p 500:500/udp \
  -p 4500:4500/udp \
  strongswan/strongswan:latest \
  /bin/bash -c "ipsec start --nofork"
EOF

# Alice launcher
cat > "$DEMO_DIR/start-alice.sh" << 'EOF'
#!/bin/bash
echo -e "\033[0;34m👩 Starting Alice - PKI Authentication with Kyber-1024...\033[0m"
echo "======================================================="
echo ""
echo -e "\033[0;32mAlice Configuration:\033[0m"
echo "  • IP: 10.10.1.50"
echo "  • Auth: PKI (Certificate-based)"
echo "  • Algorithm: Kyber-1024"
echo ""

# Wait for hub to be ready
echo "Waiting 15 seconds for hub to initialize..."
for i in {15..1}; do
    echo -ne "\rStarting in $i seconds... "
    sleep 1
done
echo ""

cd "$(dirname "$0")/client-alice"
WIN_PATH=$(pwd -W 2>/dev/null || pwd)
UNIX_PATH="/$(echo $WIN_PATH | sed 's/://' | sed 's/\\/\//g')"

echo "Connecting to hub..."
winpty docker run -it --rm --name pqc-vpn-alice \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  -v "$UNIX_PATH":/etc/ipsec.d \
  strongswan/strongswan:latest \
  /bin/bash -c "ipsec start --nofork"
EOF

# Bob launcher
cat > "$DEMO_DIR/start-bob.sh" << 'EOF'
#!/bin/bash
echo -e "\033[0;34m👨 Starting Bob - PSK Authentication with Kyber-768...\033[0m"
echo "===================================================="
echo ""
echo -e "\033[0;32mBob Configuration:\033[0m"
echo "  • IP: 10.10.1.51"
echo "  • Auth: PSK (Pre-shared Key)"
echo "  • Algorithm: Kyber-768"
echo ""

echo "Waiting 20 seconds for hub to initialize..."
for i in {20..1}; do
    echo -ne "\rStarting in $i seconds... "
    sleep 1
done
echo ""

cd "$(dirname "$0")/client-bob"
WIN_PATH=$(pwd -W 2>/dev/null || pwd)
UNIX_PATH="/$(echo $WIN_PATH | sed 's/://' | sed 's/\\/\//g')"

echo "Connecting to hub..."
winpty docker run -it --rm --name pqc-vpn-bob \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  -v "$UNIX_PATH":/etc/ipsec.d \
  strongswan/strongswan:latest \
  /bin/bash -c "ipsec start --nofork"
EOF

# Charlie launcher
cat > "$DEMO_DIR/start-charlie.sh" << 'EOF'
#!/bin/bash
echo -e "\033[0;34m🧑 Starting Charlie - Hybrid Authentication with Kyber-512...\033[0m"
echo "==========================================================="
echo ""
echo -e "\033[0;32mCharlie Configuration:\033[0m"
echo "  • IP: 10.10.1.52"
echo "  • Auth: Hybrid (PKI + PSK)"
echo "  • Algorithm: Kyber-512"
echo ""

echo "Waiting 25 seconds for hub to initialize..."
for i in {25..1}; do
    echo -ne "\rStarting in $i seconds... "
    sleep 1
done
echo ""

cd "$(dirname "$0")/client-charlie"
WIN_PATH=$(pwd -W 2>/dev/null || pwd)
UNIX_PATH="/$(echo $WIN_PATH | sed 's/://' | sed 's/\\/\//g')"

echo "Connecting to hub..."
winpty docker run -it --rm --name pqc-vpn-charlie \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  -v "$UNIX_PATH":/etc/ipsec.d \
  strongswan/strongswan:latest \
  /bin/bash -c "ipsec start --nofork"
EOF

# Dashboard launcher
cat > "$DEMO_DIR/start-dashboard.sh" << 'EOF'
#!/bin/bash
echo -e "\033[0;34m📊 Starting PQC-VPN Real-Time Dashboard...\033[0m"
echo "=========================================="
echo ""
echo -e "\033[0;32mDashboard Features:\033[0m"
echo "  • Real-time connection monitoring"
echo "  • Live system metrics"
echo "  • PQC algorithm usage tracking"
echo "  • Interactive user management"
echo ""
echo -e "\033[1;33mDashboard Access:\033[0m"
echo "  • URL: https://localhost:8443"
echo "  • Username: admin"
echo "  • Password: pqc-admin-2025"
echo ""

sleep 5

# Navigate to web directory
cd "$(dirname "$0")/../web"
export PYTHONIOENCODING=utf-8
export ADMIN_PASSWORD="${ADMIN_PASSWORD:-pqc-admin-2025}"
export API_PORT="${API_PORT:-8443}"

echo "Starting dashboard server..."
python api_server.py
EOF

# Main demo runner
cat > "$DEMO_DIR/run-demo.sh" << 'EOF'
#!/bin/bash

# Colors for Git Bash
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

show_menu() {
    clear
    echo -e "${BLUE}🐧 PQC-VPN Git Bash Demo Launcher${NC}"
    echo "=================================="
    echo ""
    echo "Select component to start:"
    echo ""
    echo -e "${GREEN}1)${NC} Hub Server ${CYAN}(start first)${NC}"
    echo -e "${GREEN}2)${NC} Alice Client ${CYAN}(PKI + Kyber-1024)${NC}"
    echo -e "${GREEN}3)${NC} Bob Client ${CYAN}(PSK + Kyber-768)${NC}"
    echo -e "${GREEN}4)${NC} Charlie Client ${CYAN}(Hybrid + Kyber-512)${NC}"
    echo -e "${GREEN}5)${NC} Dashboard ${CYAN}(Real-time monitoring)${NC}"
    echo -e "${GREEN}6)${NC} Start All ${CYAN}(automatic sequence)${NC}"
    echo -e "${GREEN}7)${NC} Test Connections"
    echo -e "${GREEN}8)${NC} View Logs"
    echo -e "${GREEN}9)${NC} Stop All Containers"
    echo -e "${GREEN}0)${NC} Exit"
    echo ""
}

start_component() {
    case $1 in
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
            start_all_sequence
            ;;
        7)
            test_connections
            ;;
        8)
            view_logs
            ;;
        9)
            stop_all_containers
            ;;
        0)
            echo -e "${GREEN}Goodbye!${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid choice. Please try again.${NC}"
            sleep 2
            ;;
    esac
}

start_all_sequence() {
    echo -e "${GREEN}🚀 Starting complete demo sequence...${NC}"
    echo ""
    
    echo "Step 1: Starting Hub Server..."
    echo "Opening new Git Bash window for Hub..."
    (cd "$(dirname "$0")" && winpty bash -c "./start-hub.sh") &
    sleep 5
    
    echo "Step 2: Starting Dashboard..."
    echo "Opening new Git Bash window for Dashboard..."
    (cd "$(dirname "$0")" && winpty bash -c "./start-dashboard.sh") &
    sleep 3
    
    echo "Step 3: Starting Alice..."
    echo "Opening new Git Bash window for Alice..."
    (cd "$(dirname "$0")" && winpty bash -c "./start-alice.sh") &
    sleep 2
    
    echo "Step 4: Starting Bob..."
    echo "Opening new Git Bash window for Bob..."
    (cd "$(dirname "$0")" && winpty bash -c "./start-bob.sh") &
    sleep 2
    
    echo "Step 5: Starting Charlie..."
    echo "Opening new Git Bash window for Charlie..."
    (cd "$(dirname "$0")" && winpty bash -c "./start-charlie.sh") &
    
    echo ""
    echo -e "${GREEN}✅ All components starting in separate windows!${NC}"
    echo ""
    echo -e "${YELLOW}📊 Access Dashboard: https://localhost:8443${NC}"
    echo -e "${YELLOW}🔑 Login: admin / pqc-admin-2025${NC}"
    echo ""
    echo -e "${CYAN}Note: Each component opens in a new Git Bash window${NC}"
    echo "Press Enter to return to menu..."
    read
}

test_connections() {
    echo -e "${BLUE}Testing Connections...${NC}"
    echo ""
    
    echo "=== Docker Containers ==="
    winpty docker ps --filter "name=pqc-vpn" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
    echo ""
    
    echo "=== Hub Status ==="
    if winpty docker exec pqc-vpn-hub ipsec status 2>/dev/null; then
        echo ""
    else
        echo "Hub not running or not accessible"
    fi
    
    echo "=== Testing Connectivity ==="
    echo "Testing Alice -> Hub:"
    if winpty docker exec pqc-vpn-alice ping -c 3 10.10.0.1 2>/dev/null; then
        echo "Alice connectivity: OK"
    else
        echo "Alice connectivity: FAILED"
    fi
    
    echo ""
    echo "Testing Bob -> Hub:"
    if winpty docker exec pqc-vpn-bob ping -c 3 10.10.0.1 2>/dev/null; then
        echo "Bob connectivity: OK"
    else
        echo "Bob connectivity: FAILED"
    fi
    
    echo ""
    echo "Testing Charlie -> Hub:"
    if winpty docker exec pqc-vpn-charlie ping -c 3 10.10.0.1 2>/dev/null; then
        echo "Charlie connectivity: OK"
    else
        echo "Charlie connectivity: FAILED"
    fi
    
    echo ""
    echo "Press Enter to return to menu..."
    read
}

view_logs() {
    echo -e "${BLUE}Viewing Container Logs...${NC}"
    echo ""
    
    containers=("pqc-vpn-hub" "pqc-vpn-alice" "pqc-vpn-bob" "pqc-vpn-charlie")
    
    for container in "${containers[@]}"; do
        echo "=== $container Logs ==="
        if winpty docker logs "$container" 2>/dev/null | tail -10; then
            echo ""
        else
            echo "$container: Not running or no logs"
            echo ""
        fi
    done
    
    echo "Press Enter to return to menu..."
    read
}

stop_all_containers() {
    echo -e "${YELLOW}🛑 Stopping all PQC-VPN containers...${NC}"
    
    containers=("pqc-vpn-hub" "pqc-vpn-alice" "pqc-vpn-bob" "pqc-vpn-charlie")
    
    for container in "${containers[@]}"; do
        if winpty docker stop "$container" 2>/dev/null; then
            echo -e "${GREEN}✅ Stopped $container${NC}"
        else
            echo -e "${YELLOW}⚠️  $container not running${NC}"
        fi
    done
    
    echo ""
    echo "All containers stopped. Press Enter to return to menu..."
    read
}

# Main loop
while true; do
    show_menu
    read -p "Enter choice [0-9]: " choice
    echo ""
    start_component "$choice"
done
EOF

# Make all scripts executable
chmod +x "$DEMO_DIR"/*.sh

# Create README
cat > "$DEMO_DIR/README.md" << 'EOF'
# PQC-VPN Git Bash Demo

This directory contains a complete demo setup for PQC-VPN using Git Bash on Windows.

## Components
- **Hub Server**: Central VPN server (10.10.0.1)
- **Alice**: PKI authentication with Kyber-1024 (10.10.1.50)
- **Bob**: PSK authentication with Kyber-768 (10.10.1.51)
- **Charlie**: Hybrid authentication with Kyber-512 (10.10.1.52)
- **Dashboard**: Real-time monitoring interface

## Quick Start
1. Open Git Bash in this directory
2. Run: `./run-demo.sh`
3. Choose option 6 to start all components automatically
4. Access dashboard at: https://localhost:8443
5. Login with: admin / pqc-admin-2025

## Manual Start
- `./start-hub.sh` - Start hub server first
- `./start-alice.sh` - Start Alice client
- `./start-bob.sh` - Start Bob client  
- `./start-charlie.sh` - Start Charlie client
- `./start-dashboard.sh` - Start monitoring dashboard

## Git Bash Specific Notes
- All Docker commands use `winpty` prefix for proper interaction
- Scripts handle Windows to Unix path conversion automatically
- Color output is supported in Git Bash terminal
- Tab completion works for easier navigation

## Testing
Once all components are running:
- Dashboard shows 3 active connections
- Different PQC algorithms in use (Kyber-1024, 768, 512)
- Real-time system metrics
- Interactive connection management

## Troubleshooting
- Ensure Docker Desktop is running
- Check that ports 500, 4500, 8443 are available
- Verify Git Bash has proper permissions
- Use `winpty docker ps` to check container status
EOF

echo ""
echo -e "${GREEN}✅ Git Bash demo setup complete!${NC}"
echo ""
echo -e "${YELLOW}📁 Demo files created in: $DEMO_DIR${NC}"
echo ""
echo -e "${BLUE}🚀 To start the demo:${NC}"
echo "   cd $DEMO_DIR"
echo "   ./run-demo.sh"
echo ""
echo -e "${BLUE}📊 Dashboard access:${NC}"
echo "   • URL: https://localhost:8443"
echo "   • Login: admin / pqc-admin-2025"
echo ""

# Ask if user wants to start demo now
echo -n "Start demo now? (y/N): "
read -r start_now
if [[ "$start_now" =~ ^[Yy]$ ]]; then
    cd "$DEMO_DIR"
    ./run-demo.sh
fi

echo ""
echo -e "${GREEN}Git Bash demo setup completed successfully!${NC}"
echo "Happy quantum-safe networking! 🐧🔐"
