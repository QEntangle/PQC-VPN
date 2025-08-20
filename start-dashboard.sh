#!/bin/bash
# -*- coding: utf-8 -*-
# PQC-VPN Dashboard Startup Script
# Starts the corrected, real-time dashboard without simulated data

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔐 Starting PQC-VPN Real-Time Dashboard${NC}"
echo "================================================"

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    echo -e "${YELLOW}⚠️  Warning: Running as root. Consider using a dedicated user.${NC}"
fi

# Set working directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEB_DIR="$SCRIPT_DIR/web"

echo -e "${BLUE}📂 Working directory: $WEB_DIR${NC}"

# Check for required files
echo -e "${BLUE}🔍 Checking dashboard files...${NC}"

REQUIRED_FILES=(
    "web/index.html"
    "web/api_server.py"
    "web/real_dashboard.py"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [[ -f "$SCRIPT_DIR/$file" ]]; then
        echo -e "${GREEN}✅ Found: $file${NC}"
    else
        echo -e "${RED}❌ Missing: $file${NC}"
        exit 1
    fi
done

# Check Python dependencies
echo -e "${BLUE}🐍 Checking Python dependencies...${NC}"

REQUIRED_PACKAGES=("flask" "flask-cors" "psutil")

for package in "${REQUIRED_PACKAGES[@]}"; do
    if python3 -c "import $package" 2>/dev/null; then
        echo -e "${GREEN}✅ $package installed${NC}"
    else
        echo -e "${YELLOW}⚠️  Installing $package...${NC}"
        pip3 install "$package" || {
            echo -e "${RED}❌ Failed to install $package${NC}"
            echo -e "${YELLOW}💡 Try: sudo pip3 install $package${NC}"
        }
    fi
done

# Create necessary directories
echo -e "${BLUE}📁 Creating directories...${NC}"
sudo mkdir -p /var/log/pqc-vpn
sudo mkdir -p /opt/pqc-vpn/data

# Set permissions
echo -e "${BLUE}🔐 Setting permissions...${NC}"
sudo chown -R $(whoami) /var/log/pqc-vpn 2>/dev/null || true
sudo chown -R $(whoami) /opt/pqc-vpn/data 2>/dev/null || true

# Choose which dashboard to start
echo ""
echo -e "${YELLOW}🚀 Choose Dashboard Mode:${NC}"
echo "1. API Server (Recommended - Real-time data)"
echo "2. Standalone Dashboard (Flask-based)"
echo "3. Both (API Server + Dashboard)"

read -p "Enter choice [1-3]: " choice

case $choice in
    1)
        echo -e "${GREEN}🚀 Starting API Server...${NC}"
        cd "$WEB_DIR"
        export PYTHONIOENCODING=utf-8
        export ADMIN_PASSWORD="${ADMIN_PASSWORD:-pqc-admin-2025}"
        export API_PORT="${API_PORT:-8443}"
        
        echo -e "${BLUE}📡 Dashboard will be available at:${NC}"
        echo -e "${GREEN}   • https://localhost:8443${NC}"
        echo -e "${GREEN}   • http://localhost:8443${NC}"
        echo ""
        echo -e "${YELLOW}🔑 Admin credentials:${NC}"
        echo -e "${GREEN}   • Username: admin${NC}"
        echo -e "${GREEN}   • Password: $ADMIN_PASSWORD${NC}"
        echo ""
        echo -e "${BLUE}🔄 Starting real-time monitoring...${NC}"
        
        python3 api_server.py
        ;;
    2)
        echo -e "${GREEN}🚀 Starting Standalone Dashboard...${NC}"
        cd "$WEB_DIR"
        export PYTHONIOENCODING=utf-8
        export ADMIN_PASSWORD="${ADMIN_PASSWORD:-pqc-admin-2025}"
        
        echo -e "${BLUE}📡 Dashboard will be available at:${NC}"
        echo -e "${GREEN}   • https://localhost:8443${NC}"
        echo ""
        echo -e "${YELLOW}🔑 Admin credentials:${NC}"
        echo -e "${GREEN}   • Username: admin${NC}"
        echo -e "${GREEN}   • Password: $ADMIN_PASSWORD${NC}"
        echo ""
        
        python3 real_dashboard.py
        ;;
    3)
        echo -e "${GREEN}🚀 Starting Both Services...${NC}"
        cd "$WEB_DIR"
        export PYTHONIOENCODING=utf-8
        export ADMIN_PASSWORD="${ADMIN_PASSWORD:-pqc-admin-2025}"
        
        echo -e "${BLUE}📡 Services will be available at:${NC}"
        echo -e "${GREEN}   • API Server: https://localhost:8443${NC}"
        echo -e "${GREEN}   • Dashboard: https://localhost:8444${NC}"
        echo ""
        
        # Start API server in background
        echo -e "${BLUE}🔄 Starting API Server (background)...${NC}"
        python3 api_server.py &
        API_PID=$!
        
        # Start dashboard on different port
        echo -e "${BLUE}🔄 Starting Dashboard...${NC}"
        export API_PORT=8444
        python3 real_dashboard.py &
        DASHBOARD_PID=$!
        
        # Cleanup function
        cleanup() {
            echo -e "${YELLOW}🛑 Stopping services...${NC}"
            kill $API_PID $DASHBOARD_PID 2>/dev/null || true
            exit 0
        }
        
        trap cleanup INT TERM
        
        echo -e "${GREEN}✅ Both services started successfully!${NC}"
        echo -e "${BLUE}Press Ctrl+C to stop all services${NC}"
        
        wait
        ;;
    *)
        echo -e "${RED}❌ Invalid choice. Exiting.${NC}"
        exit 1
        ;;
esac
