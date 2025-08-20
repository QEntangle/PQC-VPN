#!/bin/bash

# PQC-VPN Windows Setup Script
# Optimized for Docker Desktop on Windows

echo "🖥️ PQC-VPN Windows Setup"
echo "========================"

# Check if running on Windows (Git Bash/WSL)
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || -n "$WSL_DISTRO_NAME" ]]; then
    echo "✅ Windows environment detected"
    WINDOWS_ENV=true
else
    echo "ℹ️ Non-Windows environment detected"
    WINDOWS_ENV=false
fi

# Check Docker Desktop
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed."
    echo "📥 Please install Docker Desktop for Windows from:"
    echo "    https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe"
    exit 1
fi

# Check if Docker daemon is running
if ! docker info >/dev/null 2>&1; then
    echo "❌ Docker Desktop is not running."
    echo "🔄 Please start Docker Desktop and try again."
    exit 1
fi

echo "✅ Docker Desktop is running"

# Windows-specific Docker settings check
echo "🔧 Checking Windows Docker configuration..."

# Check if WSL 2 backend is available
if [ "$WINDOWS_ENV" = true ]; then
    echo "💡 Windows-specific recommendations:"
    echo "   1. Ensure WSL 2 backend is enabled in Docker Desktop"
    echo "   2. Allocate at least 4GB RAM to Docker in Docker Desktop settings"
    echo "   3. Enable 'Expose daemon on tcp://localhost:2375 without TLS' if needed"
    echo ""
fi

# Pull images first (Windows can be slower)
echo "📥 Pre-pulling Docker images (this may take a few minutes on Windows)..."
docker pull ubuntu:22.04

# Use the full PQC version or simple demo?
echo "🔐 Choose PQC-VPN version:"
echo "1) Simple Demo (ubuntu:22.04 + basic strongSwan) - Quick start"
echo "2) Full PQC Version (OpenSSL 3.3 + OQS + liboqs) - Complete features"
read -p "Enter choice (1 or 2): " choice

if [ "$choice" = "2" ]; then
    echo "🚀 Starting Full PQC-VPN with OpenSSL OQS..."
    
    # Use the production compose file with full PQC
    if [ ! -f "docker/docker-compose.production.yml" ]; then
        echo "❌ Production compose file not found. Using basic demo."
        COMPOSE_FILE="docker-compose.demo.yml"
    else
        COMPOSE_FILE="docker/docker-compose.production.yml"
        echo "✅ Using full PQC implementation with:"
        echo "   - OpenSSL 3.3 with OQS Provider"
        echo "   - liboqs (Kyber-1024, Dilithium-5)"
        echo "   - strongSwan with PQC support"
    fi
else
    echo "🚀 Starting Simple Demo..."
    COMPOSE_FILE="docker-compose.demo.yml"
fi

# Windows-specific networking adjustments
if [ "$WINDOWS_ENV" = true ]; then
    echo "🌐 Applying Windows network optimizations..."
    
    # Create Windows-optimized environment
    cat > .env.windows << 'EOF'
# Windows Docker Desktop optimizations
COMPOSE_CONVERT_WINDOWS_PATHS=1
DOCKER_BUILDKIT=1
COMPOSE_DOCKER_CLI_BUILD=1

# Network settings for Windows
HUB_IP=172.20.0.100
NETWORK_DRIVER=bridge

# Windows-friendly ports (avoiding common conflicts)
WEB_PORT=8443
API_PORT=9090
VPN_PORT_IKE=500
VPN_PORT_NATT=4500

# Performance settings
LOG_LEVEL=INFO
DEBIAN_FRONTEND=noninteractive
EOF
    
    # Use Windows environment
    export COMPOSE_FILE_ENV=".env.windows"
fi

# Start the services
echo "⏳ Starting PQC-VPN services..."
if [ "$WINDOWS_ENV" = true ] && [ -f ".env.windows" ]; then
    docker-compose --env-file .env.windows -f "$COMPOSE_FILE" up -d
else
    docker-compose -f "$COMPOSE_FILE" up -d
fi

# Windows-specific waiting message
if [ "$WINDOWS_ENV" = true ]; then
    echo ""
    echo "⏳ Windows Docker Desktop may take longer to initialize..."
    echo "   Waiting 60 seconds for full startup..."
    sleep 60
else
    echo "⏳ Waiting 30 seconds for services to start..."
    sleep 30
fi

# Check status
echo ""
echo "📊 Service Status:"
docker-compose -f "$COMPOSE_FILE" ps

echo ""
echo "🎉 PQC-VPN Setup Complete!"
echo ""

# Windows-specific access instructions
if [ "$WINDOWS_ENV" = true ]; then
    echo "🌐 Windows Access Points:"
    echo "   Hub Web Interface: http://localhost:8443"
    echo "   (Use 'localhost' not '127.0.0.1' on Windows)"
    echo ""
    echo "🖥️ Windows-Specific Commands:"
    echo "   Check status:    docker-compose -f $COMPOSE_FILE ps"
    echo "   View logs:       docker-compose -f $COMPOSE_FILE logs"
    echo "   Stop services:   docker-compose -f $COMPOSE_FILE down"
    echo ""
    echo "💡 Windows Tips:"
    echo "   - Use Windows Terminal or Git Bash for best experience"
    echo "   - If ports conflict, check Docker Desktop port settings"
    echo "   - Firewall may prompt for Docker network access - allow it"
else
    echo "🌐 Access Points:"
    echo "   Hub Web Interface: http://localhost:8443"
    echo "   Hub IP: 172.20.0.100"
fi

echo ""
echo "🔍 Verification Commands:"
echo "   docker exec -it pqc-vpn-hub ipsec status"
if [ "$choice" = "2" ]; then
    echo "   docker exec -it pqc-vpn-hub openssl list -providers"
    echo "   docker exec -it pqc-vpn-hub openssl list -kem-algorithms"
fi

echo ""
echo "✅ Setup complete! PQC-VPN is ready for Windows."
