#!/bin/bash

# PQC-VPN Quick Demo Setup - Fixed Version
# Resolves the strongswan/strongswan Docker image issue

set -e

echo "🚀 PQC-VPN Quick Demo Setup"
echo "============================"
echo "Configuration: 1 Server + 3 Clients"
echo "Docker Image: ubuntu:22.04 (no strongswan image needed)"
echo ""

# Check prerequisites
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

echo "✅ Prerequisites check passed"

# Pull the required image first to avoid timeout
echo "📥 Pulling Ubuntu 22.04 image..."
docker pull ubuntu:22.04

# Start the demo using the fixed compose file
echo "🚀 Starting PQC-VPN Demo (1 Server + 3 Clients)..."
docker-compose -f docker-compose.demo.yml up -d

echo ""
echo "⏳ Waiting for services to initialize (this takes 2-3 minutes)..."
sleep 30

# Check service status
echo ""
echo "📊 Service Status:"
docker-compose -f docker-compose.demo.yml ps

echo ""
echo "🎉 Demo Setup Complete!"
echo ""
echo "🌐 Access Points:"
echo "   Hub Web Interface: http://localhost:8443"
echo "   Direct Hub IP:     172.20.0.100"
echo ""
echo "📱 Client Information:"
echo "   Client 1:          172.20.0.101 (pqc-vpn-client1)"
echo "   Client 2:          172.20.0.102 (pqc-vpn-client2)"
echo "   Client 3:          172.20.0.103 (pqc-vpn-client3)"
echo ""
echo "🔍 Useful Commands:"
echo "   Check all status:     docker-compose -f docker-compose.demo.yml ps"
echo "   Check hub status:     docker exec pqc-vpn-hub ipsec status"
echo "   View hub logs:        docker-compose -f docker-compose.demo.yml logs pqc-vpn-hub"
echo "   View client1 logs:    docker-compose -f docker-compose.demo.yml logs pqc-vpn-client1"
echo "   Stop demo:            docker-compose -f docker-compose.demo.yml down"
echo "   Restart demo:         docker-compose -f docker-compose.demo.yml restart"
echo ""
echo "🧪 Test Commands:"
echo "   # Check VPN connections"
echo "   docker exec pqc-vpn-hub ipsec statusall"
echo ""
echo "   # Test ping from client1 to hub"
echo "   docker exec pqc-vpn-client1 ping 172.20.0.100"
echo ""
echo "   # Test ping between clients"
echo "   docker exec pqc-vpn-client1 ping 172.20.0.102"
echo ""
echo "💡 Troubleshooting:"
echo "   If connections fail, wait 1-2 more minutes for full initialization"
echo "   Check logs if issues persist: docker-compose -f docker-compose.demo.yml logs"
echo ""
echo "🔐 Security Configuration:"
echo "   - Encryption: AES-256-GCM + SHA-512"
echo "   - Key Exchange: IKEv2 with ECP-384"
echo "   - Authentication: Pre-shared keys (PSK)"
echo "   - PQC Ready: Prepared for Kyber-1024 + Dilithium-5"
