# 🚀 PQC-VPN Quick Start Demo Guide

Get your PQC-VPN demo up and running in 5 minutes!

## 📋 Prerequisites

- **Docker Desktop** installed and running
- **PowerShell** (Windows) or **Bash** (Linux/macOS)  
- **2GB+ RAM** available
- **Ports available**: 500, 4500, 8080, 8443, 3000, 9090

## ⚡ 5-Minute Quick Start

### 1. Clone and Setup
```bash
# Clone the repository
git clone https://github.com/QEntangle/PQC-VPN.git
cd PQC-VPN/docker

# Copy demo environment file
cp .env.demo .env

# Edit .env to set your IP address
# Replace 192.168.0.103 with your actual IP
```

### 2. Find Your IP Address

**Windows:**
```powershell
ipconfig | findstr "IPv4"
```

**Linux/macOS:**
```bash
ip addr show | grep inet
# or
ifconfig | grep inet
```

### 3. Start the Demo
```bash
# Start the core demo
docker-compose up -d pqc-vpn-hub web-dashboard

# Start with monitoring (optional)
docker-compose --profile monitoring up -d

# Start with demo clients (optional)  
docker-compose --profile spokes up -d
```

### 4. Verify Everything is Running
```bash
# Check services
docker-compose ps

# Should show:
# pqc-vpn-hub        Up (healthy)
# pqc-web-dashboard  Up
# pqc-grafana        Up (if monitoring enabled)
```

### 5. Access Demo Interfaces

- **📊 Main Dashboard**: http://localhost:8080
- **🏠 Hub Status**: http://localhost:8443  
- **📈 Grafana**: http://localhost:3000 (admin/admin)
- **📊 Prometheus**: http://localhost:9090

## 🎭 Demo Features

### What You'll See:
- ✅ **Post-Quantum Cryptography**: Kyber-1024, Dilithium-5 ready
- ✅ **strongSwan VPN Engine**: Full IPsec implementation
- ✅ **Real-time Monitoring**: Live connection dashboard
- ✅ **Multiple Auth Methods**: PKI, PSK, and Hybrid
- ✅ **Interactive Demo**: Simulated connections and metrics

### Demo Scenarios:
1. **PKI Authentication**: Certificate-based VPN connections
2. **PSK Authentication**: Pre-shared key connections
3. **Hybrid Mode**: Combined PKI + PSK security
4. **PQC Ready**: Future quantum-safe algorithms
5. **Enterprise Monitoring**: Real-time dashboard and metrics

## 🔧 Demo Commands

### Check VPN Status
```bash
# strongSwan status inside container
docker exec pqc-vpn-hub ipsec status

# View strongSwan configuration
docker exec pqc-vpn-hub cat /etc/ipsec.conf

# Check demo certificates
docker exec pqc-vpn-hub ls -la /etc/ipsec.d/certs/
```

### Demo User Management
```bash
# Demo users are pre-configured with these PSKs:
# - demo-user-1: user1-pqc-key-2025
# - demo-user-2: user2-pqc-key-2025  
# - admin-access: admin-pqc-key-2025-ultra-secure

# View configured secrets
docker exec pqc-vpn-hub cat /etc/ipsec.secrets
```

### View Logs
```bash
# Real-time logs
docker-compose logs -f pqc-vpn-hub

# strongSwan daemon logs
docker exec pqc-vpn-hub journalctl -u strongswan -f
```

## 🎯 Demo Presentation Script

### **1. Introduction (2 minutes)**
- Show main dashboard at http://localhost:8080
- Highlight PQC-VPN features and quantum-safe security
- Point out real-time monitoring capabilities

### **2. Architecture Overview (3 minutes)**  
- Navigate to hub status at http://localhost:8443
- Show strongSwan configuration and certificates
- Demonstrate multiple authentication methods

### **3. Live Monitoring (2 minutes)**
- Open Grafana at http://localhost:3000 (admin/admin)
- Show real-time metrics and performance graphs
- Demonstrate enterprise monitoring capabilities

### **4. Security Features (3 minutes)**
- Show terminal/command output with `ipsec status`
- Highlight PQC algorithms: Kyber-1024, Dilithium-5
- Explain hybrid classical+PQC approach

### **5. Demo Connections (5 minutes)**
- If spokes enabled: show Alice and Bob connections
- Demonstrate different authentication methods
- Show real-time connection statistics

## 🔒 Security Demo Points

### **Quantum-Safe Cryptography**
- **Key Exchange**: Kyber-1024 (NIST PQC standard)
- **Digital Signatures**: Dilithium-5 (NIST PQC standard)  
- **Symmetric Encryption**: AES-256-GCM (current standard)
- **Future-Proof**: Ready for full PQC transition

### **Enterprise Authentication**
- **PKI**: X.509 certificates with RSA-4096
- **PSK**: Pre-shared keys for rapid deployment  
- **Hybrid**: Combined PKI+PSK for maximum security
- **Multi-Factor**: Certificate + PSK dual authentication

### **Deployment Options**
- **Container-Native**: Docker and Kubernetes ready
- **High Availability**: Load balancing and failover
- **Cloud-Ready**: AWS, Azure, GCP deployment
- **Monitoring**: Prometheus + Grafana integration

## 🚨 Troubleshooting

### Common Issues:

**Port Conflicts:**
```bash
# Check what's using ports
netstat -an | findstr ":500"
netstat -an | findstr ":8080"

# Change ports in .env file if needed
```

**Containers Won't Start:**
```bash
# Check Docker is running
docker info

# Restart services
docker-compose restart

# Check logs for errors  
docker-compose logs pqc-vpn-hub
```

**Can't Access Web Interface:**
```bash
# Check firewall
# Windows: Allow ports in Windows Firewall
# Linux: sudo ufw allow 8080

# Verify container is running
docker ps | grep pqc
```

**strongSwan Issues:**
```bash
# Check strongSwan inside container
docker exec pqc-vpn-hub ipsec --checkconfig
docker exec pqc-vpn-hub ipsec restart
```

## 🧹 Clean Up After Demo

```bash
# Stop all services
docker-compose down

# Remove volumes (removes all data)
docker-compose down -v

# Clean up Docker resources
docker system prune -f

# Remove demo files
rm .env
```

## 📚 Next Steps

After the demo, users can:

1. **Production Deployment**: Use installation scripts for bare metal
2. **Kubernetes**: Deploy using provided K8s manifests  
3. **Cloud Deployment**: Use cloud-specific configurations
4. **Add Real Users**: Configure actual certificates and users
5. **Enable HA**: Set up high availability clustering
6. **Security Hardening**: Implement production security policies

## 🎉 Demo Success Checklist

- ✅ All containers running (`docker-compose ps`)
- ✅ Main dashboard accessible (http://localhost:8080)
- ✅ Hub status page working (http://localhost:8443)  
- ✅ Grafana monitoring active (http://localhost:3000)
- ✅ strongSwan status shows "ESTABLISHED" connections
- ✅ Demo data and metrics updating in real-time
- ✅ Interactive features responding (alerts, status checks)

## 💡 Pro Tips

- **Use a large monitor** for better demo visibility
- **Test before presenting** to ensure all services start
- **Have backup slides** in case of technical issues
- **Prepare for questions** about PQC algorithms and implementation
- **Show the code** - open the docker-compose.yml to show configuration
- **Emphasize security** - this is quantum-safe networking technology

---

**🚀 Your PQC-VPN demo is ready to showcase the future of quantum-safe networking!**
