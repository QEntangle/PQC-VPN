# 🔧 Docker Image Issue Fix & Quick Demo Guide

## ❌ Issue You Encountered

```bash
# This error occurs when trying to use non-existent strongswan image:
docker: Error response from daemon: pull access denied for strongswan/strongswan, repository does not exist or may require 'docker login'
```

**Root Cause**: The `strongswan/strongswan:latest` Docker image doesn't exist on Docker Hub.

## ✅ Fixed Solution

We've created a **fixed version** that uses `ubuntu:22.04` and installs strongSwan via apt-get, which is more reliable and commonly used.

---

## 🚀 Quick Start (1 Server + 3 Clients)

### Option 1: Automated Setup (Recommended)
```bash
git clone https://github.com/QEntangle/PQC-VPN.git
cd PQC-VPN
chmod +x setup-quick-demo.sh
./setup-quick-demo.sh
```

### Option 2: Manual Setup
```bash
git clone https://github.com/QEntangle/PQC-VPN.git
cd PQC-VPN

# Use the fixed compose file
docker-compose -f docker-compose.demo.yml up -d
```

---

## 📊 Demo Architecture

```
Hub Server (172.20.0.100)
├── Web Interface: http://localhost:8443
├── VPN Server: strongSwan with PQC-ready algorithms
└── Clients:
    ├── Client 1 (172.20.0.101) - PSK Auth
    ├── Client 2 (172.20.0.102) - PSK Auth  
    └── Client 3 (172.20.0.103) - PSK Auth
```

---

## 🔍 Verification Commands

### Check All Services
```bash
docker-compose -f docker-compose.demo.yml ps
```

### Check VPN Status
```bash
# Hub status
docker exec pqc-vpn-hub ipsec status

# Detailed connection info
docker exec pqc-vpn-hub ipsec statusall
```

### Test Connectivity
```bash
# Client 1 to Hub
docker exec pqc-vpn-client1 ping 172.20.0.100

# Client 1 to Client 2
docker exec pqc-vpn-client1 ping 172.20.0.102

# Client 2 to Client 3
docker exec pqc-vpn-client2 ping 172.20.0.103
```

---

## 🔐 Security Configuration

### Current Setup
- **Encryption**: AES-256-GCM + SHA-512
- **Key Exchange**: IKEv2 with ECP-384
- **Authentication**: Pre-shared keys (PSK)
- **Base Image**: Ubuntu 22.04 LTS (more secure and maintained)

### PQC-Ready Features
- **Prepared for**: Kyber-1024 (KEM) + Dilithium-5 (Digital Signatures)
- **Hybrid Mode**: Classical + Post-Quantum algorithms
- **Future-Proof**: Easy transition to full PQC when available

---

## 🛠️ Management Commands

### Start Demo
```bash
docker-compose -f docker-compose.demo.yml up -d
```

### Stop Demo
```bash
docker-compose -f docker-compose.demo.yml down
```

### Restart Services
```bash
docker-compose -f docker-compose.demo.yml restart
```

### View Logs
```bash
# All services
docker-compose -f docker-compose.demo.yml logs

# Specific service
docker-compose -f docker-compose.demo.yml logs pqc-vpn-hub
docker-compose -f docker-compose.demo.yml logs pqc-vpn-client1
```

---

## 🧪 Demo Scenarios

### Scenario 1: Basic Connectivity Test
```bash
# 1. Start demo
./setup-quick-demo.sh

# 2. Wait 2-3 minutes for initialization

# 3. Check all connections established
docker exec pqc-vpn-hub ipsec status
# Should show: client1[1], client2[2], client3[3]: ESTABLISHED

# 4. Test inter-client communication
docker exec pqc-vpn-client1 ping -c 3 172.20.0.102
docker exec pqc-vpn-client2 ping -c 3 172.20.0.103
```

### Scenario 2: Web Dashboard
```bash
# 1. Open browser to: http://localhost:8443
# 2. View real-time hub status
# 3. Monitor connection states
```

### Scenario 3: Secure File Transfer Demo
```bash
# 1. Create test file on client1
docker exec pqc-vpn-client1 bash -c "echo 'Confidential Data via PQC-VPN' > /tmp/secret.txt"

# 2. Transfer to client2 (through encrypted tunnel)
docker exec pqc-vpn-client1 bash -c "python3 -m http.server 8080 --bind 0.0.0.0 --directory /tmp" &

# 3. Download from client2
docker exec pqc-vpn-client2 curl http://172.20.0.101:8080/secret.txt
```

---

## 🆘 Troubleshooting

### Common Issues

1. **Containers not starting**
   ```bash
   # Check Docker daemon
   sudo systemctl status docker
   
   # Pull image manually
   docker pull ubuntu:22.04
   ```

2. **VPN connections not establishing**
   ```bash
   # Check hub logs
   docker exec pqc-vpn-hub journalctl -u strongswan -f
   
   # Restart strongswan
   docker exec pqc-vpn-hub ipsec restart
   ```

3. **Port conflicts**
   ```bash
   # Check what's using ports 500, 4500, 8443
   sudo netstat -tulpn | grep -E ':(500|4500|8443) '
   
   # Stop conflicting services
   sudo systemctl stop strongswan  # if running on host
   ```

### Reset Demo
```bash
# Complete reset
docker-compose -f docker-compose.demo.yml down -v
docker system prune -f
./setup-quick-demo.sh
```

---

## 📈 What's Fixed

### Before (Broken)
- ❌ Used non-existent `strongswan/strongswan:latest` image
- ❌ Complex dependency management
- ❌ Authentication and permission issues

### After (Fixed)
- ✅ Uses stable `ubuntu:22.04` base image
- ✅ Installs strongSwan via official apt packages
- ✅ Simplified configuration and setup
- ✅ Better error handling and logging
- ✅ Documented troubleshooting steps

---

## 🎯 Next Steps

1. **For Development**: Use this demo setup to test PQC algorithms
2. **For Production**: Upgrade to full enterprise version with certificates
3. **For Testing**: Modify PSK keys and add more clients as needed

---

## 📞 Support

If you encounter any issues with this fixed version:

1. Check the troubleshooting section above
2. Review logs: `docker-compose -f docker-compose.demo.yml logs`
3. Verify all prerequisites are installed
4. Ensure ports 500, 4500, and 8443 are available

**The strongswan/strongswan Docker image issue is now resolved! 🎉**
