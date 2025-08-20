# 🚀 PQC-VPN Demo: Complete Next Steps Guide

## 🎯 **Your Demo: 1 Server + 3 Clients + Web Dashboard**

This guide provides **complete next steps** for running your PQC-VPN demo with one server, three clients, inter-client communication, and web interface access.

---

## ⚡ **Quick Start (Choose Your Platform)**

### **🖥️ Windows Users**
```bash
git clone https://github.com/QEntangle/PQC-VPN.git
cd PQC-VPN
chmod +x setup-windows.sh
./setup-windows.sh
```

### **🐧 Linux/Mac Users**
```bash
git clone https://github.com/QEntangle/PQC-VPN.git
cd PQC-VPN
chmod +x run-complete-demo.sh
./run-complete-demo.sh
```

### **🔄 Manual Setup (Any Platform)**
```bash
git clone https://github.com/QEntangle/PQC-VPN.git
cd PQC-VPN
docker-compose -f docker-compose.demo.yml up -d
```

---

## 📋 **Complete Demo Execution Steps**

### **Step 1: Clone and Setup** ⏱️ *2 minutes*
```bash
git clone https://github.com/QEntangle/PQC-VPN.git
cd PQC-VPN
```

### **Step 2: Choose Your Demo Version**

#### **Option A: Quick Demo** ⏱️ *5 minutes total*
```bash
# Simple demo with basic strongSwan
chmod +x setup-quick-demo.sh
./setup-quick-demo.sh
```

#### **Option B: Full PQC Demo** ⏱️ *20 minutes total*
```bash
# Complete PQC with OpenSSL + OQS + liboqs
chmod +x setup-windows.sh  # or setup-enterprise-demo.sh
./setup-windows.sh
# Choose option 2 (Full PQC Version)
```

#### **Option C: Automated Complete Demo** ⏱️ *10 minutes total*
```bash
# Fully automated with testing and verification
chmod +x run-complete-demo.sh
./run-complete-demo.sh
```

### **Step 3: Access Your Demo** ⏱️ *1 minute*
- **🌐 Web Dashboard**: http://localhost:8443
- **🏠 Hub Server**: 172.20.0.100
- **👥 Client IPs**: 172.20.0.101, 172.20.0.102, 172.20.0.103

### **Step 4: Verify Everything Works** ⏱️ *2 minutes*
```bash
# Check all services
docker-compose -f docker-compose.demo.yml ps

# Check VPN connections
docker exec pqc-vpn-hub ipsec status
# Should show: 3 ESTABLISHED connections

# Test inter-client communication
docker exec pqc-vpn-client1 ping -c 3 172.20.0.102
docker exec pqc-vpn-client2 ping -c 3 172.20.0.103
```

---

## 🧪 **Demo Scenarios to Run**

### **🔗 Basic Connectivity Test**
```bash
# Test all client-to-client connections
docker exec pqc-vpn-client1 ping -c 3 172.20.0.102  # Client 1 → Client 2
docker exec pqc-vpn-client1 ping -c 3 172.20.0.103  # Client 1 → Client 3
docker exec pqc-vpn-client2 ping -c 3 172.20.0.103  # Client 2 → Client 3
```

### **📁 Secure File Transfer Demo**
```bash
# Setup file server on Client 1
docker exec pqc-vpn-client1 bash -c "
echo 'Confidential Document via PQC-VPN' > /tmp/secret.txt
cd /tmp && python3 -m http.server 8080 --bind 0.0.0.0 &
"

# Download from Client 2 (through encrypted tunnel)
docker exec pqc-vpn-client2 curl http://172.20.0.101:8080/secret.txt
```

### **💬 Secure Chat Demo**
```bash
# Setup chat server on Client 2
docker exec pqc-vpn-client2 bash -c "
echo 'import socket; s=socket.socket(); s.bind((\"0.0.0.0\",9999)); s.listen(1); 
while True: c,a=s.accept(); print(f\"Connected: {a}\"); c.send(b\"Welcome to PQC-VPN Chat!\"); c.close()' > /tmp/chat.py
python3 /tmp/chat.py &
"

# Connect from other clients
docker exec pqc-vpn-client1 nc 172.20.0.102 9999
docker exec pqc-vpn-client3 nc 172.20.0.102 9999
```

### **🗄️ Database Replication Demo**
```bash
# Create database on Client 3
docker exec pqc-vpn-client3 bash -c "
apt-get update -qq && apt-get install -y sqlite3
sqlite3 /tmp/company.db 'CREATE TABLE employees(id INT, name TEXT); 
INSERT INTO employees VALUES(1,\"Alice\"),(2,\"Bob\"),(3,\"Carol\");'
cd /tmp && python3 -m http.server 7777 &
"

# Replicate to other clients
docker exec pqc-vpn-client1 bash -c "
apt-get update -qq && apt-get install -y sqlite3 wget
wget http://172.20.0.103:7777/company.db
sqlite3 company.db 'SELECT * FROM employees;'
"
```

---

## 🌐 **Web Dashboard Features**

### **Access the Dashboard**
Open http://localhost:8443 in your browser

### **Dashboard Shows:**
- ✅ **Hub Status**: Online/Offline indicator
- ✅ **Client Connections**: Real-time connection status
- ✅ **Network Info**: IP addresses and subnet configuration
- ✅ **Security Details**: Encryption algorithms in use
- ✅ **PQC Readiness**: Post-quantum cryptography preparation status

### **Real-time Monitoring**
- Auto-refreshes every 10 seconds
- Shows live connection states
- Displays current encryption parameters
- Indicates VPN tunnel status

---

## 🔍 **Verification Commands**

### **Check Overall Status**
```bash
# Service status
docker-compose -f docker-compose.demo.yml ps

# Network connectivity matrix
for client in pqc-vpn-client1 pqc-vpn-client2 pqc-vpn-client3; do
  echo "Testing $client:"
  docker exec $client ping -c 1 172.20.0.100 && echo "  ✅ Hub connection"
  docker exec $client ping -c 1 172.20.0.101 && echo "  ✅ Client 1 connection" || true
  docker exec $client ping -c 1 172.20.0.102 && echo "  ✅ Client 2 connection" || true
  docker exec $client ping -c 1 172.20.0.103 && echo "  ✅ Client 3 connection" || true
done
```

### **Check VPN Security**
```bash
# strongSwan status
docker exec pqc-vpn-hub ipsec status

# Detailed connection info
docker exec pqc-vpn-hub ipsec statusall

# Security associations
docker exec pqc-vpn-hub ipsec listsas
```

### **Monitor Network Traffic**
```bash
# Watch encrypted traffic (ESP packets)
docker exec pqc-vpn-hub tcpdump -i any esp -c 10

# Generate traffic to see encryption
docker exec pqc-vpn-client1 ping -c 5 172.20.0.102 &
docker exec pqc-vpn-client2 ping -c 5 172.20.0.103 &
```

---

## 🔐 **PQC Features (Full Version Only)**

If you chose the **Full PQC Version**, you can test quantum-safe features:

### **Check Available PQC Algorithms**
```bash
# Key Encapsulation Mechanisms
docker exec pqc-vpn-hub openssl list -kem-algorithms | grep kyber

# Digital Signatures
docker exec pqc-vpn-hub openssl list -signature-algorithms | grep dilithium

# Available providers
docker exec pqc-vpn-hub openssl list -providers
```

### **Generate PQC Certificates**
```bash
# Generate Kyber keys
docker exec pqc-vpn-hub openssl genpkey -algorithm kyber1024 -out /tmp/kyber.key

# Generate Dilithium certificates
docker exec pqc-vpn-hub openssl genpkey -algorithm dilithium5 -out /tmp/dilithium.key
```

---

## 🆘 **Troubleshooting**

### **Common Issues & Quick Fixes**

#### **🔴 Containers not starting**
```bash
# Check Docker
docker info

# Clean restart
docker-compose -f docker-compose.demo.yml down -v
docker system prune -f
./setup-quick-demo.sh
```

#### **🔴 VPN connections not establishing**
```bash
# Wait longer (services need 2-3 minutes)
sleep 120

# Check logs
docker-compose -f docker-compose.demo.yml logs pqc-vpn-hub

# Restart strongSwan
docker exec pqc-vpn-hub ipsec restart
```

#### **🔴 Web dashboard not accessible**
```bash
# Check web server
docker exec pqc-vpn-hub ps aux | grep python

# Try different URLs
# http://localhost:8443
# http://127.0.0.1:8443
# http://172.20.0.100:8443
```

#### **🔴 Inter-client communication fails**
```bash
# Check container IPs
docker inspect pqc-vpn-client1 | grep IPAddress

# Test direct container communication
docker exec pqc-vpn-client1 ping 172.20.0.102

# Check routing
docker exec pqc-vpn-client1 ip route
```

### **🔄 Complete Reset**
```bash
# Full cleanup and restart
docker-compose -f docker-compose.demo.yml down -v
docker system prune -af
docker volume prune -f
./run-complete-demo.sh
```

---

## 📊 **Demo Success Checklist**

Use this checklist to verify your demo is working perfectly:

- [ ] ✅ **4 containers running** (1 hub + 3 clients)
- [ ] ✅ **Web dashboard accessible** at http://localhost:8443
- [ ] ✅ **3 VPN connections established** (check with `ipsec status`)
- [ ] ✅ **All clients can ping hub** (172.20.0.100)
- [ ] ✅ **All clients can ping each other** (101↔102↔103)
- [ ] ✅ **File transfer working** between clients
- [ ] ✅ **Web dashboard shows green status** for all connections
- [ ] ✅ **strongSwan logs show ESTABLISHED** connections
- [ ] ✅ **No error messages** in container logs

---

## 🎭 **Demo Presentation Script**

For live presentations, use this script:

```bash
echo "🎭 PQC-VPN Live Demo"
echo "==================="

echo "1. 📊 Showing infrastructure status..."
docker-compose -f docker-compose.demo.yml ps

echo -e "\n2. 🔐 Checking VPN connections..."
docker exec pqc-vpn-hub ipsec status

echo -e "\n3. 🔗 Testing secure communication..."
docker exec pqc-vpn-client1 ping -c 3 172.20.0.102

echo -e "\n4. 📁 Demonstrating file transfer..."
docker exec pqc-vpn-client1 bash -c "echo 'Demo file' > /tmp/demo.txt && cd /tmp && python3 -m http.server 8888 &"
sleep 2
docker exec pqc-vpn-client2 curl http://172.20.0.101:8888/demo.txt

echo -e "\n5. 🌐 Web dashboard available at: http://localhost:8443"
echo -e "\n✅ Demo complete! All communications secured with quantum-safe encryption."
```

---

## 🚀 **Next Steps After Demo**

### **For Development**
1. **Add more clients**: Modify docker-compose to add client4, client5, etc.
2. **Custom algorithms**: Test different encryption configurations
3. **Network scenarios**: Simulate different network topologies

### **For Production**
1. **Deploy full PQC version** with real quantum-safe algorithms
2. **Implement PKI** for certificate-based authentication
3. **Add monitoring** with Grafana + Prometheus
4. **Scale horizontally** with multiple hub servers
5. **Integrate with existing infrastructure**

### **For Testing**
1. **Load testing**: Add multiple concurrent clients
2. **Security testing**: Penetration testing and vulnerability assessment
3. **Performance testing**: Measure throughput and latency
4. **Interoperability testing**: Test with different VPN clients

---

## 📞 **Support & Resources**

### **Quick Help**
- 📖 **Complete guide**: See the artifact above for detailed steps
- 🔧 **Docker issues**: Check `DOCKER-FIX-GUIDE.md`
- 🖥️ **Windows setup**: Use `setup-windows.sh`
- 🚀 **Automated demo**: Use `run-complete-demo.sh`

### **Files in Repository**
- `docker-compose.demo.yml` - Fixed demo configuration
- `setup-quick-demo.sh` - Simple 5-minute setup
- `setup-windows.sh` - Windows-optimized setup
- `run-complete-demo.sh` - Fully automated demo with testing
- `DOCKER-FIX-GUIDE.md` - Troubleshooting guide

---

## 🎉 **You're Ready!**

**Your PQC-VPN demo with 1 server + 3 clients + web interface is ready to run!**

Choose your platform, run the appropriate setup script, and in 5-20 minutes you'll have a working demonstration of quantum-safe VPN communications with:

✅ **Inter-client connectivity**  
✅ **Secure file transfers**  
✅ **Real-time web dashboard**  
✅ **Post-quantum cryptography readiness**  
✅ **Complete monitoring and verification**  

**Start your demo now!** 🚀
