# ✅ PQC-VPN Fixed Demo Setup - READY TO USE

This document provides the **updated step-by-step process** for setting up a PQC-VPN demo with **one server and three clients** using the **fixed production configuration** that resolves all Docker Compose issues.

## 🚀 Quick Demo Setup (One Command)

```bash
# Clone repository
git clone https://github.com/QEntangle/PQC-VPN.git
cd PQC-VPN

# Make scripts executable
chmod +x setup-demo.sh start-pqc-vpn.sh

# Run complete demo setup (one command!)
./setup-demo.sh
```

**That's it!** The script will automatically:
- ✅ Clean any existing setup
- ✅ Configure demo environment  
- ✅ Build and start all services
- ✅ Create 3 demo clients
- ✅ Generate client configurations
- ✅ Start monitoring dashboard

## 🎯 What You Get

After running the demo setup:

### 🖥️ **One PQC-VPN Hub Server**
- strongSwan with Post-Quantum Cryptography
- Kyber1024 (Key Exchange) + Dilithium5 (Signatures)
- Web management interface
- Real-time monitoring

### 👥 **Three Demo Clients**
- **demo-client-1**: PKI Authentication (Engineering)
- **demo-client-2**: PSK Authentication (Marketing)  
- **demo-client-3**: PKI Authentication (Sales)

### 🌐 **Access URLs**
- **Web Interface**: https://localhost:8443 (admin / DemoAdmin123!)
- **Monitoring**: http://localhost:13000 (admin / DemoGrafana123!)
- **API**: https://localhost:9090
- **Metrics**: http://localhost:19090

### 📁 **Client Configurations**
Ready-to-use strongSwan configs in `./demo-client-configs/`

## 🔧 Manual Setup (Step-by-Step)

If you prefer manual control or need to understand each step:

### Step 1: Environment Setup
```bash
cd PQC-VPN

# Copy fixed environment configuration
cp .env.production .env

# Edit with your server IP (important!)
nano .env
# Change: HUB_IP=192.168.1.100 to your actual IP
```

### Step 2: Start Core Services
```bash
# Use the FIXED production compose file
docker-compose -f docker/docker-compose.production-fixed.yml build pqc-vpn-hub
docker-compose -f docker/docker-compose.production-fixed.yml up -d postgres redis

# Wait for databases
sleep 20
```

### Step 3: Start Main Application
```bash
# Start PQC-VPN hub
docker-compose -f docker/docker-compose.production-fixed.yml up -d pqc-vpn-hub

# Start monitoring
docker-compose -f docker/docker-compose.production-fixed.yml --profile monitoring up -d

# Wait for full initialization
sleep 30
```

### Step 4: Create Demo Clients
```bash
# Client 1 (PKI)
docker exec pqc-vpn-hub pqc-vpn-manager user add demo-client-1 client1@demo.local --auth-type pki --full-name "Demo Client 1"

# Client 2 (PSK)
docker exec pqc-vpn-hub pqc-vpn-manager user add demo-client-2 client2@demo.local --auth-type psk --full-name "Demo Client 2"

# Client 3 (PKI)
docker exec pqc-vpn-hub pqc-vpn-manager user add demo-client-3 client3@demo.local --auth-type pki --full-name "Demo Client 3"

# Verify clients
docker exec pqc-vpn-hub pqc-vpn-manager user list
```

## 🎭 Demo Presentation Flow

### 1. System Overview (2 minutes)
```bash
# Show running services
docker-compose -f docker/docker-compose.production-fixed.yml ps

# Show Post-Quantum configuration
docker exec pqc-vpn-hub pqc-vpn-manager crypto status
```

### 2. Web Interface Demo (3 minutes)
- Open https://localhost:8443
- Login: admin / DemoAdmin123!
- Show: Dashboard → Users → Connections → Certificates

### 3. Client Management (3 minutes)
```bash
# Show client list
docker exec pqc-vpn-hub pqc-vpn-manager user list

# Show client configurations
ls -la demo-client-configs/
cat demo-client-configs/client1-strongswan.conf
```

### 4. Monitoring Dashboard (2 minutes)
- Open http://localhost:13000
- Login: admin / DemoGrafana123!
- Show: System metrics, VPN connections, Performance

### 5. Real-time Operations (3 minutes)
```bash
# Show live logs
docker logs pqc-vpn-hub -f

# Show system status
docker exec pqc-vpn-hub pqc-vpn-manager status

# Show strongSwan status
docker exec pqc-vpn-hub ipsec status
```

## 🛠️ Key Fixed Issues

### ✅ **Build Context Fixed**
- **Problem**: `context: .` caused build failures when running from docker directory
- **Solution**: `context: ..` in docker-compose.production-fixed.yml

### ✅ **Port Conflicts Fixed** 
- **Problem**: Default ports conflicted with existing services
- **Solution**: Non-conflicting ports:
  - PostgreSQL: 5432 → 15432
  - Redis: 6379 → 16379
  - Grafana: 3000 → 13000
  - Prometheus: 9090 → 19090

### ✅ **Missing Dependencies Fixed**
- **Problem**: References to non-existent SQL files and configs
- **Solution**: Created working configurations and removed missing dependencies

### ✅ **Environment Issues Fixed**
- **Problem**: Unclear environment setup
- **Solution**: Clear .env.production template with secure defaults

## 📊 Demo Verification

### Check All Services
```bash
# Service status
docker-compose -f docker/docker-compose.production-fixed.yml ps

# Database health
docker exec pqc-postgres pg_isready -U pqc_admin -d pqc_vpn_enterprise

# Redis health
docker exec pqc-redis redis-cli ping

# Web interface health
curl -k https://localhost:8443/health
```

### Test Client Operations
```bash
# List all users
docker exec pqc-vpn-hub pqc-vpn-manager user list

# Check certificates
docker exec pqc-vpn-hub pqc-vpn-manager cert list

# View connection status
docker exec pqc-vpn-hub ipsec statusall
```

## 🧹 Demo Cleanup

### Stop Demo (Keep Data)
```bash
docker-compose -f docker/docker-compose.production-fixed.yml down
```

### Complete Cleanup (Remove All Data)
```bash
docker-compose -f docker/docker-compose.production-fixed.yml down -v
docker container prune -f
docker volume prune -f
rm -rf demo-client-configs
```

### Quick Restart
```bash
./setup-demo.sh  # Runs complete setup again
```

## 📋 File Structure

```
PQC-VPN/
├── setup-demo.sh                              # 🎯 ONE-COMMAND DEMO SETUP
├── start-pqc-vpn.sh                          # General startup script
├── .env.production                           # Fixed environment template
├── docker/
│   ├── docker-compose.production-fixed.yml   # 🔧 FIXED production config
│   ├── docker-compose.production.yml         # Original (has issues)
│   └── Dockerfile.pqc-hub                    # Hub container
├── configs/
│   └── prometheus/prometheus.yml             # Working monitoring config
├── QUICKSTART-FIXED.md                       # 📖 Detailed guide
└── demo-client-configs/                      # Generated client configs
    ├── client1-strongswan.conf
    ├── client2-strongswan.conf  
    ├── client3-strongswan.conf
    └── README.md
```

## 🎉 Demo Success Checklist

After running `./setup-demo.sh`, you should have:

- [ ] ✅ PQC-VPN Hub running on https://localhost:8443
- [ ] ✅ Three demo clients configured (demo-client-1, 2, 3)
- [ ] ✅ Monitoring dashboard on http://localhost:13000
- [ ] ✅ Client configs in demo-client-configs/ directory
- [ ] ✅ Database with user data (PostgreSQL on port 15432)
- [ ] ✅ Working strongSwan with Post-Quantum Crypto
- [ ] ✅ Real-time metrics and logging

## 🆘 Troubleshooting

### Script Fails?
```bash
# Check Docker
docker --version && docker-compose --version

# Check directory
pwd  # Should be in PQC-VPN root
ls   # Should see: docker/ tools/ web/ requirements.txt

# Manual cleanup and retry
docker system prune -af
./setup-demo.sh
```

### Service Not Responding?
```bash
# Check logs
docker-compose -f docker/docker-compose.production-fixed.yml logs -f pqc-vpn-hub

# Restart specific service
docker-compose -f docker/docker-compose.production-fixed.yml restart pqc-vpn-hub
```

### Port Conflicts?
Edit `.env` file and change external ports:
```bash
POSTGRES_EXTERNAL_PORT=25432
REDIS_EXTERNAL_PORT=26379
GRAFANA_EXTERNAL_PORT=23000
```

---

## 🎯 Ready for Demo!

**The fixed configuration resolves all the Docker Compose errors** from your original setup and provides a reliable, automated demo environment with one hub server and three clients showcasing Post-Quantum Cryptography VPN capabilities.

**One command gets everything running**: `./setup-demo.sh`