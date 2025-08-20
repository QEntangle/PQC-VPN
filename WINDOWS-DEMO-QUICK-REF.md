# 🚀 PQC-VPN Windows Demo - Quick Reference

## ⚡ Super Quick Start

### Option 1: Automated Setup (Recommended)
```cmd
# Run as Administrator
git clone https://github.com/QEntangle/PQC-VPN.git
cd PQC-VPN
setup-windows-demo.bat
```

### Option 2: Manual Setup
Follow the detailed guide in [WINDOWS-DEMO-GUIDE.md](WINDOWS-DEMO-GUIDE.md)

## 🖥️ Terminal Layout

| Terminal | Component | Role | Port | Algorithm |
|----------|-----------|------|------|-----------|
| 1 | Hub Server | VPN Gateway | 500/4500 | All Kyber variants |
| 2 | Alice | Client (PKI) | - | Kyber-1024 |
| 3 | Bob | Client (PSK) | - | Kyber-768 |
| 4 | Charlie | Client (Hybrid) | - | Kyber-512 |
| 5 | Dashboard | Monitoring | 8443 | Real-time data |

## 🔧 Starting Order

1. **Hub Server** (Terminal 1) - Start first
2. **Dashboard** (Terminal 5) - Start second for monitoring
3. **Alice** (Terminal 2) - Wait 15 seconds after hub
4. **Bob** (Terminal 3) - Wait 20 seconds after hub  
5. **Charlie** (Terminal 4) - Wait 25 seconds after hub

## 📊 Expected Results

### Dashboard Metrics (https://localhost:8443)
- **Active Connections**: 3
- **Total Users**: 3  
- **PQC Tunnels**: 3
- **Data Transferred**: Live traffic data

### Algorithm Distribution
- **Kyber-1024**: 1 (Alice - PKI)
- **Kyber-768**: 1 (Bob - PSK)
- **Kyber-512**: 1 (Charlie - Hybrid)

### Authentication Methods
- **PKI**: 1 (Alice with certificates)
- **PSK**: 1 (Bob with pre-shared keys)
- **Hybrid**: 1 (Charlie with both)

## 🧪 Demo Test Commands

### Connection Verification
```bash
# In each client terminal
docker exec pqc-vpn-alice ping 10.10.0.1    # Ping hub
docker exec pqc-vpn-bob ping 10.10.1.50     # Ping Alice
docker exec pqc-vpn-charlie ping 10.10.1.51 # Ping Bob
```

### Status Check
```bash
# In hub terminal
docker exec pqc-vpn-hub ipsec status
docker exec pqc-vpn-hub ipsec statusall
```

### Dashboard Features
- **Real-time refresh** every 30 seconds
- **Connection management** (disconnect/reconnect)
- **User addition** through web interface
- **Live system metrics** (CPU, memory, disk)

## 🎬 Demo Script

### 5-Minute Presentation Flow

1. **[0:00]** Show automated setup script running
2. **[0:30]** Start hub server (Terminal 1)
3. **[1:00]** Start dashboard (Terminal 5) - show empty state
4. **[1:30]** Start Alice (Terminal 2) - PKI authentication
5. **[2:00]** Dashboard shows 1 connection with Kyber-1024
6. **[2:30]** Start Bob (Terminal 3) - PSK authentication  
7. **[3:00]** Dashboard shows 2 connections, different algorithms
8. **[3:30]** Start Charlie (Terminal 4) - Hybrid authentication
9. **[4:00]** Dashboard shows 3 connections, all algorithms
10. **[4:30]** Demonstrate connection management and real-time updates

### Key Talking Points

- **Post-Quantum Security**: "This VPN uses Kyber algorithms to protect against quantum computer attacks"
- **Multiple Authentication**: "We support traditional PKI, modern PSK, and hybrid approaches"
- **Real-Time Monitoring**: "The dashboard shows live data - no simulated information"
- **Algorithm Flexibility**: "Different clients can use different quantum-safe algorithms simultaneously"

## 🛠️ Troubleshooting

### Common Issues & Solutions

| Issue | Solution |
|-------|----------|
| Docker not found | Install Docker Desktop |
| Permission denied | Run as Administrator |
| Port conflicts | Check ports 500, 4500, 8443 are free |
| Connection failed | Verify containers are running |
| Dashboard errors | Check Python dependencies installed |

### Quick Fixes
```cmd
# Check Docker status
docker ps

# Restart all containers
docker restart pqc-vpn-hub pqc-vpn-alice pqc-vpn-bob pqc-vpn-charlie

# View logs
docker logs pqc-vpn-hub
```

## 📁 File Structure After Setup

```
PQC-VPN/
├── demo-setup/
│   ├── hub/                 # Hub server config
│   ├── client-alice/        # Alice client config  
│   ├── client-bob/          # Bob client config
│   ├── client-charlie/      # Charlie client config
│   ├── start-hub.bat        # Hub launcher
│   ├── start-alice.bat      # Alice launcher
│   ├── start-bob.bat        # Bob launcher
│   ├── start-charlie.bat    # Charlie launcher
│   ├── start-dashboard.bat  # Dashboard launcher
│   └── run-demo.bat         # Main demo menu
├── web/                     # Corrected dashboard files
└── setup-windows-demo.bat  # Automated setup script
```

## 🔐 Security Features Demonstrated

### Post-Quantum Cryptography
- **Kyber-1024**: Highest security, slower performance
- **Kyber-768**: Balanced security and performance  
- **Kyber-512**: Faster performance, good security

### Authentication Methods
- **PKI**: Traditional certificate-based (Alice)
- **PSK**: Pre-shared key authentication (Bob)
- **Hybrid**: Combined PKI + PSK (Charlie)

### Real-Time Monitoring
- **Live connection tracking** without simulated data
- **Actual system metrics** using `psutil`
- **Interactive management** through web dashboard

This demo showcases a complete PQC-VPN implementation ready for quantum-safe communications! 🛡️
