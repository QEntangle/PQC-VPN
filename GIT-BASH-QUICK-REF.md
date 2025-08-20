# 🐧 Git Bash Quick Start for PQC-VPN Demo

## ⚡ Super Quick Setup

### For Git Bash Users (Recommended Unix-like Experience)
```bash
# Open Git Bash terminal
git clone https://github.com/QEntangle/PQC-VPN.git
cd PQC-VPN
chmod +x setup-gitbash-demo.sh
./setup-gitbash-demo.sh
```

### Alternative: Direct Run
```bash
# If you prefer manual setup
# Follow detailed guide in GIT-BASH-DEMO-GUIDE.md
```

## 🖥️ Git Bash Terminal Layout

| Terminal | Component | Command | Port |
|----------|-----------|---------|------|
| **Git Bash 1** | Hub Server | `./start-hub.sh` | 500/4500 |
| **Git Bash 2** | Alice (PKI) | `./start-alice.sh` | - |
| **Git Bash 3** | Bob (PSK) | `./start-bob.sh` | - |
| **Git Bash 4** | Charlie (Hybrid) | `./start-charlie.sh` | - |
| **Git Bash 5** | Dashboard | `./start-dashboard.sh` | 8443 |

## 🚀 Running in Git Bash

### Method 1: Interactive Menu (Easiest)
```bash
cd demo-setup
./run-demo.sh

# Choose from menu:
# 1) Hub Server (start first)
# 2) Alice Client 
# 3) Bob Client
# 4) Charlie Client
# 5) Dashboard
# 6) Start All (automatic)
```

### Method 2: Manual Separate Terminals
```bash
# Terminal 1 - Hub
cd /c/PQC-VPN/demo-setup
./start-hub.sh

# Terminal 2 - Alice (new Git Bash window)
cd /c/PQC-VPN/demo-setup
./start-alice.sh

# Terminal 3 - Bob (new Git Bash window)
cd /c/PQC-VPN/demo-setup
./start-bob.sh

# Terminal 4 - Charlie (new Git Bash window)  
cd /c/PQC-VPN/demo-setup
./start-charlie.sh

# Terminal 5 - Dashboard (new Git Bash window)
cd /c/PQC-VPN/demo-setup
./start-dashboard.sh
```

## 🔧 Git Bash Specific Commands

### Docker Commands (use winpty)
```bash
# Check containers
winpty docker ps

# View logs
winpty docker logs pqc-vpn-hub

# Execute commands
winpty docker exec pqc-vpn-alice ping 10.10.0.1

# Stop containers
winpty docker stop pqc-vpn-hub pqc-vpn-alice pqc-vpn-bob pqc-vpn-charlie
```

### Path Handling
```bash
# Current directory in Windows format for Docker
WIN_PATH=$(pwd -W)
UNIX_PATH="/$(echo $WIN_PATH | sed 's/://' | sed 's/\\/\//g')"
echo $UNIX_PATH  # Shows Unix-style path for Docker volumes
```

### File Permissions
```bash
# Make scripts executable
chmod +x demo-setup/*.sh

# Check permissions
ls -la demo-setup/*.sh
```

## 🎯 Expected Demo Flow

### 1. Start Hub (Terminal 1)
```bash
./start-hub.sh
# Output: Hub server starts, shows "Started IKE charon daemon"
```

### 2. Start Dashboard (Terminal 5)
```bash
./start-dashboard.sh
# Output: Flask server starts on https://localhost:8443
```

### 3. Start Alice (Terminal 2)
```bash
./start-alice.sh
# Output: 15-second countdown, then connection to hub
# Dashboard shows: 1 connection with Kyber-1024
```

### 4. Start Bob (Terminal 3)
```bash
./start-bob.sh
# Output: 20-second countdown, then PSK connection
# Dashboard shows: 2 connections, different algorithms
```

### 5. Start Charlie (Terminal 4)
```bash
./start-charlie.sh
# Output: 25-second countdown, then hybrid connection
# Dashboard shows: 3 connections, all algorithms active
```

## 📊 Verification Commands

### Check All Containers Running
```bash
winpty docker ps --filter "name=pqc-vpn"
# Should show: pqc-vpn-hub, pqc-vpn-alice, pqc-vpn-bob, pqc-vpn-charlie
```

### Verify Connections
```bash
# Hub status
winpty docker exec pqc-vpn-hub ipsec status

# Should show:
# alice-pki[1]: ESTABLISHED
# bob-psk[2]: ESTABLISHED  
# charlie-hybrid[3]: ESTABLISHED
```

### Test Connectivity
```bash
# Alice to hub
winpty docker exec pqc-vpn-alice ping -c 3 10.10.0.1

# Bob to Alice
winpty docker exec pqc-vpn-bob ping -c 3 10.10.1.50

# Charlie to Bob
winpty docker exec pqc-vpn-charlie ping -c 3 10.10.1.51
```

## 🌐 Dashboard Access

- **URL**: https://localhost:8443
- **Username**: admin
- **Password**: pqc-admin-2025

### Dashboard Features
- **Real-time metrics**: CPU, memory, network usage
- **Connection management**: View active VPN connections
- **Algorithm tracking**: See which Kyber variants are in use
- **User management**: Add/remove VPN users
- **Live updates**: 30-second refresh with real data

## 🛠️ Troubleshooting Git Bash

### Common Issues & Solutions

| Problem | Solution |
|---------|----------|
| `winpty: command not found` | Install Git for Windows properly |
| `docker: command not found` | Add Docker to PATH or restart Git Bash |
| Permission denied on scripts | Run `chmod +x demo-setup/*.sh` |
| Path mounting issues | Use `pwd -W` for Windows paths |
| Container won't start | Check Docker Desktop is running |

### Debug Commands
```bash
# Check Git Bash environment
echo $MSYSTEM
echo $TERM

# Test Docker integration
winpty docker --version
winpty docker ps

# Check Python
python --version
pip list | grep flask

# View script permissions
ls -la demo-setup/
```

## 🎬 Demo Presentation Tips

### 5-Minute Git Bash Demo
1. **[0:00]** Show automated setup: `./setup-gitbash-demo.sh`
2. **[0:30]** Open demo menu: `./run-demo.sh`
3. **[1:00]** Start hub server (option 1)
4. **[1:30]** Start dashboard (option 5) - show empty state
5. **[2:00]** Start all clients (option 6) - automatic sequence
6. **[3:00]** Show dashboard with 3 connections
7. **[3:30]** Test connectivity with `winpty docker exec` commands
8. **[4:00]** Demonstrate algorithm differences in dashboard
9. **[4:30]** Show real-time monitoring and management features

### Key Talking Points
- **Unix-like experience** on Windows with Git Bash
- **Real post-quantum cryptography** using Kyber algorithms
- **Multiple authentication methods** in single demo
- **Live monitoring** without simulated data
- **Cross-platform compatibility** (same commands work on Linux)

## 📁 Generated File Structure

```
PQC-VPN/
├── demo-setup/           # Created by setup script
│   ├── hub/             # Hub server configuration
│   ├── client-alice/    # Alice client (PKI + Kyber-1024)
│   ├── client-bob/      # Bob client (PSK + Kyber-768)  
│   ├── client-charlie/  # Charlie client (Hybrid + Kyber-512)
│   ├── start-hub.sh     # Hub launcher script
│   ├── start-alice.sh   # Alice launcher script
│   ├── start-bob.sh     # Bob launcher script
│   ├── start-charlie.sh # Charlie launcher script
│   ├── start-dashboard.sh # Dashboard launcher script
│   ├── run-demo.sh      # Interactive demo menu
│   └── README.md        # Demo-specific documentation
├── web/                 # Fixed dashboard (no simulated data)
└── setup-gitbash-demo.sh # Automated setup script
```

Git Bash provides the perfect Unix-like environment for demonstrating your PQC-VPN system on Windows! 🐧🔐
