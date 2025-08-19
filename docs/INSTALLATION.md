# PQC-VPN Installation Guide

This guide provides detailed instructions for installing PQC-VPN on both Linux and Windows systems.

## Table of Contents

- [System Requirements](#system-requirements)
- [Hub Installation](#hub-installation)
  - [Linux Hub](#linux-hub)
  - [Windows Hub](#windows-hub)
- [Spoke Installation](#spoke-installation)
  - [Linux Spoke](#linux-spoke)
  - [Windows Spoke](#windows-spoke)
- [Docker Deployment](#docker-deployment)
- [Post-Installation Configuration](#post-installation-configuration)
- [Verification](#verification)

## System Requirements

### Hardware Requirements

- **Minimum**: 2 CPU cores, 2GB RAM, 10GB storage
- **Recommended**: 4 CPU cores, 4GB RAM, 20GB storage
- **For 100+ users**: 8 CPU cores, 8GB RAM, 50GB storage

### Network Requirements

- Open ports: UDP 500 (IKE), UDP 4500 (NAT-T)
- Static IP address for hub (recommended)
- Internet connectivity for certificate updates

### Supported Operating Systems

#### Linux
- Ubuntu 20.04 LTS or later
- CentOS/RHEL 8 or later
- Debian 11 or later
- Rocky Linux 8 or later

#### Windows
- Windows 10 Pro (version 1903 or later)
- Windows 11 Pro
- Windows Server 2019 or later
- WSL2 enabled

## Hub Installation

The hub is the central server that all spoke clients connect to.

### Linux Hub

#### Prerequisites

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y  # Ubuntu/Debian
sudo yum update -y                      # CentOS/RHEL

# Install Git
sudo apt install git -y                 # Ubuntu/Debian
sudo yum install git -y                 # CentOS/RHEL
```

#### Installation Steps

1. **Clone the repository**:
   ```bash
   git clone https://github.com/QEntangle/PQC-VPN.git
   cd PQC-VPN
   ```

2. **Run the hub installation script**:
   ```bash
   sudo chmod +x scripts/install-hub-linux.sh
   sudo ./scripts/install-hub-linux.sh
   ```

3. **Follow the interactive prompts**:
   - Enter hub IP address (or accept auto-detected)
   - Configure firewall (recommended: yes)
   - Review certificate generation

4. **Verify installation**:
   ```bash
   sudo systemctl status strongswan
   sudo ipsec status
   ```

#### Manual Installation (Advanced)

If you prefer manual installation:

1. **Install dependencies**:
   ```bash
   sudo apt install -y build-essential libssl-dev libgmp-dev \
       libldap2-dev libcurl4-openssl-dev libxml2-dev \
       libsystemd-dev pkg-config cmake ninja-build
   ```

2. **Install liboqs**:
   ```bash
   cd /tmp
   git clone https://github.com/open-quantum-safe/liboqs.git
   cd liboqs
   mkdir build && cd build
   cmake -G Ninja -DCMAKE_INSTALL_PREFIX=/usr/local ..
   ninja && sudo ninja install
   sudo ldconfig
   ```

3. **Install strongSwan**:
   ```bash
   cd /tmp
   git clone https://github.com/strongswan/strongswan.git
   cd strongswan
   git checkout 5.9.14
   ./autogen.sh
   ./configure --enable-oqs --enable-openssl --enable-cmd \
       --enable-conf --enable-systemd
   make -j$(nproc) && sudo make install
   ```

4. **Configure certificates**:
   ```bash
   sudo ./scripts/generate-pqc-certs.sh --ca
   sudo ./scripts/generate-pqc-certs.sh --hub YOUR_HUB_IP
   ```

### Windows Hub

#### Prerequisites

1. **Enable WSL2**:
   ```powershell
   # Run as Administrator
   dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
   dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
   ```

2. **Restart Windows** and install Ubuntu:
   ```powershell
   wsl --install -d Ubuntu
   ```

#### Installation Steps

1. **Clone the repository**:
   ```powershell
   git clone https://github.com/QEntangle/PQC-VPN.git
   cd PQC-VPN
   ```

2. **Run the hub installation script**:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   .\scripts\install-hub-windows.ps1
   ```

3. **Follow the interactive prompts**:
   - Enter hub IP address
   - Configure Windows Firewall
   - Complete WSL2 setup if needed

4. **Verify installation**:
   ```powershell
   wsl -d Ubuntu sudo ipsec status
   Get-Service PQC-VPN-Hub
   ```

## Spoke Installation

Spoke clients connect to the hub and require certificates from the hub administrator.

### Linux Spoke

#### Installation Steps

1. **Clone the repository**:
   ```bash
   git clone https://github.com/QEntangle/PQC-VPN.git
   cd PQC-VPN
   ```

2. **Run the spoke installation script**:
   ```bash
   sudo chmod +x scripts/install-spoke-linux.sh
   sudo ./scripts/install-spoke-linux.sh
   ```

3. **Provide required information**:
   - Hub IP address
   - Your username
   - Hub administrator IP (for certificate exchange)

4. **Certificate exchange**:
   - Send the generated `.csr` file to hub administrator
   - Receive signed certificate and CA certificate
   - Install certificates:
     ```bash
     sudo /opt/pqc-vpn/scripts/install-certs.sh your-cert.pem ca-cert.pem
     ```

5. **Connect to VPN**:
   ```bash
   pqc-connect
   ```

### Windows Spoke

#### Installation Steps

1. **Clone the repository**:
   ```powershell
   git clone https://github.com/QEntangle/PQC-VPN.git
   cd PQC-VPN
   ```

2. **Run the spoke installation script**:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   .\scripts\install-spoke-windows.ps1
   ```

3. **Provide required information**:
   - Hub IP address
   - Your username

4. **Certificate exchange**:
   - Send certificate request from `C:\PQC-VPN-Spoke\certs\`
   - Receive certificates from hub administrator
   - Install using: `.\scripts\install-certs.bat your-cert.pem ca-cert.pem`

5. **Connect to VPN**:
   - Use desktop shortcut "PQC-VPN Connect"
   - Or run: `.\scripts\connect.bat`

## Docker Deployment

For containerized deployment:

### Hub Deployment

1. **Clone repository**:
   ```bash
   git clone https://github.com/QEntangle/PQC-VPN.git
   cd PQC-VPN
   ```

2. **Set environment variables**:
   ```bash
   export HUB_IP=your-hub-ip
   export TZ=your-timezone
   ```

3. **Deploy hub**:
   ```bash
   cd docker
   docker-compose up -d pqc-vpn-hub
   ```

### Full Stack Deployment

```bash
# Deploy hub with monitoring
docker-compose --profile monitoring up -d

# Deploy with example spokes
docker-compose --profile spokes --profile monitoring up -d
```

### Custom Deployment

```bash
# Create data directories
mkdir -p data/{hub,spokes}/{certs,logs}

# Deploy hub only
docker-compose up -d pqc-vpn-hub

# Check status
docker-compose ps
docker-compose logs pqc-vpn-hub
```

## Post-Installation Configuration

### Hub Configuration

1. **Add users**:
   ```bash
   sudo ./scripts/add-spoke-user.sh alice --email alice@company.com
   sudo ./scripts/add-spoke-user.sh bob --group admins
   ```

2. **Configure monitoring**:
   ```bash
   sudo ./scripts/monitor-vpn.sh dashboard
   ```

3. **Set up backup**:
   ```bash
   sudo python3 tools/vpn-manager.py backup
   ```

### Network Configuration

1. **Configure firewall** (if not done automatically):
   ```bash
   # UFW (Ubuntu)
   sudo ufw allow 500/udp
   sudo ufw allow 4500/udp

   # firewalld (CentOS/RHEL)
   sudo firewall-cmd --permanent --add-port=500/udp
   sudo firewall-cmd --permanent --add-port=4500/udp
   sudo firewall-cmd --reload

   # iptables (manual)
   sudo iptables -A INPUT -p udp --dport 500 -j ACCEPT
   sudo iptables -A INPUT -p udp --dport 4500 -j ACCEPT
   ```

2. **Configure NAT traversal** (if behind NAT):
   ```bash
   # Edit /etc/ipsec.conf
   sudo nano /etc/ipsec.conf
   # Add: forceencaps=yes
   ```

## Verification

### Hub Verification

1. **Check strongSwan status**:
   ```bash
   sudo systemctl status strongswan
   sudo ipsec status
   ```

2. **Verify certificate generation**:
   ```bash
   sudo ls -la /opt/pqc-vpn/certs/
   sudo openssl x509 -in /opt/pqc-vpn/certs/ca/ca-cert.pem -text -noout
   ```

3. **Test connectivity**:
   ```bash
   sudo ss -ulpn | grep -E ':500|:4500'
   ```

### Spoke Verification

1. **Check connection status**:
   ```bash
   pqc-status                    # Linux
   .\scripts\status.bat         # Windows
   ```

2. **Test connectivity**:
   ```bash
   ping 10.10.0.1               # Ping hub
   traceroute 10.10.0.1         # Trace route to hub
   ```

3. **Verify encryption**:
   ```bash
   sudo ipsec statusall
   ```

### Network Testing

1. **Test hub-to-spoke communication**:
   ```bash
   # From hub
   ping 10.10.1.10              # Ping spoke IP
   ```

2. **Test spoke-to-spoke communication**:
   ```bash
   # From one spoke to another
   ping 10.10.1.11
   ```

3. **Performance testing**:
   ```bash
   # Install iperf3
   sudo apt install iperf3      # Ubuntu/Debian
   sudo yum install iperf3      # CentOS/RHEL

   # Run bandwidth test
   iperf3 -s                    # On one end
   iperf3 -c 10.10.1.10         # On the other end
   ```

## Common Installation Issues

### Issue: strongSwan fails to start

**Symptoms**: Service fails to start, connection refused

**Solutions**:
1. Check configuration syntax:
   ```bash
   sudo ipsec --checkconfig
   ```

2. Check certificate permissions:
   ```bash
   sudo chmod 600 /etc/ipsec.d/private/*
   sudo chmod 644 /etc/ipsec.d/certs/*
   ```

3. Check logs:
   ```bash
   sudo journalctl -u strongswan -f
   ```

### Issue: Certificate generation fails

**Symptoms**: OpenSSL errors, missing PQC algorithms

**Solutions**:
1. Verify liboqs installation:
   ```bash
   openssl list -providers
   ```

2. Reinstall liboqs:
   ```bash
   sudo ldconfig
   ```

3. Fall back to RSA:
   ```bash
   ./scripts/generate-pqc-certs.sh --algorithm rsa --ca
   ```

### Issue: Windows WSL2 problems

**Symptoms**: WSL2 not starting, Ubuntu not installing

**Solutions**:
1. Enable Windows features:
   ```powershell
   Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux
   Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform
   ```

2. Update WSL:
   ```powershell
   wsl --update
   ```

3. Reset WSL:
   ```powershell
   wsl --shutdown
   wsl --unregister Ubuntu
   wsl --install -d Ubuntu
   ```

### Issue: Connection timeouts

**Symptoms**: IKE timeouts, connection fails

**Solutions**:
1. Check firewall:
   ```bash
   sudo ufw status
   telnet hub-ip 500
   ```

2. Check NAT settings:
   ```bash
   # Add to ipsec.conf
   forceencaps=yes
   ```

3. Check routing:
   ```bash
   ip route show
   ping hub-ip
   ```

## Next Steps

After successful installation:

1. **Read the Configuration Manual**: [CONFIGURATION.md](CONFIGURATION.md)
2. **Set up monitoring**: [Monitoring Guide](MONITORING.md)
3. **Review security**: [Security Guide](SECURITY.md)
4. **Plan for production**: [Production Guide](PRODUCTION.md)

## Support

For installation issues:

1. Check the [Troubleshooting Guide](docs/TROUBLESHOOTING.md)
2. Review logs: `/var/log/pqc-vpn/` or `/var/log/syslog`
3. Open an issue on GitHub with:
   - Operating system details
   - Installation logs
   - Error messages
   - Configuration files (remove sensitive data)

---

**Installation complete!** Your PQC-VPN should now be ready for use.