# 🚀 PQC-VPN Quick Start Guide

**Get your quantum-safe VPN running in 10 minutes!**

## 📋 Prerequisites

### System Requirements
- **Linux**: Ubuntu 20.04+, CentOS 8+, or Debian 11+
- **Windows**: Windows 10/11 or Windows Server 2019+
- **macOS**: macOS 11+ (experimental)
- **Hardware**: 4+ CPU cores, 8GB+ RAM, 100GB+ storage

### Network Requirements
- Public IP address for hub server
- Ports: 500/UDP, 4500/UDP, 8443/TCP
- Internet connectivity for all nodes

## 🐳 Option 1: Docker Deployment (Fastest)

### Step 1: Clone Repository
```bash
git clone https://github.com/QEntangle/PQC-VPN.git
cd PQC-VPN
```

### Step 2: Configure Environment
```bash
# Set your public IP address
export HUB_IP=YOUR_PUBLIC_IP

# Set secure admin password
export ADMIN_PASSWORD=your_secure_password_here

# Optional: Customize domain
export DOMAIN_NAME=vpn.yourcompany.com
```

### Step 3: Deploy with Docker
```bash
cd docker
docker-compose -f docker-compose.production.yml up -d
```

### Step 4: Verify Deployment
```bash
# Check containers are running
docker ps

# Verify PQC algorithms are available
docker exec pqc-vpn-hub /usr/local/oqs-openssl/bin/openssl list -signature-algorithms | grep dilithium

# Check web interface
curl -k https://$HUB_IP:8443/health
```

### Step 5: Access Management Dashboard
Open your browser to: `https://YOUR_IP:8443`
- **Username**: `admin`
- **Password**: `your_secure_password_here`

## 🖥️ Option 2: Native Linux Installation

### Step 1: Clone and Prepare
```bash
git clone https://github.com/QEntangle/PQC-VPN.git
cd PQC-VPN
chmod +x scripts/*.sh
```

### Step 2: Install Hub (Ubuntu/Debian)
```bash
sudo ./scripts/install-hub-linux.sh \
  --hub-ip YOUR_PUBLIC_IP \
  --admin-password your_secure_password \
  --enable-monitoring \
  --enable-api
```

### Step 3: Install Hub (CentOS/RHEL)
```bash
sudo ./scripts/install-hub-linux.sh \
  --hub-ip YOUR_PUBLIC_IP \
  --admin-password your_secure_password \
  --distro centos \
  --enable-monitoring \
  --enable-api
```

### Step 4: Verify Installation
```bash
# Check strongSwan status
sudo ipsec status

# Verify PQC support
/usr/local/oqs-openssl/bin/openssl list -signature-algorithms | grep dilithium

# Check web dashboard
sudo systemctl status pqc-vpn-dashboard
```

## 🪟 Option 3: Windows Installation

### Step 1: Download and Prepare
```powershell
# Clone repository (Git for Windows required)
git clone https://github.com/QEntangle/PQC-VPN.git
cd PQC-VPN

# Run as Administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Step 2: Install Hub
```powershell
.\scripts\install-hub-windows.ps1 `
  -HubIP "YOUR_PUBLIC_IP" `
  -AdminPassword "your_secure_password" `
  -EnableMonitoring `
  -EnableAPI
```

### Step 3: Verify Installation
```powershell
# Check strongSwan service
Get-Service strongSwan

# Check web dashboard service
Get-Service PQC-VPN-Dashboard

# Test PQC algorithms
& "C:\Program Files\strongSwan\bin\openssl.exe" list -signature-algorithms | Select-String "dilithium"
```

## ☸️ Option 4: Kubernetes Deployment

### Step 1: Prepare Kubernetes Environment
```bash
# Ensure kubectl is configured
kubectl cluster-info

# Create namespace
kubectl create namespace pqc-vpn
```

### Step 2: Configure Deployment
```bash
# Edit configuration
cp kubernetes/values-example.yaml kubernetes/values.yaml
nano kubernetes/values.yaml

# Set your values:
# hubIP: "YOUR_PUBLIC_IP"
# adminPassword: "your_secure_password"
# domain: "vpn.yourcompany.com"
```

### Step 3: Deploy to Kubernetes
```bash
# Apply configurations
kubectl apply -f kubernetes/namespace.yaml
kubectl apply -f kubernetes/configmap.yaml
kubectl apply -f kubernetes/secrets.yaml
kubectl apply -f kubernetes/deployment.yaml
kubectl apply -f kubernetes/service.yaml
kubectl apply -f kubernetes/ingress.yaml
```

### Step 4: Verify Deployment
```bash
# Check pods
kubectl get pods -n pqc-vpn

# Check services
kubectl get svc -n pqc-vpn

# Get external IP
kubectl get ingress -n pqc-vpn
```

## 👥 Adding Your First Users

### Method 1: Web Dashboard
1. Login to `https://YOUR_IP:8443`
2. Navigate to **Users** → **Add User**
3. Fill in user details:
   - Username: `alice`
   - Email: `alice@company.com`
   - Authentication: `PKI` or `PSK`
4. Click **Generate Configuration**
5. Download client configuration

### Method 2: Command Line
```bash
# Add PKI user
sudo python3 tools/pqc-vpn-manager.py user add alice alice@company.com --auth-type pki

# Add PSK user
sudo python3 tools/pqc-vpn-manager.py user add bob bob@company.com --auth-type psk --psk "secure_shared_key"

# Generate client configuration
sudo python3 tools/pqc-vpn-manager.py client-config alice --output-format strongswan
```

## 📱 Client Installation

### Linux Client
```bash
# Download client package
wget https://YOUR_HUB_IP:8443/api/client/download/linux
tar -xzf pqc-vpn-client-linux.tar.gz

# Install client
sudo ./install-spoke-linux.sh --hub-ip YOUR_HUB_IP --username alice
```

### Windows Client
```powershell
# Download and install
Invoke-WebRequest -Uri "https://YOUR_HUB_IP:8443/api/client/download/windows" -OutFile "pqc-vpn-client.msi"
Start-Process msiexec.exe -ArgumentList "/i pqc-vpn-client.msi /quiet" -Wait
```

### Android/iOS
1. Install strongSwan app from app store
2. Import client configuration from web dashboard
3. Connect using the app

## 🔧 Basic Configuration

### Security Profiles
```bash
# List available profiles
sudo python3 tools/pqc-vpn-manager.py profile list

# Apply maximum security profile
sudo python3 tools/pqc-vpn-manager.py profile apply maximum-security

# Apply balanced performance profile
sudo python3 tools/pqc-vpn-manager.py profile apply balanced

# Apply high performance profile
sudo python3 tools/pqc-vpn-manager.py profile apply high-performance
```

### Network Configuration
```bash
# Configure hub network settings
sudo python3 tools/pqc-vpn-manager.py network configure \
  --subnet 10.10.0.0/16 \
  --dns-servers 8.8.8.8,8.8.4.4 \
  --domain company.local
```

### Certificate Management
```bash
# Generate new CA certificate
sudo python3 tools/pqc-vpn-manager.py cert generate-ca --algorithm dilithium5

# Generate server certificate
sudo python3 tools/pqc-vpn-manager.py cert generate-server --hostname vpn.company.com

# List certificates
sudo python3 tools/pqc-vpn-manager.py cert list
```

## 📊 Monitoring and Verification

### Check System Status
```bash
# Overall system status
sudo python3 tools/pqc-vpn-manager.py status

# Check active connections
sudo ipsec statusall

# Monitor real-time connections
sudo python3 tools/connection-monitor.py --live
```

### Verify PQC Implementation
```bash
# Check available PQC algorithms
/usr/local/oqs-openssl/bin/openssl list -signature-algorithms | grep -E "(dilithium|falcon)"
/usr/local/oqs-openssl/bin/openssl list -kem-algorithms | grep kyber

# Verify certificates use PQC
/usr/local/oqs-openssl/bin/openssl x509 -in /etc/ipsec.d/cacerts/ca-cert.pem -text | grep "Signature Algorithm"

# Check active VPN connections use PQC
sudo ipsec statusall | grep -E "(kyber|dilithium)"
```

### Performance Monitoring
```bash
# Real-time performance metrics
sudo python3 tools/metrics-collector.py --dashboard

# Generate performance report
sudo python3 tools/pqc-vpn-manager.py report performance --last-24h

# Network throughput test
sudo python3 tools/pqc-vpn-manager.py test throughput --duration 60
```

## 🔒 Security Verification

### Authentication Test
```bash
# Test PKI authentication
sudo python3 tools/pqc-vpn-manager.py test auth-pki --user alice

# Test PSK authentication
sudo python3 tools/pqc-vpn-manager.py test auth-psk --user bob

# Test multi-factor authentication
sudo python3 tools/pqc-vpn-manager.py test auth-mfa --user admin
```

### Security Audit
```bash
# Run security audit
sudo python3 tools/pqc-vpn-manager.py audit security

# Check for vulnerabilities
sudo python3 tools/pqc-vpn-manager.py scan vulnerabilities

# Verify compliance
sudo python3 tools/pqc-vpn-manager.py compliance check --standard nist
```

## 🚨 Troubleshooting

### Common Issues

#### Connection Problems
```bash
# Check firewall rules
sudo ufw status
sudo iptables -L

# Verify DNS resolution
nslookup YOUR_HUB_IP
dig YOUR_HUB_IP

# Test network connectivity
telnet YOUR_HUB_IP 500
telnet YOUR_HUB_IP 4500
```

#### Certificate Issues
```bash
# Regenerate certificates
sudo python3 tools/pqc-vpn-manager.py cert regenerate --force

# Check certificate validity
sudo python3 tools/pqc-vpn-manager.py cert verify --all

# Fix certificate permissions
sudo chown -R root:root /etc/ipsec.d/
sudo chmod 600 /etc/ipsec.d/private/*
sudo chmod 644 /etc/ipsec.d/certs/*
```

#### Performance Issues
```bash
# Check system resources
htop
iostat 1 5
netstat -i

# Optimize system performance
sudo python3 tools/pqc-vpn-manager.py optimize --performance

# Check for bottlenecks
sudo python3 tools/pqc-vpn-manager.py diagnose --performance
```

### Getting Help
```bash
# View detailed logs
sudo journalctl -u strongswan -f
sudo tail -f /var/log/charon.log

# Generate debug report
sudo python3 tools/pqc-vpn-manager.py debug-report --include-logs

# Check documentation
sudo python3 tools/pqc-vpn-manager.py help --topic troubleshooting
```

## 🎯 Next Steps

### Production Readiness
1. **Change Default Passwords**: Update all default credentials
2. **Configure Backup**: Set up automated backups
3. **Enable Monitoring**: Configure alerting and monitoring
4. **Security Hardening**: Apply security best practices
5. **Load Testing**: Validate performance under load

### Advanced Features
1. **High Availability**: Configure clustered deployment
2. **LDAP Integration**: Connect to corporate directory
3. **API Integration**: Integrate with existing systems
4. **Mobile Management**: Deploy mobile device management
5. **Compliance**: Configure audit logging and reporting

### Scaling
1. **Multi-Region**: Deploy across multiple regions
2. **Load Balancing**: Configure load balancers
3. **Auto-Scaling**: Set up automatic scaling
4. **Monitoring**: Deploy comprehensive monitoring
5. **Disaster Recovery**: Plan disaster recovery procedures

## 📚 Additional Resources

- **[Installation Guide](docs/installation.md)**: Detailed installation procedures
- **[Configuration Guide](docs/configuration.md)**: Advanced configuration options
- **[Security Guide](docs/security.md)**: Security best practices
- **[API Documentation](docs/api-reference.md)**: REST API reference
- **[Troubleshooting Guide](docs/troubleshooting.md)**: Problem resolution

## 🎉 Success!

Your PQC-VPN is now running with quantum-safe cryptography!

### Verify Your Installation
✅ Hub server running with PQC algorithms  
✅ Web dashboard accessible  
✅ Users can authenticate and connect  
✅ Traffic encrypted with post-quantum cryptography  

### What You've Achieved
🔐 **Quantum-Safe Security**: Your network is protected against quantum computer attacks  
🚀 **Enterprise Features**: Full management dashboard and monitoring  
⚡ **High Performance**: Optimized for enterprise workloads  
🌐 **Scalable Architecture**: Ready for growth and expansion  

**Welcome to the quantum-safe future of networking!**

---

*🔐 **PQC-VPN v1.0.0** - Enterprise quantum-safe VPN solution*
