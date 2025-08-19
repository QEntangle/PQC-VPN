# 🔐 PQC-VPN: Enterprise Post-Quantum Cryptography VPN v1.0.0

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![strongSwan](https://img.shields.io/badge/strongSwan-5.9.14+-green.svg)](https://strongswan.org/)
[![Docker](https://img.shields.io/badge/Docker-supported-blue.svg)](https://www.docker.com/)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-supported-blue.svg)](https://kubernetes.io/)
[![Enterprise Ready](https://img.shields.io/badge/Enterprise-Ready-green.svg)](https://github.com/QEntangle/PQC-VPN)

**Enterprise-grade VPN solution implementing NIST-standardized Post-Quantum Cryptography algorithms for quantum-resistant secure communications.**

---

## 🎯 **FIXED DEMO SETUP - READY TO USE!**

### ⚡ **One-Command Demo Setup (Recommended)**

```bash
git clone https://github.com/QEntangle/PQC-VPN.git
cd PQC-VPN
chmod +x setup-demo.sh
./setup-demo.sh
```

**✅ What you get in 5 minutes:**
- 🖥️ **One PQC-VPN Hub Server** with Post-Quantum Crypto
- 👥 **Three Demo Clients** (2 PKI + 1 PSK authentication)
- 🌐 **Web Management Interface** at https://localhost:8443
- 📊 **Monitoring Dashboard** at http://localhost:13000
- 📁 **Client Configuration Files** ready for distribution

### 🔧 **Fixed Production Issues**
- ✅ **Build Context Fixed**: Resolved Docker Compose build errors
- ✅ **Port Conflicts Fixed**: Non-conflicting ports (PostgreSQL: 15432, Redis: 16379, etc.)
- ✅ **Missing Dependencies Fixed**: All required configurations included
- ✅ **Environment Issues Fixed**: Clear .env setup with secure defaults

### 📋 **Alternative Setup Options**

| **Method** | **Use Case** | **Command** |
|------------|-------------|-------------|
| **One-Command Demo** | Quick demonstration | `./setup-demo.sh` |
| **Production Setup** | Enterprise deployment | `./start-pqc-vpn.sh --with-monitoring` |
| **Manual Setup** | Custom configuration | See [DEMO-SETUP-FIXED.md](DEMO-SETUP-FIXED.md) |

### 🎭 **Demo Access Information**
After running the demo setup:
- **Web Interface**: https://localhost:8443 (admin / DemoAdmin123!)
- **Grafana Monitoring**: http://localhost:13000 (admin / DemoGrafana123!)
- **API Endpoint**: https://localhost:9090
- **Client Configs**: `./demo-client-configs/`

📖 **[Complete Demo Guide →](DEMO-SETUP-FIXED.md)**

---

## 🎯 Enterprise Features

### Core Security
- **🔐 NIST-Standardized PQC**: Kyber-1024, Dilithium-5, and Falcon-1024 algorithms
- **🛡️ Quantum-Resistant**: Protection against current and future quantum computer attacks
- **🔑 Hybrid Authentication**: PKI, PSK, and multi-factor authentication support
- **📜 Certificate Management**: Automated certificate lifecycle management with Dilithium-5 signatures
- **🔄 Cryptographic Agility**: Easy algorithm switching and upgrade paths

### Enterprise Operations
- **📊 Advanced Monitoring**: Real-time connection monitoring, performance metrics, and security analytics
- **🎛️ Management Dashboard**: Web-based administration with role-based access control
- **🔧 API Integration**: RESTful APIs for enterprise system integration
- **📈 Scalability**: Support for thousands of concurrent connections
- **☁️ Multi-Cloud**: Deployment across AWS, Azure, GCP, and hybrid environments

### High Availability & Performance
- **⚖️ Load Balancing**: Active-active hub configuration with automatic failover
- **🌐 Global Deployment**: Multi-region deployment with intelligent routing
- **📦 Container Ready**: Docker and Kubernetes native deployment
- **🔄 Zero-Downtime Updates**: Rolling updates without service interruption
- **📊 Performance Optimization**: Optimized for high-throughput enterprise workloads

## 🚀 Quick Start

### Option 1: Docker Deployment (Recommended)

```bash
# Clone repository
git clone https://github.com/QEntangle/PQC-VPN.git
cd PQC-VPN

# Configure environment
export HUB_IP=your-public-ip
export ADMIN_PASSWORD=your-secure-password

# Deploy enterprise stack
cd docker
docker-compose -f docker-compose.production.yml up -d

# Verify deployment
docker exec pqc-vpn-hub /usr/local/oqs-openssl/bin/openssl list -signature-algorithms | grep dilithium
```

### Option 2: Kubernetes Deployment

```bash
# Clone repository
git clone https://github.com/QEntangle/PQC-VPN.git
cd PQC-VPN

# Configure Kubernetes deployment
kubectl apply -f kubernetes/namespace.yaml
kubectl apply -f kubernetes/pqc-vpn-production.yaml

# Monitor deployment
kubectl get pods -n pqc-vpn
```

### Option 3: Native Installation

```bash
# Ubuntu/Debian/CentOS
sudo ./scripts/install-hub-linux.sh --hub-ip YOUR_IP --enterprise-mode

# Windows Server
.\scripts\install-hub-windows.ps1 -HubIP "YOUR_IP" -EnterpriseMode
```

## 🏗️ Enterprise Architecture

### Hub-and-Spoke Topology

```
                    🔐 PQC-VPN Hub Cluster
                   ┌─────────────────────────┐
                   │    Load Balancer        │
                   │   (High Availability)   │
                   └─────────┬───────────────┘
                             │
                   ┌─────────┴───────────────┐
                   │                         │
              ┌────▼────┐               ┌────▼────┐
              │ Hub-01  │               │ Hub-02  │
              │Primary  │◄─────────────►│Standby  │
              └────┬────┘               └────┬────┘
                   │                         │
        ┌──────────┼─────────────────────────┼──────────┐
        │          │                         │          │
    ┌───▼───┐  ┌───▼───┐               ┌───▼───┐  ┌───▼───┐
    │Site-A │  │Site-B │               │Site-C │  │Site-D │
    │Spoke  │  │Spoke  │               │Spoke  │  │Spoke  │
    └───────┘  └───────┘               └───────┘  └───────┘
```

### Security Stack

```
┌─────────────────────────────────────────┐
│        Application Layer Security       │
│     (Role-based Access Control)        │
├─────────────────────────────────────────┤
│         Management Interface            │
│    (Web Dashboard + REST APIs)         │
├─────────────────────────────────────────┤
│          strongSwan IPsec Engine        │
│      (PQC-enabled configuration)       │
├─────────────────────────────────────────┤
│          OQS-OpenSSL Provider          │
│    (Post-Quantum Algorithm Support)    │
├─────────────────────────────────────────┤
│             liboqs Library             │
│       (NIST-standardized PQC)          │
├─────────────────────────────────────────┤
│         Operating System Kernel        │
│        (Linux/Windows/macOS)           │
└─────────────────────────────────────────┘
```

## 🔬 Post-Quantum Cryptography Implementation

### Supported Algorithms

| **Algorithm** | **Type** | **NIST Level** | **Key Size** | **Use Case** |
|---------------|----------|----------------|--------------|--------------| 
| **Kyber-1024** | KEM | 5 (256-bit) | 1,568 bytes | High Security |
| **Kyber-768** | KEM | 3 (192-bit) | 1,184 bytes | Balanced |
| **Kyber-512** | KEM | 1 (128-bit) | 800 bytes | High Performance |
| **Dilithium-5** | Signature | 5 (256-bit) | 4,595 bytes | High Security |
| **Dilithium-3** | Signature | 3 (192-bit) | 3,293 bytes | Balanced |
| **Dilithium-2** | Signature | 2 (128-bit) | 2,420 bytes | High Performance |
| **Falcon-1024** | Signature | 5 (256-bit) | 1,793 bytes | Compact Signatures |

### Security Configuration Profiles

```yaml
# Maximum Security Profile
maximum_security:
  ike: aes256gcm16-sha512-kyber1024-dilithium5!
  esp: aes256gcm16-sha512-kyber1024!
  signature: dilithium5
  lifetime: 3600s

# Balanced Security Profile  
balanced_security:
  ike: aes256gcm16-sha384-kyber768-dilithium3!
  esp: aes256gcm16-sha384-kyber768!
  signature: dilithium3
  lifetime: 7200s

# High Performance Profile
high_performance:
  ike: aes128gcm16-sha256-kyber512-dilithium2!
  esp: aes128gcm16-sha256-kyber512!
  signature: dilithium2
  lifetime: 14400s
```

## 💼 Enterprise Management

### Web Management Dashboard

Access the enterprise dashboard at: `https://your-hub-ip:8443`

**Features:**
- **📊 Real-time Monitoring**: Connection status, bandwidth usage, security metrics
- **👥 User Management**: User provisioning, role assignment, certificate management
- **🔧 Configuration Management**: Security policies, algorithm selection, network settings
- **📈 Analytics**: Traffic analysis, security reports, performance metrics
- **🚨 Alerting**: Real-time security alerts and system notifications
- **📋 Audit Logging**: Comprehensive audit trails for compliance

### Command Line Management

```bash
# User management
sudo python3 tools/pqc-vpn-manager.py user add alice alice@company.com --role admin --auth-type pki
sudo python3 tools/pqc-vpn-manager.py user list --role-filter admin
sudo python3 tools/pqc-vpn-manager.py user revoke bob --reason "terminated"

# Certificate management
sudo python3 tools/pqc-vpn-manager.py cert generate --algorithm dilithium5 --validity 365
sudo python3 tools/pqc-vpn-manager.py cert rotate --dry-run
sudo python3 tools/pqc-vpn-manager.py cert audit --expired

# System monitoring
sudo python3 tools/pqc-vpn-manager.py status --detailed
sudo python3 tools/pqc-vpn-manager.py metrics --export-format json
sudo python3 tools/pqc-vpn-manager.py security-scan --full
```

### REST API Integration

```bash
# Authentication
curl -X POST https://hub-ip:8443/api/auth \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"secure_password"}'

# User management
curl -X GET https://hub-ip:8443/api/users \
  -H "Authorization: Bearer $TOKEN"

# Connection monitoring
curl -X GET https://hub-ip:8443/api/connections/active \
  -H "Authorization: Bearer $TOKEN"

# Security metrics
curl -X GET https://hub-ip:8443/api/metrics/security \
  -H "Authorization: Bearer $TOKEN"
```

## 🚀 Deployment Options

### Production Deployment Architectures

#### Single Data Center
```yaml
deployment_type: single_datacenter
hub_configuration:
  primary_hub: hub-01.company.com
  standby_hub: hub-02.company.com
  load_balancer: pqc-vpn-lb.company.com
  database: postgresql-cluster
```

#### Multi-Region Deployment
```yaml
deployment_type: multi_region
regions:
  us_east:
    hub: pqc-vpn-us-east.company.com
    spokes: ["office-ny", "office-boston"]
  us_west:
    hub: pqc-vpn-us-west.company.com
    spokes: ["office-sf", "office-seattle"]
  europe:
    hub: pqc-vpn-eu.company.com
    spokes: ["office-london", "office-berlin"]
```

#### Cloud-Native Deployment
```yaml
deployment_type: cloud_native
kubernetes:
  replicas: 3
  service_type: LoadBalancer
  persistent_storage: true
  auto_scaling: true
monitoring:
  prometheus: enabled
  grafana: enabled
  alertmanager: enabled
```

### Infrastructure Requirements

#### Minimum Requirements
- **CPU**: 4 cores, 2.4 GHz
- **RAM**: 8 GB
- **Storage**: 100 GB SSD
- **Network**: 1 Gbps
- **OS**: Ubuntu 20.04+, CentOS 8+, Windows Server 2019+

#### Recommended for Enterprise
- **CPU**: 16 cores, 3.2 GHz
- **RAM**: 32 GB
- **Storage**: 500 GB NVMe SSD
- **Network**: 10 Gbps
- **OS**: Ubuntu 22.04 LTS, Windows Server 2022

#### High-Scale Enterprise
- **CPU**: 32+ cores, 3.5 GHz
- **RAM**: 128 GB
- **Storage**: 2 TB NVMe SSD (RAID 10)
- **Network**: 25+ Gbps
- **OS**: Ubuntu 22.04 LTS, RHEL 9

## 📚 Documentation

### Quick Start Guides
- **[Fixed Demo Setup](DEMO-SETUP-FIXED.md)**: One-command demo with 1 hub + 3 clients
- **[Quick Start Fixed](QUICKSTART-FIXED.md)**: Step-by-step setup guide
- **[Production Setup](start-pqc-vpn.sh)**: Automated production deployment

### Administrator Guides
- **[Installation Guide](docs/installation.md)**: Detailed installation procedures
- **[Configuration Guide](docs/configuration.md)**: Advanced configuration options
- **[Security Guide](docs/security.md)**: Security best practices and hardening
- **[Troubleshooting Guide](docs/troubleshooting.md)**: Common issues and solutions
- **[API Reference](docs/api-reference.md)**: Complete API documentation

### User Guides
- **[Client Setup Guide](docs/client-setup.md)**: Client installation and configuration
- **[Mobile Client Guide](docs/mobile-clients.md)**: iOS and Android client setup
- **[User Management](docs/user-management.md)**: User administration procedures

### Technical Documentation
- **[Architecture Overview](docs/architecture.md)**: System architecture and design
- **[PQC Implementation](docs/pqc-implementation.md)**: Post-quantum cryptography details
- **[Performance Tuning](docs/performance-tuning.md)**: Optimization guidelines
- **[Monitoring Guide](docs/monitoring.md)**: Monitoring and alerting setup

## ⚠️ Production Deployment Checklist

### Security Configuration
- [ ] Change all default passwords
- [ ] Generate production certificates
- [ ] Configure firewall rules
- [ ] Enable audit logging
- [ ] Set up intrusion detection
- [ ] Configure backup procedures

### Network Configuration
- [ ] Configure load balancing
- [ ] Set up DNS records
- [ ] Configure monitoring
- [ ] Test failover procedures
- [ ] Validate connectivity
- [ ] Performance testing

### Operational Readiness
- [ ] Train administration staff
- [ ] Document procedures
- [ ] Set up monitoring alerts
- [ ] Configure backup/recovery
- [ ] Test disaster recovery
- [ ] Schedule maintenance windows

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Contact & Support

### Commercial Inquiries
- **Email**: sales@qentangle.com
- **Phone**: +1-800-QUANTUM (1-800-782-6886)
- **Web**: https://qentangle.com/pqc-vpn

### Technical Support
- **Email**: support@qentangle.com
- **Documentation**: https://docs.qentangle.com/pqc-vpn
- **Community**: https://community.qentangle.com

### Security Issues
- **Security Email**: security@qentangle.com
- **PGP Key**: Available at https://qentangle.com/security.asc
- **Responsible Disclosure**: 90-day disclosure policy

## 🙏 Acknowledgments

- **strongSwan Team**: Core IPsec implementation
- **Open Quantum Safe Project**: Post-quantum cryptography libraries
- **NIST**: Post-quantum cryptography standardization
- **Enterprise Contributors**: Beta testing and feedback

---

## 🔐 Enterprise-Ready Quantum Security

**PQC-VPN v1.0.0 delivers enterprise-grade post-quantum cryptography today.**

Protect your organization's communications against current and future quantum computer threats with NIST-standardized algorithms, enterprise management features, and 24x7 support.

[![Demo Setup](https://img.shields.io/badge/Try-Demo-green.svg?style=for-the-badge)](DEMO-SETUP-FIXED.md)
[![Contact Sales](https://img.shields.io/badge/Contact-Sales-blue.svg?style=for-the-badge)](mailto:sales@qentangle.com)

---

*🔐 **PQC-VPN v1.0.0** - Enterprise quantum-safe networking solution*