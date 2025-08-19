# 🔐 PQC-VPN: Real Post-Quantum Cryptography VPN v2.0.0

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![strongSwan](https://img.shields.io/badge/strongSwan-5.9.14+-green.svg)](https://strongswan.org/)
[![Docker](https://img.shields.io/badge/Docker-supported-blue.svg)](https://www.docker.com/)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-supported-blue.svg)](https://kubernetes.io/)
[![Real PQC](https://img.shields.io/badge/PQC-Real%20Implementation-red.svg)](https://github.com/QEntangle/PQC-VPN)

**VPN with ACTUAL Post-Quantum Cryptography implementation using real Kyber-1024 and Dilithium-5 algorithms.**

⚠️ **This is NOT a simulation** - This implements real NIST-standardized post-quantum algorithms that protect against quantum computer attacks.

## 🎯 What Makes This Different

| Feature | Other "PQC" VPNs | **This PQC-VPN** |
|---------|------------------|-------------------|
| **Algorithms** | Classical crypto only | ✅ **Real Kyber-1024 + Dilithium-5** |
| **Implementation** | Promises/roadmaps | ✅ **Working implementation now** |
| **Certificates** | RSA/ECDSA | ✅ **Dilithium-5 signatures** |
| **Key Exchange** | ECDH/DHE | ✅ **Kyber-1024 KEM** |
| **Quantum Safe** | Future maybe | ✅ **Quantum-safe today** |
| **Verification** | Trust us | ✅ **Verifiable with commands** |

## 🚀 Quick Start (5 Minutes)

### Option 1: Docker (Fastest)

```bash
# Clone repository
git clone https://github.com/QEntangle/PQC-VPN.git
cd PQC-VPN

# Set your IP and deploy
export HUB_IP=your-actual-ip
cd docker
docker-compose -f docker-compose.production.yml up -d

# Verify real PQC is working
docker exec pqc-vpn-hub-real /usr/local/oqs-openssl/bin/openssl list -signature-algorithms | grep dilithium
```

### Option 2: Native Linux

```bash
# Clone and install
git clone https://github.com/QEntangle/PQC-VPN.git
cd PQC-VPN
sudo ./scripts/install-hub-linux-real.sh --hub-ip YOUR_IP
```

### Option 3: Windows

```powershell
# Run as Administrator
git clone https://github.com/QEntangle/PQC-VPN.git
cd PQC-VPN
.\scripts\install-hub-windows-real.ps1 -HubIP "YOUR_IP"
```

**📖 Complete Guide**: [QUICKSTART-REAL.md](QUICKSTART-REAL.md)

## 🔬 Verify It's Real PQC

### Check Algorithms Are Available

```bash
# Verify Dilithium signatures
/usr/local/oqs-openssl/bin/openssl list -signature-algorithms | grep dilithium

# Verify Kyber key exchange
/usr/local/oqs-openssl/bin/openssl list -kem-algorithms | grep kyber

# Expected output:
# dilithium2, dilithium3, dilithium5
# kyber512, kyber768, kyber1024
```

### Check Certificates Use PQC

```bash
# Check CA certificate
/usr/local/oqs-openssl/bin/openssl x509 -in /etc/ipsec.d/cacerts/ca-cert.pem -text | grep "Signature Algorithm"

# Should show: Signature Algorithm: dilithium5
# NOT: Signature Algorithm: sha256WithRSAEncryption
```

### Check strongSwan Configuration

```bash
# Verify configuration uses PQC algorithms
cat /etc/ipsec.conf | grep -E "(kyber|dilithium)"

# Should show lines like:
# ike=aes256gcm16-sha512-kyber1024-dilithium5!
# esp=aes256gcm16-sha512-kyber1024!
```

### Check Active Connections

```bash
# Verify live connections use PQC
/usr/local/strongswan/sbin/ipsec statusall | grep -E "(kyber|dilithium)"

# Shows real PQC in active VPN tunnels
```

## 🏗️ Architecture

### Real PQC Implementation Stack

```
┌─────────────────────────────────────────┐
│           Management Dashboard          │
│          (Basic monitoring)            │
├─────────────────────────────────────────┤
│         strongSwan IPsec Engine         │
│      (Built with PQC extensions)       │
├─────────────────────────────────────────┤
│          OQS-OpenSSL Provider          │
│      (Real PQC algorithm support)      │
├─────────────────────────────────────────┤
│             liboqs Library             │
│    (NIST standardized algorithms)      │
├─────────────────────────────────────────┤
│        Operating System Kernel         │
│         (Linux/Windows/macOS)          │
└─────────────────────────────────────────┘
```

### Network Topology

```
                🔐 Hub (PQC-VPN Server)
                Real Kyber + Dilithium
                      |
          ┌───────────┼───────────┐
          │           │           │
      👤 Alice    👤 Bob     👤 Charlie
    (PKI Auth)  (PSK Auth) (Hybrid Auth)
    
All connections protected by:
✅ Kyber-1024 key exchange
✅ Dilithium-5 signatures  
✅ AES-256-GCM encryption
```

## 📦 What's Included

### Core Components

- **🔐 Real PQC Hub**: strongSwan with liboqs + OQS-OpenSSL
- **📱 PQC Clients**: Cross-platform spoke clients
- **🖥️ Management Dashboard**: Basic monitoring and management
- **🔑 Certificate Authority**: Dilithium-5 certificate generation
- **👥 User Management**: Basic user administration
- **📊 Monitoring**: Basic connection monitoring

### Supported Algorithms

| **Algorithm** | **Type** | **NIST Level** | **Status** |
|---------------|----------|----------------|------------|
| **Kyber-1024** | Key Exchange | 5 (256-bit) | ✅ **Implemented** |
| **Kyber-768** | Key Exchange | 3 (192-bit) | ✅ **Implemented** |
| **Kyber-512** | Key Exchange | 1 (128-bit) | ✅ **Implemented** |
| **Dilithium-5** | Digital Signature | 5 (256-bit) | ✅ **Implemented** |
| **Dilithium-3** | Digital Signature | 3 (192-bit) | ✅ **Implemented** |
| **Dilithium-2** | Digital Signature | 2 (128-bit) | ✅ **Implemented** |
| **Falcon-1024** | Digital Signature | 5 (256-bit) | ✅ **Implemented** |

### Authentication Methods

- **🔐 PKI**: X.509 certificates with Dilithium-5 signatures
- **🔑 PSK**: Pre-shared keys
- **🛡️ Hybrid**: PKI + PSK for enhanced security

## 💻 Platform Support

### Operating Systems

| **Platform** | **Status** | **Installation** |
|--------------|------------|------------------|
| **Ubuntu 20.04+** | ✅ Full Support | `install-hub-linux-real.sh` |
| **CentOS 8+** | ✅ Full Support | `install-hub-linux-real.sh` |
| **Debian 11+** | ✅ Full Support | `install-hub-linux-real.sh` |
| **Windows 10/11** | ✅ Full Support | `install-hub-windows-real.ps1` |
| **Windows Server** | ✅ Full Support | `install-hub-windows-real.ps1` |
| **macOS 11+** | ⚠️ Experimental | Manual build required |

### Deployment Options

- **🐳 Docker**: `docker-compose.production.yml`
- **☸️ Kubernetes**: `kubernetes/pqc-vpn-production.yaml`
- **☁️ Cloud**: AWS, Azure, GCP support
- **🖥️ Bare Metal**: Native installation scripts

## 🎯 Use Cases

### Enterprise Network Security
- **Remote Workers**: Quantum-safe VPN for employees
- **Site-to-Site**: Secure branch office connections
- **Cloud Hybrid**: Secure cloud-to-premises links
- **IoT Security**: Post-quantum device protection

### Government & Defense
- **Classified Networks**: Future-proof secure communications
- **Critical Infrastructure**: Quantum-threat protection
- **International Communications**: Diplomatic secure channels
- **Research Networks**: Academic collaboration security

### Financial Services
- **Trading Networks**: High-frequency trading protection
- **Banking**: Customer data transmission security
- **Payment Processing**: Transaction security
- **Regulatory Compliance**: Future quantum regulations

## 📊 Performance

### Performance Considerations

⚠️ **Post-quantum cryptography introduces computational overhead compared to classical algorithms.**

- **CPU Usage**: PQC algorithms are more computationally intensive
- **Memory Usage**: Larger key sizes require more memory
- **Network Overhead**: Larger certificates and signatures
- **Connection Establishment**: Slower initial handshake

### Recommendations

- Use **Kyber-512** for high-performance scenarios requiring lower latency
- Use **Kyber-768** for balanced security and performance
- Use **Kyber-1024** for maximum security where performance is less critical
- Test performance in your specific environment before production deployment

## 🔒 Security

### Quantum Threat Protection

✅ **Protects Against**:
- Shor's Algorithm (breaks RSA, ECDSA)
- Grover's Algorithm (weakens symmetric crypto)
- Future quantum computers
- Harvest-now-decrypt-later attacks

✅ **Security Standards**:
- NIST Post-Quantum Cryptography standards
- Uses algorithms from NIST Round 3 standardization

### Cryptographic Agility

```yaml
# Easy algorithm switching
high_security:
  ike: aes256gcm16-sha512-kyber1024-dilithium5
  esp: aes256gcm16-sha512-kyber1024

balanced:
  ike: aes256gcm16-sha384-kyber768-dilithium3
  esp: aes256gcm16-sha384-kyber768

performance:
  ike: aes128gcm16-sha256-kyber512-dilithium2
  esp: aes128gcm16-sha256-kyber512
```

## 🛠️ Management & Monitoring

### Web Dashboard

- **URL**: `https://your-hub-ip:8443`
- **Features**: Basic monitoring, user management, certificate administration
- **Authentication**: Username/password authentication

### Command Line Tools

```bash
# User management
sudo python3 tools/pqc-vpn-manager.py user add alice alice@company.com --auth-type pki

# System monitoring
sudo python3 tools/pqc-vpn-manager.py status

# Certificate management
sudo python3 tools/pqc-vpn-manager.py cert rotate
```

## 📚 Documentation

### Quick References
- **[QUICKSTART-REAL.md](QUICKSTART-REAL.md)**: Get running in 5 minutes
- **[DEMO-QUICKSTART.md](DEMO-QUICKSTART.md)**: Demo environment setup

### Detailed Guides
- **Installation**: Platform-specific installation guides
- **Configuration**: Advanced configuration options
- **Troubleshooting**: Common issues and solutions
- **Security**: Best practices and hardening

### Algorithm Details
- **Kyber**: NIST ML-KEM implementation details
- **Dilithium**: NIST ML-DSA implementation details
- **Migration**: Transition from classical cryptography

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Clone repository
git clone https://github.com/QEntangle/PQC-VPN.git
cd PQC-VPN

# Set up development environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run tests
pytest tests/

# Code formatting
black tools/ scripts/
flake8 tools/ scripts/
```

## 🎯 Roadmap

### v2.1 (Q2 2025)
- [ ] Performance optimizations for PQC operations
- [ ] Enhanced monitoring and metrics collection
- [ ] Improved mobile client applications
- [ ] Additional certificate management features

### v2.2 (Q3 2025)
- [ ] Integration with hardware security modules (HSM)
- [ ] RADIUS/LDAP authentication support
- [ ] Advanced load balancing features
- [ ] Enhanced logging and audit capabilities

### v3.0 (Q4 2025)
- [ ] Full IPv6 post-quantum support
- [ ] Multi-protocol support (WireGuard, OpenVPN)
- [ ] Enterprise directory integration
- [ ] Advanced threat detection

## ⚠️ Important Notes

### Production Deployment
- **Update default passwords** immediately after installation
- **Use proper certificates** in production (not self-signed)
- **Regular security updates** for all components
- **Monitor for security advisories** on PQC algorithms

### Performance Considerations
- **PQC overhead**: Expect performance impact compared to classical algorithms
- **Memory usage**: Higher than classical algorithms
- **Network overhead**: Larger packet sizes
- **CPU intensive**: Especially key generation

### Compatibility
- **Client compatibility**: Requires PQC-enabled clients
- **Network equipment**: May need MTU adjustments
- **Legacy systems**: Migration planning required

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Support

### Community Support
- **GitHub Issues**: [Report bugs](https://github.com/QEntangle/PQC-VPN/issues)
- **Discussions**: [Community Q&A](https://github.com/QEntangle/PQC-VPN/discussions)
- **Documentation**: Comprehensive guides included

### Security Issues
For security vulnerabilities, please email: security@qentangle.com

## 🙏 Acknowledgments

- **strongSwan Team**: IPsec foundation
- **Open Quantum Safe**: PQC algorithm implementations
- **NIST**: Post-quantum cryptography standardization
- **Contributors**: Community developers and testers

---

## 🎉 Ready for the Quantum Future

**This is real post-quantum cryptography, implemented today.**

Your network traffic is now protected against both classical and quantum computer attacks using NIST-standardized algorithms.

[![Get Started](https://img.shields.io/badge/Get%20Started-Now-green.svg?style=for-the-badge)](QUICKSTART-REAL.md)
[![View Demo](https://img.shields.io/badge/View%20Demo-Setup-blue.svg?style=for-the-badge)](DEMO-QUICKSTART.md)

---

*🔐 **PQC-VPN v2.0.0** - Protecting today's communications from tomorrow's quantum threats*
