# PQC-VPN Troubleshooting Guide

This guide helps you diagnose and resolve common issues with PQC-VPN.

## Table of Contents

- [General Troubleshooting](#general-troubleshooting)
- [Installation Issues](#installation-issues)
- [Connection Problems](#connection-problems)
- [Certificate Issues](#certificate-issues)
- [Performance Problems](#performance-problems)
- [Platform-Specific Issues](#platform-specific-issues)
- [Log Analysis](#log-analysis)
- [Diagnostic Tools](#diagnostic-tools)

## General Troubleshooting

### Basic Diagnostic Steps

1. **Check service status**:
   ```bash
   sudo systemctl status strongswan
   sudo ipsec status
   ```

2. **Verify configuration**:
   ```bash
   sudo ipsec --checkconfig
   ```

3. **Check connectivity**:
   ```bash
   ping hub-ip
   telnet hub-ip 500
   nc -u hub-ip 4500
   ```

4. **Review logs**:
   ```bash
   sudo journalctl -u strongswan -f
   tail -f /var/log/syslog | grep -i ipsec
   ```

### Quick Health Check

Run the built-in health check:
```bash
sudo ./scripts/monitor-vpn.sh health
```

Or use the Python tool:
```bash
sudo python3 tools/connection-monitor.py status
```

## Installation Issues

### Issue: Script Permission Denied

**Symptoms**: 
```
bash: ./install-hub-linux.sh: Permission denied
```

**Solution**:
```bash
chmod +x scripts/install-hub-linux.sh
sudo ./scripts/install-hub-linux.sh
```

### Issue: Package Installation Fails

**Symptoms**: apt/yum package installation errors

**Solutions**:

1. **Update package lists**:
   ```bash
   sudo apt update        # Ubuntu/Debian
   sudo yum update        # CentOS/RHEL
   ```

2. **Fix broken packages**:
   ```bash
   sudo apt --fix-broken install    # Ubuntu/Debian
   sudo yum clean all && sudo yum makecache    # CentOS/RHEL
   ```

3. **Install build dependencies**:
   ```bash
   sudo apt install build-essential    # Ubuntu/Debian
   sudo yum groupinstall "Development Tools"    # CentOS/RHEL
   ```

### Issue: liboqs Compilation Fails

**Symptoms**: cmake or ninja build errors

**Solutions**:

1. **Install cmake and ninja**:
   ```bash
   sudo apt install cmake ninja-build    # Ubuntu/Debian
   sudo yum install cmake ninja-build    # CentOS/RHEL
   ```

2. **Check compiler version**:
   ```bash
   gcc --version    # Should be 7.0 or higher
   ```

3. **Clean and rebuild**:
   ```bash
   cd liboqs/build
   rm -rf *
   cmake -G Ninja -DCMAKE_INSTALL_PREFIX=/usr/local ..
   ninja
   sudo ninja install
   sudo ldconfig
   ```

### Issue: strongSwan Configuration Fails

**Symptoms**: ./configure script fails

**Solutions**:

1. **Install missing dependencies**:
   ```bash
   sudo apt install libssl-dev libgmp-dev libtspi-dev
   ```

2. **Check configure options**:
   ```bash
   ./configure --help | grep -i oqs
   ```

3. **Use minimal configuration**:
   ```bash
   ./configure --enable-openssl --enable-oqs --disable-des
   ```

## Connection Problems

### Issue: IKE Negotiation Fails

**Symptoms**: 
```
no IKE config found for host-ip...host-ip, sending NO_PROPOSAL_CHOSEN
```

**Solutions**:

1. **Check IKE algorithms**:
   ```bash
   # Edit /etc/ipsec.conf
   ike=aes256gcm16-prfsha256-kyber1024!
   ```

2. **Verify certificates**:
   ```bash
   sudo ipsec listcerts
   sudo ipsec listpubkeys
   ```

3. **Check time synchronization**:
   ```bash
   sudo ntpdate -s time.nist.gov
   sudo systemctl enable ntp
   ```

### Issue: Connection Timeouts

**Symptoms**: Connection attempts timeout

**Solutions**:

1. **Check firewall**:
   ```bash
   # Test connectivity
   telnet hub-ip 500
   nc -u hub-ip 4500
   
   # Fix firewall
   sudo ufw allow 500/udp
   sudo ufw allow 4500/udp
   ```

2. **Check NAT traversal**:
   ```bash
   # Add to ipsec.conf
   forceencaps=yes
   ```

3. **Increase timeouts**:
   ```bash
   # Add to ipsec.conf
   keyingtries=3
   keyexchange=ikev2
   ```

### Issue: Authentication Failures

**Symptoms**: 
```
authentication failed, received AUTHENTICATION_FAILED notify
```

**Solutions**:

1. **Verify certificates**:
   ```bash
   sudo openssl verify -CAfile /etc/ipsec.d/cacerts/ca-cert.pem /etc/ipsec.d/certs/cert.pem
   ```

2. **Check certificate dates**:
   ```bash
   sudo openssl x509 -in /etc/ipsec.d/certs/cert.pem -dates -noout
   ```

3. **Verify identity matching**:
   ```bash
   # Check ipsec.conf
   leftid=@hub.pqc-vpn.local
   rightid=@username
   ```

### Issue: Tunnel Established but No Traffic

**Symptoms**: ipsec status shows ESTABLISHED but ping fails

**Solutions**:

1. **Check routing**:
   ```bash
   ip route show table 220
   sudo ipsec route
   ```

2. **Verify traffic selectors**:
   ```bash
   sudo ipsec statusall
   ```

3. **Check firewall rules**:
   ```bash
   sudo iptables -L -n -v
   ```

4. **Test with specific routes**:
   ```bash
   sudo ip route add 10.10.0.0/16 dev ipsec0
   ```

## Certificate Issues

### Issue: Certificate Validation Fails

**Symptoms**: Certificate chain verification errors

**Solutions**:

1. **Check certificate chain**:
   ```bash
   sudo openssl verify -CAfile ca-cert.pem cert.pem
   ```

2. **Verify certificate installation**:
   ```bash
   sudo ls -la /etc/ipsec.d/cacerts/
   sudo ls -la /etc/ipsec.d/certs/
   sudo ls -la /etc/ipsec.d/private/
   ```

3. **Check permissions**:
   ```bash
   sudo chmod 644 /etc/ipsec.d/cacerts/*
   sudo chmod 644 /etc/ipsec.d/certs/*
   sudo chmod 600 /etc/ipsec.d/private/*
   sudo chmod 600 /etc/ipsec.secrets
   ```

### Issue: Certificate Expired

**Symptoms**: 
```
certificate validation failed, received AUTHENTICATION_FAILED
```

**Solutions**:

1. **Check expiry dates**:
   ```bash
   sudo python3 tools/connection-monitor.py certificates
   ```

2. **Renew certificates**:
   ```bash
   sudo ./scripts/generate-pqc-certs.sh --spoke username
   ```

3. **Update certificate database**:
   ```bash
   sudo ipsec reload
   ```

### Issue: PQC Algorithm Not Supported

**Symptoms**: Unknown algorithm errors

**Solutions**:

1. **Check OpenSSL PQC support**:
   ```bash
   openssl list -providers
   openssl list -signature-algorithms
   ```

2. **Fall back to RSA**:
   ```bash
   sudo ./scripts/generate-pqc-certs.sh --algorithm rsa --ca
   ```

3. **Reinstall liboqs**:
   ```bash
   cd /tmp
   git clone https://github.com/open-quantum-safe/liboqs.git
   cd liboqs && mkdir build && cd build
   cmake -G Ninja -DCMAKE_INSTALL_PREFIX=/usr/local ..
   ninja && sudo ninja install && sudo ldconfig
   ```

## Performance Problems

### Issue: Slow Connection Speeds

**Symptoms**: Low throughput, high latency

**Solutions**:

1. **Check CPU usage**:
   ```bash
   top -p $(pgrep charon)
   ```

2. **Optimize algorithms**:
   ```bash
   # Use faster algorithms in ipsec.conf
   ike=aes128gcm16-prfsha256-kyber512!
   esp=aes128gcm16-kyber512!
   ```

3. **Enable hardware acceleration**:
   ```bash
   # Check for AES-NI support
   grep -i aes /proc/cpuinfo
   ```

4. **Tune network settings**:
   ```bash
   # Increase buffer sizes
   echo 'net.core.rmem_max = 134217728' >> /etc/sysctl.conf
   echo 'net.core.wmem_max = 134217728' >> /etc/sysctl.conf
   sysctl -p
   ```

### Issue: High Memory Usage

**Symptoms**: strongSwan consuming excessive memory

**Solutions**:

1. **Check memory usage**:
   ```bash
   ps aux | grep charon
   ```

2. **Reduce connection limits**:
   ```bash
   # In strongswan.conf
   charon {
       max_packet = 1024
       threads = 16
   }
   ```

3. **Clear connection state**:
   ```bash
   sudo ipsec down-all
   sudo ipsec reload
   ```

### Issue: Connection Drops

**Symptoms**: Frequent disconnections

**Solutions**:

1. **Enable Dead Peer Detection**:
   ```bash
   # In ipsec.conf
   dpdaction=restart
   dpddelay=30s
   dpdtimeout=120s
   ```

2. **Check network stability**:
   ```bash
   ping -c 100 hub-ip
   mtr hub-ip
   ```

3. **Increase keepalive**:
   ```bash
   # In ipsec.conf
   margintime=3m
   lifetime=8h
   ```

## Platform-Specific Issues

### Linux Issues

#### systemd Service Problems

**Symptoms**: strongSwan service fails to start

**Solutions**:
```bash
sudo systemctl daemon-reload
sudo systemctl enable strongswan
sudo systemctl start strongswan
sudo journalctl -u strongswan --since today
```

#### SELinux/AppArmor Issues

**Symptoms**: Permission denied errors with SELinux/AppArmor

**Solutions**:
```bash
# SELinux (CentOS/RHEL)
sudo setsebool -P ipsec_mgmt_generic_ipsec_prog 1
sudo semanage permissive -a ipsec_t

# AppArmor (Ubuntu)
sudo aa-complain /usr/lib/ipsec/charon
```

### Windows Issues

#### WSL2 Network Problems

**Symptoms**: WSL2 cannot reach external networks

**Solutions**:
```powershell
# Reset WSL network
wsl --shutdown
Get-NetAdapter "vEthernet (WSL)" | Restart-NetAdapter

# Fix DNS
echo "nameserver 8.8.8.8" | wsl -d Ubuntu sudo tee /etc/resolv.conf
```

#### Windows Firewall Blocking

**Symptoms**: Connection fails from Windows

**Solutions**:
```powershell
# Allow strongSwan through firewall
New-NetFirewallRule -DisplayName "strongSwan IKE" -Direction Inbound -Protocol UDP -LocalPort 500 -Action Allow
New-NetFirewallRule -DisplayName "strongSwan NAT-T" -Direction Inbound -Protocol UDP -LocalPort 4500 -Action Allow
```

#### Service Management Issues

**Symptoms**: Windows service won't start

**Solutions**:
```powershell
# Check service status
Get-Service PQC-VPN-Hub
Get-Service PQC-VPN-Spoke

# Restart services
Restart-Service PQC-VPN-Hub
```

## Log Analysis

### Understanding strongSwan Logs

#### Common Log Patterns

**Successful connection**:
```
CHILD_SA pqc-vpn{1} established with SPIs
```

**Authentication failure**:
```
authentication of 'username' with RSA signature failed
```

**Certificate issues**:
```
building CRED_CERTIFICATE - X509 failed
```

**Network issues**:
```
sending retransmit 1 of request message ID
```

#### Log Locations

- **Linux**: `/var/log/syslog`, `/var/log/daemon.log`
- **systemd**: `journalctl -u strongswan`
- **Custom**: `/var/log/pqc-vpn/`

#### Log Analysis Commands

```bash
# Filter strongSwan logs
sudo grep -i ipsec /var/log/syslog | tail -50

# Search for errors
sudo journalctl -u strongswan | grep -i error

# Monitor live logs
sudo journalctl -u strongswan -f

# Export logs for analysis
sudo journalctl -u strongswan --since "1 hour ago" > strongswan.log
```

### Debug Mode

Enable debug logging for detailed troubleshooting:

```bash
# Edit /etc/strongswan.conf
charon {
    filelog {
        /var/log/pqc-vpn/charon.log {
            time_format = %b %e %T
            ike_name = yes
            append = no
            default = 2
            flush_line = yes
        }
    }
}
```

## Diagnostic Tools

### Built-in Diagnostics

1. **VPN Manager health check**:
   ```bash
   sudo python3 tools/vpn-manager.py status
   ```

2. **Connection monitor**:
   ```bash
   sudo python3 tools/connection-monitor.py monitor
   ```

3. **Certificate status**:
   ```bash
   sudo python3 tools/connection-monitor.py certificates
   ```

### Network Diagnostics

1. **Test connectivity**:
   ```bash
   ping hub-ip
   traceroute hub-ip
   mtr hub-ip
   ```

2. **Port testing**:
   ```bash
   nmap -sU -p 500,4500 hub-ip
   telnet hub-ip 500
   ```

3. **Bandwidth testing**:
   ```bash
   iperf3 -s                    # On hub
   iperf3 -c hub-ip            # On spoke
   ```

### Security Diagnostics

1. **Certificate validation**:
   ```bash
   sudo openssl verify -CAfile ca-cert.pem cert.pem
   sudo openssl x509 -in cert.pem -text -noout
   ```

2. **Algorithm support**:
   ```bash
   openssl list -signature-algorithms | grep -i dilithium
   ipsec listalgos
   ```

3. **Connection security**:
   ```bash
   sudo ipsec statusall
   sudo ipsec listcerts
   ```

## Getting Help

### Information to Collect

When seeking help, collect:

1. **System information**:
   ```bash
   uname -a
   cat /etc/os-release
   strongswan --version
   ```

2. **Configuration files** (sanitized):
   ```bash
   sudo cat /etc/ipsec.conf
   sudo cat /etc/strongswan.conf
   ```

3. **Log excerpts**:
   ```bash
   sudo journalctl -u strongswan --since "1 hour ago"
   ```

4. **Network configuration**:
   ```bash
   ip addr show
   ip route show
   sudo iptables -L -n
   ```

### Support Channels

1. **GitHub Issues**: Report bugs and get community support
2. **Documentation**: Check all documentation in `docs/`
3. **strongSwan Community**: For strongSwan-specific issues
4. **liboqs Community**: For PQC algorithm issues

### Creating Effective Bug Reports

Include:
- Detailed description of the problem
- Steps to reproduce
- Expected vs actual behavior
- System information
- Relevant log excerpts
- Configuration files (remove sensitive data)

---

**Remember**: Always remove sensitive information (private keys, passwords, IP addresses) before sharing logs or configurations.