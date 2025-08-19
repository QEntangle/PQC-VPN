# PQC-VPN Configuration Guide

This guide explains how to configure PQC-VPN for different scenarios and customize its behavior.

## Table of Contents

- [Configuration Overview](#configuration-overview)
- [Hub Configuration](#hub-configuration)
- [Spoke Configuration](#spoke-configuration)
- [Security Settings](#security-settings)
- [Network Configuration](#network-configuration)
- [Performance Tuning](#performance-tuning)
- [Advanced Configuration](#advanced-configuration)
- [Configuration Examples](#configuration-examples)

## Configuration Overview

PQC-VPN uses several configuration files:

- `/etc/ipsec.conf` - IPsec connection definitions
- `/etc/ipsec.secrets` - Authentication credentials
- `/etc/strongswan.conf` - strongSwan daemon configuration
- `/opt/pqc-vpn/config.yaml` - PQC-VPN management configuration

## Hub Configuration

### Basic Hub Setup

The hub configuration is located in `/etc/ipsec.conf`:

```bash
# PQC-VPN Hub Configuration
config setup
    charondebug="ike 2, knl 2, cfg 2"
    strictcrlpolicy=no
    uniqueids=never

conn %default
    keyexchange=ikev2
    ike=aes256gcm16-prfsha256-kyber1024!
    esp=aes256gcm16-kyber1024!
    authby=pubkey
    compress=no
    type=tunnel
    left=%defaultroute
    leftid=@hub.pqc-vpn.local
    leftcert=hub-cert.pem
    leftsubnet=10.10.0.0/16
    auto=add
    lifetime=24h
    ikelifetime=24h
    margintime=3m
    keyingtries=3
    rekeymargin=3m
    mobike=yes
    fragmentation=yes
    forceencaps=yes

# Template for spoke connections
conn spoke-template
    right=%any
    rightsubnet=0.0.0.0/0
    rightcert=%any
    auto=add
    dpdaction=restart
    dpddelay=30s
    dpdtimeout=120s
```

### Hub Network Settings

Configure the hub's network parameters:

```yaml
# /opt/pqc-vpn/config.yaml
hub:
  ip: "10.10.0.1"
  network: "10.10.0.0/16"
  port: 500
  nat_port: 4500
  dns_servers:
    - "8.8.8.8"
    - "1.1.1.1"
  
network:
  spoke_ranges:
    - "10.10.1.0/24"    # Regular users
    - "10.10.2.0/24"    # Admin users
    - "10.10.3.0/24"    # Guest users
  
  routing:
    hub_subnet: "10.10.0.0/24"
    default_gateway: "10.10.0.1"
```

### User Groups Configuration

Define different user groups with varying access:

```bash
# Admin users - full access
conn admin-users
    also=spoke-template
    rightsubnet=10.10.0.0/16
    rightgroups=@admin

# Regular users - limited access
conn regular-users
    also=spoke-template
    rightsubnet=10.10.1.0/24,192.168.100.0/24
    rightgroups=@users

# Guest users - internet only
conn guest-users
    also=spoke-template
    rightsubnet=0.0.0.0/0
    rightgroups=@guests
```

### Firewall Integration

Configure iptables rules for the hub:

```bash
#!/bin/bash
# /opt/pqc-vpn/scripts/configure-firewall.sh

# Allow VPN traffic
iptables -A INPUT -p udp --dport 500 -j ACCEPT
iptables -A INPUT -p udp --dport 4500 -j ACCEPT
iptables -A INPUT -p esp -j ACCEPT

# Allow forwarding between VPN subnets
iptables -A FORWARD -s 10.10.0.0/16 -d 10.10.0.0/16 -j ACCEPT

# NAT for internet access
iptables -t nat -A POSTROUTING -s 10.10.0.0/16 -o eth0 -j MASQUERADE

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
```

## Spoke Configuration

### Basic Spoke Setup

Spoke configuration template:

```bash
# PQC-VPN Spoke Configuration
config setup
    charondebug="ike 2, knl 2, cfg 2"
    strictcrlpolicy=no
    uniqueids=never

conn %default
    keyexchange=ikev2
    ike=aes256gcm16-prfsha256-kyber1024!
    esp=aes256gcm16-kyber1024!
    authby=pubkey
    compress=no
    type=tunnel

conn pqc-vpn
    left=%defaultroute
    leftid=@%SPOKE_USER%
    leftcert=%SPOKE_USER%-cert.pem
    leftsubnet=0.0.0.0/0
    right=%HUB_IP%
    rightid=@hub.pqc-vpn.local
    rightsubnet=10.10.0.0/16
    auto=start
    lifetime=24h
    ikelifetime=24h
    margintime=3m
    keyingtries=3
    rekeymargin=3m
    mobike=yes
    fragmentation=yes
    forceencaps=yes
    dpdaction=restart
    dpddelay=30s
    dpdtimeout=120s
```

### Split Tunneling

Configure split tunneling for specific routes:

```bash
# Only route VPN subnet through tunnel
conn pqc-vpn-split
    also=pqc-vpn
    rightsubnet=10.10.0.0/16,192.168.100.0/24
    
# Route all traffic through tunnel
conn pqc-vpn-full
    also=pqc-vpn
    rightsubnet=0.0.0.0/0
```

### DNS Configuration

Configure DNS for spoke clients:

```bash
# /etc/systemd/resolved.conf
[Resolve]
DNS=10.10.0.1
Domains=pqc-vpn.local
```

Or using resolvconf:

```bash
# Add to /etc/dhcp/dhclient-enter-hooks.d/resolvconf
if [ "$interface" = "ipsec0" ]; then
    new_domain_name="pqc-vpn.local"
    new_domain_name_servers="10.10.0.1"
fi
```

## Security Settings

### Encryption Algorithms

Configure Post-Quantum Cryptography algorithms:

```bash
# Strong PQC configuration
ike=aes256gcm16-prfsha256-kyber1024!
esp=aes256gcm16-kyber1024!

# Balanced PQC configuration
ike=aes256gcm16-prfsha256-kyber768!
esp=aes256gcm16-kyber768!

# Fast PQC configuration
ike=aes128gcm16-prfsha256-kyber512!
esp=aes128gcm16-kyber512!

# Fallback to classical cryptography
ike=aes256gcm16-prfsha256-modp2048!
esp=aes256gcm16-modp2048!
```

### Certificate Validation

Strict certificate validation:

```bash
# /etc/strongswan.conf
charon {
    plugins {
        x509 {
            enforce_critical = yes
        }
        pubkey {
            key_verify = yes
        }
    }
    
    # Certificate revocation
    plugins {
        revocation {
            enable_crl = yes
            enable_ocsp = yes
        }
    }
}
```

### Authentication Methods

Different authentication configurations:

```bash
# Certificate-only authentication
authby=pubkey

# Certificate + PSK
authby=secret

# EAP authentication
authby=eap
eap_identity=%identity

# Mutual certificate authentication
leftauth=pubkey
rightauth=pubkey
```

## Network Configuration

### DHCP Integration

Configure DHCP for automatic IP assignment:

```bash
# /etc/strongswan.conf
charon {
    plugins {
        dhcp {
            identity_lease = yes
            force_server_address = yes
            server = 10.10.0.1
        }
    }
}
```

### VLAN Support

Configure VLAN tags for network segmentation:

```bash
# Different VLANs for different user groups
conn admin-vlan100
    also=spoke-template
    rightsubnet=10.10.100.0/24
    mark=100

conn user-vlan200
    also=spoke-template
    rightsubnet=10.10.200.0/24
    mark=200
```

### Quality of Service

Configure QoS marking:

```bash
# /etc/strongswan.conf
charon {
    plugins {
        socket-default {
            set_source = yes
            set_sourceif = yes
        }
    }
    
    # Mark packets for QoS
    mark = 42
    mark_out = 42
}
```

## Performance Tuning

### CPU Optimization

Optimize for multi-core systems:

```bash
# /etc/strongswan.conf
charon {
    # Number of worker threads
    threads = 16
    
    # Processor affinity
    processor {
        priority_threads = {
            high = 2
            medium = 4
            low = 10
        }
    }
    
    # Memory pools
    leak_detective {
        detailed = no
    }
}
```

### Network Buffer Tuning

Optimize network buffers:

```bash
# /etc/sysctl.conf
# Increase buffer sizes
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 8388608
net.core.wmem_default = 8388608

# TCP settings
net.ipv4.tcp_rmem = 4096 8388608 134217728
net.ipv4.tcp_wmem = 4096 8388608 134217728

# UDP settings
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
```

### Connection Limits

Configure connection limits:

```bash
# /etc/strongswan.conf
charon {
    # Maximum IKE_SAs
    max_ikev2_exchanges = 3
    
    # Cookie threshold
    cookie_threshold = 100
    
    # Half-open threshold
    half_open_threshold = 500
    
    # Retransmission settings
    retransmit_tries = 5
    retransmit_timeout = 4.0
    retransmit_base = 1.8
}
```

## Advanced Configuration

### High Availability

Configure hub redundancy:

```bash
# Primary hub
conn pqc-vpn-primary
    right=10.1.1.100
    rightid=@hub1.pqc-vpn.local
    auto=start

# Backup hub
conn pqc-vpn-backup
    right=10.1.1.101
    rightid=@hub2.pqc-vpn.local
    auto=add
```

### Load Balancing

Configure load balancing with multiple hubs:

```bash
# /etc/strongswan.conf
charon {
    plugins {
        load-balancer {
            enable = yes
            pool = 10.1.1.100,10.1.1.101,10.1.1.102
            method = round-robin
        }
    }
}
```

### Integration with Directory Services

LDAP authentication:

```bash
# /etc/strongswan.conf
charon {
    plugins {
        ldap {
            server = ldap://ldap.company.com
            base = dc=company,dc=com
            filter = (&(objectClass=person)(uid=%s))
            bind_dn = cn=vpn,ou=services,dc=company,dc=com
            bind_pw = password
        }
    }
}
```

### Logging Configuration

Detailed logging setup:

```bash
# /etc/strongswan.conf
charon {
    filelog {
        /var/log/pqc-vpn/charon.log {
            time_format = %b %e %T
            ike_name = yes
            append = no
            default = 2
            flush_line = yes
        }
        
        /var/log/pqc-vpn/ike.log {
            ike = 3
            knl = 3
            default = 0
        }
    }
    
    syslog {
        daemon {
            default = 1
            ike = 2
        }
    }
}
```

## Configuration Examples

### Small Office Setup

For a small office with 10-20 users:

```yaml
# config.yaml
hub:
  ip: "192.168.1.100"
  network: "10.10.0.0/24"

security:
  ike_algorithms: "aes256gcm16-prfsha256-kyber768"
  esp_algorithms: "aes256gcm16-kyber768"
  
certificates:
  algorithm: "dilithium3"
  validity: 365

users:
  default_group: "office"
  ip_range: "10.10.1.0/24"
```

### Enterprise Setup

For enterprise deployment with 500+ users:

```yaml
# config.yaml
hub:
  ip: "10.0.0.1"
  network: "10.0.0.0/8"
  
security:
  ike_algorithms: "aes256gcm16-prfsha256-kyber1024"
  esp_algorithms: "aes256gcm16-kyber1024"
  
certificates:
  algorithm: "dilithium5"
  ca_validity: 3650
  cert_validity: 365

users:
  groups:
    admin:
      ip_range: "10.1.0.0/16"
      access: "full"
    employee:
      ip_range: "10.2.0.0/16" 
      access: "limited"
    contractor:
      ip_range: "10.3.0.0/16"
      access: "minimal"

monitoring:
  enabled: true
  retention_days: 90
  alerts:
    email: "admin@company.com"
    webhook: "https://monitoring.company.com/webhook"
```

### Remote Access Setup

For remote workers:

```bash
# Spoke configuration for remote workers
conn company-vpn
    left=%defaultroute
    leftid=@employee.username
    leftcert=employee-cert.pem
    right=vpn.company.com
    rightid=@hub.company.com
    rightsubnet=10.0.0.0/8,172.16.0.0/12
    auto=start
    
    # Optimize for variable connections
    mobike=yes
    fragmentation=yes
    forceencaps=yes
    
    # Aggressive reconnection
    dpdaction=restart
    dpddelay=10s
    dpdtimeout=60s
    keyingtries=0
```

### Site-to-Site VPN

For connecting office branches:

```bash
# Main office to branch office
conn branch-office-1
    left=10.0.0.1
    leftid=@main.company.com
    leftsubnet=10.0.0.0/16
    leftcert=main-office-cert.pem
    
    right=192.168.100.1
    rightid=@branch1.company.com
    rightsubnet=192.168.100.0/24
    rightcert=branch1-cert.pem
    
    auto=start
    type=tunnel
    
    # Site-to-site optimizations
    compress=yes
    mobike=no
    dpdaction=hold
```

## Configuration Validation

### Testing Configuration

Validate configuration before deployment:

```bash
# Check configuration syntax
sudo ipsec --checkconfig

# Test connection without establishing
sudo ipsec stroke_conftest

# Dry run certificate validation
sudo openssl verify -CAfile ca-cert.pem cert.pem
```

### Configuration Migration

Migrating from old configurations:

```bash
# Backup current configuration
sudo cp /etc/ipsec.conf /etc/ipsec.conf.backup

# Convert old PSK configuration to certificates
sudo ./scripts/migrate-to-certificates.sh

# Test new configuration
sudo ipsec reload
sudo ipsec status
```

### Best Practices

1. **Always backup** configurations before changes
2. **Test in staging** environment first
3. **Use version control** for configuration files
4. **Document all changes** with comments
5. **Monitor performance** after configuration changes
6. **Regular security audits** of algorithms and certificates

---

This configuration guide provides the foundation for customizing PQC-VPN to meet specific deployment requirements while maintaining security and performance.