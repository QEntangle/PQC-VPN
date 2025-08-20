# 🔐 PQC-VPN Real Enterprise Dashboard Guide

## 🎯 **ENTERPRISE DASHBOARD - REAL STRONGSWAN INTEGRATION**

**✅ FIXED**: Dashboard now shows **real strongSwan data** instead of simulated information!

---

## 🚀 **Quick Start with Real Dashboard**

### **One-Command Setup**
```bash
git clone https://github.com/QEntangle/PQC-VPN.git
cd PQC-VPN
chmod +x setup-enterprise-demo.sh
./setup-enterprise-demo.sh
```

### **Access Enterprise Dashboard**
- **URL**: `https://localhost:8443`
- **Login**: `admin` / `EnterpriseAdmin123!`
- **Features**: Real-time strongSwan monitoring with live data

---

## 📊 **REAL DASHBOARD FEATURES**

### **Live Connection Monitor**
Shows actual strongSwan connections in real-time:
```
🔐 engineering-alice | 10.0.0.101 | PKI | Kyber-1024 | ESTABLISHED
🔐 sales-bob         | 10.0.0.102 | PSK | Kyber-1024 | ESTABLISHED  
🔐 executive-carol   | 10.0.0.103 | PKI | Kyber-1024 | ESTABLISHED
```

**Data Source**: Direct integration with `ipsec status` and `swanctl --list-sas`

### **Real System Metrics**
Live system performance from actual server:
- **CPU Usage**: Real-time CPU utilization
- **Memory Usage**: Actual memory consumption
- **Network I/O**: Live network traffic statistics
- **strongSwan Process**: Actual process status and resource usage

### **Authentic Traffic Statistics**
Real VPN traffic data:
- **Bytes In/Out**: Actual data transferred per connection
- **Connection Duration**: Real connection timestamps
- **Algorithm Usage**: Live PQC algorithm verification
- **Authentication Status**: Real PKI/PSK authentication results

---

## 🔧 **ENTERPRISE DASHBOARD ARCHITECTURE**

### **Real Data Sources**
```
┌─────────────────────────────────────────────────────────┐
│                ENTERPRISE DASHBOARD                     │
│             (web/enterprise_dashboard.py)              │
└─────────────────┬───────────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────────┐
│            ENTERPRISE VPN MANAGER                       │
│          (Real strongSwan Integration)                  │
├─────────────────────────────────────────────────────────┤
│ • ipsec status / statusall                              │
│ • swanctl --list-sas                                    │
│ • /usr/local/oqs-openssl/bin/openssl                    │
│ • psutil (system metrics)                               │
│ • PostgreSQL (user data)                                │
│ • Redis (real-time cache)                               │
└─────────────────────────────────────────────────────────┘
```

### **No More Simulation**
**❌ Old**: `api_server.py` with mock data  
**✅ New**: `enterprise_dashboard.py` with real strongSwan integration

---

## 👥 **REAL USER MANAGEMENT**

### **Database-Backed Users**
Enterprise PostgreSQL database with real user management:

```sql
-- View real users
SELECT username, auth_type, department, status, last_login 
FROM users ORDER BY created_at DESC;

-- View active connections  
SELECT * FROM active_connections;

-- View connection statistics
SELECT * FROM user_connection_summary;
```

### **Live User Operations**
```bash
# Add real user (via CLI)
docker exec pqc-vpn-hub python3 /opt/pqc-vpn/tools/pqc-vpn-manager.py user add \
  real-user user@company.com --auth-type pki

# Add user via Web Dashboard
# 1. Go to https://localhost:8443/users
# 2. Click "Add New User"  
# 3. User is immediately added to strongSwan configuration

# Add user via API
curl -k -X POST https://localhost:8443/api/users \
  -H "Content-Type: application/json" \
  -d '{"username": "api-user", "email": "api@company.com", "auth_type": "psk"}'
```

---

## 🔍 **REAL-TIME MONITORING VERIFICATION**

### **Prove Dashboard Shows Real Data**

#### **1. Check strongSwan Direct**
```bash
# Get actual strongSwan status
docker exec pqc-vpn-hub ipsec status

# Get detailed connection info
docker exec pqc-vpn-hub ipsec statusall
```

#### **2. Compare with Dashboard**
1. Open dashboard: `https://localhost:8443`
2. Check connection list
3. **Verify**: Data matches exactly with `ipsec status` output

#### **3. Real-Time Updates**
```bash
# Connect a new client
sudo ipsec up new-connection

# Watch dashboard update immediately (30-second refresh)
# OR force refresh: https://localhost:8443/api/enterprise/status
```

#### **4. Traffic Verification**
```bash
# Generate traffic between clients
ping 10.0.0.102  # From client 1 to client 2

# Watch dashboard traffic counters increase in real-time
# Dashboard shows actual bytes_in/bytes_out from strongSwan
```

---

## 📈 **ENTERPRISE ANALYTICS**

### **Real Metrics Collection**
The enterprise dashboard collects and displays:

1. **Connection Metrics**:
   - Real connection timestamps
   - Actual authentication methods used
   - Live traffic statistics from strongSwan
   - Real PQC algorithm verification

2. **System Performance**:
   - Live CPU/Memory usage via `psutil`
   - Real network I/O statistics
   - Actual strongSwan process monitoring
   - Live system load averages

3. **Security Events**:
   - Real authentication successes/failures
   - Actual certificate validation events
   - Live security alerts and warnings

### **Prometheus Integration**
Real metrics exported to Prometheus:
```bash
# View real metrics
curl http://localhost:9100/metrics

# Metrics include:
# - pqc_vpn_active_connections (real count)
# - pqc_vpn_system_cpu_percent (actual CPU usage)
# - pqc_vpn_connection_duration (real connection times)
# - pqc_vpn_bytes_transferred (actual traffic data)
```

### **Grafana Dashboards**
Access real analytics: `http://localhost:13000`
- Real connection trends over time
- Actual traffic analysis by user
- Live system performance monitoring
- Real security event correlation

---

## 🔐 **POST-QUANTUM CRYPTOGRAPHY VERIFICATION**

### **Real PQC Algorithm Detection**
```bash
# Verify PQC support
docker exec pqc-vpn-hub /usr/local/oqs-openssl/bin/openssl list -kem-algorithms | grep kyber

# Check real connections use PQC
docker exec pqc-vpn-hub ipsec statusall | grep -i kyber

# Dashboard shows real algorithm usage
curl -k https://localhost:8443/api/enterprise/status | jq '.vpn_status.pqc_support'
```

### **Algorithm Verification in Dashboard**
Dashboard displays real PQC algorithm usage:
- **Kyber-1024**: Real key exchange algorithm verification
- **Dilithium-5**: Actual signature algorithm detection  
- **AES-256-GCM**: Live encryption algorithm confirmation

---

## 🛠️ **ENTERPRISE API ENDPOINTS**

### **Real-Time Status API**
```bash
# Get complete real status
curl -k https://localhost:8443/api/enterprise/status

# Response includes real strongSwan data:
{
  "vpn_status": {
    "service_status": {"status": "running"},  // Real strongSwan status
    "connections": [...],                     // Actual active connections
    "active_count": 3,                        // Real connection count
    "pqc_count": 3                           // Actual PQC connections
  },
  "system_metrics": {
    "cpu": {"percent": 15.2},                // Real CPU usage
    "memory": {"percent": 58.3},             // Actual memory usage
    "network": {...}                         // Live network statistics
  }
}
```

### **User Management API**
```bash
# List real users
curl -k https://localhost:8443/api/users

# Add real user
curl -k -X POST https://localhost:8443/api/users \
  -H "Content-Type: application/json" \
  -d '{"username": "real-user", "email": "real@company.com", "auth_type": "pki"}'

# User is immediately active in strongSwan
```

---

## 🎯 **DEMO SCENARIOS WITH REAL DATA**

### **Scenario 1: Real Connection Monitoring**
```bash
# 1. Start with no connections
docker exec pqc-vpn-hub ipsec status
# Output: No connections

# 2. Dashboard shows "No active connections"
curl -k https://localhost:8443/api/enterprise/status | jq '.vpn_status.active_count'
# Output: 0

# 3. Connect client
sudo ipsec up engineering-alice

# 4. Dashboard immediately shows real connection
curl -k https://localhost:8443/api/enterprise/status | jq '.vpn_status.connections'
# Output: Real connection data with actual IP, auth method, etc.
```

### **Scenario 2: Real Traffic Monitoring**
```bash
# 1. Check initial traffic (should be 0)
curl -k https://localhost:8443/api/enterprise/status | jq '.vpn_status.connections[0].bytes_in'

# 2. Generate traffic
ping -c 100 10.0.0.102  # From client 1 to client 2

# 3. Watch traffic counters increase in real-time
curl -k https://localhost:8443/api/enterprise/status | jq '.vpn_status.connections[0].bytes_in'
# Numbers increase with actual traffic
```

### **Scenario 3: Real User Management**
```bash
# 1. Add user via dashboard
# Go to https://localhost:8443/users, add "demo-user"

# 2. Verify user in database
docker exec pqc-postgres psql -U pqc_admin -d pqc_vpn_enterprise -c "SELECT * FROM users WHERE username='demo-user';"

# 3. Verify user in strongSwan config
docker exec pqc-vpn-hub grep demo-user /etc/ipsec.secrets

# 4. User can immediately connect (real integration)
```

---

## 🔄 **REAL VS SIMULATED COMPARISON**

### **❌ OLD (Simulated)**
```python
# api_server.py - Mock data
connections = [
    {
        'id': hash(conn_name),
        'user': 'demo-user',
        'ip': 'Unknown',
        'status': 'online',
        'connected': '30m'  # Fake duration
    }
]
```

### **✅ NEW (Real Integration)**
```python
# enterprise_dashboard.py - Real strongSwan data
def _get_active_connections(self) -> List[Dict[str, Any]]:
    # Get real strongSwan data
    result = subprocess.run([self.swanctl_bin, '--list-sas'], ...)
    connections = self._parse_swanctl_output(result.stdout)
    
    # Enrich with real traffic data
    for conn in connections:
        conn.update(self._get_connection_traffic(conn.get('name', '')))
    
    return connections  # Real data from strongSwan
```

---

## 🏆 **ENTERPRISE VERIFICATION CHECKLIST**

### ✅ **Real Integration Verification**
- [ ] Dashboard shows actual `ipsec status` data
- [ ] Connection counts match `ipsec status` exactly  
- [ ] Traffic statistics come from strongSwan, not simulation
- [ ] System metrics show real CPU/memory/network usage
- [ ] User management updates strongSwan configuration immediately
- [ ] PQC algorithm detection from real OpenSSL/OQS integration
- [ ] Database stores actual connection events, not mock data

### ✅ **Enterprise Feature Verification**
- [ ] PostgreSQL database with real user/connection tables
- [ ] Redis caching real-time strongSwan data
- [ ] Prometheus collecting actual VPN metrics
- [ ] Grafana displaying real analytics and trends
- [ ] API endpoints returning live strongSwan data
- [ ] Multi-authentication (PKI + PSK) working with real certificates

---

## 📞 **SUPPORT & TROUBLESHOOTING**

### **Verify Real Integration**
```bash
# Test 1: Verify dashboard matches strongSwan
STRONGSWAN_STATUS=$(docker exec pqc-vpn-hub ipsec status | grep ESTABLISHED | wc -l)
DASHBOARD_COUNT=$(curl -s -k https://localhost:8443/api/enterprise/status | jq '.vpn_status.active_count')
echo "strongSwan: $STRONGSWAN_STATUS, Dashboard: $DASHBOARD_COUNT"
# Should match exactly

# Test 2: Verify real-time updates
# Watch: docker exec pqc-vpn-hub ipsec status
# Compare with: curl -k https://localhost:8443/api/enterprise/status
# Data should be identical
```

### **Troubleshooting Real Data Issues**
```bash
# 1. Check strongSwan service
docker exec pqc-vpn-hub systemctl status strongswan-starter

# 2. Check OQS integration
docker exec pqc-vpn-hub /usr/local/oqs-openssl/bin/openssl version

# 3. Check database connection
docker exec pqc-postgres pg_isready -U pqc_admin -d pqc_vpn_enterprise

# 4. Check dashboard logs
docker logs pqc-web-dashboard -f

# 5. Force data refresh
curl -k https://localhost:8443/api/enterprise/status
```

---

**🎯 CONCLUSION: The PQC-VPN enterprise dashboard now provides real strongSwan integration with live data, comprehensive user management, and production-ready monitoring - no more simulated data!**

**🔐 Ready for enterprise demonstration with authentic post-quantum VPN capabilities!**
