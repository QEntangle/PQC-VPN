# PQC-VPN Quick Start Guide (Fixed Production Deployment)

This guide helps you get PQC-VPN running quickly with the fixed production configuration that resolves common Docker Compose errors.

## 🚀 Quick Start (Automated)

### Option 1: One-Command Startup
```bash
# Clone and start with automated script
git clone https://github.com/QEntangle/PQC-VPN.git
cd PQC-VPN
chmod +x start-pqc-vpn.sh

# Basic deployment
./start-pqc-vpn.sh

# Or with monitoring (Grafana + Prometheus)
./start-pqc-vpn.sh --with-monitoring
```

### Option 2: Manual Steps (if you prefer control)
```bash
# 1. Clone repository
git clone https://github.com/QEntangle/PQC-VPN.git
cd PQC-VPN

# 2. Create environment configuration
cp .env.production .env
nano .env  # Edit with your settings (see below)

# 3. Start core services
docker-compose -f docker/docker-compose.production-fixed.yml up -d postgres redis

# 4. Wait for databases (important!)
sleep 15

# 5. Start main application
docker-compose -f docker/docker-compose.production-fixed.yml up -d pqc-vpn-hub

# 6. Optional: Start monitoring
docker-compose -f docker/docker-compose.production-fixed.yml --profile monitoring up -d
```

## 🔧 Configuration

### Required Environment Variables (.env file)
```bash
# REQUIRED: Change these values
HUB_IP=YOUR_SERVER_IP                    # Your actual server IP
ADMIN_PASSWORD=YourSecurePassword123!    # Web admin password
SECRET_KEY=your-32-char-secret-key       # Application secret

# Database passwords (change from defaults)
POSTGRES_PASSWORD=YourPostgresPassword123!
REDIS_PASSWORD=YourRedisPassword123!
GRAFANA_PASSWORD=YourGrafanaPassword123!

# Organization details for certificates
ORGANIZATION=YourCompany
COUNTRY=US
STATE=California
LOCALITY=YourCity
```

### Fixed Port Configuration
The fixed configuration uses non-conflicting ports:
- **VPN**: 500/udp, 4500/udp (standard)
- **Web Interface**: 8443 (HTTPS)
- **API**: 9090
- **PostgreSQL**: 15432 (instead of 5432)
- **Redis**: 16379 (instead of 6379)
- **Grafana**: 13000 (instead of 3000)
- **Prometheus**: 19090 (instead of 9090)

## 🌐 Access Your PQC-VPN

After startup, access these URLs:

### Core Services
- **Web Interface**: https://localhost:8443
- **Admin Login**: `admin` / `your-admin-password`
- **API**: https://localhost:9090/api/
- **Metrics**: http://localhost:9100/metrics

### Monitoring (if enabled)
- **Grafana**: http://localhost:13000
- **Prometheus**: http://localhost:19090

### Database Access
- **PostgreSQL**: `localhost:15432`
- **Redis**: `localhost:16379`

## 🐛 Troubleshooting

### Common Error: "Port already in use"
✅ **Fixed** - The new configuration uses non-conflicting ports.

### Common Error: "Build context incorrect"
✅ **Fixed** - Build context corrected to parent directory.

### Common Error: "Database connection failed"
```bash
# Check database status
docker logs pqc-postgres

# Test connection
docker exec pqc-postgres pg_isready -U pqc_admin -d pqc_vpn_enterprise
```

### Common Error: "Environment variables missing"
```bash
# Make sure .env file exists
ls -la .env

# Copy from template if missing
cp .env.production .env
```

### View Logs
```bash
# All services
docker-compose -f docker/docker-compose.production-fixed.yml logs -f

# Specific service
docker logs pqc-vpn-hub -f
docker logs pqc-postgres -f
docker logs pqc-redis -f
```

### Reset Everything (if problems)
```bash
# Stop and remove all containers/volumes
docker-compose -f docker/docker-compose.production-fixed.yml down -v
docker container prune -f
docker volume prune -f

# Start fresh
./start-pqc-vpn.sh
```

## 📊 Health Checks

### Verify Services
```bash
# Check container status
docker-compose -f docker/docker-compose.production-fixed.yml ps

# Test web interface
curl -k https://localhost:8443/health

# Test API
curl -k https://localhost:9090/api/status

# Test database
docker exec pqc-postgres pg_isready -U pqc_admin -d pqc_vpn_enterprise

# Test Redis
docker exec pqc-redis redis-cli ping
```

## 🔒 Adding VPN Users

### Web Interface Method
1. Open https://localhost:8443
2. Login with admin credentials
3. Go to Users section
4. Add new users with certificates

### Command Line Method
```bash
# Add PKI user
docker exec pqc-vpn-hub pqc-vpn-manager user add client1 client1@company.com --auth-type pki

# Add PSK user
docker exec pqc-vpn-hub pqc-vpn-manager user add client2 client2@company.com --auth-type psk

# List users
docker exec pqc-vpn-hub pqc-vpn-manager user list
```

## 🛑 Stopping Services

```bash
# Stop all services
docker-compose -f docker/docker-compose.production-fixed.yml down

# Stop and remove all data (CAUTION!)
docker-compose -f docker/docker-compose.production-fixed.yml down -v
```

## 📁 File Structure

```
PQC-VPN/
├── start-pqc-vpn.sh                           # Automated startup script
├── .env.production                            # Environment template
├── docker/
│   ├── docker-compose.production-fixed.yml    # Fixed production config
│   ├── docker-compose.production.yml          # Original (has issues)
│   └── Dockerfile.pqc-hub                     # Hub container
├── configs/
│   └── prometheus/
│       └── prometheus.yml                     # Monitoring config
├── tools/                                     # Management tools
├── web/                                       # Web interface
└── scripts/                                   # Utility scripts
```

## 🔄 Updates and Backups

### Update PQC-VPN
```bash
git pull origin main
docker-compose -f docker/docker-compose.production-fixed.yml build pqc-vpn-hub
docker-compose -f docker/docker-compose.production-fixed.yml up -d pqc-vpn-hub
```

### Backup Data
```bash
# Backup database
docker exec pqc-postgres pg_dumpall -U pqc_admin > backup.sql

# Backup certificates
docker cp pqc-vpn-hub:/etc/ipsec.d ./certs-backup/
```

## 🆘 Getting Help

If you encounter issues:

1. **Check logs**: `docker-compose -f docker/docker-compose.production-fixed.yml logs`
2. **Verify environment**: Ensure `.env` file is properly configured
3. **Reset if needed**: Use the reset commands above
4. **Use the automated script**: `./start-pqc-vpn.sh` handles most common issues

The fixed configuration resolves the major Docker Compose issues mentioned in your original requirements and provides a reliable production deployment.