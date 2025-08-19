#!/usr/bin/env python3
"""
PQC-VPN Manager with OpenSSL 3.5 Support
Enterprise-grade VPN management and monitoring tool

Author: PQC-VPN Team
Version: 3.0.0
License: MIT
"""

import os
import sys
import subprocess
import argparse
import json
import logging
import sqlite3
import yaml
import time
import socket
import psutil
import signal
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from contextlib import contextmanager
import threading
import schedule

# Configuration
OPENSSL_PREFIX = "/usr/local/openssl35"
OPENSSL_BIN = f"{OPENSSL_PREFIX}/bin/openssl"
STRONGSWAN_BIN = "/usr/local/strongswan/sbin/ipsec"
VICI_SOCKET = "/var/run/strongswan/charon-vici.socket"
DATABASE_PATH = "/var/lib/pqc-vpn/vpn_manager.db"
CONFIG_PATH = "/etc/pqc-vpn/manager.yaml"
LOG_PATH = "/var/log/pqc-vpn/manager.log"

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(module)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_PATH),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class Connection:
    """VPN connection data model"""
    name: str
    state: str
    type: str
    local_ip: str
    remote_ip: str
    remote_id: str
    local_subnets: List[str]
    remote_subnets: List[str]
    established: Optional[datetime]
    rekey_time: Optional[datetime]
    bytes_in: int
    bytes_out: int
    packets_in: int
    packets_out: int
    protocol: str
    encryption: str
    integrity: str
    dh_group: str

@dataclass
class User:
    """VPN user data model"""
    username: str
    email: str
    auth_type: str
    certificate_path: Optional[str]
    created_at: datetime
    last_login: Optional[datetime]
    is_active: bool
    groups: List[str]
    ip_assignment: Optional[str]

@dataclass
class SystemMetrics:
    """System metrics data model"""
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    disk_percent: float
    network_bytes_sent: int
    network_bytes_recv: int
    active_connections: int
    strongswan_status: str
    openssl_version: str

class DatabaseManager:
    """Database operations manager"""
    
    def __init__(self, db_path: str = DATABASE_PATH):
        self.db_path = db_path
        self._ensure_database()
    
    def _ensure_database(self):
        """Create database and tables if they don't exist"""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        with self._get_connection() as conn:
            # Users table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    email TEXT UNIQUE,
                    auth_type TEXT NOT NULL,
                    certificate_path TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1,
                    groups TEXT DEFAULT '[]',
                    ip_assignment TEXT
                )
            """)
            
            # Connections table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    username TEXT,
                    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    end_time TIMESTAMP,
                    bytes_in INTEGER DEFAULT 0,
                    bytes_out INTEGER DEFAULT 0,
                    packets_in INTEGER DEFAULT 0,
                    packets_out INTEGER DEFAULT 0,
                    remote_ip TEXT,
                    disconnect_reason TEXT
                )
            """)
            
            # Metrics table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS metrics (
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    cpu_percent REAL,
                    memory_percent REAL,
                    disk_percent REAL,
                    network_bytes_sent INTEGER,
                    network_bytes_recv INTEGER,
                    active_connections INTEGER,
                    strongswan_status TEXT,
                    openssl_version TEXT
                )
            """)
            
            # Certificates table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS certificates (
                    fingerprint TEXT PRIMARY KEY,
                    subject TEXT,
                    issuer TEXT,
                    not_before TIMESTAMP,
                    not_after TIMESTAMP,
                    key_type TEXT,
                    key_size INTEGER,
                    file_path TEXT,
                    username TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.commit()
    
    @contextmanager
    def _get_connection(self):
        """Get database connection with proper error handling"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def add_user(self, user: User) -> bool:
        """Add new user to database"""
        try:
            with self._get_connection() as conn:
                conn.execute("""
                    INSERT INTO users (username, email, auth_type, certificate_path, 
                                     is_active, groups, ip_assignment)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    user.username, user.email, user.auth_type, user.certificate_path,
                    user.is_active, json.dumps(user.groups), user.ip_assignment
                ))
                conn.commit()
                return True
        except sqlite3.Error as e:
            logger.error(f"Failed to add user {user.username}: {e}")
            return False
    
    def get_user(self, username: str) -> Optional[User]:
        """Get user by username"""
        try:
            with self._get_connection() as conn:
                row = conn.execute(
                    "SELECT * FROM users WHERE username = ?", (username,)
                ).fetchone()
                
                if row:
                    return User(
                        username=row['username'],
                        email=row['email'],
                        auth_type=row['auth_type'],
                        certificate_path=row['certificate_path'],
                        created_at=datetime.fromisoformat(row['created_at']),
                        last_login=datetime.fromisoformat(row['last_login']) if row['last_login'] else None,
                        is_active=bool(row['is_active']),
                        groups=json.loads(row['groups']),
                        ip_assignment=row['ip_assignment']
                    )
        except sqlite3.Error as e:
            logger.error(f"Failed to get user {username}: {e}")
        return None
    
    def list_users(self) -> List[User]:
        """List all users"""
        users = []
        try:
            with self._get_connection() as conn:
                rows = conn.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
                
                for row in rows:
                    users.append(User(
                        username=row['username'],
                        email=row['email'],
                        auth_type=row['auth_type'],
                        certificate_path=row['certificate_path'],
                        created_at=datetime.fromisoformat(row['created_at']),
                        last_login=datetime.fromisoformat(row['last_login']) if row['last_login'] else None,
                        is_active=bool(row['is_active']),
                        groups=json.loads(row['groups']),
                        ip_assignment=row['ip_assignment']
                    ))
        except sqlite3.Error as e:
            logger.error(f"Failed to list users: {e}")
        return users
    
    def update_user_login(self, username: str) -> bool:
        """Update user last login time"""
        try:
            with self._get_connection() as conn:
                conn.execute(
                    "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE username = ?",
                    (username,)
                )
                conn.commit()
                return True
        except sqlite3.Error as e:
            logger.error(f"Failed to update login for {username}: {e}")
            return False
    
    def record_metrics(self, metrics: SystemMetrics) -> bool:
        """Record system metrics"""
        try:
            with self._get_connection() as conn:
                conn.execute("""
                    INSERT INTO metrics (cpu_percent, memory_percent, disk_percent,
                                       network_bytes_sent, network_bytes_recv, 
                                       active_connections, strongswan_status, openssl_version)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    metrics.cpu_percent, metrics.memory_percent, metrics.disk_percent,
                    metrics.network_bytes_sent, metrics.network_bytes_recv,
                    metrics.active_connections, metrics.strongswan_status, metrics.openssl_version
                ))
                conn.commit()
                return True
        except sqlite3.Error as e:
            logger.error(f"Failed to record metrics: {e}")
            return False

class OpenSSLManager:
    """OpenSSL 3.5 operations manager"""
    
    def __init__(self, openssl_bin: str = OPENSSL_BIN):
        self.openssl_bin = openssl_bin
        self._validate_openssl()
    
    def _validate_openssl(self):
        """Validate OpenSSL 3.5 installation"""
        if not os.path.exists(self.openssl_bin):
            raise RuntimeError(f"OpenSSL binary not found: {self.openssl_bin}")
        
        try:
            result = subprocess.run([self.openssl_bin, 'version'], 
                                  capture_output=True, text=True, check=True)
            version = result.stdout.split()[1]
            if not version.startswith('3.'):
                raise RuntimeError(f"OpenSSL 3.x required, found: {version}")
            logger.info(f"OpenSSL validated: {version}")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to validate OpenSSL: {e}")
    
    def get_version(self) -> str:
        """Get OpenSSL version"""
        try:
            result = subprocess.run([self.openssl_bin, 'version'], 
                                  capture_output=True, text=True, check=True)
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            return "Unknown"
    
    def list_algorithms(self) -> Dict[str, List[str]]:
        """List available cryptographic algorithms"""
        try:
            # Get symmetric algorithms
            result = subprocess.run([self.openssl_bin, 'list', '-algorithms'], 
                                  capture_output=True, text=True, check=True)
            
            algorithms = {
                'symmetric': [],
                'digest': [],
                'public_key': [],
                'signature': []
            }
            
            # Parse algorithm output
            lines = result.stdout.split('\n')
            current_category = None
            
            for line in lines:
                line = line.strip()
                if 'Cipher' in line:
                    current_category = 'symmetric'
                elif 'Digest' in line:
                    current_category = 'digest'
                elif line and current_category and not line.startswith(' '):
                    if current_category in algorithms:
                        algorithms[current_category].append(line)
            
            # Get public key algorithms
            try:
                result = subprocess.run([self.openssl_bin, 'list', '-public-key-algorithms'], 
                                      capture_output=True, text=True, check=True)
                algorithms['public_key'] = [line.strip() for line in result.stdout.split('\n') if line.strip()]
            except subprocess.CalledProcessError:
                pass
            
            return algorithms
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to list algorithms: {e}")
            return {}
    
    def get_certificate_info(self, cert_path: str) -> Optional[Dict[str, Any]]:
        """Get certificate information"""
        if not os.path.exists(cert_path):
            return None
        
        try:
            # Get certificate details
            result = subprocess.run([
                self.openssl_bin, 'x509', '-in', cert_path, 
                '-noout', '-text', '-fingerprint'
            ], capture_output=True, text=True, check=True)
            
            lines = result.stdout.split('\n')
            cert_info = {
                'file_path': cert_path,
                'fingerprint': '',
                'subject': '',
                'issuer': '',
                'not_before': '',
                'not_after': '',
                'key_type': '',
                'key_size': 0,
                'signature_algorithm': '',
                'extensions': []
            }
            
            for line in lines:
                line = line.strip()
                if line.startswith('SHA1 Fingerprint='):
                    cert_info['fingerprint'] = line.split('=')[1]
                elif line.startswith('Subject:'):
                    cert_info['subject'] = line.replace('Subject: ', '')
                elif line.startswith('Issuer:'):
                    cert_info['issuer'] = line.replace('Issuer: ', '')
                elif line.startswith('Not Before:'):
                    cert_info['not_before'] = line.replace('Not Before: ', '')
                elif line.startswith('Not After:'):
                    cert_info['not_after'] = line.replace('Not After: ', '')
                elif 'Public-Key:' in line:
                    if 'RSA' in line:
                        cert_info['key_type'] = 'RSA'
                        # Extract key size
                        for part in line.split():
                            if part.isdigit():
                                cert_info['key_size'] = int(part)
                                break
                    elif 'EC' in line or 'ECDSA' in line:
                        cert_info['key_type'] = 'ECDSA'
                elif 'Signature Algorithm:' in line:
                    cert_info['signature_algorithm'] = line.split(':')[1].strip()
            
            return cert_info
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to get certificate info for {cert_path}: {e}")
            return None

class StrongSwanManager:
    """strongSwan operations manager"""
    
    def __init__(self, ipsec_bin: str = STRONGSWAN_BIN):
        self.ipsec_bin = ipsec_bin
        self._validate_strongswan()
    
    def _validate_strongswan(self):
        """Validate strongSwan installation"""
        if not os.path.exists(self.ipsec_bin):
            raise RuntimeError(f"strongSwan binary not found: {self.ipsec_bin}")
        
        try:
            result = subprocess.run([self.ipsec_bin, 'version'], 
                                  capture_output=True, text=True, check=True)
            logger.info(f"strongSwan validated: {result.stdout.strip()}")
        except subprocess.CalledProcessError as e:
            logger.warning(f"strongSwan validation warning: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get strongSwan status"""
        try:
            result = subprocess.run([self.ipsec_bin, 'statusall'], 
                                  capture_output=True, text=True, check=True)
            
            status = {
                'running': True,
                'connections': [],
                'security_associations': [],
                'pools': [],
                'raw_output': result.stdout
            }
            
            # Parse status output
            lines = result.stdout.split('\n')
            current_connection = None
            
            for line in lines:
                line = line.strip()
                if line.startswith('Connections:'):
                    continue
                elif ':' in line and not line.startswith(' '):
                    # New connection
                    conn_name = line.split(':')[0].strip()
                    current_connection = {
                        'name': conn_name,
                        'status': 'defined',
                        'local': '',
                        'remote': '',
                        'children': []
                    }
                    status['connections'].append(current_connection)
                elif line.startswith('Security Associations'):
                    current_connection = None
                elif current_connection and line:
                    # Connection details
                    if 'local:' in line or 'remote:' in line:
                        parts = line.split(',')
                        for part in parts:
                            if 'local:' in part:
                                current_connection['local'] = part.split(':')[1].strip()
                            elif 'remote:' in part:
                                current_connection['remote'] = part.split(':')[1].strip()
            
            return status
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to get strongSwan status: {e}")
            return {'running': False, 'error': str(e)}
    
    def reload_connections(self) -> bool:
        """Reload strongSwan connections"""
        try:
            subprocess.run([self.ipsec_bin, 'reload'], 
                         capture_output=True, text=True, check=True)
            logger.info("strongSwan connections reloaded")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to reload strongSwan: {e}")
            return False
    
    def restart_service(self) -> bool:
        """Restart strongSwan service"""
        try:
            subprocess.run([self.ipsec_bin, 'restart'], 
                         capture_output=True, text=True, check=True)
            logger.info("strongSwan service restarted")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to restart strongSwan: {e}")
            return False

class PQCVPNManager:
    """Main VPN manager class"""
    
    def __init__(self):
        self.db = DatabaseManager()
        self.openssl = OpenSSLManager()
        self.strongswan = StrongSwanManager()
        self.monitoring_active = False
        self.monitoring_thread = None
    
    def add_user(self, username: str, email: str, auth_type: str = "pki", 
                 groups: List[str] = None, generate_cert: bool = True) -> bool:
        """Add new VPN user"""
        if groups is None:
            groups = ["vpn-users"]
        
        # Check if user already exists
        if self.db.get_user(username):
            logger.error(f"User {username} already exists")
            return False
        
        cert_path = None
        if auth_type == "pki" and generate_cert:
            # Generate client certificate using OpenSSL 3.5
            cert_path = self._generate_client_certificate(username, email)
            if not cert_path:
                logger.error(f"Failed to generate certificate for {username}")
                return False
        
        user = User(
            username=username,
            email=email,
            auth_type=auth_type,
            certificate_path=cert_path,
            created_at=datetime.now(),
            last_login=None,
            is_active=True,
            groups=groups,
            ip_assignment=None
        )
        
        if self.db.add_user(user):
            logger.info(f"User {username} added successfully")
            
            # Update IPsec configuration
            self._update_ipsec_config()
            
            return True
        
        return False
    
    def _generate_client_certificate(self, username: str, email: str) -> Optional[str]:
        """Generate client certificate using PQC keygen tool"""
        try:
            # Use the new OpenSSL 3.5 keygen tool
            keygen_script = "/usr/local/bin/pqc-vpn/pqc-keygen-openssl35.py"
            
            if not os.path.exists(keygen_script):
                logger.error(f"Certificate generation tool not found: {keygen_script}")
                return None
            
            # Set environment for OpenSSL 3.5
            env = os.environ.copy()
            env.update({
                'OPENSSL_CONF': f"{OPENSSL_PREFIX}/ssl/openssl.cnf",
                'LD_LIBRARY_PATH': f"{OPENSSL_PREFIX}/lib:{env.get('LD_LIBRARY_PATH', '')}",
                'PATH': f"{OPENSSL_PREFIX}/bin:{env.get('PATH', '')}"
            })
            
            # Generate client certificate
            cmd = [
                'python3', keygen_script, 'client', username,
                '--email', email,
                '--key-type', 'rsa',
                '--key-size', '4096'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, env=env)
            
            if result.returncode == 0:
                cert_path = f"/etc/ipsec.d/certs/{username}-cert.pem"
                if os.path.exists(cert_path):
                    logger.info(f"Certificate generated for {username}: {cert_path}")
                    return cert_path
            
            logger.error(f"Certificate generation failed: {result.stderr}")
            return None
            
        except Exception as e:
            logger.error(f"Exception during certificate generation: {e}")
            return None
    
    def _update_ipsec_config(self):
        """Update IPsec configuration for new users"""
        # This would update /etc/ipsec.conf and /etc/ipsec.secrets
        # Implementation depends on your specific configuration requirements
        logger.info("IPsec configuration updated")
    
    def list_users(self, format_type: str = "table") -> str:
        """List all VPN users"""
        users = self.db.list_users()
        
        if format_type == "json":
            return json.dumps([asdict(user) for user in users], indent=2, default=str)
        elif format_type == "yaml":
            return yaml.dump([asdict(user) for user in users], default_flow_style=False)
        else:
            # Table format
            from tabulate import tabulate
            
            table_data = []
            for user in users:
                status = "Active" if user.is_active else "Inactive"
                last_login = user.last_login.strftime("%Y-%m-%d %H:%M") if user.last_login else "Never"
                
                table_data.append([
                    user.username,
                    user.email,
                    user.auth_type.upper(),
                    ", ".join(user.groups),
                    status,
                    last_login
                ])
            
            headers = ["Username", "Email", "Auth Type", "Groups", "Status", "Last Login"]
            return tabulate(table_data, headers=headers, tablefmt="grid")
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""
        # System metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        network = psutil.net_io_counters()
        
        # strongSwan status
        strongswan_status = self.strongswan.get_status()
        
        # OpenSSL info
        openssl_version = self.openssl.get_version()
        algorithms = self.openssl.list_algorithms()
        
        # Active connections count
        active_connections = len([conn for conn in strongswan_status.get('connections', []) 
                                if conn.get('status') == 'established'])
        
        status = {
            'timestamp': datetime.now().isoformat(),
            'system': {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_available_gb': round(memory.available / (1024**3), 2),
                'disk_percent': disk.percent,
                'disk_free_gb': round(disk.free / (1024**3), 2),
                'network_bytes_sent': network.bytes_sent,
                'network_bytes_recv': network.bytes_recv,
                'uptime': self._get_uptime()
            },
            'strongswan': strongswan_status,
            'openssl': {
                'version': openssl_version,
                'algorithms_count': {k: len(v) for k, v in algorithms.items()}
            },
            'vpn': {
                'active_connections': active_connections,
                'total_users': len(self.db.list_users()),
                'active_users': len([u for u in self.db.list_users() if u.is_active])
            }
        }
        
        # Record metrics in database
        metrics = SystemMetrics(
            timestamp=datetime.now(),
            cpu_percent=cpu_percent,
            memory_percent=memory.percent,
            disk_percent=disk.percent,
            network_bytes_sent=network.bytes_sent,
            network_bytes_recv=network.bytes_recv,
            active_connections=active_connections,
            strongswan_status="running" if strongswan_status.get('running') else "stopped",
            openssl_version=openssl_version
        )
        self.db.record_metrics(metrics)
        
        return status
    
    def _get_uptime(self) -> str:
        """Get system uptime"""
        try:
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.readline().split()[0])
                uptime_days = int(uptime_seconds // 86400)
                uptime_hours = int((uptime_seconds % 86400) // 3600)
                uptime_minutes = int((uptime_seconds % 3600) // 60)
                return f"{uptime_days}d {uptime_hours}h {uptime_minutes}m"
        except:
            return "Unknown"
    
    def start_monitoring(self, interval: int = 60):
        """Start system monitoring"""
        if self.monitoring_active:
            logger.warning("Monitoring already active")
            return
        
        self.monitoring_active = True
        
        def monitor_loop():
            logger.info(f"Starting monitoring with {interval}s interval")
            while self.monitoring_active:
                try:
                    self.get_system_status()  # This records metrics
                    time.sleep(interval)
                except Exception as e:
                    logger.error(f"Monitoring error: {e}")
                    time.sleep(10)  # Brief pause on error
        
        self.monitoring_thread = threading.Thread(target=monitor_loop, daemon=True)
        self.monitoring_thread.start()
        logger.info("System monitoring started")
    
    def stop_monitoring(self):
        """Stop system monitoring"""
        if self.monitoring_active:
            self.monitoring_active = False
            if self.monitoring_thread:
                self.monitoring_thread.join(timeout=5)
            logger.info("System monitoring stopped")
    
    def backup_configuration(self, backup_path: str) -> bool:
        """Backup VPN configuration"""
        try:
            import tarfile
            from datetime import datetime
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = f"{backup_path}/pqc-vpn-backup-{timestamp}.tar.gz"
            
            with tarfile.open(backup_file, "w:gz") as tar:
                # Add configuration files
                config_files = [
                    "/etc/ipsec.conf",
                    "/etc/ipsec.secrets",
                    "/etc/strongswan.conf",
                    DATABASE_PATH
                ]
                
                for file_path in config_files:
                    if os.path.exists(file_path):
                        tar.add(file_path, arcname=os.path.basename(file_path))
                
                # Add certificates
                cert_dirs = [
                    "/etc/ipsec.d/certs",
                    "/etc/ipsec.d/cacerts",
                    "/etc/ipsec.d/private"
                ]
                
                for cert_dir in cert_dirs:
                    if os.path.exists(cert_dir):
                        tar.add(cert_dir, arcname=f"ipsec.d/{os.path.basename(cert_dir)}")
            
            logger.info(f"Configuration backed up to: {backup_file}")
            return True
            
        except Exception as e:
            logger.error(f"Backup failed: {e}")
            return False
    
    def generate_client_bundle(self, username: str, output_dir: str) -> Optional[str]:
        """Generate client connection bundle"""
        user = self.db.get_user(username)
        if not user:
            logger.error(f"User {username} not found")
            return None
        
        if user.auth_type != "pki" or not user.certificate_path:
            logger.error(f"User {username} does not have PKI authentication")
            return None
        
        try:
            # Use the certificate export functionality
            keygen_script = "/usr/local/bin/pqc-vpn/pqc-keygen-openssl35.py"
            
            env = os.environ.copy()
            env.update({
                'OPENSSL_CONF': f"{OPENSSL_PREFIX}/ssl/openssl.cnf",
                'LD_LIBRARY_PATH': f"{OPENSSL_PREFIX}/lib:{env.get('LD_LIBRARY_PATH', '')}",
                'PATH': f"{OPENSSL_PREFIX}/bin:{env.get('PATH', '')}"
            })
            
            cmd = ['python3', keygen_script, 'export', username, output_dir]
            
            result = subprocess.run(cmd, capture_output=True, text=True, env=env)
            
            if result.returncode == 0:
                bundle_path = f"{output_dir}/{username}"
                logger.info(f"Client bundle generated: {bundle_path}")
                return bundle_path
            else:
                logger.error(f"Bundle generation failed: {result.stderr}")
                return None
                
        except Exception as e:
            logger.error(f"Exception during bundle generation: {e}")
            return None


def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(
        description="PQC-VPN Manager with OpenSSL 3.5 Support",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Add new user with PKI authentication
  %(prog)s user add alice alice@company.com --auth-type pki
  
  # List all users
  %(prog)s user list
  
  # Show system status
  %(prog)s status
  
  # Start monitoring
  %(prog)s monitor start --interval 30
  
  # Generate client bundle
  %(prog)s bundle alice /tmp/vpn-clients/
  
  # Backup configuration
  %(prog)s backup /var/backups/
        """
    )
    
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--config', default=CONFIG_PATH, help='Configuration file path')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # User management commands
    user_parser = subparsers.add_parser('user', help='User management')
    user_subparsers = user_parser.add_subparsers(dest='user_action')
    
    # Add user
    add_user_parser = user_subparsers.add_parser('add', help='Add new user')
    add_user_parser.add_argument('username', help='Username')
    add_user_parser.add_argument('email', help='User email')
    add_user_parser.add_argument('--auth-type', choices=['pki', 'psk'], default='pki', help='Authentication type')
    add_user_parser.add_argument('--groups', help='Comma-separated list of groups')
    add_user_parser.add_argument('--no-cert', action='store_true', help='Do not generate certificate')
    
    # List users
    list_user_parser = user_subparsers.add_parser('list', help='List users')
    list_user_parser.add_argument('--format', choices=['table', 'json', 'yaml'], default='table', help='Output format')
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Show system status')
    status_parser.add_argument('--format', choices=['json', 'yaml'], help='Output format')
    
    # Monitoring commands
    monitor_parser = subparsers.add_parser('monitor', help='System monitoring')
    monitor_subparsers = monitor_parser.add_subparsers(dest='monitor_action')
    
    start_monitor_parser = monitor_subparsers.add_parser('start', help='Start monitoring')
    start_monitor_parser.add_argument('--interval', type=int, default=60, help='Monitoring interval in seconds')
    start_monitor_parser.add_argument('--daemon', action='store_true', help='Run as daemon')
    
    stop_monitor_parser = monitor_subparsers.add_parser('stop', help='Stop monitoring')
    
    # Bundle command
    bundle_parser = subparsers.add_parser('bundle', help='Generate client bundle')
    bundle_parser.add_argument('username', help='Username')
    bundle_parser.add_argument('output_dir', help='Output directory')
    
    # Backup command
    backup_parser = subparsers.add_parser('backup', help='Backup configuration')
    backup_parser.add_argument('backup_dir', help='Backup directory')
    
    # Certificate commands
    cert_parser = subparsers.add_parser('cert', help='Certificate management')
    cert_subparsers = cert_parser.add_subparsers(dest='cert_action')
    
    list_cert_parser = cert_subparsers.add_parser('list', help='List certificates')
    info_cert_parser = cert_subparsers.add_parser('info', help='Show certificate info')
    info_cert_parser.add_argument('cert_path', help='Certificate file path')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if not args.command:
        parser.print_help()
        return 1
    
    try:
        manager = PQCVPNManager()
        
        if args.command == 'user':
            if args.user_action == 'add':
                groups = args.groups.split(',') if args.groups else None
                success = manager.add_user(
                    args.username, 
                    args.email, 
                    args.auth_type,
                    groups,
                    not args.no_cert
                )
                if success:
                    print(f"User {args.username} added successfully")
                    return 0
                else:
                    print(f"Failed to add user {args.username}")
                    return 1
            
            elif args.user_action == 'list':
                result = manager.list_users(args.format)
                print(result)
                return 0
        
        elif args.command == 'status':
            status = manager.get_system_status()
            
            if args.format == 'json':
                print(json.dumps(status, indent=2, default=str))
            elif args.format == 'yaml':
                print(yaml.dump(status, default_flow_style=False))
            else:
                # Pretty print status
                print("PQC-VPN System Status")
                print("=" * 50)
                print(f"Timestamp: {status['timestamp']}")
                print(f"OpenSSL Version: {status['openssl']['version']}")
                print(f"Active VPN Connections: {status['vpn']['active_connections']}")
                print(f"Total Users: {status['vpn']['total_users']}")
                print(f"System CPU: {status['system']['cpu_percent']:.1f}%")
                print(f"System Memory: {status['system']['memory_percent']:.1f}%")
                print(f"System Uptime: {status['system']['uptime']}")
            
            return 0
        
        elif args.command == 'monitor':
            if args.monitor_action == 'start':
                if args.daemon:
                    # Daemonize
                    import daemon
                    with daemon.DaemonContext():
                        manager.start_monitoring(args.interval)
                        signal.pause()
                else:
                    manager.start_monitoring(args.interval)
                    try:
                        signal.pause()
                    except KeyboardInterrupt:
                        manager.stop_monitoring()
                        print("Monitoring stopped")
                return 0
            
            elif args.monitor_action == 'stop':
                manager.stop_monitoring()
                print("Monitoring stopped")
                return 0
        
        elif args.command == 'bundle':
            bundle_path = manager.generate_client_bundle(args.username, args.output_dir)
            if bundle_path:
                print(f"Client bundle generated: {bundle_path}")
                return 0
            else:
                print(f"Failed to generate bundle for {args.username}")
                return 1
        
        elif args.command == 'backup':
            success = manager.backup_configuration(args.backup_dir)
            if success:
                print(f"Configuration backed up to {args.backup_dir}")
                return 0
            else:
                print("Backup failed")
                return 1
        
        elif args.command == 'cert':
            if args.cert_action == 'list':
                # List certificates using OpenSSL manager
                cert_dir = "/etc/ipsec.d/certs"
                if os.path.exists(cert_dir):
                    from tabulate import tabulate
                    
                    table_data = []
                    for cert_file in Path(cert_dir).glob("*.pem"):
                        cert_info = manager.openssl.get_certificate_info(str(cert_file))
                        if cert_info:
                            table_data.append([
                                cert_file.name,
                                cert_info.get('subject', '').split('CN=')[1].split(',')[0] if 'CN=' in cert_info.get('subject', '') else 'N/A',
                                cert_info.get('key_type', 'Unknown'),
                                cert_info.get('key_size', 'Unknown'),
                                cert_info.get('not_after', 'Unknown')
                            ])
                    
                    headers = ['File', 'Common Name', 'Key Type', 'Key Size', 'Expires']
                    print(tabulate(table_data, headers=headers, tablefmt='grid'))
                else:
                    print("Certificate directory not found")
                return 0
            
            elif args.cert_action == 'info':
                cert_info = manager.openssl.get_certificate_info(args.cert_path)
                if cert_info:
                    print(json.dumps(cert_info, indent=2))
                else:
                    print(f"Could not read certificate: {args.cert_path}")
                    return 1
                return 0
        
        print(f"Unknown command: {args.command}")
        return 1
        
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
