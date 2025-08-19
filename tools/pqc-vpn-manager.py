#!/usr/bin/env python3
"""
Real PQC-VPN Enterprise Management Tool
Comprehensive management for production Post-Quantum Cryptography VPN
"""

import argparse
import sqlite3
import subprocess
import json
import os
import sys
import hashlib
import secrets
import time
from datetime import datetime, timedelta
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/opt/pqc-vpn/logs/manager.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class RealPQCVPNManager:
    """Real PQC-VPN Enterprise Management System"""
    
    def __init__(self, config_path='/opt/pqc-vpn/data'):
        self.config_path = Path(config_path)
        self.db_path = self.config_path / 'pqc-vpn.db'
        self.strongswan_bin = '/usr/local/strongswan/sbin/ipsec'
        self.openssl_bin = '/usr/local/oqs-openssl/bin/openssl'
        self.certs_path = Path('/etc/ipsec.d')
        
        # Ensure directories exist
        self.config_path.mkdir(parents=True, exist_ok=True)
        self._init_database()
    
    def _init_database(self):
        """Initialize enterprise database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Enhanced users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT,
                full_name TEXT,
                department TEXT,
                auth_type TEXT NOT NULL,
                certificate_path TEXT NULL,
                psk_key TEXT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP NULL,
                login_count INTEGER DEFAULT 0,
                status TEXT DEFAULT 'active',
                expiry_date DATE NULL,
                created_by TEXT,
                notes TEXT
            )
        ''')
        
        # Enhanced connections table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                client_ip TEXT,
                server_ip TEXT,
                connect_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                disconnect_time TIMESTAMP NULL,
                bytes_in INTEGER DEFAULT 0,
                bytes_out INTEGER DEFAULT 0,
                auth_method TEXT,
                pqc_algorithms TEXT,
                cipher_suite TEXT,
                status TEXT DEFAULT 'active',
                session_duration INTEGER DEFAULT 0,
                disconnect_reason TEXT NULL
            )
        ''')
        
        # System metrics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                active_connections INTEGER,
                cpu_usage REAL,
                memory_usage REAL,
                disk_usage REAL,
                network_in INTEGER,
                network_out INTEGER,
                pqc_connections INTEGER,
                failed_attempts INTEGER DEFAULT 0
            )
        ''')
        
        # Security events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                event_type TEXT,
                source_ip TEXT,
                user_id TEXT NULL,
                severity TEXT,
                message TEXT,
                details JSON NULL
            )
        ''')
        
        # Certificates table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                common_name TEXT NOT NULL,
                certificate_type TEXT,
                issuer TEXT,
                subject TEXT,
                serial_number TEXT,
                not_before TIMESTAMP,
                not_after TIMESTAMP,
                fingerprint TEXT,
                pqc_algorithm TEXT,
                status TEXT DEFAULT 'active',
                file_path TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Configuration table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS configuration (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                section TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT,
                description TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_by TEXT,
                UNIQUE(section, key)
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
    
    def add_user(self, username, email, full_name=None, department=None, 
                 auth_type='pki', expiry_days=365, created_by='admin'):
        """Add a new VPN user with enterprise features"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if user already exists
            cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
            if cursor.fetchone():
                logger.error(f"User {username} already exists")
                return {'success': False, 'error': 'User already exists'}
            
            # Generate credentials based on auth type
            psk_key = None
            cert_path = None
            
            if auth_type in ['psk', 'hybrid']:
                psk_key = secrets.token_urlsafe(32)
                logger.info(f"Generated PSK for user {username}")
            
            if auth_type in ['pki', 'hybrid']:
                cert_result = self._generate_user_certificate(username, email)
                if cert_result['success']:
                    cert_path = cert_result['certificate_path']
                    logger.info(f"Generated certificate for user {username}")
                else:
                    logger.error(f"Failed to generate certificate for {username}")
                    return cert_result
            
            # Calculate expiry date
            expiry_date = datetime.now() + timedelta(days=expiry_days)
            
            # Insert user
            cursor.execute('''
                INSERT INTO users 
                (username, email, full_name, department, auth_type, certificate_path, 
                 psk_key, expiry_date, created_by, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
            ''', (username, email, full_name, department, auth_type, 
                  cert_path, psk_key, expiry_date, created_by))
            
            user_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            # Update strongSwan configuration
            if auth_type in ['psk', 'hybrid']:
                self._update_ipsec_secrets()
            
            # Log security event
            self._log_security_event('USER_CREATED', None, username, 'INFO', 
                                   f'User {username} created with {auth_type} authentication')
            
            logger.info(f"Successfully created user {username}")
            return {
                'success': True,
                'user_id': user_id,
                'username': username,
                'psk_key': psk_key,
                'certificate_path': cert_path,
                'expiry_date': expiry_date.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error adding user {username}: {e}")
            return {'success': False, 'error': str(e)}
    
    def _generate_user_certificate(self, username, email):
        """Generate PQC certificate for user"""
        try:
            # Ensure certificate directories exist
            private_dir = self.certs_path / 'private'
            certs_dir = self.certs_path / 'certs'
            private_dir.mkdir(exist_ok=True)
            certs_dir.mkdir(exist_ok=True)
            
            key_path = private_dir / f'{username}-key.pem'
            cert_path = certs_dir / f'{username}-cert.pem'
            csr_path = f'/tmp/{username}.csr'
            
            # Generate PQC private key
            cmd = [
                self.openssl_bin, 'genpkey',
                '-algorithm', 'dilithium5',
                '-out', str(key_path)
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                return {'success': False, 'error': f'Key generation failed: {result.stderr}'}
            
            # Set proper permissions
            os.chmod(key_path, 0o600)
            
            # Generate certificate signing request
            subject = f'/C=US/ST=CA/L=San Francisco/O=PQC-VPN-Enterprise/OU=VPN User/CN={username}/emailAddress={email}'
            cmd = [
                self.openssl_bin, 'req', '-new',
                '-key', str(key_path),
                '-out', csr_path,
                '-subj', subject
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                return {'success': False, 'error': f'CSR generation failed: {result.stderr}'}
            
            # Sign certificate with CA
            ca_cert = self.certs_path / 'cacerts' / 'ca-cert.pem'
            ca_key = self.certs_path / 'private' / 'ca-key.pem'
            
            if not ca_cert.exists() or not ca_key.exists():
                return {'success': False, 'error': 'CA certificate or key not found'}
            
            # Create certificate extensions
            ext_file = f'/tmp/{username}_ext.conf'
            with open(ext_file, 'w') as f:
                f.write('''basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = @alt_names

[alt_names]
email.1 = {email}
DNS.1 = {username}
'''.format(email=email, username=username))
            
            cmd = [
                self.openssl_bin, 'x509', '-req',
                '-in', csr_path,
                '-CA', str(ca_cert),
                '-CAkey', str(ca_key),
                '-CAcreateserial',
                '-out', str(cert_path),
                '-days', '365',
                '-extensions', 'v3_ext',
                '-extfile', ext_file
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Clean up temporary files
            for temp_file in [csr_path, ext_file]:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            
            if result.returncode != 0:
                return {'success': False, 'error': f'Certificate signing failed: {result.stderr}'}
            
            # Store certificate information in database
            self._store_certificate_info(username, str(cert_path))
            
            return {
                'success': True,
                'certificate_path': str(cert_path),
                'private_key_path': str(key_path)
            }
            
        except Exception as e:
            logger.error(f"Certificate generation error: {e}")
            return {'success': False, 'error': str(e)}
    
    def _store_certificate_info(self, username, cert_path):
        """Store certificate information in database"""
        try:
            # Extract certificate information
            cmd = [self.openssl_bin, 'x509', '-in', cert_path, '-text', '-noout']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                logger.error(f"Failed to read certificate {cert_path}")
                return
            
            cert_info = result.stdout
            
            # Parse certificate details (simplified parsing)
            import re
            subject_match = re.search(r'Subject: (.+)', cert_info)
            issuer_match = re.search(r'Issuer: (.+)', cert_info)
            not_before_match = re.search(r'Not Before: (.+)', cert_info)
            not_after_match = re.search(r'Not After : (.+)', cert_info)
            serial_match = re.search(r'Serial Number:\s*([a-f0-9:]+)', cert_info)
            
            # Calculate fingerprint
            cmd = [self.openssl_bin, 'x509', '-in', cert_path, '-fingerprint', '-sha256', '-noout']
            fp_result = subprocess.run(cmd, capture_output=True, text=True)
            fingerprint = fp_result.stdout.split('=')[1].strip() if fp_result.returncode == 0 else None
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO certificates 
                (common_name, certificate_type, issuer, subject, serial_number,
                 not_before, not_after, fingerprint, pqc_algorithm, file_path)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                username, 'client',
                issuer_match.group(1) if issuer_match else None,
                subject_match.group(1) if subject_match else None,
                serial_match.group(1) if serial_match else None,
                not_before_match.group(1) if not_before_match else None,
                not_after_match.group(1) if not_after_match else None,
                fingerprint,
                'dilithium5',
                cert_path
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error storing certificate info: {e}")
    
    def _update_ipsec_secrets(self):
        """Update IPsec secrets file with current PSK users"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT username, psk_key FROM users 
                WHERE psk_key IS NOT NULL AND status = 'active'
            ''')
            users = cursor.fetchall()
            conn.close()
            
            secrets_file = '/etc/ipsec.secrets'
            
            # Read existing secrets file
            existing_lines = []
            if os.path.exists(secrets_file):
                with open(secrets_file, 'r') as f:
                    existing_lines = f.readlines()
            
            # Keep non-user lines
            new_lines = []
            for line in existing_lines:
                if not line.strip().startswith((': RSA', ': PSK')) or 'ca-key.pem' in line or 'hub-key.pem' in line:
                    new_lines.append(line)
            
            # Add current users
            for username, psk_key in users:
                new_lines.append(f'{username} : PSK "{psk_key}"\n')
            
            # Write updated file
            with open(secrets_file, 'w') as f:
                f.writelines(new_lines)
            
            os.chmod(secrets_file, 0o600)
            
            # Reload strongSwan
            subprocess.run([self.strongswan_bin, 'reload'], capture_output=True)
            logger.info("Updated IPsec secrets and reloaded strongSwan")
            
        except Exception as e:
            logger.error(f"Error updating IPsec secrets: {e}")
    
    def list_users(self, status='all'):
        """List all users with filtering"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            query = 'SELECT * FROM users'
            params = []
            
            if status != 'all':
                query += ' WHERE status = ?'
                params.append(status)
            
            query += ' ORDER BY created_at DESC'
            
            cursor.execute(query, params)
            users = cursor.fetchall()
            conn.close()
            
            # Format users for display
            user_list = []
            for user in users:
                user_dict = {
                    'id': user[0],
                    'username': user[1],
                    'email': user[2],
                    'full_name': user[3],
                    'department': user[4],
                    'auth_type': user[5],
                    'created_at': user[8],
                    'last_login': user[9],
                    'login_count': user[10],
                    'status': user[11],
                    'expiry_date': user[12]
                }
                user_list.append(user_dict)
            
            return {'success': True, 'users': user_list}
            
        except Exception as e:
            logger.error(f"Error listing users: {e}")
            return {'success': False, 'error': str(e)}
    
    def delete_user(self, username, deleted_by='admin'):
        """Delete a user and revoke access"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get user info
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            
            if not user:
                return {'success': False, 'error': 'User not found'}
            
            # Revoke certificate if PKI
            if user[5] in ['pki', 'hybrid'] and user[6]:  # auth_type and certificate_path
                self._revoke_certificate(user[6])
            
            # Delete user
            cursor.execute('DELETE FROM users WHERE username = ?', (username,))
            conn.commit()
            conn.close()
            
            # Update strongSwan configuration
            if user[5] in ['psk', 'hybrid']:  # auth_type
                self._update_ipsec_secrets()
            
            # Log security event
            self._log_security_event('USER_DELETED', None, username, 'WARNING', 
                                   f'User {username} deleted by {deleted_by}')
            
            logger.info(f"Successfully deleted user {username}")
            return {'success': True, 'message': f'User {username} deleted'}
            
        except Exception as e:
            logger.error(f"Error deleting user {username}: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_system_status(self):
        """Get comprehensive system status"""
        try:
            # Get strongSwan status
            result = subprocess.run([self.strongswan_bin, 'status'], 
                                  capture_output=True, text=True)
            strongswan_status = result.stdout if result.returncode == 0 else 'Error'
            
            # Count active connections
            active_connections = strongswan_status.count('ESTABLISHED')
            
            # Get system metrics
            import psutil
            cpu_usage = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            network = psutil.net_io_counters()
            
            # Get database statistics
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT COUNT(*) FROM users WHERE status = "active"')
            active_users = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM connections WHERE status = "active"')
            total_connections = cursor.fetchone()[0]
            
            cursor.execute('''
                SELECT COUNT(*) FROM security_events 
                WHERE timestamp > datetime('now', '-24 hours')
            ''')
            recent_events = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                'success': True,
                'status': {
                    'strongswan_running': result.returncode == 0,
                    'active_connections': active_connections,
                    'active_users': active_users,
                    'total_connections': total_connections,
                    'recent_security_events': recent_events,
                    'system': {
                        'cpu_usage': cpu_usage,
                        'memory_usage': memory.percent,
                        'disk_usage': (disk.used / disk.total) * 100,
                        'network_bytes_sent': network.bytes_sent,
                        'network_bytes_recv': network.bytes_recv
                    },
                    'timestamp': datetime.now().isoformat()
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting system status: {e}")
            return {'success': False, 'error': str(e)}
    
    def _log_security_event(self, event_type, source_ip, user_id, severity, message, details=None):
        """Log security event to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO security_events 
                (event_type, source_ip, user_id, severity, message, details)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (event_type, source_ip, user_id, severity, message, 
                  json.dumps(details) if details else None))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error logging security event: {e}")

def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(description='Real PQC-VPN Enterprise Management')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # User management commands
    user_parser = subparsers.add_parser('user', help='User management')
    user_subparsers = user_parser.add_subparsers(dest='user_action')
    
    # Add user
    add_user_parser = user_subparsers.add_parser('add', help='Add new user')
    add_user_parser.add_argument('username', help='Username')
    add_user_parser.add_argument('email', help='Email address')
    add_user_parser.add_argument('--full-name', help='Full name')
    add_user_parser.add_argument('--department', help='Department')
    add_user_parser.add_argument('--auth-type', choices=['pki', 'psk', 'hybrid'], 
                                default='pki', help='Authentication type')
    add_user_parser.add_argument('--expiry-days', type=int, default=365, 
                                help='Certificate expiry in days')
    
    # List users
    list_user_parser = user_subparsers.add_parser('list', help='List users')
    list_user_parser.add_argument('--status', choices=['active', 'inactive', 'all'], 
                                 default='all', help='Filter by status')
    
    # Delete user
    del_user_parser = user_subparsers.add_parser('delete', help='Delete user')
    del_user_parser.add_argument('username', help='Username to delete')
    
    # System commands
    status_parser = subparsers.add_parser('status', help='System status')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    manager = RealPQCVPNManager()
    
    try:
        if args.command == 'user':
            if args.user_action == 'add':
                result = manager.add_user(
                    args.username, args.email, args.full_name, 
                    args.department, args.auth_type, args.expiry_days
                )
                if result['success']:
                    print(f"✅ User {args.username} created successfully")
                    if result.get('psk_key'):
                        print(f"🔑 PSK: {result['psk_key']}")
                    if result.get('certificate_path'):
                        print(f"📜 Certificate: {result['certificate_path']}")
                else:
                    print(f"❌ Error: {result['error']}")
            
            elif args.user_action == 'list':
                result = manager.list_users(args.status)
                if result['success']:
                    users = result['users']
                    print(f"\n📊 Users ({len(users)} total):")
                    print("-" * 80)
                    for user in users:
                        print(f"👤 {user['username']:<15} | {user['email']:<25} | {user['auth_type']:<8} | {user['status']}")
                else:
                    print(f"❌ Error: {result['error']}")
            
            elif args.user_action == 'delete':
                result = manager.delete_user(args.username)
                if result['success']:
                    print(f"✅ {result['message']}")
                else:
                    print(f"❌ Error: {result['error']}")
        
        elif args.command == 'status':
            result = manager.get_system_status()
            if result['success']:
                status = result['status']
                print("\n🔐 PQC-VPN System Status")
                print("=" * 50)
                print(f"strongSwan: {'✅ Running' if status['strongswan_running'] else '❌ Stopped'}")
                print(f"Active Connections: {status['active_connections']}")
                print(f"Active Users: {status['active_users']}")
                print(f"System Load: CPU {status['system']['cpu_usage']:.1f}% | Memory {status['system']['memory_usage']:.1f}%")
                print(f"Recent Security Events: {status['recent_security_events']}")
                print(f"Last Updated: {status['timestamp']}")
            else:
                print(f"❌ Error: {result['error']}")
    
    except KeyboardInterrupt:
        print("\n⚠️ Operation cancelled")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        print(f"❌ Unexpected error: {e}")

if __name__ == '__main__':
    main()
