#!/usr/bin/env python3
"""
PQC-VPN Enterprise Management Tool v1.0.0
Enterprise-grade management for Post-Quantum Cryptography VPN

This tool provides comprehensive management capabilities for the PQC-VPN
enterprise solution including user management, certificate handling,
system monitoring, and security administration.
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
import ssl
import socket
from datetime import datetime, timedelta
import logging
from pathlib import Path
import yaml
import psutil
from typing import Dict, List, Optional, Any
import ipaddress
import re

# Version information
VERSION = "1.0.0"
BUILD_DATE = "2025-08-19"
PRODUCT_NAME = "PQC-VPN Enterprise"

# Configure logging
def setup_logging(log_level="INFO", log_file="/var/log/pqc-vpn/manager.log"):
    """Setup enterprise logging with proper formatting"""
    log_dir = Path(log_file).parent
    log_dir.mkdir(parents=True, exist_ok=True)
    
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - [%(funcName)s:%(lineno)d] - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger(__name__)

logger = setup_logging()

class PQCVPNManager:
    """Enterprise PQC-VPN Management System
    
    Comprehensive management system for Post-Quantum Cryptography VPN
    infrastructure with enterprise features including user management,
    certificate lifecycle, security monitoring, and system administration.
    """
    
    def __init__(self, config_path='/opt/pqc-vpn', debug=False):
        """Initialize the PQC-VPN Manager
        
        Args:
            config_path (str): Base configuration directory
            debug (bool): Enable debug logging
        """
        self.config_path = Path(config_path)
        self.data_path = self.config_path / 'data'
        self.db_path = self.data_path / 'pqc-vpn-enterprise.db'
        self.certs_path = Path('/etc/ipsec.d')
        self.config_file = self.config_path / 'config.yaml'
        
        # Enterprise paths
        self.strongswan_bin = '/usr/local/strongswan/sbin/ipsec'
        self.openssl_bin = '/usr/local/oqs-openssl/bin/openssl'
        self.backup_path = Path('/var/backups/pqc-vpn')
        
        # Create necessary directories
        for path in [self.config_path, self.data_path, self.backup_path]:
            path.mkdir(parents=True, exist_ok=True)
        
        # Initialize configuration
        self.config = self._load_configuration()
        
        # Initialize database
        self._init_enterprise_database()
        
        # Set debug logging if requested
        if debug:
            logging.getLogger().setLevel(logging.DEBUG)
            logger.debug("Debug logging enabled")
        
        logger.info(f"{PRODUCT_NAME} Manager v{VERSION} initialized")
    
    def _load_configuration(self) -> Dict[str, Any]:
        """Load enterprise configuration from file"""
        default_config = {
            'enterprise': {
                'organization': 'Enterprise',
                'country': 'US',
                'state': 'California',
                'locality': 'San Francisco',
                'domain': 'pqc-vpn.enterprise.local'
            },
            'security': {
                'pqc_kem_algorithm': 'kyber1024',
                'pqc_sig_algorithm': 'dilithium5',
                'certificate_validity_days': 365,
                'ca_validity_days': 3650,
                'auto_renewal_enabled': True,
                'auto_renewal_threshold_days': 30,
                'password_complexity': {
                    'min_length': 12,
                    'require_uppercase': True,
                    'require_lowercase': True,
                    'require_numbers': True,
                    'require_symbols': True
                }
            },
            'network': {
                'hub_subnet': '10.10.0.0/16',
                'dns_servers': ['8.8.8.8', '8.8.4.4'],
                'mtu': 1436,
                'keepalive': 30
            },
            'monitoring': {
                'metrics_enabled': True,
                'health_check_interval': 60,
                'log_retention_days': 90,
                'alert_thresholds': {
                    'cpu_usage': 80,
                    'memory_usage': 85,
                    'disk_usage': 90,
                    'connection_failure_rate': 5
                }
            },
            'backup': {
                'enabled': True,
                'schedule': '0 2 * * *',  # Daily at 2 AM
                'retention_days': 30,
                'encryption_enabled': True
            }
        }
        
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    config = yaml.safe_load(f)
                # Merge with defaults
                default_config.update(config)
                logger.info("Configuration loaded from file")
            except Exception as e:
                logger.warning(f"Error loading config file: {e}, using defaults")
        else:
            # Create default config file
            try:
                with open(self.config_file, 'w') as f:
                    yaml.dump(default_config, f, default_flow_style=False, indent=2)
                logger.info("Created default configuration file")
            except Exception as e:
                logger.error(f"Error creating config file: {e}")
        
        return default_config
    
    def _init_enterprise_database(self):
        """Initialize enterprise-grade database schema with comprehensive tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Enable foreign keys
        cursor.execute('PRAGMA foreign_keys = ON')
        
        # Users table with enterprise features
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT NOT NULL,
                full_name TEXT,
                department TEXT,
                role TEXT DEFAULT 'user',
                auth_type TEXT NOT NULL CHECK (auth_type IN ('pki', 'psk', 'hybrid', 'mfa')),
                certificate_path TEXT,
                certificate_serial TEXT,
                psk_key TEXT,
                totp_secret TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_by TEXT DEFAULT 'system',
                last_login TIMESTAMP,
                login_count INTEGER DEFAULT 0,
                failed_login_attempts INTEGER DEFAULT 0,
                account_locked_until TIMESTAMP,
                status TEXT DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended', 'expired')),
                expiry_date DATE,
                last_password_change TIMESTAMP,
                notes TEXT,
                metadata JSON
            )
        ''')
        
        # VPN connections table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vpn_connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_id TEXT UNIQUE NOT NULL,
                client_ip TEXT,
                client_hostname TEXT,
                server_ip TEXT,
                connect_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                disconnect_time TIMESTAMP,
                bytes_in INTEGER DEFAULT 0,
                bytes_out INTEGER DEFAULT 0,
                packets_in INTEGER DEFAULT 0,
                packets_out INTEGER DEFAULT 0,
                auth_method TEXT,
                pqc_algorithms TEXT,
                cipher_suite TEXT,
                status TEXT DEFAULT 'active' CHECK (status IN ('active', 'disconnected', 'failed')),
                duration_seconds INTEGER DEFAULT 0,
                disconnect_reason TEXT,
                client_version TEXT,
                geolocation TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
        
        # System metrics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                metric_type TEXT NOT NULL,
                metric_name TEXT NOT NULL,
                metric_value REAL NOT NULL,
                unit TEXT,
                node_id TEXT DEFAULT 'hub-01',
                metadata JSON
            )
        ''')
        
        # Security events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                event_type TEXT NOT NULL,
                event_category TEXT NOT NULL,
                source_ip TEXT,
                user_id INTEGER,
                user_agent TEXT,
                severity TEXT NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
                title TEXT NOT NULL,
                description TEXT,
                details JSON,
                remediation_status TEXT DEFAULT 'open' CHECK (remediation_status IN ('open', 'investigating', 'resolved', 'false_positive')),
                assigned_to TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
            )
        ''')
        
        # Certificates table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                common_name TEXT NOT NULL,
                certificate_type TEXT NOT NULL CHECK (certificate_type IN ('ca', 'server', 'client')),
                issuer_dn TEXT,
                subject_dn TEXT,
                serial_number TEXT UNIQUE,
                not_before TIMESTAMP,
                not_after TIMESTAMP,
                fingerprint_sha256 TEXT,
                fingerprint_sha1 TEXT,
                pqc_algorithm TEXT,
                key_size INTEGER,
                status TEXT DEFAULT 'valid' CHECK (status IN ('valid', 'expired', 'revoked', 'pending')),
                file_path TEXT,
                private_key_path TEXT,
                revocation_reason TEXT,
                revoked_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_by TEXT,
                auto_renew BOOLEAN DEFAULT 1,
                renewal_threshold_days INTEGER DEFAULT 30
            )
        ''')
        
        # Certificate revocation list
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS certificate_revocations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                certificate_id INTEGER NOT NULL,
                serial_number TEXT NOT NULL,
                revocation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reason_code INTEGER,
                reason_text TEXT,
                revoked_by TEXT,
                FOREIGN KEY (certificate_id) REFERENCES certificates (id) ON DELETE CASCADE
            )
        ''')
        
        # Configuration table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS configuration (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                section TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT,
                data_type TEXT DEFAULT 'string',
                description TEXT,
                is_secret BOOLEAN DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_by TEXT,
                version INTEGER DEFAULT 1,
                UNIQUE(section, key)
            )
        ''')
        
        # Audit log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                action TEXT NOT NULL,
                resource_type TEXT,
                resource_id TEXT,
                old_values JSON,
                new_values JSON,
                ip_address TEXT,
                user_agent TEXT,
                success BOOLEAN DEFAULT 1,
                error_message TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
            )
        ''')
        
        # Backup records table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS backup_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                backup_type TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_size INTEGER,
                checksum TEXT,
                encryption_enabled BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                status TEXT DEFAULT 'completed' CHECK (status IN ('in_progress', 'completed', 'failed'))
            )
        ''')
        
        # Create indexes for performance
        indexes = [
            'CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)',
            'CREATE INDEX IF NOT EXISTS idx_users_status ON users(status)',
            'CREATE INDEX IF NOT EXISTS idx_users_expiry_date ON users(expiry_date)',
            'CREATE INDEX IF NOT EXISTS idx_vpn_connections_user_id ON vpn_connections(user_id)',
            'CREATE INDEX IF NOT EXISTS idx_vpn_connections_status ON vpn_connections(status)',
            'CREATE INDEX IF NOT EXISTS idx_vpn_connections_connect_time ON vpn_connections(connect_time)',
            'CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp)',
            'CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events(severity)',
            'CREATE INDEX IF NOT EXISTS idx_security_events_user_id ON security_events(user_id)',
            'CREATE INDEX IF NOT EXISTS idx_certificates_serial_number ON certificates(serial_number)',
            'CREATE INDEX IF NOT EXISTS idx_certificates_status ON certificates(status)',
            'CREATE INDEX IF NOT EXISTS idx_certificates_not_after ON certificates(not_after)',
            'CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp)',
            'CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id)',
            'CREATE INDEX IF NOT EXISTS idx_system_metrics_timestamp ON system_metrics(timestamp)',
            'CREATE INDEX IF NOT EXISTS idx_system_metrics_type ON system_metrics(metric_type)'
        ]
        
        for index in indexes:
            cursor.execute(index)
        
        # Insert initial configuration if empty
        cursor.execute('SELECT COUNT(*) FROM configuration')
        if cursor.fetchone()[0] == 0:
            initial_config = [
                ('system', 'version', VERSION, 'string', 'PQC-VPN version'),
                ('system', 'installation_date', datetime.now().isoformat(), 'datetime', 'Installation date'),
                ('system', 'node_id', 'hub-01', 'string', 'Node identifier'),
                ('security', 'password_policy_enabled', 'true', 'boolean', 'Enable password policy'),
                ('monitoring', 'metrics_collection_enabled', 'true', 'boolean', 'Enable metrics collection'),
                ('backup', 'auto_backup_enabled', 'true', 'boolean', 'Enable automatic backups')
            ]
            
            cursor.executemany('''
                INSERT INTO configuration (section, key, value, data_type, description, updated_by)
                VALUES (?, ?, ?, ?, ?, 'system')
            ''', initial_config)
        
        conn.commit()
        conn.close()
        
        logger.info("Enterprise database schema initialized successfully")
    
    def add_user(self, username: str, email: str, full_name: str = None, 
                 department: str = None, role: str = 'user', auth_type: str = 'pki',
                 expiry_days: int = 365, created_by: str = 'admin') -> Dict[str, Any]:
        """Add a new VPN user with enterprise security features
        
        Args:
            username: Unique username
            email: User email address
            full_name: Full name of the user
            department: Department/organization
            role: User role (user, admin, auditor)
            auth_type: Authentication type (pki, psk, hybrid, mfa)
            expiry_days: Account expiry in days
            created_by: Administrator creating the user
            
        Returns:
            Dict containing success status and user details
        """
        try:
            # Validate input
            if not self._validate_username(username):
                return {'success': False, 'error': 'Invalid username format'}
            
            if not self._validate_email(email):
                return {'success': False, 'error': 'Invalid email format'}
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if user already exists
            cursor.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
            if cursor.fetchone():
                conn.close()
                return {'success': False, 'error': 'User already exists'}
            
            # Generate credentials based on auth type
            credentials = {}
            
            if auth_type in ['psk', 'hybrid']:
                credentials['psk_key'] = self._generate_secure_psk()
                logger.info(f"Generated PSK for user {username}")
            
            if auth_type in ['pki', 'hybrid', 'mfa']:
                cert_result = self._generate_user_certificate(username, email, full_name)
                if cert_result['success']:
                    credentials.update(cert_result)
                    logger.info(f"Generated PQC certificate for user {username}")
                else:
                    conn.close()
                    return cert_result
            
            if auth_type == 'mfa':
                credentials['totp_secret'] = self._generate_totp_secret()
                logger.info(f"Generated TOTP secret for user {username}")
            
            # Calculate expiry date
            expiry_date = datetime.now() + timedelta(days=expiry_days)
            
            # Insert user into database
            cursor.execute('''
                INSERT INTO users 
                (username, email, full_name, department, role, auth_type, 
                 certificate_path, certificate_serial, psk_key, totp_secret,
                 expiry_date, created_by, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
            ''', (
                username, email, full_name, department, role, auth_type,
                credentials.get('certificate_path'),
                credentials.get('certificate_serial'),
                credentials.get('psk_key'),
                credentials.get('totp_secret'),
                expiry_date, created_by
            ))
            
            user_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            # Update VPN configuration
            self._update_vpn_configuration()
            
            # Log security event and audit trail
            self._log_security_event(
                'USER_CREATED', 'ACCESS_CONTROL', None, user_id,
                'MEDIUM', f'User {username} created',
                f'New user {username} created with {auth_type} authentication',
                {'user_id': user_id, 'auth_type': auth_type, 'created_by': created_by}
            )
            
            self._log_audit_event(
                user_id, 'CREATE_USER', 'user', str(user_id),
                None, {'username': username, 'auth_type': auth_type}
            )
            
            logger.info(f"Successfully created user {username} (ID: {user_id})")
            
            result = {
                'success': True,
                'user_id': user_id,
                'username': username,
                'auth_type': auth_type,
                'expiry_date': expiry_date.isoformat()
            }
            result.update(credentials)
            
            return result
            
        except Exception as e:
            logger.error(f"Error creating user {username}: {e}")
            return {'success': False, 'error': str(e)}
    
    def _validate_username(self, username: str) -> bool:
        """Validate username against enterprise policies"""
        if not username or len(username) < 3 or len(username) > 32:
            return False
        
        # Only alphanumeric characters, hyphens, and underscores
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            return False
        
        # Must start with letter
        if not username[0].isalpha():
            return False
        
        return True
    
    def _validate_email(self, email: str) -> bool:
        """Validate email address format"""
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(email_pattern, email))
    
    def _generate_secure_psk(self) -> str:
        """Generate cryptographically secure pre-shared key"""
        return secrets.token_urlsafe(48)  # 64 characters, 256 bits of entropy
    
    def _generate_totp_secret(self) -> str:
        """Generate TOTP secret for multi-factor authentication"""
        return secrets.token_urlsafe(32)
    
    def _generate_user_certificate(self, username: str, email: str, 
                                 full_name: str = None) -> Dict[str, Any]:
        """Generate PQC certificate for user authentication
        
        Args:
            username: Username for certificate CN
            email: Email for certificate SAN
            full_name: Full name for certificate subject
            
        Returns:
            Dict containing certificate details or error
        """
        try:
            # Ensure certificate directories exist
            private_dir = self.certs_path / 'private'
            certs_dir = self.certs_path / 'certs'
            for dir_path in [private_dir, certs_dir]:
                dir_path.mkdir(parents=True, exist_ok=True)
            
            key_path = private_dir / f'{username}-key.pem'
            cert_path = certs_dir / f'{username}-cert.pem'
            csr_path = f'/tmp/{username}-{int(time.time())}.csr'
            
            # Get PQC algorithm from config
            pqc_sig_algorithm = self.config['security']['pqc_sig_algorithm']
            
            # Generate PQC private key
            cmd = [
                self.openssl_bin, 'genpkey',
                '-algorithm', pqc_sig_algorithm,
                '-out', str(key_path)
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logger.error(f"Private key generation failed: {result.stderr}")
                return {'success': False, 'error': f'Key generation failed: {result.stderr}'}
            
            # Set secure permissions
            os.chmod(key_path, 0o600)
            
            # Create certificate subject
            org_config = self.config['enterprise']
            subject_parts = [
                f"C={org_config['country']}",
                f"ST={org_config['state']}",
                f"L={org_config['locality']}",
                f"O={org_config['organization']}",
                "OU=VPN Users"
            ]
            
            if full_name:
                subject_parts.append(f"CN={full_name} ({username})")
            else:
                subject_parts.append(f"CN={username}")
            
            subject_parts.append(f"emailAddress={email}")
            subject = "/" + "/".join(subject_parts)
            
            # Generate certificate signing request
            cmd = [
                self.openssl_bin, 'req', '-new',
                '-key', str(key_path),
                '-out', csr_path,
                '-subj', subject
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logger.error(f"CSR generation failed: {result.stderr}")
                return {'success': False, 'error': f'CSR generation failed: {result.stderr}'}
            
            # Check for CA certificate and key
            ca_cert = self.certs_path / 'cacerts' / 'ca-cert.pem'
            ca_key = self.certs_path / 'private' / 'ca-key.pem'
            
            if not ca_cert.exists() or not ca_key.exists():
                return {'success': False, 'error': 'CA certificate or key not found. Please initialize CA first.'}
            
            # Create certificate extensions file
            ext_file = f'/tmp/{username}-ext-{int(time.time())}.conf'
            with open(ext_file, 'w') as f:
                f.write(f'''[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = @alt_names
certificatePolicies = @pol_sect

[alt_names]
email.1 = {email}
DNS.1 = {username}
DNS.2 = {username}.{org_config['domain']}

[pol_sect]
policyIdentifier = 1.3.6.1.4.1.99999.1
CPS.1 = "https://{org_config['domain']}/ca/cps"
userNotice.1 = @notice

[notice]
explicitText = "PQC-VPN Enterprise Certificate Policy"
''')
            
            # Sign certificate with CA
            validity_days = self.config['security']['certificate_validity_days']
            cmd = [
                self.openssl_bin, 'x509', '-req',
                '-in', csr_path,
                '-CA', str(ca_cert),
                '-CAkey', str(ca_key),
                '-CAcreateserial',
                '-out', str(cert_path),
                '-days', str(validity_days),
                '-extensions', 'v3_req',
                '-extfile', ext_file
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Clean up temporary files
            for temp_file in [csr_path, ext_file]:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            
            if result.returncode != 0:
                logger.error(f"Certificate signing failed: {result.stderr}")
                return {'success': False, 'error': f'Certificate signing failed: {result.stderr}'}
            
            # Extract certificate information
            cert_info = self._extract_certificate_info(cert_path)
            
            # Store certificate in database
            self._store_certificate_info(username, str(cert_path), str(key_path), cert_info)
            
            logger.info(f"Successfully generated PQC certificate for {username}")
            
            return {
                'success': True,
                'certificate_path': str(cert_path),
                'private_key_path': str(key_path),
                'certificate_serial': cert_info.get('serial_number'),
                'fingerprint': cert_info.get('fingerprint_sha256'),
                'not_after': cert_info.get('not_after')
            }
            
        except Exception as e:
            logger.error(f"Certificate generation error for {username}: {e}")
            return {'success': False, 'error': str(e)}
    
    def _extract_certificate_info(self, cert_path: str) -> Dict[str, Any]:
        """Extract comprehensive information from certificate"""
        try:
            # Get certificate text information
            cmd = [self.openssl_bin, 'x509', '-in', cert_path, '-text', '-noout']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                logger.error(f"Failed to read certificate {cert_path}")
                return {}
            
            cert_text = result.stdout
            
            # Get certificate in DER format for fingerprints
            cmd = [self.openssl_bin, 'x509', '-in', cert_path, '-outform', 'DER']
            der_result = subprocess.run(cmd, capture_output=True)
            
            cert_info = {}
            
            # Parse certificate details
            patterns = {
                'serial_number': r'Serial Number:\\s*([a-f0-9:]+)',
                'issuer': r'Issuer: (.+)',
                'subject': r'Subject: (.+)',
                'not_before': r'Not Before: (.+)',
                'not_after': r'Not After : (.+)'
            }
            
            for key, pattern in patterns.items():
                match = re.search(pattern, cert_text, re.IGNORECASE)
                if match:
                    cert_info[key] = match.group(1).strip()
            
            # Calculate fingerprints
            if der_result.returncode == 0:
                sha256_hash = hashlib.sha256(der_result.stdout).hexdigest()
                sha1_hash = hashlib.sha1(der_result.stdout).hexdigest()
                
                cert_info['fingerprint_sha256'] = ':'.join([sha256_hash[i:i+2] for i in range(0, len(sha256_hash), 2)]).upper()
                cert_info['fingerprint_sha1'] = ':'.join([sha1_hash[i:i+2] for i in range(0, len(sha1_hash), 2)]).upper()
            
            return cert_info
            
        except Exception as e:
            logger.error(f"Error extracting certificate info: {e}")
            return {}
    
    def _store_certificate_info(self, username: str, cert_path: str, 
                               key_path: str, cert_info: Dict[str, Any]):
        """Store certificate information in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            pqc_algorithm = self.config['security']['pqc_sig_algorithm']
            
            cursor.execute('''
                INSERT INTO certificates 
                (common_name, certificate_type, issuer_dn, subject_dn, serial_number,
                 not_before, not_after, fingerprint_sha256, fingerprint_sha1,
                 pqc_algorithm, status, file_path, private_key_path, created_by, auto_renew)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'valid', ?, ?, 'system', 1)
            ''', (
                username, 'client',
                cert_info.get('issuer'),
                cert_info.get('subject'),
                cert_info.get('serial_number'),
                cert_info.get('not_before'),
                cert_info.get('not_after'),
                cert_info.get('fingerprint_sha256'),
                cert_info.get('fingerprint_sha1'),
                pqc_algorithm,
                cert_path,
                key_path
            ))
            
            conn.commit()
            conn.close()
            
            logger.debug(f"Stored certificate info for {username} in database")
            
        except Exception as e:
            logger.error(f"Error storing certificate info: {e}")
    
    def _update_vpn_configuration(self):
        """Update VPN configuration files with current users and settings"""
        try:
            # Update IPsec secrets for PSK users
            self._update_ipsec_secrets()
            
            # Reload strongSwan configuration
            result = subprocess.run([self.strongswan_bin, 'reload'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info("VPN configuration updated and reloaded successfully")
            else:
                logger.warning(f"VPN reload warning: {result.stderr}")
                
        except Exception as e:
            logger.error(f"Error updating VPN configuration: {e}")
    
    def _update_ipsec_secrets(self):
        """Update IPsec secrets file with active PSK users"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT username, psk_key FROM users 
                WHERE psk_key IS NOT NULL AND status = 'active' AND expiry_date > datetime('now')
            ''')
            active_psk_users = cursor.fetchall()
            conn.close()
            
            secrets_file = '/etc/ipsec.secrets'
            backup_file = f'{secrets_file}.backup.{int(time.time())}'
            
            # Backup existing file
            if os.path.exists(secrets_file):
                subprocess.run(['cp', secrets_file, backup_file])
            
            # Read existing secrets file
            existing_lines = []
            if os.path.exists(secrets_file):
                with open(secrets_file, 'r') as f:
                    existing_lines = f.readlines()
            
            # Keep system lines (CA, server keys)
            new_lines = []
            for line in existing_lines:
                line = line.strip()
                if (line.startswith(': RSA') or 
                    line.startswith(': ECDSA') or 
                    line.startswith(': Ed25519') or
                    line.startswith('# ') or
                    not line or
                    'ca-key.pem' in line or 
                    'hub-key.pem' in line or
                    'server-key.pem' in line):
                    new_lines.append(line + '\n')
            
            # Add header for user PSK section
            new_lines.append('\n# PQC-VPN User PSK Entries\n')
            new_lines.append(f'# Generated: {datetime.now().isoformat()}\n\n')
            
            # Add active PSK users
            for username, psk_key in active_psk_users:
                new_lines.append(f'{username} : PSK "{psk_key}"\n')
            
            # Write updated secrets file
            with open(secrets_file, 'w') as f:
                f.writelines(new_lines)
            
            # Set secure permissions
            os.chmod(secrets_file, 0o600)
            
            logger.info(f"Updated IPsec secrets with {len(active_psk_users)} PSK users")
            
        except Exception as e:
            logger.error(f"Error updating IPsec secrets: {e}")
    
    def _log_security_event(self, event_type: str, category: str, source_ip: str,
                           user_id: int, severity: str, title: str, 
                           description: str, details: Dict[str, Any] = None):
        """Log security event to database and external systems"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO security_events 
                (event_type, event_category, source_ip, user_id, severity, 
                 title, description, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (event_type, category, source_ip, user_id, severity, 
                  title, description, json.dumps(details) if details else None))
            
            conn.commit()
            conn.close()
            
            # Log to system logger for SIEM integration
            if severity in ['HIGH', 'CRITICAL']:
                logger.warning(f"SECURITY_EVENT: {title} - {description}")
            else:
                logger.info(f"SECURITY_EVENT: {title}")
                
        except Exception as e:
            logger.error(f"Error logging security event: {e}")
    
    def _log_audit_event(self, user_id: int, action: str, resource_type: str,
                        resource_id: str, old_values: Dict = None, 
                        new_values: Dict = None, ip_address: str = None):
        """Log audit event for compliance and tracking"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO audit_log 
                (user_id, action, resource_type, resource_id, old_values, 
                 new_values, ip_address, success)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1)
            ''', (user_id, action, resource_type, resource_id,
                  json.dumps(old_values) if old_values else None,
                  json.dumps(new_values) if new_values else None,
                  ip_address))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error logging audit event: {e}")
    
    def list_users(self, status: str = 'all', include_expired: bool = False) -> Dict[str, Any]:
        """List users with comprehensive filtering options"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            query = '''
                SELECT u.*, c.not_after as cert_expiry, c.status as cert_status
                FROM users u
                LEFT JOIN certificates c ON u.username = c.common_name AND c.certificate_type = 'client'
                WHERE 1=1
            '''
            params = []
            
            if status != 'all':
                query += ' AND u.status = ?'
                params.append(status)
            
            if not include_expired:
                query += ' AND (u.expiry_date IS NULL OR u.expiry_date > datetime("now"))'
            
            query += ' ORDER BY u.created_at DESC'
            
            cursor.execute(query, params)
            users = cursor.fetchall()
            conn.close()
            
            # Format user data
            user_list = []
            for user in users:
                user_dict = {
                    'id': user[0],
                    'username': user[1],
                    'email': user[2],
                    'full_name': user[3],
                    'department': user[4],
                    'role': user[5],
                    'auth_type': user[6],
                    'created_at': user[11],
                    'last_login': user[13],
                    'login_count': user[14],
                    'failed_login_attempts': user[15],
                    'status': user[17],
                    'expiry_date': user[18],
                    'certificate_expiry': user[21],
                    'certificate_status': user[22]
                }
                user_list.append(user_dict)
            
            return {
                'success': True,
                'users': user_list,
                'total_count': len(user_list)
            }
            
        except Exception as e:
            logger.error(f"Error listing users: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_system_status(self, detailed: bool = False) -> Dict[str, Any]:
        """Get comprehensive system status and health information"""
        try:
            status = {
                'timestamp': datetime.now().isoformat(),
                'version': VERSION,
                'system': {},
                'services': {},
                'database': {},
                'certificates': {},
                'connections': {},
                'security': {}
            }
            
            # System metrics
            status['system'] = {
                'cpu_usage': psutil.cpu_percent(interval=1),
                'memory': {
                    'total': psutil.virtual_memory().total,
                    'available': psutil.virtual_memory().available,
                    'percent': psutil.virtual_memory().percent
                },
                'disk': {
                    'total': psutil.disk_usage('/').total,
                    'free': psutil.disk_usage('/').free,
                    'percent': psutil.disk_usage('/').percent
                },
                'load_average': os.getloadavg() if hasattr(os, 'getloadavg') else None,
                'uptime': int(time.time() - psutil.boot_time())
            }
            
            # Service status
            strongswan_result = subprocess.run([self.strongswan_bin, 'status'], 
                                             capture_output=True, text=True)
            status['services']['strongswan'] = {
                'running': strongswan_result.returncode == 0,
                'active_connections': strongswan_result.stdout.count('ESTABLISHED') if strongswan_result.returncode == 0 else 0
            }
            
            # Database connectivity
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # User statistics
                cursor.execute('SELECT COUNT(*) FROM users WHERE status = "active"')
                active_users = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM users')
                total_users = cursor.fetchone()[0]
                
                # Connection statistics
                cursor.execute('SELECT COUNT(*) FROM vpn_connections WHERE status = "active"')
                active_vpn_connections = cursor.fetchone()[0]
                
                cursor.execute('''
                    SELECT COUNT(*) FROM vpn_connections 
                    WHERE connect_time > datetime('now', '-24 hours')
                ''')
                connections_24h = cursor.fetchone()[0]
                
                # Security events
                cursor.execute('''
                    SELECT COUNT(*) FROM security_events 
                    WHERE timestamp > datetime('now', '-24 hours') AND severity IN ('HIGH', 'CRITICAL')
                ''')
                critical_events_24h = cursor.fetchone()[0]
                
                # Certificate status
                cursor.execute('''
                    SELECT COUNT(*) FROM certificates 
                    WHERE status = 'valid' AND not_after > datetime('now')
                ''')
                valid_certificates = cursor.fetchone()[0]
                
                cursor.execute('''
                    SELECT COUNT(*) FROM certificates 
                    WHERE status = 'valid' AND not_after < datetime('now', '+30 days')
                ''')
                expiring_certificates = cursor.fetchone()[0]
                
                conn.close()
                
                status['database'] = {
                    'connected': True,
                    'users': {
                        'active': active_users,
                        'total': total_users
                    },
                    'connections': {
                        'active': active_vpn_connections,
                        'last_24h': connections_24h
                    },
                    'security_events_24h': critical_events_24h
                }
                
                status['certificates'] = {
                    'valid': valid_certificates,
                    'expiring_soon': expiring_certificates
                }
                
            except Exception as e:
                status['database'] = {
                    'connected': False,
                    'error': str(e)
                }
            
            # Network interface status
            if detailed:
                status['network'] = {}
                for interface, addrs in psutil.net_if_addrs().items():
                    if interface != 'lo':  # Skip loopback
                        status['network'][interface] = {
                            'addresses': [addr.address for addr in addrs if addr.family == socket.AF_INET],
                            'stats': psutil.net_if_stats()[interface]._asdict() if interface in psutil.net_if_stats() else None
                        }
            
            # Health check summary
            health_checks = []
            
            if status['services']['strongswan']['running']:
                health_checks.append('strongSwan service is running')
            else:
                health_checks.append('⚠️ strongSwan service is not running')
            
            if status['database']['connected']:
                health_checks.append('Database is accessible')
            else:
                health_checks.append('⚠️ Database connection failed')
            
            if status['system']['cpu_usage'] < 80:
                health_checks.append('CPU usage is normal')
            else:
                health_checks.append(f"⚠️ High CPU usage: {status['system']['cpu_usage']:.1f}%")
            
            if status['system']['memory']['percent'] < 85:
                health_checks.append('Memory usage is normal')
            else:
                health_checks.append(f"⚠️ High memory usage: {status['system']['memory']['percent']:.1f}%")
            
            status['health_checks'] = health_checks
            status['overall_health'] = 'healthy' if not any('⚠️' in check for check in health_checks) else 'warning'
            
            return {'success': True, 'status': status}
            
        except Exception as e:
            logger.error(f"Error getting system status: {e}")
            return {'success': False, 'error': str(e)}
    
    def delete_user(self, username: str, deleted_by: str = 'admin', 
                   revoke_certificates: bool = True) -> Dict[str, Any]:
        """Delete user and optionally revoke certificates"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get user information
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            
            if not user:
                conn.close()
                return {'success': False, 'error': 'User not found'}
            
            user_id = user[0]
            auth_type = user[6]
            
            # Revoke certificates if requested
            if revoke_certificates and auth_type in ['pki', 'hybrid', 'mfa']:
                cursor.execute('''
                    SELECT id, serial_number FROM certificates 
                    WHERE common_name = ? AND certificate_type = 'client' AND status = 'valid'
                ''', (username,))
                certificates = cursor.fetchall()
                
                for cert_id, serial_number in certificates:
                    # Add to revocation list
                    cursor.execute('''
                        INSERT INTO certificate_revocations 
                        (certificate_id, serial_number, reason_code, reason_text, revoked_by)
                        VALUES (?, ?, 4, 'User account deleted', ?)
                    ''', (cert_id, serial_number, deleted_by))
                    
                    # Update certificate status
                    cursor.execute('''
                        UPDATE certificates 
                        SET status = 'revoked', revocation_reason = 'User account deleted',
                            revoked_at = datetime('now')
                        WHERE id = ?
                    ''', (cert_id,))
            
            # Delete user (cascade will handle related records)
            cursor.execute('DELETE FROM users WHERE username = ?', (username,))
            
            conn.commit()
            conn.close()
            
            # Update VPN configuration
            self._update_vpn_configuration()
            
            # Log security event and audit
            self._log_security_event(
                'USER_DELETED', 'ACCESS_CONTROL', None, user_id,
                'HIGH', f'User {username} deleted',
                f'User account {username} was deleted by {deleted_by}',
                {'deleted_by': deleted_by, 'certificates_revoked': revoke_certificates}
            )
            
            self._log_audit_event(
                user_id, 'DELETE_USER', 'user', str(user_id),
                {'username': username}, None
            )
            
            logger.info(f"Successfully deleted user {username}")
            
            return {
                'success': True,
                'message': f'User {username} deleted successfully',
                'certificates_revoked': revoke_certificates
            }
            
        except Exception as e:
            logger.error(f"Error deleting user {username}: {e}")
            return {'success': False, 'error': str(e)}

def create_cli_parser():
    """Create comprehensive CLI argument parser"""
    parser = argparse.ArgumentParser(
        description=f'{PRODUCT_NAME} Management Tool v{VERSION}',
        epilog=f'Build Date: {BUILD_DATE}',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--version', action='version', version=f'{PRODUCT_NAME} v{VERSION}')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--config-path', default='/opt/pqc-vpn', 
                       help='Configuration directory path')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # User management commands
    user_parser = subparsers.add_parser('user', help='User management operations')
    user_subparsers = user_parser.add_subparsers(dest='user_action')
    
    # Add user command
    add_user_parser = user_subparsers.add_parser('add', help='Add new VPN user')
    add_user_parser.add_argument('username', help='Unique username (3-32 alphanumeric characters)')
    add_user_parser.add_argument('email', help='Email address')
    add_user_parser.add_argument('--full-name', help='Full name of the user')
    add_user_parser.add_argument('--department', help='Department or organization unit')
    add_user_parser.add_argument('--role', choices=['user', 'admin', 'auditor'], 
                                default='user', help='User role')
    add_user_parser.add_argument('--auth-type', choices=['pki', 'psk', 'hybrid', 'mfa'],
                                default='pki', help='Authentication method')
    add_user_parser.add_argument('--expiry-days', type=int, default=365,
                                help='Account expiry in days')
    add_user_parser.add_argument('--created-by', default='admin',
                                help='Administrator creating the user')
    
    # List users command
    list_user_parser = user_subparsers.add_parser('list', help='List VPN users')
    list_user_parser.add_argument('--status', choices=['active', 'inactive', 'suspended', 'expired', 'all'],
                                 default='all', help='Filter by user status')
    list_user_parser.add_argument('--include-expired', action='store_true',
                                 help='Include expired users')
    list_user_parser.add_argument('--format', choices=['table', 'json', 'csv'],
                                 default='table', help='Output format')
    
    # Delete user command
    delete_user_parser = user_subparsers.add_parser('delete', help='Delete VPN user')
    delete_user_parser.add_argument('username', help='Username to delete')
    delete_user_parser.add_argument('--deleted-by', default='admin',
                                   help='Administrator deleting the user')
    delete_user_parser.add_argument('--keep-certificates', action='store_true',
                                   help='Do not revoke certificates')
    
    # System commands
    status_parser = subparsers.add_parser('status', help='System status and health')
    status_parser.add_argument('--detailed', action='store_true',
                              help='Show detailed system information')
    status_parser.add_argument('--format', choices=['text', 'json'],
                              default='text', help='Output format')
    status_parser.add_argument('--quick', action='store_true',
                              help='Quick health check (exit code only)')
    
    # Certificate commands
    cert_parser = subparsers.add_parser('cert', help='Certificate management')
    cert_subparsers = cert_parser.add_subparsers(dest='cert_action')
    
    cert_list_parser = cert_subparsers.add_parser('list', help='List certificates')
    cert_list_parser.add_argument('--type', choices=['ca', 'server', 'client', 'all'],
                                 default='all', help='Certificate type filter')
    cert_list_parser.add_argument('--status', choices=['valid', 'expired', 'revoked', 'all'],
                                 default='all', help='Certificate status filter')
    cert_list_parser.add_argument('--expiring-days', type=int,
                                 help='Show certificates expiring within N days')
    
    # Configuration commands
    config_parser = subparsers.add_parser('config', help='Configuration management')
    config_subparsers = config_parser.add_subparsers(dest='config_action')
    
    config_show_parser = config_subparsers.add_parser('show', help='Show configuration')
    config_show_parser.add_argument('--section', help='Show specific section')
    
    config_set_parser = config_subparsers.add_parser('set', help='Set configuration value')
    config_set_parser.add_argument('key', help='Configuration key (section.key)')
    config_set_parser.add_argument('value', help='Configuration value')
    
    return parser

def format_table_output(data: List[Dict], headers: List[str]) -> str:
    """Format data as a table for CLI output"""
    if not data:
        return "No data to display"
    
    # Calculate column widths
    widths = {}
    for header in headers:
        widths[header] = len(header)
        for row in data:
            value = str(row.get(header, ''))
            widths[header] = max(widths[header], len(value))
    
    # Create table
    lines = []
    
    # Header
    header_line = " | ".join(header.ljust(widths[header]) for header in headers)
    lines.append(header_line)
    lines.append("-" * len(header_line))
    
    # Data rows
    for row in data:
        data_line = " | ".join(str(row.get(header, '')).ljust(widths[header]) for header in headers)
        lines.append(data_line)
    
    return "\n".join(lines)

def main():
    """Main CLI interface"""
    parser = create_cli_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    try:
        # Initialize manager
        manager = PQCVPNManager(args.config_path, args.debug)
        
        # Handle commands
        if args.command == 'user':
            if args.user_action == 'add':
                result = manager.add_user(
                    args.username, args.email, args.full_name,
                    args.department, args.role, args.auth_type,
                    args.expiry_days, args.created_by
                )
                
                if result['success']:
                    print(f"✅ User {args.username} created successfully")
                    print(f"   User ID: {result['user_id']}")
                    print(f"   Auth Type: {result['auth_type']}")
                    print(f"   Expires: {result['expiry_date']}")
                    
                    if result.get('psk_key'):
                        print(f"   🔑 PSK: {result['psk_key']}")
                    if result.get('certificate_path'):
                        print(f"   📜 Certificate: {result['certificate_path']}")
                    if result.get('totp_secret'):
                        print(f"   🔐 TOTP Secret: {result['totp_secret']}")
                else:
                    print(f"❌ Error: {result['error']}")
                    return 1
            
            elif args.user_action == 'list':
                result = manager.list_users(args.status, args.include_expired)
                
                if result['success']:
                    users = result['users']
                    
                    if args.format == 'json':
                        print(json.dumps(result, indent=2, default=str))
                    elif args.format == 'csv':
                        if users:
                            headers = users[0].keys()
                            print(','.join(headers))
                            for user in users:
                                print(','.join(str(user.get(h, '')) for h in headers))
                    else:  # table format
                        if users:
                            headers = ['username', 'email', 'full_name', 'role', 'auth_type', 'status', 'expiry_date']
                            print(f"\n📊 Users ({len(users)} total):")
                            print(format_table_output(users, headers))
                        else:
                            print("No users found")
                else:
                    print(f"❌ Error: {result['error']}")
                    return 1
            
            elif args.user_action == 'delete':
                result = manager.delete_user(
                    args.username, args.deleted_by,
                    not args.keep_certificates
                )
                
                if result['success']:
                    print(f"✅ {result['message']}")
                    if result.get('certificates_revoked'):
                        print("   🔒 Certificates revoked")
                else:
                    print(f"❌ Error: {result['error']}")
                    return 1
        
        elif args.command == 'status':
            result = manager.get_system_status(args.detailed)
            
            if result['success']:
                status = result['status']
                
                if args.quick:
                    # Quick health check - exit with code
                    return 0 if status['overall_health'] == 'healthy' else 1
                
                if args.format == 'json':
                    print(json.dumps(result, indent=2, default=str))
                else:
                    print(f"\n🔐 {PRODUCT_NAME} v{VERSION} - System Status")
                    print("=" * 60)
                    print(f"Timestamp: {status['timestamp']}")
                    print(f"Overall Health: {'✅ Healthy' if status['overall_health'] == 'healthy' else '⚠️ Warning'}")
                    print()
                    
                    # Services
                    print("📊 Services:")
                    strongswan = status['services']['strongswan']
                    print(f"   strongSwan: {'✅ Running' if strongswan['running'] else '❌ Stopped'}")
                    print(f"   Active VPN Connections: {strongswan['active_connections']}")
                    
                    # Database
                    if status['database']['connected']:
                        db = status['database']
                        print(f"   Database: ✅ Connected")
                        print(f"   Active Users: {db['users']['active']}/{db['users']['total']}")
                        print(f"   Active Sessions: {db['connections']['active']}")
                        print(f"   Connections (24h): {db['connections']['last_24h']}")
                        if db['security_events_24h'] > 0:
                            print(f"   ⚠️ Critical Security Events (24h): {db['security_events_24h']}")
                    else:
                        print(f"   Database: ❌ Error - {status['database'].get('error', 'Unknown')}")
                    
                    # System resources
                    sys_info = status['system']
                    print(f"\n💻 System Resources:")
                    print(f"   CPU Usage: {sys_info['cpu_usage']:.1f}%")
                    print(f"   Memory Usage: {sys_info['memory']['percent']:.1f}%")
                    print(f"   Disk Usage: {sys_info['disk']['percent']:.1f}%")
                    print(f"   Uptime: {sys_info['uptime']//3600:.0f} hours")
                    
                    # Certificates
                    if 'certificates' in status:
                        cert_info = status['certificates']
                        print(f"\n📜 Certificates:")
                        print(f"   Valid: {cert_info['valid']}")
                        if cert_info['expiring_soon'] > 0:
                            print(f"   ⚠️ Expiring Soon: {cert_info['expiring_soon']}")
                    
                    # Health checks summary
                    print(f"\n🔍 Health Checks:")
                    for check in status['health_checks']:
                        print(f"   {check}")
            else:
                print(f"❌ Error: {result['error']}")
                return 1
        
        return 0
        
    except KeyboardInterrupt:
        print("\n⚠️ Operation cancelled by user")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        print(f"❌ Unexpected error: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())
