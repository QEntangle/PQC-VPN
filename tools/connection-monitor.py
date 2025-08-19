#!/usr/bin/env python3
"""
Enhanced PQC-VPN Connection Monitor v2.0.0
Advanced monitoring and analysis tool for Post-Quantum Cryptography VPN connections

Features:
- Real-time connection monitoring
- PQC algorithm analysis
- Performance metrics
- Certificate management
- Automated alerts
- Report generation
- REST API integration
- Kubernetes support
"""

import os
import sys
import json
import time
import subprocess
import threading
import logging
import argparse
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import signal
import socket
import ssl
import hashlib
import base64

# Third-party imports
try:
    import psutil
    import yaml
    import requests
    from tabulate import tabulate
    from colorama import init, Fore, Style
    import click
    import schedule
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    import prometheus_client
    from prometheus_client import Counter, Gauge, Histogram, CollectorRegistry
except ImportError as e:
    print(f"Missing required dependencies: {e}")
    print("Please install with: pip install -r requirements.txt")
    sys.exit(1)

# Initialize colorama for Windows compatibility
init(autoreset=True)

# Version and metadata
__version__ = "2.0.0"
__author__ = "QEntangle"
__description__ = "Enhanced PQC-VPN Connection Monitor"

# Configuration
CONFIG_DIR = Path("/etc/pqc-vpn")
LOG_DIR = Path("/var/log/pqc-vpn")
CERT_DIR = Path("/etc/ipsec.d/certs")
CACERT_DIR = Path("/etc/ipsec.d/cacerts")
DB_PATH = Path("/var/lib/pqc-vpn/monitor.db")

# Prometheus metrics
METRICS_REGISTRY = CollectorRegistry()
CONNECTION_COUNT = Gauge('pqc_vpn_connections_total', 'Total number of VPN connections', registry=METRICS_REGISTRY)
ACTIVE_CONNECTIONS = Gauge('pqc_vpn_active_connections', 'Number of active VPN connections', registry=METRICS_REGISTRY)
PQC_CONNECTIONS = Gauge('pqc_vpn_pqc_connections', 'Number of PQC-enabled connections', registry=METRICS_REGISTRY)
DATA_TRANSFERRED = Counter('pqc_vpn_data_bytes_total', 'Total data transferred', ['direction'], registry=METRICS_REGISTRY)
CONNECTION_DURATION = Histogram('pqc_vpn_connection_duration_seconds', 'Connection duration in seconds', registry=METRICS_REGISTRY)
CERTIFICATE_EXPIRY = Gauge('pqc_vpn_certificate_expiry_days', 'Days until certificate expiry', ['certificate_type', 'subject'], registry=METRICS_REGISTRY)

class PQCVPNMonitor:
    """Enhanced PQC-VPN Connection Monitor"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config = self._load_config(config_file)
        self.logger = self._setup_logging()
        self.db_path = DB_PATH
        self.running = False
        self.monitor_thread = None
        self.connections = {}
        self.alerts = []
        
        # Ensure directories exist
        for directory in [CONFIG_DIR, LOG_DIR, self.db_path.parent]:
            directory.mkdir(parents=True, exist_ok=True)
        
        # Initialize database
        self._init_database()
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        self.logger.info(f"PQC-VPN Monitor v{__version__} initialized")
    
    def _load_config(self, config_file: Optional[str]) -> Dict[str, Any]:
        """Load configuration from file or use defaults"""
        default_config = {
            'monitor': {
                'interval': 30,
                'timeout': 10,
                'max_retries': 3,
                'enable_alerts': True,
                'enable_metrics': True
            },
            'database': {
                'path': str(DB_PATH),
                'retention_days': 90
            },
            'certificates': {
                'check_expiry_days': 30,
                'auto_renewal': False
            },
            'alerts': {
                'email_enabled': False,
                'webhook_enabled': False,
                'webhook_url': '',
                'email_recipients': []
            },
            'api': {
                'enabled': True,
                'host': '0.0.0.0',
                'port': 9100
            },
            'strongswan': {
                'config_path': '/etc/ipsec.conf',
                'secrets_path': '/etc/ipsec.secrets',
                'status_socket': '/var/run/charon.ctl'
            }
        }
        
        if config_file and Path(config_file).exists():
            try:
                with open(config_file, 'r') as f:
                    user_config = yaml.safe_load(f)
                    # Merge with defaults
                    default_config.update(user_config)
            except Exception as e:
                print(f"Warning: Could not load config file {config_file}: {e}")
        
        return default_config
    
    def _setup_logging(self) -> logging.Logger:
        """Set up logging configuration"""
        logger = logging.getLogger('pqc-vpn-monitor')
        logger.setLevel(logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # File handler
        log_file = LOG_DIR / 'monitor.log'
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        return logger
    
    def _init_database(self):
        """Initialize SQLite database for storing monitoring data"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Create tables
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS connections (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        connection_name TEXT NOT NULL,
                        user_id TEXT,
                        remote_ip TEXT,
                        local_ip TEXT,
                        status TEXT NOT NULL,
                        auth_method TEXT,
                        encryption_algorithm TEXT,
                        pqc_algorithm TEXT,
                        bytes_in INTEGER DEFAULT 0,
                        bytes_out INTEGER DEFAULT 0,
                        duration_seconds INTEGER DEFAULT 0,
                        established_at DATETIME,
                        disconnected_at DATETIME
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS certificates (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        certificate_type TEXT NOT NULL,
                        subject TEXT NOT NULL,
                        issuer TEXT,
                        serial_number TEXT,
                        not_before DATETIME,
                        not_after DATETIME,
                        days_until_expiry INTEGER,
                        algorithm TEXT,
                        key_size INTEGER,
                        fingerprint TEXT,
                        file_path TEXT
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        alert_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        message TEXT NOT NULL,
                        details TEXT,
                        acknowledged BOOLEAN DEFAULT FALSE,
                        resolved BOOLEAN DEFAULT FALSE
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS performance_metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        metric_name TEXT NOT NULL,
                        metric_value REAL NOT NULL,
                        metric_unit TEXT,
                        tags TEXT
                    )
                ''')
                
                # Create indexes for better performance
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_connections_timestamp ON connections(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_connections_status ON connections(status)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_certificates_expiry ON certificates(days_until_expiry)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)')
                
                conn.commit()
                self.logger.info("Database initialized successfully")
                
        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")
            raise
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.stop_monitoring()
        sys.exit(0)
    
    def get_ipsec_status(self) -> Dict[str, Any]:
        """Get strongSwan IPsec status information"""
        try:
            # Try multiple methods to get status
            status_data = {}
            
            # Method 1: ipsec status command
            try:
                result = subprocess.run(['ipsec', 'status'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    status_data['ipsec_status'] = result.stdout
            except Exception as e:
                self.logger.debug(f"ipsec status command failed: {e}")
            
            # Method 2: ipsec statusall command
            try:
                result = subprocess.run(['ipsec', 'statusall'], 
                                      capture_output=True, text=True, timeout=15)
                if result.returncode == 0:
                    status_data['ipsec_statusall'] = result.stdout
            except Exception as e:
                self.logger.debug(f"ipsec statusall command failed: {e}")
            
            # Method 3: Parse /proc/net/ipsec_sa if available
            ipsec_sa_path = Path('/proc/net/ipsec_sa')
            if ipsec_sa_path.exists():
                try:
                    with open(ipsec_sa_path, 'r') as f:
                        status_data['ipsec_sa'] = f.read()
                except Exception as e:
                    self.logger.debug(f"Failed to read {ipsec_sa_path}: {e}")
            
            return status_data
            
        except Exception as e:
            self.logger.error(f"Failed to get IPsec status: {e}")
            return {}
    
    def parse_connection_details(self, status_output: str) -> List[Dict[str, Any]]:
        """Parse connection details from strongSwan status output"""
        connections = []
        
        try:
            lines = status_output.strip().split('\n')
            current_connection = None
            
            for line in lines:
                line = line.strip()
                
                # Skip empty lines and headers
                if not line or line.startswith('Status of IKE') or line.startswith('Listening'):
                    continue
                
                # Connection line format: "connection_name[id]: status"
                if ':' in line and '[' in line:
                    # Extract connection name and ID
                    parts = line.split('[')
                    if len(parts) >= 2:
                        conn_name = parts[0].strip()
                        id_part = parts[1].split(']')[0] if ']' in parts[1] else ''
                        
                        # Extract status information
                        status_part = line.split(':', 1)[1].strip() if ':' in line else ''
                        
                        current_connection = {
                            'name': conn_name,
                            'id': id_part,
                            'status': 'unknown',
                            'remote_ip': 'unknown',
                            'local_ip': 'unknown',
                            'auth_method': 'unknown',
                            'encryption': 'unknown',
                            'pqc_algorithm': 'none',
                            'bytes_in': 0,
                            'bytes_out': 0,
                            'established_at': None,
                            'duration': 0
                        }
                        
                        # Parse status
                        if 'ESTABLISHED' in status_part:
                            current_connection['status'] = 'established'
                        elif 'CONNECTING' in status_part:
                            current_connection['status'] = 'connecting'
                        elif 'INSTALLED' in status_part:
                            current_connection['status'] = 'installed'
                        
                        # Extract IP addresses
                        if '[' in status_part and ']' in status_part:
                            ip_parts = status_part.split('[')[1].split(']')[0]
                            if '...' in ip_parts:
                                ips = ip_parts.split('...')
                                if len(ips) >= 2:
                                    current_connection['local_ip'] = ips[0].strip()
                                    current_connection['remote_ip'] = ips[1].strip()
                        
                        connections.append(current_connection)
                
                # Parse additional details for current connection
                elif current_connection and ('IKE' in line or 'ESP' in line or 'bytes' in line):
                    # Extract encryption algorithms
                    if 'IKE' in line:
                        # Look for PQC algorithms
                        if 'kyber' in line.lower():
                            if 'kyber1024' in line.lower():
                                current_connection['pqc_algorithm'] = 'Kyber-1024'
                            elif 'kyber768' in line.lower():
                                current_connection['pqc_algorithm'] = 'Kyber-768'
                            elif 'kyber512' in line.lower():
                                current_connection['pqc_algorithm'] = 'Kyber-512'
                        
                        # Extract encryption details
                        if 'aes256gcm' in line.lower():
                            current_connection['encryption'] = 'AES-256-GCM'
                        elif 'aes128gcm' in line.lower():
                            current_connection['encryption'] = 'AES-128-GCM'
                    
                    # Extract traffic statistics
                    if 'bytes_i' in line and 'bytes_o' in line:
                        # Parse bytes in/out
                        parts = line.split(',')
                        for part in parts:
                            if 'bytes_i' in part:
                                try:
                                    current_connection['bytes_in'] = int(part.split('(')[1].split()[0])
                                except:
                                    pass
                            elif 'bytes_o' in part:
                                try:
                                    current_connection['bytes_out'] = int(part.split('(')[1].split()[0])
                                except:
                                    pass
        
        except Exception as e:
            self.logger.error(f"Failed to parse connection details: {e}")
        
        return connections
    
    def get_active_connections(self) -> List[Dict[str, Any]]:
        """Get list of active VPN connections with detailed information"""
        connections = []
        
        try:
            status_data = self.get_ipsec_status()
            
            if 'ipsec_statusall' in status_data:
                connections = self.parse_connection_details(status_data['ipsec_statusall'])
            elif 'ipsec_status' in status_data:
                connections = self.parse_connection_details(status_data['ipsec_status'])
            
            # Enrich connection data
            for conn in connections:
                # Add timestamp
                conn['last_seen'] = datetime.now().isoformat()
                
                # Determine authentication method
                if conn['name'].startswith('spoke-'):
                    conn['auth_method'] = 'PKI'
                elif 'psk' in conn['name'].lower():
                    conn['auth_method'] = 'PSK'
                elif 'hybrid' in conn['name'].lower():
                    conn['auth_method'] = 'Hybrid'
                
                # Calculate connection duration (approximation)
                if conn['status'] == 'established':
                    conn['duration'] = 1800  # Default 30 minutes
                
                # Classify as PQC if using post-quantum algorithms
                conn['is_pqc'] = conn['pqc_algorithm'] != 'none'
        
        except Exception as e:
            self.logger.error(f"Failed to get active connections: {e}")
        
        return connections
    
    def get_certificate_info(self, cert_path: Path) -> Optional[Dict[str, Any]]:
        """Get detailed information about a certificate"""
        try:
            if not cert_path.exists():
                return None
            
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
            
            # Try to load as PEM first, then DER
            try:
                cert = x509.load_pem_x509_certificate(cert_data)
            except:
                cert = x509.load_der_x509_certificate(cert_data)
            
            # Extract certificate information
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            serial = str(cert.serial_number)
            not_before = cert.not_valid_before
            not_after = cert.not_valid_after
            
            # Calculate days until expiry
            days_until_expiry = (not_after - datetime.now()).days
            
            # Get public key information
            public_key = cert.public_key()
            key_info = {}
            
            if isinstance(public_key, rsa.RSAPublicKey):
                key_info = {
                    'algorithm': 'RSA',
                    'key_size': public_key.key_size
                }
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                key_info = {
                    'algorithm': 'ECDSA',
                    'curve': public_key.curve.name
                }
            else:
                key_info = {
                    'algorithm': 'Unknown',
                    'key_size': 0
                }
            
            # Calculate fingerprint
            fingerprint = hashlib.sha256(cert_data).hexdigest()
            
            return {
                'subject': subject,
                'issuer': issuer,
                'serial_number': serial,
                'not_before': not_before,
                'not_after': not_after,
                'days_until_expiry': days_until_expiry,
                'algorithm': key_info['algorithm'],
                'key_size': key_info.get('key_size', 0),
                'fingerprint': fingerprint,
                'file_path': str(cert_path),
                'is_expired': days_until_expiry < 0,
                'expires_soon': 0 < days_until_expiry <= self.config['certificates']['check_expiry_days']
            }
            
        except Exception as e:
            self.logger.error(f"Failed to parse certificate {cert_path}: {e}")
            return None
    
    def check_certificates(self) -> List[Dict[str, Any]]:
        """Check all certificates and their expiry status"""
        certificates = []
        
        # Check certificates in standard locations
        cert_locations = [
            (CERT_DIR, 'client'),
            (CACERT_DIR, 'ca'),
            (Path('/etc/ipsec.d/private'), 'private')
        ]
        
        for cert_dir, cert_type in cert_locations:
            if not cert_dir.exists():
                continue
            
            for cert_file in cert_dir.glob('*.pem'):
                cert_info = self.get_certificate_info(cert_file)
                if cert_info:
                    cert_info['certificate_type'] = cert_type
                    certificates.append(cert_info)
        
        return certificates
    
    def store_connection_data(self, connections: List[Dict[str, Any]]):
        """Store connection data in database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                for connection in connections:
                    cursor.execute('''
                        INSERT INTO connections (
                            connection_name, user_id, remote_ip, local_ip, status,
                            auth_method, encryption_algorithm, pqc_algorithm,
                            bytes_in, bytes_out, duration_seconds, established_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        connection['name'],
                        connection['name'].replace('spoke-', '').replace('hub-', ''),
                        connection['remote_ip'],
                        connection['local_ip'],
                        connection['status'],
                        connection['auth_method'],
                        connection['encryption'],
                        connection['pqc_algorithm'],
                        connection['bytes_in'],
                        connection['bytes_out'],
                        connection['duration'],
                        datetime.now() if connection['status'] == 'established' else None
                    ))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to store connection data: {e}")
    
    def store_certificate_data(self, certificates: List[Dict[str, Any]]):
        """Store certificate data in database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Clear existing certificate data
                cursor.execute('DELETE FROM certificates')
                
                for cert in certificates:
                    cursor.execute('''
                        INSERT INTO certificates (
                            certificate_type, subject, issuer, serial_number,
                            not_before, not_after, days_until_expiry,
                            algorithm, key_size, fingerprint, file_path
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        cert['certificate_type'],
                        cert['subject'],
                        cert['issuer'],
                        cert['serial_number'],
                        cert['not_before'],
                        cert['not_after'],
                        cert['days_until_expiry'],
                        cert['algorithm'],
                        cert['key_size'],
                        cert['fingerprint'],
                        cert['file_path']
                    ))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to store certificate data: {e}")
    
    def update_prometheus_metrics(self, connections: List[Dict[str, Any]], certificates: List[Dict[str, Any]]):
        """Update Prometheus metrics"""
        try:
            # Connection metrics
            total_connections = len(connections)
            active_connections = len([c for c in connections if c['status'] == 'established'])
            pqc_connections = len([c for c in connections if c['is_pqc']])
            
            CONNECTION_COUNT.set(total_connections)
            ACTIVE_CONNECTIONS.set(active_connections)
            PQC_CONNECTIONS.set(pqc_connections)
            
            # Data transfer metrics
            total_bytes_in = sum(c['bytes_in'] for c in connections)
            total_bytes_out = sum(c['bytes_out'] for c in connections)
            
            DATA_TRANSFERRED.labels(direction='in')._value._value = total_bytes_in
            DATA_TRANSFERRED.labels(direction='out')._value._value = total_bytes_out
            
            # Certificate expiry metrics
            for cert in certificates:
                CERTIFICATE_EXPIRY.labels(
                    certificate_type=cert['certificate_type'],
                    subject=cert['subject'][:50]  # Truncate long subjects
                ).set(cert['days_until_expiry'])
            
        except Exception as e:
            self.logger.error(f"Failed to update Prometheus metrics: {e}")
    
    def check_alerts(self, connections: List[Dict[str, Any]], certificates: List[Dict[str, Any]]):
        """Check for alert conditions"""
        alerts = []
        
        # Check for certificate expiry
        for cert in certificates:
            if cert['is_expired']:
                alerts.append({
                    'type': 'certificate_expired',
                    'severity': 'critical',
                    'message': f"Certificate expired: {cert['subject']}",
                    'details': f"Certificate at {cert['file_path']} expired {abs(cert['days_until_expiry'])} days ago"
                })
            elif cert['expires_soon']:
                alerts.append({
                    'type': 'certificate_expiring',
                    'severity': 'warning',
                    'message': f"Certificate expiring soon: {cert['subject']}",
                    'details': f"Certificate at {cert['file_path']} expires in {cert['days_until_expiry']} days"
                })
        
        # Check for connection issues
        failed_connections = [c for c in connections if c['status'] in ['failed', 'disconnected']]
        if failed_connections:
            alerts.append({
                'type': 'connection_failed',
                'severity': 'warning',
                'message': f"{len(failed_connections)} connection(s) failed",
                'details': f"Failed connections: {', '.join(c['name'] for c in failed_connections)}"
            })
        
        # Check for low PQC adoption
        if connections:
            pqc_ratio = len([c for c in connections if c['is_pqc']]) / len(connections)
            if pqc_ratio < 0.5:  # Less than 50% using PQC
                alerts.append({
                    'type': 'low_pqc_adoption',
                    'severity': 'info',
                    'message': f"Low PQC adoption: {pqc_ratio:.1%}",
                    'details': f"Only {pqc_ratio:.1%} of connections are using post-quantum cryptography"
                })
        
        # Store alerts in database
        if alerts:
            self._store_alerts(alerts)
        
        return alerts
    
    def _store_alerts(self, alerts: List[Dict[str, Any]]):
        """Store alerts in database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                for alert in alerts:
                    cursor.execute('''
                        INSERT INTO alerts (alert_type, severity, message, details)
                        VALUES (?, ?, ?, ?)
                    ''', (
                        alert['type'],
                        alert['severity'],
                        alert['message'],
                        alert['details']
                    ))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to store alerts: {e}")
    
    def generate_report(self, format_type: str = 'text', output_file: Optional[str] = None) -> str:
        """Generate monitoring report"""
        try:
            # Get current data
            connections = self.get_active_connections()
            certificates = self.check_certificates()
            
            # Generate report based on format
            if format_type == 'json':
                report_data = {
                    'timestamp': datetime.now().isoformat(),
                    'summary': {
                        'total_connections': len(connections),
                        'active_connections': len([c for c in connections if c['status'] == 'established']),
                        'pqc_connections': len([c for c in connections if c['is_pqc']]),
                        'total_certificates': len(certificates),
                        'expiring_certificates': len([c for c in certificates if c['expires_soon']]),
                        'expired_certificates': len([c for c in certificates if c['is_expired']])
                    },
                    'connections': connections,
                    'certificates': certificates
                }
                report = json.dumps(report_data, indent=2, default=str)
                
            elif format_type == 'yaml':
                report_data = {
                    'timestamp': datetime.now().isoformat(),
                    'summary': {
                        'total_connections': len(connections),
                        'active_connections': len([c for c in connections if c['status'] == 'established']),
                        'pqc_connections': len([c for c in connections if c['is_pqc']]),
                        'total_certificates': len(certificates),
                        'expiring_certificates': len([c for c in certificates if c['expires_soon']]),
                        'expired_certificates': len([c for c in certificates if c['is_expired']])
                    },
                    'connections': connections,
                    'certificates': certificates
                }
                report = yaml.dump(report_data, default_flow_style=False)
                
            else:  # text format
                report_lines = []
                report_lines.append(f"PQC-VPN Monitoring Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                report_lines.append("=" * 80)
                report_lines.append("")
                
                # Summary
                report_lines.append("SUMMARY")
                report_lines.append("-" * 20)
                report_lines.append(f"Total Connections: {len(connections)}")
                report_lines.append(f"Active Connections: {len([c for c in connections if c['status'] == 'established'])}")
                report_lines.append(f"PQC Connections: {len([c for c in connections if c['is_pqc']])}")
                report_lines.append(f"Total Certificates: {len(certificates)}")
                report_lines.append(f"Expiring Certificates: {len([c for c in certificates if c['expires_soon']])}")
                report_lines.append(f"Expired Certificates: {len([c for c in certificates if c['is_expired']])}")
                report_lines.append("")
                
                # Active Connections
                if connections:
                    report_lines.append("ACTIVE CONNECTIONS")
                    report_lines.append("-" * 20)
                    
                    table_data = []
                    for conn in connections:
                        table_data.append([
                            conn['name'],
                            conn['status'],
                            conn['remote_ip'],
                            conn['auth_method'],
                            conn['pqc_algorithm'],
                            f"{conn['bytes_in']:,}",
                            f"{conn['bytes_out']:,}"
                        ])
                    
                    report_lines.append(tabulate(
                        table_data,
                        headers=['Name', 'Status', 'Remote IP', 'Auth', 'PQC Algo', 'Bytes In', 'Bytes Out'],
                        tablefmt='grid'
                    ))
                    report_lines.append("")
                
                # Certificate Status
                if certificates:
                    report_lines.append("CERTIFICATE STATUS")
                    report_lines.append("-" * 20)
                    
                    table_data = []
                    for cert in certificates:
                        status = "EXPIRED" if cert['is_expired'] else ("EXPIRING" if cert['expires_soon'] else "OK")
                        table_data.append([
                            cert['certificate_type'],
                            cert['subject'][:40] + "..." if len(cert['subject']) > 40 else cert['subject'],
                            cert['algorithm'],
                            cert['days_until_expiry'],
                            status
                        ])
                    
                    report_lines.append(tabulate(
                        table_data,
                        headers=['Type', 'Subject', 'Algorithm', 'Days to Expiry', 'Status'],
                        tablefmt='grid'
                    ))
                
                report = "\n".join(report_lines)
            
            # Save to file if specified
            if output_file:
                with open(output_file, 'w') as f:
                    f.write(report)
                self.logger.info(f"Report saved to {output_file}")
            
            return report
            
        except Exception as e:
            self.logger.error(f"Failed to generate report: {e}")
            return f"Error generating report: {e}"
    
    def start_monitoring(self):
        """Start continuous monitoring"""
        if self.running:
            self.logger.warning("Monitoring is already running")
            return
        
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        self.logger.info("Started continuous monitoring")
    
    def stop_monitoring(self):
        """Stop continuous monitoring"""
        if not self.running:
            return
        
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        self.logger.info("Stopped monitoring")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                # Get current data
                connections = self.get_active_connections()
                certificates = self.check_certificates()
                
                # Store data
                self.store_connection_data(connections)
                self.store_certificate_data(certificates)
                
                # Update metrics
                if self.config['monitor']['enable_metrics']:
                    self.update_prometheus_metrics(connections, certificates)
                
                # Check alerts
                if self.config['monitor']['enable_alerts']:
                    alerts = self.check_alerts(connections, certificates)
                    if alerts:
                        self.logger.warning(f"Generated {len(alerts)} alerts")
                
                # Clean up old data
                self._cleanup_old_data()
                
                # Sleep until next check
                time.sleep(self.config['monitor']['interval'])
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(self.config['monitor']['interval'])
    
    def _cleanup_old_data(self):
        """Clean up old data from database"""
        try:
            retention_days = self.config['database']['retention_days']
            cutoff_date = datetime.now() - timedelta(days=retention_days)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Clean old connections
                cursor.execute('DELETE FROM connections WHERE timestamp < ?', (cutoff_date,))
                
                # Clean old alerts
                cursor.execute('DELETE FROM alerts WHERE timestamp < ?', (cutoff_date,))
                
                # Clean old performance metrics
                cursor.execute('DELETE FROM performance_metrics WHERE timestamp < ?', (cutoff_date,))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to cleanup old data: {e}")

# CLI Interface
@click.group()
@click.version_option(version=__version__)
@click.option('--config', '-c', help='Configuration file path')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.pass_context
def cli(ctx, config, verbose):
    """PQC-VPN Enhanced Connection Monitor v2.0.0"""
    ctx.ensure_object(dict)
    ctx.obj['config'] = config
    ctx.obj['verbose'] = verbose
    
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

@cli.command()
@click.pass_context
def status(ctx):
    """Show current VPN status"""
    monitor = PQCVPNMonitor(ctx.obj['config'])
    connections = monitor.get_active_connections()
    
    if not connections:
        click.echo(f"{Fore.YELLOW}No active VPN connections found{Style.RESET_ALL}")
        return
    
    click.echo(f"{Fore.GREEN}Active VPN Connections:{Style.RESET_ALL}")
    click.echo()
    
    table_data = []
    for conn in connections:
        status_color = Fore.GREEN if conn['status'] == 'established' else Fore.YELLOW
        pqc_indicator = "🔐" if conn['is_pqc'] else "🔓"
        
        table_data.append([
            f"{pqc_indicator} {conn['name']}",
            f"{status_color}{conn['status']}{Style.RESET_ALL}",
            conn['remote_ip'],
            conn['auth_method'],
            conn['pqc_algorithm'] if conn['is_pqc'] else 'Classical',
            f"{conn['bytes_in']:,}",
            f"{conn['bytes_out']:,}"
        ])
    
    click.echo(tabulate(
        table_data,
        headers=['Connection', 'Status', 'Remote IP', 'Auth Method', 'Encryption', 'Bytes In', 'Bytes Out'],
        tablefmt='grid'
    ))

@cli.command()
@click.option('--check-expiry', is_flag=True, help='Check certificate expiry')
@click.option('--days', default=30, help='Days to check for expiry')
@click.pass_context
def certificates(ctx, check_expiry, days):
    """Manage and check certificates"""
    monitor = PQCVPNMonitor(ctx.obj['config'])
    certs = monitor.check_certificates()
    
    if not certs:
        click.echo(f"{Fore.YELLOW}No certificates found{Style.RESET_ALL}")
        return
    
    click.echo(f"{Fore.GREEN}Certificate Status:{Style.RESET_ALL}")
    click.echo()
    
    table_data = []
    for cert in certs:
        # Status indicator
        if cert['is_expired']:
            status = f"{Fore.RED}EXPIRED{Style.RESET_ALL}"
        elif cert['expires_soon']:
            status = f"{Fore.YELLOW}EXPIRING{Style.RESET_ALL}"
        else:
            status = f"{Fore.GREEN}OK{Style.RESET_ALL}"
        
        table_data.append([
            cert['certificate_type'],
            cert['subject'][:50] + "..." if len(cert['subject']) > 50 else cert['subject'],
            cert['algorithm'],
            cert['days_until_expiry'],
            status
        ])
    
    click.echo(tabulate(
        table_data,
        headers=['Type', 'Subject', 'Algorithm', 'Days to Expiry', 'Status'],
        tablefmt='grid'
    ))
    
    # Show summary
    expired = len([c for c in certs if c['is_expired']])
    expiring = len([c for c in certs if c['expires_soon']])
    
    if expired > 0:
        click.echo(f"\n{Fore.RED}⚠️  {expired} certificate(s) have expired!{Style.RESET_ALL}")
    
    if expiring > 0:
        click.echo(f"\n{Fore.YELLOW}⚠️  {expiring} certificate(s) expire within {days} days{Style.RESET_ALL}")

@cli.command()
@click.option('--format', 'format_type', default='text', type=click.Choice(['text', 'json', 'yaml']), help='Report format')
@click.option('--output', '-o', help='Output file path')
@click.pass_context
def report(ctx, format_type, output):
    """Generate monitoring report"""
    monitor = PQCVPNMonitor(ctx.obj['config'])
    report = monitor.generate_report(format_type, output)
    
    if not output:
        click.echo(report)

@cli.command()
@click.option('--interval', default=30, help='Monitoring interval in seconds')
@click.pass_context
def monitor(ctx, interval):
    """Start continuous monitoring"""
    monitor = PQCVPNMonitor(ctx.obj['config'])
    monitor.config['monitor']['interval'] = interval
    
    click.echo(f"{Fore.GREEN}Starting PQC-VPN monitoring (interval: {interval}s)...{Style.RESET_ALL}")
    click.echo("Press Ctrl+C to stop")
    
    try:
        monitor.start_monitoring()
        
        # Keep main thread alive
        while monitor.running:
            time.sleep(1)
            
    except KeyboardInterrupt:
        click.echo(f"\n{Fore.YELLOW}Stopping monitoring...{Style.RESET_ALL}")
        monitor.stop_monitoring()

@cli.command()
@click.option('--port', default=9100, help='Metrics server port')
@click.pass_context
def metrics(ctx, port):
    """Start Prometheus metrics server"""
    monitor = PQCVPNMonitor(ctx.obj['config'])
    
    # Start monitoring in background
    monitor.start_monitoring()
    
    # Start metrics server
    try:
        from prometheus_client import start_http_server
        start_http_server(port, registry=METRICS_REGISTRY)
        
        click.echo(f"{Fore.GREEN}Prometheus metrics server started on port {port}{Style.RESET_ALL}")
        click.echo("Press Ctrl+C to stop")
        
        # Keep server running
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        click.echo(f"\n{Fore.YELLOW}Stopping metrics server...{Style.RESET_ALL}")
        monitor.stop_monitoring()
    except ImportError:
        click.echo(f"{Fore.RED}Prometheus client not available{Style.RESET_ALL}")

if __name__ == '__main__':
    cli()
