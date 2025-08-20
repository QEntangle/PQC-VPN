#!/usr/bin/env python3
"""
Enterprise PQC-VPN Management Dashboard
Real-time integration with strongSwan and system monitoring
"""

import os
import sys
import json
import subprocess
import threading
import time
import sqlite3
import redis
import psutil
import hashlib
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging
import re

from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, send_from_directory
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/pqc-vpn/enterprise-dashboard.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Flask app configuration
app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'postgresql://pqc_admin:password@localhost:15432/pqc_vpn_enterprise')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Redis for real-time data caching
try:
    redis_client = redis.Redis(
        host=os.environ.get('REDIS_HOST', 'localhost'), 
        port=int(os.environ.get('REDIS_EXTERNAL_PORT', 16379)), 
        db=0, 
        decode_responses=True,
        password=os.environ.get('REDIS_PASSWORD')
    )
    redis_client.ping()
except Exception as e:
    logger.warning(f"Redis connection failed: {e}")
    redis_client = None

class AdminUser(UserMixin):
    def __init__(self, id, username, role='admin'):
        self.id = id
        self.username = username
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    return AdminUser(user_id, 'admin')

class EnterpriseVPNManager:
    """Enterprise VPN management with real strongSwan integration"""
    
    def __init__(self):
        self.strongswan_bin = '/usr/sbin/ipsec'
        self.swanctl_bin = '/usr/sbin/swanctl'
        self.db_url = app.config['SQLALCHEMY_DATABASE_URI']
        self.redis = redis_client
        self.monitoring_active = False
        self.last_update = None
        
        # strongSwan configuration paths
        self.ipsec_conf = '/etc/ipsec.conf'
        self.ipsec_secrets = '/etc/ipsec.secrets'
        self.strongswan_conf = '/etc/strongswan.conf'
        
        # Initialize monitoring
        self.start_monitoring()
    
    def start_monitoring(self):
        """Start background monitoring thread"""
        if not self.monitoring_active:
            self.monitoring_active = True
            monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            monitor_thread.start()
            logger.info("Enterprise monitoring started")
    
    def _monitoring_loop(self):
        """Background monitoring loop"""
        while self.monitoring_active:
            try:
                # Collect real-time data
                vpn_status = self.get_real_vpn_status()
                system_metrics = self.get_system_metrics()
                connection_stats = self.get_connection_statistics()
                
                # Cache in Redis if available
                if self.redis:
                    cache_data = {
                        'vpn_status': vpn_status,
                        'system_metrics': system_metrics,
                        'connection_stats': connection_stats,
                        'timestamp': datetime.now().isoformat()
                    }
                    self.redis.setex('enterprise_vpn_status', 60, json.dumps(cache_data))
                
                self.last_update = datetime.now()
                time.sleep(30)  # Update every 30 seconds
                
            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
                time.sleep(60)  # Wait longer on error
    
    def get_real_vpn_status(self) -> Dict[str, Any]:
        """Get actual strongSwan status and connection information"""
        try:
            # Check strongSwan service status
            service_status = self._check_service_status()
            
            # Get active connections
            connections = self._get_active_connections()
            
            # Get strongSwan version and capabilities
            version_info = self._get_strongswan_version()
            
            # Get PQC algorithm support
            pqc_support = self._check_pqc_support()
            
            return {
                'service_status': service_status,
                'connections': connections,
                'version_info': version_info,
                'pqc_support': pqc_support,
                'active_count': len(connections),
                'pqc_count': sum(1 for c in connections if self._is_pqc_connection(c)),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Error getting VPN status: {e}")
            return {'error': str(e), 'timestamp': datetime.now().isoformat()}
    
    def _check_service_status(self) -> Dict[str, Any]:
        """Check strongSwan service status"""
        try:
            # Check systemd service
            result = subprocess.run(
                ['systemctl', 'is-active', 'strongswan-starter'], 
                capture_output=True, text=True, timeout=10
            )
            
            service_active = result.returncode == 0 and result.stdout.strip() == 'active'
            
            # Check ipsec status
            result = subprocess.run(
                [self.strongswan_bin, 'status'], 
                capture_output=True, text=True, timeout=10
            )
            
            ipsec_running = result.returncode == 0
            
            return {
                'service_active': service_active,
                'ipsec_running': ipsec_running,
                'status': 'running' if (service_active and ipsec_running) else 'stopped',
                'last_check': datetime.now().isoformat()
            }
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def _get_active_connections(self) -> List[Dict[str, Any]]:
        """Get list of active VPN connections with detailed information"""
        connections = []
        
        try:
            # Get connection status using swanctl
            result = subprocess.run(
                [self.swanctl_bin, '--list-sas'], 
                capture_output=True, text=True, timeout=15
            )
            
            if result.returncode == 0:
                connections.extend(self._parse_swanctl_output(result.stdout))
            
            # Fallback to ipsec status
            if not connections:
                result = subprocess.run(
                    [self.strongswan_bin, 'statusall'], 
                    capture_output=True, text=True, timeout=15
                )
                
                if result.returncode == 0:
                    connections.extend(self._parse_ipsec_status(result.stdout))
            
            # Enrich connection data with additional information
            for conn in connections:
                conn.update(self._enrich_connection_data(conn))
                
        except Exception as e:
            logger.error(f"Error getting active connections: {e}")
        
        return connections
    
    def _parse_swanctl_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse swanctl --list-sas output"""
        connections = []
        current_connection = None
        
        lines = output.strip().split('\n')
        for line in lines:
            line = line.strip()
            
            if line.startswith('conn-'):
                # New connection
                if current_connection:
                    connections.append(current_connection)
                
                current_connection = {
                    'name': line.rstrip(':'),
                    'status': 'ESTABLISHED',
                    'established_time': datetime.now(),
                    'type': 'swanctl'
                }
            
            elif current_connection and ':' in line:
                # Parse connection details
                key, value = line.split(':', 1)
                key = key.strip().lower().replace(' ', '_')
                value = value.strip()
                
                if key == 'local':
                    current_connection['local_ip'] = value
                elif key == 'remote':
                    current_connection['remote_ip'] = value
                elif key == 'encryption':
                    current_connection['encryption'] = value
                elif key == 'integrity':
                    current_connection['integrity'] = value
                elif key == 'dh_group':
                    current_connection['dh_group'] = value
        
        if current_connection:
            connections.append(current_connection)
        
        return connections
    
    def _parse_ipsec_status(self, output: str) -> List[Dict[str, Any]]:
        """Parse ipsec statusall output"""
        connections = []
        lines = output.strip().split('\n')
        
        for line in lines:
            if 'ESTABLISHED' in line and '[' in line:
                # Parse established connection
                match = re.match(r'(\w+)\[(\d+)\]:\s+ESTABLISHED\s+(.+)', line)
                if match:
                    conn_name = match.group(1)
                    conn_id = match.group(2)
                    details = match.group(3)
                    
                    # Extract IP addresses
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)\[([^\]]+)\]\.\.\.(\d+\.\d+\.\d+\.\d+)\[([^\]]+)\]', details)
                    
                    connection = {
                        'name': conn_name,
                        'id': conn_id,
                        'status': 'ESTABLISHED',
                        'type': 'ipsec',
                        'established_time': datetime.now()
                    }
                    
                    if ip_match:
                        connection.update({
                            'local_ip': ip_match.group(1),
                            'local_id': ip_match.group(2),
                            'remote_ip': ip_match.group(3),
                            'remote_id': ip_match.group(4)
                        })
                    
                    connections.append(connection)
        
        return connections
    
    def _enrich_connection_data(self, conn: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich connection data with additional information"""
        enriched = {}
        
        # Extract user information from connection name or ID
        if 'name' in conn:
            if 'spoke-' in conn['name']:
                enriched['user'] = conn['name'].replace('spoke-', '')
            elif 'client-' in conn['name']:
                enriched['user'] = conn['name'].replace('client-', '')
            else:
                enriched['user'] = conn['name']
        
        # Determine authentication type
        enriched['auth_type'] = 'PKI'  # Default
        if 'psk' in conn.get('name', '').lower():
            enriched['auth_type'] = 'PSK'
        
        # Detect PQC algorithms
        encryption = conn.get('encryption', '').lower()
        if 'kyber' in encryption:
            if 'kyber1024' in encryption:
                enriched['pqc_algorithm'] = 'Kyber-1024'
            elif 'kyber768' in encryption:
                enriched['pqc_algorithm'] = 'Kyber-768'
            elif 'kyber512' in encryption:
                enriched['pqc_algorithm'] = 'Kyber-512'
        
        # Calculate connection duration
        if 'established_time' in conn:
            duration = datetime.now() - conn['established_time']
            enriched['duration'] = str(duration).split('.')[0]  # Remove microseconds
        
        # Get traffic statistics
        enriched.update(self._get_connection_traffic(conn.get('name', '')))
        
        return enriched
    
    def _get_connection_traffic(self, conn_name: str) -> Dict[str, int]:
        """Get traffic statistics for a specific connection"""
        try:
            result = subprocess.run(
                [self.strongswan_bin, 'statusall', conn_name], 
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0:
                # Parse traffic data from output
                traffic_match = re.search(r'bytes_i\((\d+)\),bytes_o\((\d+)\)', result.stdout)
                if traffic_match:
                    return {
                        'bytes_in': int(traffic_match.group(1)),
                        'bytes_out': int(traffic_match.group(2))
                    }
        except Exception as e:
            logger.error(f"Error getting traffic for {conn_name}: {e}")
        
        return {'bytes_in': 0, 'bytes_out': 0}
    
    def _is_pqc_connection(self, conn: Dict[str, Any]) -> bool:
        """Check if connection uses post-quantum cryptography"""
        encryption = conn.get('encryption', '').lower()
        dh_group = conn.get('dh_group', '').lower()
        pqc_algorithm = conn.get('pqc_algorithm', '')
        
        return any([
            'kyber' in encryption,
            'dilithium' in encryption,
            'falcon' in encryption,
            'kyber' in dh_group,
            bool(pqc_algorithm)
        ])
    
    def _get_strongswan_version(self) -> Dict[str, str]:
        """Get strongSwan version and build information"""
        try:
            result = subprocess.run(
                [self.strongswan_bin, '--version'], 
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0:
                version_line = result.stdout.split('\n')[0]
                return {
                    'version': version_line,
                    'full_output': result.stdout
                }
        except Exception as e:
            logger.error(f"Error getting strongSwan version: {e}")
        
        return {'version': 'Unknown', 'full_output': ''}
    
    def _check_pqc_support(self) -> Dict[str, Any]:
        """Check for post-quantum cryptography support"""
        pqc_support = {
            'oqs_provider': False,
            'kyber_variants': [],
            'dilithium_variants': [],
            'falcon_variants': []
        }
        
        try:
            # Check for OQS provider
            result = subprocess.run(
                ['/usr/local/oqs-openssl/bin/openssl', 'list', '-providers'], 
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0 and 'oqsprovider' in result.stdout:
                pqc_support['oqs_provider'] = True
            
            # Check available KEM algorithms
            result = subprocess.run(
                ['/usr/local/oqs-openssl/bin/openssl', 'list', '-kem-algorithms'], 
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0:
                algorithms = result.stdout.lower()
                if 'kyber512' in algorithms:
                    pqc_support['kyber_variants'].append('Kyber-512')
                if 'kyber768' in algorithms:
                    pqc_support['kyber_variants'].append('Kyber-768')
                if 'kyber1024' in algorithms:
                    pqc_support['kyber_variants'].append('Kyber-1024')
            
            # Check available signature algorithms
            result = subprocess.run(
                ['/usr/local/oqs-openssl/bin/openssl', 'list', '-signature-algorithms'], 
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0:
                algorithms = result.stdout.lower()
                for variant in ['dilithium2', 'dilithium3', 'dilithium5']:
                    if variant in algorithms:
                        pqc_support['dilithium_variants'].append(variant.capitalize())
                
                for variant in ['falcon512', 'falcon1024']:
                    if variant in algorithms:
                        pqc_support['falcon_variants'].append(variant.capitalize())
        
        except Exception as e:
            logger.error(f"Error checking PQC support: {e}")
        
        return pqc_support
    
    def get_system_metrics(self) -> Dict[str, Any]:
        """Get comprehensive system performance metrics"""
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()
            
            # Memory metrics
            memory = psutil.virtual_memory()
            
            # Disk metrics
            disk = psutil.disk_usage('/')
            
            # Network metrics
            network = psutil.net_io_counters()
            
            # Load average
            load_avg = os.getloadavg() if hasattr(os, 'getloadavg') else (0, 0, 0)
            
            # Process information
            strongswan_processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                if 'charon' in proc.info['name'] or 'starter' in proc.info['name']:
                    strongswan_processes.append(proc.info)
            
            return {
                'cpu': {
                    'percent': round(cpu_percent, 2),
                    'count': cpu_count,
                    'load_avg': load_avg
                },
                'memory': {
                    'total': memory.total,
                    'used': memory.used,
                    'percent': round(memory.percent, 2),
                    'available': memory.available
                },
                'disk': {
                    'total': disk.total,
                    'used': disk.used,
                    'percent': round((disk.used / disk.total) * 100, 2),
                    'free': disk.free
                },
                'network': {
                    'bytes_sent': network.bytes_sent,
                    'bytes_recv': network.bytes_recv,
                    'packets_sent': network.packets_sent,
                    'packets_recv': network.packets_recv
                },
                'processes': {
                    'strongswan': strongswan_processes,
                    'total_processes': len(list(psutil.process_iter()))
                },
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Error getting system metrics: {e}")
            return {'error': str(e), 'timestamp': datetime.now().isoformat()}
    
    def get_connection_statistics(self) -> Dict[str, Any]:
        """Get VPN connection statistics and analytics"""
        try:
            connections = self._get_active_connections()
            
            # Basic statistics
            total_connections = len(connections)
            pqc_connections = sum(1 for c in connections if self._is_pqc_connection(c))
            
            # Authentication breakdown
            auth_types = {}
            for conn in connections:
                auth_type = conn.get('auth_type', 'Unknown')
                auth_types[auth_type] = auth_types.get(auth_type, 0) + 1
            
            # Algorithm usage
            algorithms = {}
            for conn in connections:
                alg = conn.get('pqc_algorithm', 'Classical')
                algorithms[alg] = algorithms.get(alg, 0) + 1
            
            # Traffic statistics
            total_bytes_in = sum(c.get('bytes_in', 0) for c in connections)
            total_bytes_out = sum(c.get('bytes_out', 0) for c in connections)
            
            return {
                'total_connections': total_connections,
                'pqc_connections': pqc_connections,
                'classical_connections': total_connections - pqc_connections,
                'auth_types': auth_types,
                'algorithms': algorithms,
                'traffic': {
                    'total_bytes_in': total_bytes_in,
                    'total_bytes_out': total_bytes_out,
                    'total_bytes': total_bytes_in + total_bytes_out
                },
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Error getting connection statistics: {e}")
            return {'error': str(e), 'timestamp': datetime.now().isoformat()}
    
    def add_user(self, username: str, email: str, auth_type: str = 'pki') -> Dict[str, Any]:
        """Add a new VPN user"""
        try:
            # Add user to database
            with app.app_context():
                # Use raw SQL for now - would use SQLAlchemy models in production
                from sqlalchemy import text
                
                # Generate PSK if needed
                psk_key = None
                if auth_type in ['psk', 'hybrid']:
                    psk_key = secrets.token_urlsafe(32)
                
                query = text('''
                    INSERT INTO users (username, email, auth_type, psk_key, status, created_at)
                    VALUES (:username, :email, :auth_type, :psk_key, 'active', :created_at)
                ''')
                
                db.engine.execute(query, {
                    'username': username,
                    'email': email,
                    'auth_type': auth_type,
                    'psk_key': psk_key,
                    'created_at': datetime.now()
                })
                
                # Update strongSwan configuration
                self._update_strongswan_config()
                
                logger.info(f"User {username} added successfully")
                return {
                    'success': True,
                    'username': username,
                    'auth_type': auth_type,
                    'psk_key': psk_key
                }
                
        except Exception as e:
            logger.error(f"Error adding user {username}: {e}")
            return {'success': False, 'error': str(e)}
    
    def _update_strongswan_config(self):
        """Update strongSwan configuration with current users"""
        try:
            # Reload strongSwan configuration
            subprocess.run([self.strongswan_bin, 'reload'], check=True, timeout=30)
            logger.info("strongSwan configuration reloaded")
        except Exception as e:
            logger.error(f"Error reloading strongSwan: {e}")

# Initialize the enterprise manager
enterprise_manager = EnterpriseVPNManager()

# Flask Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Enhanced authentication (use proper password hashing in production)
        admin_password = os.environ.get('ADMIN_PASSWORD', 'DemoAdmin123!')
        
        if username == 'admin' and password == admin_password:
            user = AdminUser('admin', username)
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')
    
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>PQC-VPN Enterprise Dashboard</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .login-container {
                background: rgba(255,255,255,0.95);
                padding: 40px;
                border-radius: 20px;
                box-shadow: 0 15px 35px rgba(0,0,0,0.1);
                backdrop-filter: blur(10px);
                border: 1px solid rgba(255,255,255,0.2);
                max-width: 400px;
                width: 100%;
            }
            h1 { 
                text-align: center; 
                color: #333; 
                margin-bottom: 30px; 
                font-size: 2em;
                background: linear-gradient(45deg, #667eea, #764ba2);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }
            .subtitle {
                text-align: center;
                color: #666;
                margin-bottom: 30px;
                font-style: italic;
            }
            input {
                width: 100%;
                padding: 15px;
                margin: 10px 0;
                border: 2px solid #e1e1e1;
                border-radius: 10px;
                font-size: 16px;
                transition: border-color 0.3s ease;
            }
            input:focus {
                outline: none;
                border-color: #667eea;
                box-shadow: 0 0 10px rgba(102, 126, 234, 0.1);
            }
            button {
                width: 100%;
                padding: 15px;
                background: linear-gradient(45deg, #667eea, #764ba2);
                color: white;
                border: none;
                border-radius: 10px;
                cursor: pointer;
                font-size: 16px;
                font-weight: bold;
                transition: transform 0.3s ease;
            }
            button:hover { transform: translateY(-2px); }
            .alert {
                background: #f8d7da;
                color: #721c24;
                padding: 15px;
                border-radius: 10px;
                margin: 15px 0;
                border: 1px solid #f5c6cb;
            }
            .features {
                text-align: center;
                margin-top: 30px;
                padding-top: 20px;
                border-top: 1px solid #e1e1e1;
            }
            .feature-list {
                display: flex;
                justify-content: space-around;
                flex-wrap: wrap;
                gap: 10px;
                margin-top: 15px;
            }
            .feature {
                font-size: 12px;
                color: #666;
                background: #f8f9fa;
                padding: 5px 10px;
                border-radius: 15px;
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <h1>🔐 PQC-VPN</h1>
            <p class="subtitle">Enterprise Post-Quantum Dashboard</p>
            
            {% with messages = get_flashed_messages() %}
                {% if messages %}
                    {% for message in messages %}
                        <div class="alert">🚨 {{ message }}</div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            
            <form method="POST">
                <input type="text" name="username" placeholder="👤 Username" required>
                <input type="password" name="password" placeholder="🔒 Password" required>
                <button type="submit">🚀 Access Dashboard</button>
            </form>
            
            <div class="features">
                <div style="font-weight: bold; color: #333; margin-bottom: 10px;">Enterprise Features</div>
                <div class="feature-list">
                    <div class="feature">🔐 PQC Algorithms</div>
                    <div class="feature">📊 Real-time Monitor</div>
                    <div class="feature">👥 User Management</div>
                    <div class="feature">📈 Analytics</div>
                </div>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/dashboard')
@login_required
def dashboard():
    """Enterprise dashboard with real-time data"""
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>PQC-VPN Enterprise Dashboard</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                color: #333;
            }
            
            .header {
                background: rgba(0,0,0,0.1);
                padding: 20px;
                color: white;
                backdrop-filter: blur(10px);
                border-bottom: 1px solid rgba(255,255,255,0.1);
            }
            
            .header h1 { font-size: 2.5em; margin-bottom: 5px; }
            .header .subtitle { opacity: 0.9; font-size: 1.1em; }
            
            .nav-bar {
                display: flex;
                gap: 20px;
                margin-top: 15px;
                flex-wrap: wrap;
            }
            
            .nav-item {
                background: rgba(255,255,255,0.2);
                padding: 10px 20px;
                border-radius: 25px;
                color: white;
                text-decoration: none;
                transition: all 0.3s ease;
            }
            
            .nav-item:hover {
                background: rgba(255,255,255,0.3);
                transform: translateY(-2px);
            }
            
            .container { padding: 30px; max-width: 1400px; margin: 0 auto; }
            
            .status-overview {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }
            
            .overview-card {
                background: rgba(255,255,255,0.95);
                border-radius: 15px;
                padding: 25px;
                text-align: center;
                box-shadow: 0 8px 32px rgba(0,0,0,0.1);
                backdrop-filter: blur(20px);
                border: 1px solid rgba(255,255,255,0.2);
                transition: transform 0.3s ease;
            }
            
            .overview-card:hover { transform: translateY(-5px); }
            
            .overview-card .icon {
                font-size: 3em;
                margin-bottom: 15px;
                display: block;
            }
            
            .overview-card .title {
                font-size: 1.1em;
                color: #666;
                margin-bottom: 10px;
            }
            
            .overview-card .value {
                font-size: 2.5em;
                font-weight: bold;
                color: #333;
                margin-bottom: 5px;
            }
            
            .overview-card .subtitle {
                font-size: 0.9em;
                color: #888;
            }
            
            .main-grid {
                display: grid;
                grid-template-columns: 2fr 1fr;
                gap: 30px;
                margin-bottom: 30px;
            }
            
            .card {
                background: rgba(255,255,255,0.95);
                border-radius: 15px;
                padding: 25px;
                box-shadow: 0 8px 32px rgba(0,0,0,0.1);
                backdrop-filter: blur(20px);
                border: 1px solid rgba(255,255,255,0.2);
            }
            
            .card h3 {
                color: #333;
                margin-bottom: 20px;
                font-size: 1.4em;
                display: flex;
                align-items: center;
            }
            
            .card h3 .icon {
                font-size: 1.3em;
                margin-right: 10px;
            }
            
            .status-indicator {
                display: inline-block;
                width: 12px;
                height: 12px;
                border-radius: 50%;
                margin-right: 8px;
            }
            
            .status-online { background: #4CAF50; }
            .status-offline { background: #f44336; }
            .status-warning { background: #ff9800; }
            
            .connection-list {
                max-height: 400px;
                overflow-y: auto;
            }
            
            .connection-item {
                background: #f8f9fa;
                padding: 15px;
                margin: 10px 0;
                border-radius: 10px;
                border-left: 4px solid #4CAF50;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            
            .connection-item.pqc {
                border-left-color: #9c27b0;
                background: linear-gradient(135deg, #f3e5f5 0%, #e1bee7 100%);
            }
            
            .connection-info {
                flex-grow: 1;
            }
            
            .connection-name {
                font-weight: bold;
                color: #333;
                margin-bottom: 5px;
            }
            
            .connection-details {
                font-size: 0.9em;
                color: #666;
            }
            
            .connection-badge {
                background: #2196F3;
                color: white;
                padding: 4px 12px;
                border-radius: 20px;
                font-size: 0.8em;
                font-weight: bold;
                margin-left: 10px;
            }
            
            .connection-badge.pqc {
                background: linear-gradient(45deg, #9c27b0, #673ab7);
            }
            
            .metric {
                display: flex;
                justify-content: space-between;
                padding: 12px 0;
                border-bottom: 1px solid #eee;
            }
            
            .metric:last-child { border-bottom: none; }
            
            .metric-label { color: #666; }
            .metric-value { 
                font-weight: bold; 
                color: #333;
                font-family: 'Courier New', monospace;
            }
            
            .progress-bar {
                width: 100%;
                height: 8px;
                background: #e0e0e0;
                border-radius: 4px;
                overflow: hidden;
                margin: 5px 0;
            }
            
            .progress-fill {
                height: 100%;
                background: linear-gradient(45deg, #4CAF50, #45a049);
                border-radius: 4px;
                transition: width 0.5s ease;
            }
            
            .refresh-info {
                text-align: center;
                color: rgba(255,255,255,0.8);
                margin-top: 30px;
                padding: 15px;
                background: rgba(0,0,0,0.1);
                border-radius: 10px;
                backdrop-filter: blur(10px);
            }
            
            .loading {
                display: inline-block;
                width: 20px;
                height: 20px;
                border: 3px solid rgba(255,255,255,0.3);
                border-radius: 50%;
                border-top-color: white;
                animation: spin 1s ease-in-out infinite;
            }
            
            @keyframes spin {
                to { transform: rotate(360deg); }
            }
            
            .error-state {
                background: #ffebee;
                color: #c62828;
                padding: 15px;
                border-radius: 10px;
                border-left: 4px solid #f44336;
                margin: 10px 0;
            }
            
            @media (max-width: 768px) {
                .main-grid {
                    grid-template-columns: 1fr;
                }
                
                .status-overview {
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                }
            }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🔐 PQC-VPN Enterprise Dashboard</h1>
            <p class="subtitle">Real-time Post-Quantum Cryptography VPN Management</p>
            <div class="nav-bar">
                <a href="/dashboard" class="nav-item">🏠 Dashboard</a>
                <a href="/connections" class="nav-item">🔗 Connections</a>
                <a href="/users" class="nav-item">👥 Users</a>
                <a href="/system" class="nav-item">🖥️ System</a>
                <a href="/security" class="nav-item">🛡️ Security</a>
                <a href="/logout" class="nav-item">🚪 Logout</a>
            </div>
        </div>
        
        <div class="container">
            <!-- Status Overview -->
            <div class="status-overview">
                <div class="overview-card">
                    <span class="icon">🚀</span>
                    <div class="title">Service Status</div>
                    <div class="value" id="service-status">
                        <span class="loading"></span>
                    </div>
                    <div class="subtitle">strongSwan Engine</div>
                </div>
                
                <div class="overview-card">
                    <span class="icon">🔗</span>
                    <div class="title">Active Connections</div>
                    <div class="value" id="active-connections">
                        <span class="loading"></span>
                    </div>
                    <div class="subtitle">Real-time Tunnels</div>
                </div>
                
                <div class="overview-card">
                    <span class="icon">🔐</span>
                    <div class="title">PQC Connections</div>
                    <div class="value" id="pqc-connections">
                        <span class="loading"></span>
                    </div>
                    <div class="subtitle">Quantum-Safe Tunnels</div>
                </div>
                
                <div class="overview-card">
                    <span class="icon">📊</span>
                    <div class="title">CPU Usage</div>
                    <div class="value" id="cpu-usage">
                        <span class="loading"></span>
                    </div>
                    <div class="subtitle">System Performance</div>
                </div>
            </div>
            
            <!-- Main Content Grid -->
            <div class="main-grid">
                <!-- Active Connections -->
                <div class="card">
                    <h3><span class="icon">🔗</span>Live Connection Monitor</h3>
                    <div class="connection-list" id="connection-list">
                        <div style="text-align: center; padding: 40px; color: #666;">
                            <span class="loading"></span>
                            <p style="margin-top: 15px;">Loading real-time connection data...</p>
                        </div>
                    </div>
                </div>
                
                <!-- System Metrics -->
                <div class="card">
                    <h3><span class="icon">📈</span>System Metrics</h3>
                    <div class="metric">
                        <span class="metric-label">Memory Usage:</span>
                        <span class="metric-value" id="memory-usage">-</span>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-fill" id="memory-progress" style="width: 0%"></div>
                    </div>
                    
                    <div class="metric">
                        <span class="metric-label">Disk Usage:</span>
                        <span class="metric-value" id="disk-usage">-</span>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-fill" id="disk-progress" style="width: 0%"></div>
                    </div>
                    
                    <div class="metric">
                        <span class="metric-label">Network In:</span>
                        <span class="metric-value" id="network-in">-</span>
                    </div>
                    
                    <div class="metric">
                        <span class="metric-label">Network Out:</span>
                        <span class="metric-value" id="network-out">-</span>
                    </div>
                    
                    <div class="metric">
                        <span class="metric-label">Load Average:</span>
                        <span class="metric-value" id="load-average">-</span>
                    </div>
                    
                    <div class="metric">
                        <span class="metric-label">strongSwan Version:</span>
                        <span class="metric-value" id="strongswan-version">-</span>
                    </div>
                </div>
            </div>
            
            <div class="refresh-info" id="refresh-info">
                <span class="loading"></span>
                <span style="margin-left: 10px;">Connecting to enterprise monitoring system...</span>
            </div>
        </div>
        
        <script>
            function formatBytes(bytes) {
                if (bytes === 0) return '0 B';
                const k = 1024;
                const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
                const i = Math.floor(Math.log(bytes) / Math.log(k));
                return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
            }
            
            function updateDashboard() {
                fetch('/api/enterprise/status')
                    .then(response => response.json())
                    .then(data => {
                        if (data.error) {
                            showError(data.error);
                            return;
                        }
                        
                        // Update service status
                        const serviceStatus = document.getElementById('service-status');
                        const vpnStatus = data.vpn_status?.service_status?.status || 'unknown';
                        
                        if (vpnStatus === 'running') {
                            serviceStatus.innerHTML = '<span class="status-indicator status-online"></span>ONLINE';
                            serviceStatus.style.color = '#4CAF50';
                        } else if (vpnStatus === 'stopped') {
                            serviceStatus.innerHTML = '<span class="status-indicator status-offline"></span>OFFLINE';
                            serviceStatus.style.color = '#f44336';
                        } else {
                            serviceStatus.innerHTML = '<span class="status-indicator status-warning"></span>UNKNOWN';
                            serviceStatus.style.color = '#ff9800';
                        }
                        
                        // Update connection counts
                        const activeConnections = data.vpn_status?.active_count || 0;
                        const pqcConnections = data.vpn_status?.pqc_count || 0;
                        
                        document.getElementById('active-connections').textContent = activeConnections;
                        document.getElementById('pqc-connections').textContent = pqcConnections;
                        
                        // Update system metrics
                        const sysMetrics = data.system_metrics;
                        if (sysMetrics && !sysMetrics.error) {
                            const cpuPercent = sysMetrics.cpu?.percent || 0;
                            const memoryPercent = sysMetrics.memory?.percent || 0;
                            const diskPercent = sysMetrics.disk?.percent || 0;
                            
                            document.getElementById('cpu-usage').textContent = cpuPercent + '%';
                            document.getElementById('memory-usage').textContent = memoryPercent + '%';
                            document.getElementById('disk-usage').textContent = diskPercent + '%';
                            
                            // Update progress bars
                            document.getElementById('memory-progress').style.width = memoryPercent + '%';
                            document.getElementById('disk-progress').style.width = diskPercent + '%';
                            
                            // Network stats
                            document.getElementById('network-in').textContent = formatBytes(sysMetrics.network?.bytes_recv || 0);
                            document.getElementById('network-out').textContent = formatBytes(sysMetrics.network?.bytes_sent || 0);
                            
                            // Load average
                            const loadAvg = sysMetrics.cpu?.load_avg || [0, 0, 0];
                            document.getElementById('load-average').textContent = loadAvg.map(l => l.toFixed(2)).join(', ');
                        }
                        
                        // Update strongSwan version
                        const versionInfo = data.vpn_status?.version_info?.version || 'Unknown';
                        document.getElementById('strongswan-version').textContent = versionInfo.split(' ')[1] || 'Unknown';
                        
                        // Update connections list
                        updateConnectionsList(data.vpn_status?.connections || []);
                        
                        // Update refresh info
                        const refreshInfo = document.getElementById('refresh-info');
                        refreshInfo.innerHTML = `
                            <span style="color: #4CAF50;">●</span>
                            <span style="margin-left: 10px;">Last updated: ${new Date().toLocaleString()}</span>
                            <span style="margin-left: 20px; opacity: 0.7;">Auto-refresh: 30s</span>
                        `;
                    })
                    .catch(error => {
                        console.error('Dashboard update error:', error);
                        showError('Failed to fetch dashboard data: ' + error.message);
                    });
            }
            
            function updateConnectionsList(connections) {
                const connectionList = document.getElementById('connection-list');
                
                if (connections.length === 0) {
                    connectionList.innerHTML = `
                        <div style="text-align: center; padding: 40px; color: #666;">
                            <span style="font-size: 3em;">🔍</span>
                            <p style="margin-top: 15px;">No active connections</p>
                            <p style="font-size: 0.9em; opacity: 0.7;">Connections will appear here when clients connect</p>
                        </div>
                    `;
                    return;
                }
                
                connectionList.innerHTML = connections.map(conn => {
                    const isPQC = conn.pqc_algorithm || false;
                    const authType = conn.auth_type || 'Unknown';
                    const duration = conn.duration || 'Unknown';
                    const user = conn.user || conn.name || 'Unknown';
                    const remoteIP = conn.remote_ip || 'Unknown';
                    
                    return `
                        <div class="connection-item ${isPQC ? 'pqc' : ''}">
                            <div class="connection-info">
                                <div class="connection-name">
                                    ${isPQC ? '🔐' : '🔗'} ${user}
                                </div>
                                <div class="connection-details">
                                    ${remoteIP} • ${authType} Auth • Duration: ${duration}
                                    ${isPQC ? ` • ${conn.pqc_algorithm}` : ''}
                                </div>
                            </div>
                            <div>
                                <span class="connection-badge ${isPQC ? 'pqc' : ''}">
                                    ${isPQC ? 'POST-QUANTUM' : 'CLASSICAL'}
                                </span>
                            </div>
                        </div>
                    `;
                }).join('');
            }
            
            function showError(message) {
                const refreshInfo = document.getElementById('refresh-info');
                refreshInfo.innerHTML = `
                    <div class="error-state">
                        <strong>⚠️ Error:</strong> ${message}
                        <div style="margin-top: 10px; font-size: 0.9em;">
                            Retrying in 30 seconds...
                        </div>
                    </div>
                `;
            }
            
            // Initialize dashboard
            updateDashboard();
            
            // Auto-refresh every 30 seconds
            setInterval(updateDashboard, 30000);
        </script>
    </body>
    </html>
    '''

@app.route('/api/enterprise/status')
@login_required
def enterprise_status_api():
    """Enterprise API endpoint with real strongSwan data"""
    try:
        # Get cached data from Redis if available
        if enterprise_manager.redis:
            cached_data = enterprise_manager.redis.get('enterprise_vpn_status')
            if cached_data:
                data = json.loads(cached_data)
                # Add real-time timestamp
                data['api_timestamp'] = datetime.now().isoformat()
                return jsonify(data)
        
        # Fallback to direct data collection
        vpn_status = enterprise_manager.get_real_vpn_status()
        system_metrics = enterprise_manager.get_system_metrics()
        connection_stats = enterprise_manager.get_connection_statistics()
        
        return jsonify({
            'vpn_status': vpn_status,
            'system_metrics': system_metrics,
            'connection_stats': connection_stats,
            'api_timestamp': datetime.now().isoformat(),
            'data_source': 'direct'
        })
        
    except Exception as e:
        logger.error(f"Enterprise status API error: {e}")
        return jsonify({
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Additional enterprise routes would go here...

if __name__ == '__main__':
    print("🚀 Starting PQC-VPN Enterprise Dashboard...")
    print("🔐 Real strongSwan Integration Enabled")
    print("📊 Enterprise Monitoring Active")
    
    # Start the enterprise dashboard
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('WEB_PORT', 8443)),
        debug=os.environ.get('DEBUG', 'false').lower() == 'true',
        ssl_context='adhoc'  # Use adhoc SSL for HTTPS
    )
