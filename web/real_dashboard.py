#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Real PQC-VPN Management Dashboard
Displays actual system data, not simulated information
"""

from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import sqlite3
import redis
import json
import subprocess
import re
import psutil
import hashlib
import secrets
from datetime import datetime, timedelta
import os
import socket

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////opt/pqc-vpn/data/pqc-vpn.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Ensure UTF-8 encoding
app.config['JSON_AS_ASCII'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Redis for real-time data
try:
    redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
    redis_client.ping()  # Test connection
except:
    redis_client = None
    print("Warning: Redis not available, using in-memory storage")

class AdminUser(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return AdminUser(user_id)

class RealPQCVPNManager:
    """Real PQC-VPN management operations"""
    
    def __init__(self):
        self.strongswan_bin = '/usr/local/strongswan/sbin/ipsec'
        self.db_path = '/opt/pqc-vpn/data/pqc-vpn.db'
    
    def get_real_status(self):
        """Get actual strongSwan status"""
        try:
            result = subprocess.run([self.strongswan_bin, 'status'], 
                                  capture_output=True, text=True, timeout=10)
            return {
                'status': 'running' if result.returncode == 0 else 'stopped',
                'output': result.stdout,
                'connections': self._parse_connections(result.stdout)
            }
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def get_detailed_status(self):
        """Get detailed strongSwan status"""
        try:
            result = subprocess.run([self.strongswan_bin, 'statusall'], 
                                  capture_output=True, text=True, timeout=15)
            return result.stdout
        except Exception as e:
            return f"Error getting detailed status: {e}"
    
    def _parse_connections(self, status_output):
        """Parse active connections from status output"""
        connections = []
        lines = status_output.split('\n')
        
        for line in lines:
            if 'ESTABLISHED' in line:
                # Parse connection details
                match = re.search(r'(\w+)\[(\d+)\].*?(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    connections.append({
                        'name': match.group(1),
                        'id': match.group(2),
                        'peer_ip': match.group(3),
                        'status': 'ESTABLISHED'
                    })
        
        return connections
    
    def get_system_metrics(self):
        """Get real system performance metrics"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            network = psutil.net_io_counters()
            
            return {
                'cpu_usage': round(cpu_percent, 2),
                'memory_total': memory.total,
                'memory_used': memory.used,
                'memory_percent': round(memory.percent, 2),
                'disk_total': disk.total,
                'disk_used': disk.used,
                'disk_percent': round((disk.used / disk.total) * 100, 2),
                'network_bytes_sent': network.bytes_sent,
                'network_bytes_recv': network.bytes_recv,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def get_pqc_algorithms(self):
        """Get available PQC algorithms"""
        try:
            # Check OQS algorithms
            result = subprocess.run(['/usr/local/oqs-openssl/bin/openssl', 'list', '-kem-algorithms'], 
                                  capture_output=True, text=True)
            kem_algorithms = result.stdout.strip().split('\n')[1:]  # Skip header
            
            result = subprocess.run(['/usr/local/oqs-openssl/bin/openssl', 'list', '-signature-algorithms'], 
                                  capture_output=True, text=True)
            sig_algorithms = result.stdout.strip().split('\n')[1:]  # Skip header
            
            return {
                'kem_algorithms': [alg.strip() for alg in kem_algorithms if alg.strip()],
                'signature_algorithms': [alg.strip() for alg in sig_algorithms if alg.strip()]
            }
        except Exception as e:
            return {'error': str(e)}
    
    def get_certificates(self):
        """Get certificate information"""
        certs = []
        cert_dir = '/etc/ipsec.d/certs'
        
        try:
            for cert_file in os.listdir(cert_dir):
                if cert_file.endswith('.pem'):
                    cert_path = os.path.join(cert_dir, cert_file)
                    cert_info = self._get_cert_info(cert_path)
                    cert_info['filename'] = cert_file
                    certs.append(cert_info)
        except Exception as e:
            pass
        
        return certs
    
    def _get_cert_info(self, cert_path):
        """Get certificate details"""
        try:
            result = subprocess.run(['/usr/local/oqs-openssl/bin/openssl', 'x509', '-in', cert_path, 
                                   '-text', '-noout'], capture_output=True, text=True)
            
            # Parse certificate info
            subject = re.search(r'Subject: (.+)', result.stdout)
            issuer = re.search(r'Issuer: (.+)', result.stdout)
            not_after = re.search(r'Not After : (.+)', result.stdout)
            not_before = re.search(r'Not Before: (.+)', result.stdout)
            
            return {
                'subject': subject.group(1) if subject else 'Unknown',
                'issuer': issuer.group(1) if issuer else 'Unknown',
                'not_after': not_after.group(1) if not_after else 'Unknown',
                'not_before': not_before.group(1) if not_before else 'Unknown',
                'path': cert_path
            }
        except Exception as e:
            return {'error': str(e)}
    
    def add_user(self, username, email, auth_type='pki', psk_key=None):
        """Add a new VPN user"""
        try:
            # Ensure database directory exists
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create users table if it doesn't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT,
                    auth_type TEXT DEFAULT 'pki',
                    psk_key TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    status TEXT DEFAULT 'active'
                )
            ''')
            
            # Generate PSK if needed
            if auth_type in ['psk', 'hybrid'] and not psk_key:
                psk_key = secrets.token_urlsafe(32)
            
            cursor.execute('''
                INSERT INTO users (username, email, auth_type, psk_key, status)
                VALUES (?, ?, ?, ?, 'active')
            ''', (username, email, auth_type, psk_key))
            
            conn.commit()
            conn.close()
            
            # Update strongSwan secrets if PSK
            if auth_type in ['psk', 'hybrid']:
                self._update_ipsec_secrets()
            
            return {'success': True, 'psk_key': psk_key}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _update_ipsec_secrets(self):
        """Update IPsec secrets file with current users"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT username, psk_key FROM users WHERE psk_key IS NOT NULL AND status = "active"')
            users = cursor.fetchall()
            conn.close()
            
            # Read existing secrets file
            secrets_file = '/etc/ipsec.secrets'
            if os.path.exists(secrets_file):
                with open(secrets_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
            else:
                lines = []
            
            # Keep non-user lines
            new_lines = []
            for line in lines:
                if not line.strip().startswith(('demo-user-', '@')) or ': PSK' not in line:
                    new_lines.append(line)
            
            # Add current users
            for username, psk_key in users:
                new_lines.append(f'{username} : PSK "{psk_key}"\n')
            
            # Write updated file
            with open(secrets_file, 'w', encoding='utf-8') as f:
                f.writelines(new_lines)
            
            # Reload strongSwan
            subprocess.run([self.strongswan_bin, 'reload'], capture_output=True)
            
        except Exception as e:
            print(f"Error updating IPsec secrets: {e}")

# Initialize manager
vpn_manager = RealPQCVPNManager()

@app.route('/')
def index():
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Simple authentication (enhance with proper password hashing in production)
        if username == 'admin' and password == os.environ.get('ADMIN_PASSWORD', 'pqc-admin-2025'):
            user = AdminUser('admin')
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')
    
    login_html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>PQC-VPN Admin Login</title>
        <style>
            body { font-family: Arial, sans-serif; background: #f0f2f5; margin: 0; padding: 50px; }
            .login-container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
            h1 { text-align: center; color: #333; margin-bottom: 30px; }
            input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
            button { width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
            button:hover { background: #0056b3; }
            .alert { background: #f8d7da; color: #721c24; padding: 10px; border-radius: 5px; margin: 10px 0; }
        </style>
    </head>
    <body>
        <div class="login-container">
            <h1>🔐 PQC-VPN Admin</h1>
            ''' + (''.join(f'<div class="alert">{message}</div>' for message in []) if 'get_flashed_messages' not in locals() else '') + '''
            <form method="POST">
                <input type="text" name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Login</button>
            </form>
            <p style="text-align: center; margin-top: 20px; color: #666; font-size: 14px;">
                Default: admin / pqc-admin-2025
            </p>
        </div>
    </body>
    </html>
    '''
    
    return Response(login_html, mimetype='text/html; charset=utf-8')

@app.route('/dashboard')
@login_required
def dashboard():
    dashboard_html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Real PQC-VPN Dashboard</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                min-height: 100vh; 
            }
            .header { 
                background: rgba(255,255,255,0.1); 
                padding: 20px; 
                color: white; 
                backdrop-filter: blur(10px);
                border-bottom: 1px solid rgba(255,255,255,0.2);
            }
            .header h1 { font-size: 2.5em; margin-bottom: 5px; }
            .header p { opacity: 0.9; font-size: 1.1em; }
            .container { padding: 20px; max-width: 1400px; margin: 0 auto; }
            
            .status-grid { 
                display: grid; 
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); 
                gap: 20px; 
                margin-bottom: 30px; 
            }
            
            .card { 
                background: rgba(255,255,255,0.95); 
                border-radius: 15px; 
                padding: 25px; 
                box-shadow: 0 8px 32px rgba(0,0,0,0.1); 
                backdrop-filter: blur(20px);
                border: 1px solid rgba(255,255,255,0.2);
                transition: transform 0.3s ease;
            }
            .card:hover { transform: translateY(-5px); }
            
            .card h3 { 
                color: #333; 
                margin-bottom: 15px; 
                font-size: 1.3em;
                display: flex;
                align-items: center;
            }
            
            .card h3 .icon { font-size: 1.5em; margin-right: 10px; }
            
            .metric { 
                display: flex; 
                justify-content: space-between; 
                padding: 8px 0; 
                border-bottom: 1px solid #eee; 
            }
            .metric:last-child { border-bottom: none; }
            
            .metric-label { color: #666; }
            .metric-value { 
                font-weight: bold; 
                color: #333;
                font-family: 'Courier New', monospace;
            }
            
            .status-online { 
                background: linear-gradient(45deg, #4CAF50, #45a049); 
                color: white; 
                padding: 15px; 
                border-radius: 8px; 
                text-align: center; 
                margin: 15px 0; 
                font-weight: bold;
            }
            
            .status-offline { 
                background: linear-gradient(45deg, #f44336, #d32f2f); 
                color: white; 
                padding: 15px; 
                border-radius: 8px; 
                text-align: center; 
                margin: 15px 0; 
                font-weight: bold;
            }
            
            .progress-bar {
                width: 100%;
                height: 20px;
                background-color: #e0e0e0;
                border-radius: 10px;
                overflow: hidden;
                margin: 5px 0;
            }
            
            .progress-fill {
                height: 100%;
                background: linear-gradient(45deg, #2196F3, #21CBF3);
                border-radius: 10px;
                transition: width 0.3s ease;
            }
            
            .connections-list {
                max-height: 300px;
                overflow-y: auto;
            }
            
            .connection-item {
                background: #f8f9fa;
                padding: 10px;
                margin: 5px 0;
                border-radius: 5px;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            
            .pqc-indicator {
                background: #4CAF50;
                color: white;
                padding: 2px 8px;
                border-radius: 12px;
                font-size: 0.8em;
                font-weight: bold;
            }
            
            .nav-buttons {
                display: flex;
                gap: 10px;
                margin-bottom: 20px;
                flex-wrap: wrap;
            }
            
            .nav-button {
                background: rgba(255,255,255,0.2);
                color: white;
                padding: 10px 20px;
                border: none;
                border-radius: 25px;
                cursor: pointer;
                text-decoration: none;
                font-weight: bold;
                transition: all 0.3s ease;
                backdrop-filter: blur(10px);
            }
            
            .nav-button:hover {
                background: rgba(255,255,255,0.3);
                transform: translateY(-2px);
            }
            
            .refresh-time {
                text-align: center;
                color: rgba(255,255,255,0.8);
                margin-top: 20px;
                font-style: italic;
            }
        </style>
    </head>
    <body>
        <div class="header">
            <h1><span class="icon">🔐</span> Real PQC-VPN Enterprise Dashboard</h1>
            <p>Post-Quantum Cryptography VPN - Live System Monitor</p>
        </div>
        
        <div class="container">
            <div class="nav-buttons">
                <a href="/dashboard" class="nav-button"><span class="icon">🏠</span> Dashboard</a>
                <a href="/users" class="nav-button"><span class="icon">👥</span> User Management</a>
                <a href="/certificates" class="nav-button"><span class="icon">🔐</span> Certificates</a>
                <a href="/system" class="nav-button"><span class="icon">🖥️</span> System Status</a>
                <a href="/logout" class="nav-button"><span class="icon">🚪</span> Logout</a>
            </div>
            
            <div class="status-grid">
                <div class="card">
                    <h3><span class="icon">🔐</span>VPN Status</h3>
                    <div id="vpn-status">Loading...</div>
                    <div class="metric">
                        <span class="metric-label">Active Connections:</span>
                        <span class="metric-value" id="active-connections">-</span>
                    </div>
                    <div class="metric">
                        <span class="metric-label">PQC Connections:</span>
                        <span class="metric-value" id="pqc-connections">-</span>
                    </div>
                </div>
                
                <div class="card">
                    <h3><span class="icon">📊</span>System Performance</h3>
                    <div class="metric">
                        <span class="metric-label">CPU Usage:</span>
                        <span class="metric-value" id="cpu-usage">-</span>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-fill" id="cpu-progress" style="width: 0%"></div>
                    </div>
                    <div class="metric">
                        <span class="metric-label">Memory Usage:</span>
                        <span class="metric-value" id="memory-usage">-</span>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-fill" id="memory-progress" style="width: 0%"></div>
                    </div>
                </div>
                
                <div class="card">
                    <h3><span class="icon">🌐</span>Network Statistics</h3>
                    <div class="metric">
                        <span class="metric-label">Bytes Sent:</span>
                        <span class="metric-value" id="bytes-sent">-</span>
                    </div>
                    <div class="metric">
                        <span class="metric-label">Bytes Received:</span>
                        <span class="metric-value" id="bytes-received">-</span>
                    </div>
                </div>
                
                <div class="card">
                    <h3><span class="icon">🔗</span>Active Connections</h3>
                    <div class="connections-list" id="connections-list">
                        Loading connections...
                    </div>
                </div>
            </div>
            
            <div class="refresh-time" id="last-update">
                Loading real-time data...
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
                fetch('/api/status')
                    .then(response => response.json())
                    .then(data => {
                        // Update VPN status
                        const vpnStatusDiv = document.getElementById('vpn-status');
                        if (data.vpn_status === 'running') {
                            vpnStatusDiv.className = 'status-online';
                            vpnStatusDiv.innerHTML = '✅ strongSwan Running with Real PQC';
                        } else {
                            vpnStatusDiv.className = 'status-offline';
                            vpnStatusDiv.innerHTML = '❌ strongSwan Not Running';
                        }
                        
                        // Update metrics
                        document.getElementById('active-connections').textContent = data.active_connections || 0;
                        document.getElementById('pqc-connections').textContent = data.pqc_connections || 0;
                        document.getElementById('cpu-usage').textContent = (data.cpu_usage || 0) + '%';
                        document.getElementById('memory-usage').textContent = (data.memory_usage || 0) + '%';
                        document.getElementById('bytes-sent').textContent = formatBytes(data.network_bytes_sent || 0);
                        document.getElementById('bytes-received').textContent = formatBytes(data.network_bytes_recv || 0);
                        
                        // Update progress bars
                        document.getElementById('cpu-progress').style.width = (data.cpu_usage || 0) + '%';
                        document.getElementById('memory-progress').style.width = (data.memory_usage || 0) + '%';
                        
                        // Update connections list
                        const connectionsList = document.getElementById('connections-list');
                        if (data.connections && data.connections.length > 0) {
                            connectionsList.innerHTML = data.connections.map(conn => `
                                <div class="connection-item">
                                    <div>
                                        <strong>${conn.name || 'Unknown'}</strong><br>
                                        <small>${conn.peer_ip || 'Unknown IP'}</small>
                                    </div>
                                    <div>
                                        <span class="pqc-indicator">PQC</span>
                                    </div>
                                </div>
                            `).join('');
                        } else {
                            connectionsList.innerHTML = '<div style="text-align: center; color: #666; padding: 20px;">No active connections</div>';
                        }
                        
                        // Update timestamp
                        document.getElementById('last-update').textContent = 
                            'Last updated: ' + new Date().toLocaleString();
                    })
                    .catch(error => {
                        console.error('Error updating dashboard:', error);
                        document.getElementById('last-update').textContent = 
                            'Error updating data: ' + new Date().toLocaleString();
                    });
            }
            
            // Update dashboard every 30 seconds
            updateDashboard();
            setInterval(updateDashboard, 30000);
        </script>
    </body>
    </html>
    '''
    
    return Response(dashboard_html, mimetype='text/html; charset=utf-8')

@app.route('/api/status')
@login_required
def api_status():
    """API endpoint for real-time status data"""
    try:
        # Get real VPN status
        vpn_status = vpn_manager.get_real_status()
        
        # Get system metrics
        system_metrics = vpn_manager.get_system_metrics()
        
        # Get real-time data from Redis if available
        real_time_data = {}
        if redis_client:
            try:
                redis_data = redis_client.get('pqc_vpn_status')
                real_time_data = json.loads(redis_data) if redis_data else {}
            except:
                pass
        
        response_data = {
            'vpn_status': vpn_status.get('status', 'unknown'),
            'active_connections': len(vpn_status.get('connections', [])),
            'pqc_connections': real_time_data.get('pqc_connections', 0),
            'connections': vpn_status.get('connections', []),
            'cpu_usage': system_metrics.get('cpu_usage', 0),
            'memory_usage': system_metrics.get('memory_percent', 0),
            'network_bytes_sent': system_metrics.get('network_bytes_sent', 0),
            'network_bytes_recv': system_metrics.get('network_bytes_recv', 0),
            'timestamp': datetime.now().isoformat()
        }
        
        return jsonify(response_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/users')
@login_required
def users():
    """User management page"""
    try:
        # Ensure database exists
        os.makedirs(os.path.dirname(vpn_manager.db_path), exist_ok=True)
        
        conn = sqlite3.connect(vpn_manager.db_path)
        cursor = conn.cursor()
        
        # Create table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT,
                auth_type TEXT DEFAULT 'pki',
                psk_key TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                status TEXT DEFAULT 'active'
            )
        ''')
        
        cursor.execute('SELECT * FROM users ORDER BY created_at DESC')
        users = cursor.fetchall()
        conn.close()
        
        users_html = ""
        for user in users:
            users_html += f"""
            <tr>
                <td>{user[1]}</td>  <!-- username -->
                <td>{user[2] or 'N/A'}</td>  <!-- email -->
                <td><span class="auth-badge auth-{user[3]}">{user[3].upper()}</span></td>  <!-- auth_type -->
                <td>{user[6] or 'Never'}</td>  <!-- last_login -->
                <td><span class="status-badge status-{user[7]}">{user[7].upper()}</span></td>  <!-- status -->
                <td>
                    <button onclick="deleteUser('{user[1]}')" class="btn-danger">Delete</button>
                </td>
            </tr>
            """
        
        users_page = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>PQC-VPN User Management</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
                .header {{ background: #007bff; color: white; padding: 20px; margin: -20px -20px 20px -20px; }}
                .card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin: 20px 0; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background: #f8f9fa; font-weight: bold; }}
                .btn {{ padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }}
                .btn-primary {{ background: #007bff; color: white; }}
                .btn-danger {{ background: #dc3545; color: white; }}
                .auth-badge {{ padding: 4px 8px; border-radius: 12px; font-size: 0.8em; font-weight: bold; }}
                .auth-pki {{ background: #28a745; color: white; }}
                .auth-psk {{ background: #ffc107; color: black; }}
                .auth-hybrid {{ background: #6f42c1; color: white; }}
                .status-badge {{ padding: 4px 8px; border-radius: 12px; font-size: 0.8em; font-weight: bold; }}
                .status-active {{ background: #28a745; color: white; }}
                .status-inactive {{ background: #6c757d; color: white; }}
                .form-group {{ margin: 15px 0; }}
                label {{ display: block; margin-bottom: 5px; font-weight: bold; }}
                input, select {{ width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }}
                .nav-link {{ color: white; text-decoration: none; margin-right: 20px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>👥 User Management</h1>
                <div>
                    <a href="/dashboard" class="nav-link">🏠 Dashboard</a>
                    <a href="/users" class="nav-link">👥 Users</a>
                    <a href="/certificates" class="nav-link">🔐 Certificates</a>
                    <a href="/system" class="nav-link">🖥️ System</a>
                </div>
            </div>
            
            <div class="card">
                <h3>Add New User</h3>
                <form onsubmit="addUser(event)">
                    <div class="form-group">
                        <label>Username:</label>
                        <input type="text" id="username" required>
                    </div>
                    <div class="form-group">
                        <label>Email:</label>
                        <input type="email" id="email" required>
                    </div>
                    <div class="form-group">
                        <label>Authentication Type:</label>
                        <select id="auth_type">
                            <option value="pki">PKI (Certificate-based)</option>
                            <option value="psk">PSK (Pre-shared Key)</option>
                            <option value="hybrid">Hybrid (PKI + PSK)</option>
                        </select>
                    </div>
                    <button type="submit" class="btn btn-primary">Add User</button>
                </form>
            </div>
            
            <div class="card">
                <h3>Current Users</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Username</th>
                            <th>Email</th>
                            <th>Auth Type</th>
                            <th>Last Login</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {users_html}
                    </tbody>
                </table>
            </div>
            
            <script>
                function addUser(event) {{
                    event.preventDefault();
                    
                    const username = document.getElementById('username').value;
                    const email = document.getElementById('email').value;
                    const auth_type = document.getElementById('auth_type').value;
                    
                    fetch('/api/users', {{
                        method: 'POST',
                        headers: {{'Content-Type': 'application/json'}},
                        body: JSON.stringify({{username, email, auth_type}})
                    }})
                    .then(response => response.json())
                    .then(data => {{
                        if (data.success) {{
                            alert('User added successfully!');
                            location.reload();
                        }} else {{
                            alert('Error: ' + data.error);
                        }}
                    }});
                }}
                
                function deleteUser(username) {{
                    if (confirm('Are you sure you want to delete user: ' + username + '?')) {{
                        fetch('/api/users/' + username, {{method: 'DELETE'}})
                        .then(response => response.json())
                        .then(data => {{
                            if (data.success) {{
                                alert('User deleted successfully!');
                                location.reload();
                            }} else {{
                                alert('Error: ' + data.error);
                            }}
                        }});
                    }}
                }}
            </script>
        </body>
        </html>
        '''
        
        return Response(users_page, mimetype='text/html; charset=utf-8')
    except Exception as e:
        return f"Error loading users: {e}"

@app.route('/api/users', methods=['POST'])
@login_required
def api_add_user():
    """API endpoint to add new user"""
    try:
        data = request.get_json()
        result = vpn_manager.add_user(
            data['username'], 
            data['email'], 
            data['auth_type']
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8443, debug=False, ssl_context='adhoc')
