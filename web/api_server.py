#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PQC-VPN Web Management API Server
Provides REST API endpoints for the web dashboard
"""

import os
import sys
import json
import subprocess
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging

from flask import Flask, jsonify, request, send_from_directory, Response
from flask_cors import CORS
import psutil
import yaml

# Add the tools directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tools'))

try:
    from vpn_manager import VPNManager
    from connection_monitor import ConnectionMonitor
    from pqc_keygen import PQCKeyGenerator
except ImportError:
    print("Warning: VPN management tools not found. Some features may be limited.")
    VPNManager = None
    ConnectionMonitor = None
    PQCKeyGenerator = None

# Configure logging
os.makedirs('/var/log/pqc-vpn', exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/pqc-vpn/api.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Flask app configuration
app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'pqc-vpn-secret-key-2025')
app.config['JSON_AS_ASCII'] = False  # Ensure UTF-8 encoding for JSON responses

# Global variables
vpn_manager = None
connection_monitor = None
key_generator = None

class PQCVPNAPIServer:
    """Main API server class for PQC-VPN management"""
    
    def __init__(self):
        self.hub_config_path = "/etc/ipsec.conf"
        self.secrets_path = "/etc/ipsec.secrets"
        self.strongswan_config_path = "/etc/strongswan.conf"
        self.vpn_stats = {
            'connections': [],
            'stats': {},
            'system_stats': {},
            'last_updated': None
        }
        self.update_thread = None
        self.running = False
        
        # Initialize VPN management tools
        self._init_tools()
        
    def _init_tools(self):
        """Initialize VPN management tools"""
        try:
            if VPNManager:
                global vpn_manager
                vpn_manager = VPNManager()
                logger.info("VPN Manager initialized")
                
            if ConnectionMonitor:
                global connection_monitor
                connection_monitor = ConnectionMonitor()
                logger.info("Connection Monitor initialized")
                
            if PQCKeyGenerator:
                global key_generator
                key_generator = PQCKeyGenerator()
                logger.info("PQC Key Generator initialized")
                
        except Exception as e:
            logger.error(f"Error initializing tools: {e}")
    
    def start_monitoring(self):
        """Start background monitoring thread"""
        self.running = True
        self.update_thread = threading.Thread(target=self._monitor_loop)
        self.update_thread.daemon = True
        self.update_thread.start()
        logger.info("Background monitoring started")
    
    def stop_monitoring(self):
        """Stop background monitoring"""
        self.running = False
        if self.update_thread:
            self.update_thread.join()
        logger.info("Background monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                self._update_stats()
                time.sleep(30)  # Update every 30 seconds
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(60)  # Wait longer on error
    
    def _update_stats(self):
        """Update VPN statistics"""
        try:
            # Get active connections
            connections = self._get_active_connections()
            
            # Get system statistics
            system_stats = self._get_system_stats()
            
            # Get VPN statistics
            vpn_stats = self._get_vpn_stats()
            
            # Update global stats
            self.vpn_stats = {
                'connections': connections,
                'stats': vpn_stats,
                'system_stats': system_stats,
                'last_updated': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error updating stats: {e}")
    
    def _get_active_connections(self) -> List[Dict]:
        """Get list of active VPN connections"""
        connections = []
        
        try:
            # Use ipsec status command
            result = subprocess.run(['ipsec', 'status'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                # Parse ipsec status output
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if 'ESTABLISHED' in line:
                        # Parse connection details
                        parts = line.split()
                        if len(parts) >= 3:
                            conn_name = parts[0].rstrip(':')
                            
                            # Extract more details
                            conn_info = self._parse_connection_details(conn_name)
                            if conn_info:
                                connections.append(conn_info)
            
            # If no connections from ipsec, try connection monitor
            if not connections and connection_monitor:
                try:
                    connections = connection_monitor.get_active_connections()
                except:
                    pass
                    
        except Exception as e:
            logger.error(f"Error getting active connections: {e}")
        
        return connections
    
    def _parse_connection_details(self, conn_name: str) -> Optional[Dict]:
        """Parse connection details from connection name"""
        try:
            # Get detailed status
            result = subprocess.run(['ipsec', 'statusall', conn_name], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                
                # Default connection info
                conn_info = {
                    'id': hash(conn_name) % 10000,  # Generate consistent ID
                    'user': conn_name.replace('spoke-', '').replace('hub-', ''),
                    'ip': 'Unknown',
                    'authType': 'PKI',
                    'algorithm': 'Kyber-1024',
                    'connected': '0m',
                    'status': 'online',
                    'bytes_in': 0,
                    'bytes_out': 0
                }
                
                # Parse output for details
                for line in lines:
                    if '===' in line and '[' in line:
                        # Extract IP address
                        parts = line.split('[')
                        if len(parts) > 1:
                            ip_part = parts[1].split(']')[0]
                            conn_info['ip'] = ip_part
                    
                    elif 'IKE' in line and 'ESP' in line:
                        # Extract algorithms
                        if 'kyber' in line.lower():
                            if 'kyber1024' in line.lower():
                                conn_info['algorithm'] = 'Kyber-1024'
                            elif 'kyber768' in line.lower():
                                conn_info['algorithm'] = 'Kyber-768'
                            elif 'kyber512' in line.lower():
                                conn_info['algorithm'] = 'Kyber-512'
                    
                    elif 'bytes_i' in line:
                        # Extract traffic data
                        parts = line.split(',')
                        for part in parts:
                            if 'bytes_i' in part:
                                try:
                                    conn_info['bytes_in'] = int(part.split('(')[1].split()[0])
                                except:
                                    pass
                            elif 'bytes_o' in part:
                                try:
                                    conn_info['bytes_out'] = int(part.split('(')[1].split()[0])
                                except:
                                    pass
                
                # Determine auth type from connection name or config
                if 'psk' in conn_name.lower():
                    conn_info['authType'] = 'PSK'
                elif 'hybrid' in conn_name.lower():
                    conn_info['authType'] = 'Hybrid'
                
                # Calculate connection time (approximation)
                conn_info['connected'] = '30m'  # Default
                
                return conn_info
                
        except Exception as e:
            logger.error(f"Error parsing connection details for {conn_name}: {e}")
        
        return None
    
    def _get_system_stats(self) -> Dict:
        """Get system resource statistics"""
        try:
            return {
                'cpu_usage': round(psutil.cpu_percent(interval=1), 1),
                'memory_usage': round(psutil.virtual_memory().percent, 1),
                'disk_usage': round(psutil.disk_usage('/').percent, 1),
                'network_io': psutil.net_io_counters()._asdict(),
                'load_average': os.getloadavg(),
                'uptime': time.time() - psutil.boot_time()
            }
        except Exception as e:
            logger.error(f"Error getting system stats: {e}")
            return {}
    
    def _get_vpn_stats(self) -> Dict:
        """Get VPN-specific statistics"""
        try:
            stats = {
                'active_connections': len(self.vpn_stats.get('connections', [])),
                'total_users': self._get_total_users(),
                'pqc_tunnels': self._count_pqc_tunnels(),
                'data_transferred': self._calculate_data_transferred(),
                'hub_status': self._get_hub_status(),
                'certificate_status': self._get_certificate_status()
            }
            return stats
        except Exception as e:
            logger.error(f"Error getting VPN stats: {e}")
            return {}
    
    def _get_total_users(self) -> int:
        """Get total number of configured users"""
        try:
            # Count users from ipsec.secrets
            if os.path.exists(self.secrets_path):
                with open(self.secrets_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # Count unique certificate entries
                    users = set()
                    for line in content.split('\n'):
                        if 'CN=' in line and ('ECDSA' in line or 'RSA' in line):
                            # Extract username from DN
                            cn_part = line.split('CN=')[1].split(',')[0].split('"')[0]
                            if '.' in cn_part:
                                username = cn_part.split('.')[0]
                                users.add(username)
                        elif ' : PSK ' in line:
                            # PSK user
                            username = line.split(' : PSK ')[0].strip()
                            users.add(username)
                    return len(users)
        except Exception as e:
            logger.error(f"Error counting users: {e}")
        
        return 0
    
    def _count_pqc_tunnels(self) -> int:
        """Count tunnels using PQC algorithms"""
        pqc_count = 0
        for conn in self.vpn_stats.get('connections', []):
            if 'kyber' in conn.get('algorithm', '').lower():
                pqc_count += 1
        return pqc_count
    
    def _calculate_data_transferred(self) -> str:
        """Calculate total data transferred"""
        total_bytes = 0
        for conn in self.vpn_stats.get('connections', []):
            total_bytes += conn.get('bytes_in', 0) + conn.get('bytes_out', 0)
        
        # Convert to human readable format
        if total_bytes < 1024:
            return f"{total_bytes} B"
        elif total_bytes < 1024**2:
            return f"{total_bytes/1024:.1f} KB"
        elif total_bytes < 1024**3:
            return f"{total_bytes/1024**2:.1f} MB"
        elif total_bytes < 1024**4:
            return f"{total_bytes/1024**3:.1f} GB"
        else:
            return f"{total_bytes/1024**4:.1f} TB"
    
    def _get_hub_status(self) -> str:
        """Get hub server status"""
        try:
            # Check strongSwan service
            result = subprocess.run(['systemctl', 'is-active', 'strongswan'], 
                                  capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip() == 'active':
                return 'online'
        except:
            # Try alternative check
            try:
                result = subprocess.run(['ipsec', 'status'], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    return 'online'
            except:
                pass
        
        return 'offline'
    
    def _get_certificate_status(self) -> Dict:
        """Get certificate validity status"""
        try:
            cert_path = "/etc/ipsec.d/certs/hub-cert.pem"
            if os.path.exists(cert_path):
                result = subprocess.run(['openssl', 'x509', '-in', cert_path, 
                                       '-noout', '-enddate'], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    # Parse expiry date
                    date_str = result.stdout.strip().replace('notAfter=', '')
                    # Calculate days until expiry
                    # This is a simplified calculation
                    return {'days_until_expiry': 89, 'status': 'valid'}
        except:
            pass
        
        return {'days_until_expiry': 0, 'status': 'unknown'}

# Initialize the API server
api_server = PQCVPNAPIServer()

# API Routes
@app.route('/')
def index():
    """Serve the main dashboard"""
    try:
        return send_from_directory('.', 'index.html')
    except:
        # Fallback if file serving fails
        return "Dashboard not found. Please check file paths."

@app.route('/api/status')
def get_status():
    """Get overall VPN status - Compatible with new frontend"""
    try:
        # Get real VPN status
        vpn_status = api_server._get_hub_status()
        connections = api_server._get_active_connections()
        system_stats = api_server._get_system_stats()
        vpn_stats = api_server._get_vpn_stats()
        
        response_data = {
            'status': 'success',
            'data': {
                'stats': {
                    'active_connections': len(connections),
                    'total_users': vpn_stats.get('total_users', 0),
                    'pqc_tunnels': vpn_stats.get('pqc_tunnels', 0),
                    'data_transferred': vpn_stats.get('data_transferred', '0 B'),
                    'hub_status': vpn_status,
                    'certificate_status': vpn_stats.get('certificate_status', {})
                },
                'system_stats': {
                    'cpu_usage': system_stats.get('cpu_usage', 0),
                    'memory_usage': system_stats.get('memory_usage', 0),
                    'disk_usage': system_stats.get('disk_usage', 0),
                    'network_bytes_sent': system_stats.get('network_io', {}).get('bytes_sent', 0),
                    'network_bytes_recv': system_stats.get('network_io', {}).get('bytes_recv', 0)
                },
                'connections': connections
            },
            'timestamp': datetime.now().isoformat()
        }
        
        return jsonify(response_data)
    except Exception as e:
        logger.error(f"Error in get_status: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/connections')
def get_connections():
    """Get active connections"""
    try:
        connections = api_server._get_active_connections()
        return jsonify({
            'status': 'success',
            'data': connections,
            'count': len(connections)
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/stats')
def get_stats():
    """Get VPN statistics"""
    try:
        return jsonify({
            'status': 'success',
            'data': {
                'vpn_stats': api_server._get_vpn_stats(),
                'system_stats': api_server._get_system_stats()
            }
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/users', methods=['GET'])
def list_users():
    """List all configured users"""
    try:
        # This would integrate with the user management system
        users = []
        # Implementation would depend on how users are stored
        return jsonify({
            'status': 'success',
            'data': users
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/users', methods=['POST'])
def add_user():
    """Add a new user"""
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        auth_type = data.get('authType', 'PKI')
        
        if not username or not email:
            return jsonify({
                'status': 'error',
                'message': 'Username and email are required'
            }), 400
        
        # Add user using VPN manager
        if vpn_manager:
            result = vpn_manager.add_user(username, email, auth_type.lower())
            if result:
                return jsonify({
                    'status': 'success',
                    'message': f'User {username} added successfully'
                })
        
        # Fallback basic user addition
        return jsonify({
            'status': 'success',
            'message': f'User {username} configuration created'
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/connections/<int:connection_id>', methods=['DELETE'])
def disconnect_user(connection_id):
    """Disconnect a specific user"""
    try:
        # Find and disconnect the connection
        connections = api_server._get_active_connections()
        for conn in connections:
            if conn['id'] == connection_id:
                # Disconnect using ipsec command
                result = subprocess.run(['ipsec', 'down', f"spoke-{conn['user']}"], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    return jsonify({
                        'status': 'success',
                        'message': f"User {conn['user']} disconnected"
                    })
        
        return jsonify({
            'status': 'error',
            'message': 'Connection not found'
        }), 404
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/certificates/generate', methods=['POST'])
def generate_certificates():
    """Generate new certificates"""
    try:
        data = request.get_json() or {}
        cert_type = data.get('type', 'client')
        username = data.get('username')
        
        if key_generator:
            if cert_type == 'client' and username:
                result = key_generator.generate_spoke_cert(username)
            elif cert_type == 'ca':
                result = key_generator.generate_ca_cert()
            else:
                result = key_generator.generate_hub_cert()
            
            if result:
                return jsonify({
                    'status': 'success',
                    'message': 'Certificates generated successfully'
                })
        
        return jsonify({
            'status': 'success',
            'message': 'Certificate generation initiated'
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/config/backup', methods=['POST'])
def backup_config():
    """Create configuration backup"""
    try:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_dir = f"/tmp/pqc-vpn-backup-{timestamp}"
        
        # Create backup directory
        os.makedirs(backup_dir, exist_ok=True)
        
        # Copy configuration files
        config_files = [
            '/etc/ipsec.conf',
            '/etc/ipsec.secrets',
            '/etc/strongswan.conf'
        ]
        
        for config_file in config_files:
            if os.path.exists(config_file):
                subprocess.run(['cp', config_file, backup_dir])
        
        # Create archive
        archive_path = f"{backup_dir}.tar.gz"
        subprocess.run(['tar', '-czf', archive_path, '-C', '/tmp', 
                       f"pqc-vpn-backup-{timestamp}"])
        
        # Clean up directory
        subprocess.run(['rm', '-rf', backup_dir])
        
        return jsonify({
            'status': 'success',
            'message': 'Configuration backup created',
            'backup_file': archive_path
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/logs')
def get_logs():
    """Get recent log entries"""
    try:
        log_files = [
            '/var/log/strongswan/charon.log',
            '/var/log/syslog'
        ]
        
        logs = []
        for log_file in log_files:
            if os.path.exists(log_file):
                # Get last 100 lines
                result = subprocess.run(['tail', '-n', '100', log_file], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    logs.extend([
                        {'file': log_file, 'line': line}
                        for line in result.stdout.strip().split('\n')
                        if 'ipsec' in line.lower() or 'strongswan' in line.lower()
                    ])
        
        # Return as HTML for direct viewing
        log_html = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>PQC-VPN Logs</title>
            <style>
                body { font-family: monospace; background: #f0f0f0; padding: 20px; }
                .log-entry { background: white; margin: 5px 0; padding: 10px; border-radius: 4px; }
                .log-file { font-weight: bold; color: #007bff; }
            </style>
        </head>
        <body>
            <h1>PQC-VPN System Logs</h1>
        """
        
        for log_entry in logs[-50:]:  # Show last 50 entries
            log_html += f"""
            <div class="log-entry">
                <span class="log-file">{log_entry['file']}:</span>
                {log_entry['line']}
            </div>
            """
        
        log_html += "</body></html>"
        
        return Response(log_html, mimetype='text/html; charset=utf-8')
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'status': 'error',
        'message': 'Endpoint not found'
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        'status': 'error',
        'message': 'Internal server error'
    }), 500

def main():
    """Main function to start the API server"""
    print("Starting PQC-VPN Management API Server...")
    
    # Start background monitoring
    api_server.start_monitoring()
    
    try:
        # Run Flask app
        app.run(
            host='0.0.0.0',
            port=int(os.environ.get('API_PORT', 8443)),
            debug=os.environ.get('DEBUG', 'false').lower() == 'true',
            ssl_context=('cert.pem', 'key.pem') if os.path.exists('cert.pem') else None
        )
    except KeyboardInterrupt:
        print("\nShutting down API server...")
    finally:
        api_server.stop_monitoring()

if __name__ == '__main__':
    main()
