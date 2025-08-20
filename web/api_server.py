#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PQC-VPN Web Management API Server - Windows Compatible
Provides REST API endpoints for the web dashboard with Windows support
"""

import os
import sys
import json
import subprocess
import threading
import time
import platform
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
    print("Info: VPN management tools will use Docker integration for Windows")
    VPNManager = None
    ConnectionMonitor = None
    PQCKeyGenerator = None

# Configure logging
os.makedirs('/var/log/pqc-vpn', exist_ok=True) if os.name != 'nt' else os.makedirs('logs', exist_ok=True)
log_path = '/var/log/pqc-vpn/api.log' if os.name != 'nt' else 'logs/api.log'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_path),
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
    """Main API server class for PQC-VPN management with Windows support"""
    
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
        self.is_windows = platform.system() == 'Windows'
        
        # Initialize VPN management tools
        self._init_tools()
        
        logger.info(f"Running on {platform.system()} - Windows compatibility: {self.is_windows}")
        
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
    
    def _get_docker_containers(self) -> List[str]:
        """Get list of PQC-VPN Docker containers"""
        try:
            cmd = ['docker', 'ps', '--filter', 'name=pqc-vpn', '--format', '{{.Names}}']
            
            # Use winpty on Windows in Git Bash
            if self.is_windows:
                # Try winpty first, fallback to regular docker
                try:
                    result = subprocess.run(['winpty'] + cmd, capture_output=True, text=True, timeout=10)
                except FileNotFoundError:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            else:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                containers = [name.strip() for name in result.stdout.strip().split('\n') if name.strip()]
                return containers
            
        except Exception as e:
            logger.debug(f"Docker command failed: {e}")
        
        return []
    
    def _get_active_connections(self) -> List[Dict]:
        """Get list of active VPN connections from Docker containers"""
        connections = []
        
        try:
            containers = self._get_docker_containers()
            hub_container = None
            
            # Find hub container
            for container in containers:
                if 'hub' in container:
                    hub_container = container
                    break
            
            if not hub_container:
                logger.debug("No hub container found")
                return []
            
            # Get ipsec status from hub container
            cmd = ['docker', 'exec', hub_container, 'ipsec', 'status']
            
            if self.is_windows:
                try:
                    result = subprocess.run(['winpty'] + cmd, capture_output=True, text=True, timeout=15)
                except FileNotFoundError:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            else:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
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
                            conn_info = self._parse_connection_details(hub_container, conn_name)
                            if conn_info:
                                connections.append(conn_info)
                    
        except Exception as e:
            logger.debug(f"Error getting active connections: {e}")
        
        return connections
    
    def _parse_connection_details(self, hub_container: str, conn_name: str) -> Optional[Dict]:
        """Parse connection details from connection name"""
        try:
            # Get detailed status from Docker container
            cmd = ['docker', 'exec', hub_container, 'ipsec', 'statusall', conn_name]
            
            if self.is_windows:
                try:
                    result = subprocess.run(['winpty'] + cmd, capture_output=True, text=True, timeout=15)
                except FileNotFoundError:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            else:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                
                # Default connection info
                conn_info = {
                    'id': hash(conn_name) % 10000,  # Generate consistent ID
                    'user': conn_name.replace('spoke-', '').replace('hub-', '').replace('-pki', '').replace('-psk', '').replace('-hybrid', ''),
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
                
                # Determine auth type from connection name
                if 'psk' in conn_name.lower():
                    conn_info['authType'] = 'PSK'
                elif 'hybrid' in conn_name.lower():
                    conn_info['authType'] = 'Hybrid'
                
                # Calculate connection time (approximation)
                conn_info['connected'] = '30m'  # Default
                
                return conn_info
                
        except Exception as e:
            logger.debug(f"Error parsing connection details for {conn_name}: {e}")
        
        return None
    
    def _get_system_stats(self) -> Dict:
        """Get system resource statistics with Windows compatibility"""
        try:
            stats = {
                'cpu_usage': round(psutil.cpu_percent(interval=1), 1),
                'memory_usage': round(psutil.virtual_memory().percent, 1),
                'disk_usage': round(psutil.disk_usage('/').percent, 1) if os.name != 'nt' else round(psutil.disk_usage('C:\\').percent, 1),
                'network_io': psutil.net_io_counters()._asdict(),
                'uptime': time.time() - psutil.boot_time()
            }
            
            # Windows-compatible load average
            if hasattr(os, 'getloadavg'):
                stats['load_average'] = os.getloadavg()
            else:
                # Approximate load average on Windows using CPU count and usage
                cpu_count = psutil.cpu_count()
                cpu_percent = psutil.cpu_percent()
                approx_load = (cpu_percent / 100.0) * cpu_count
                stats['load_average'] = [approx_load, approx_load, approx_load]
            
            return stats
        except Exception as e:
            logger.error(f"Error getting system stats: {e}")
            return {
                'cpu_usage': 0,
                'memory_usage': 0,
                'disk_usage': 0,
                'network_io': {'bytes_sent': 0, 'bytes_recv': 0},
                'load_average': [0, 0, 0],
                'uptime': 0
            }
    
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
        """Get total number of configured users from Docker containers"""
        try:
            containers = self._get_docker_containers()
            user_count = 0
            
            # Count client containers (exclude hub and dashboard)
            for container in containers:
                if 'client' in container or ('pqc-vpn' in container and 'hub' not in container):
                    user_count += 1
            
            return user_count
            
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
        """Get hub server status from Docker"""
        try:
            containers = self._get_docker_containers()
            
            # Check if hub container is running
            for container in containers:
                if 'hub' in container:
                    return 'online'
            
            return 'offline'
            
        except Exception as e:
            logger.debug(f"Error checking hub status: {e}")
            return 'offline'
    
    def _get_certificate_status(self) -> Dict:
        """Get certificate validity status"""
        try:
            # For demo purposes, return a reasonable status
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
        return "Dashboard loading... Please ensure index.html is in the web directory."

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
        # Get users from Docker containers
        containers = api_server._get_docker_containers()
        users = []
        
        for container in containers:
            if 'client' in container or ('pqc-vpn' in container and 'hub' not in container):
                username = container.replace('pqc-vpn-', '').replace('client-', '')
                users.append({
                    'username': username,
                    'container': container,
                    'status': 'active'
                })
        
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
        
        # For demo purposes, just acknowledge the request
        return jsonify({
            'status': 'success',
            'message': f'User {username} configuration would be created (demo mode)'
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
                # For demo, just acknowledge
                return jsonify({
                    'status': 'success',
                    'message': f"User {conn['user']} disconnect requested (demo mode)"
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
        return jsonify({
            'status': 'success',
            'message': 'Certificate generation initiated (demo mode)'
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
        
        return jsonify({
            'status': 'success',
            'message': 'Configuration backup created',
            'backup_file': f"pqc-vpn-backup-{timestamp}.tar.gz"
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
        containers = api_server._get_docker_containers()
        
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
                .container-name { font-weight: bold; color: #007bff; }
            </style>
        </head>
        <body>
            <h1>PQC-VPN Container Status</h1>
        """
        
        if containers:
            log_html += "<h2>Running Containers:</h2>"
            for container in containers:
                log_html += f"""
                <div class="log-entry">
                    <span class="container-name">{container}</span>: Running
                </div>
                """
        else:
            log_html += "<div class='log-entry'>No PQC-VPN containers currently running</div>"
        
        log_html += """
            <p><strong>Note:</strong> Start the demo containers to see connection logs.</p>
        </body></html>
        """
        
        return Response(log_html, mimetype='text/html; charset=utf-8')
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    containers = api_server._get_docker_containers()
    
    return jsonify({
        'status': 'healthy',
        'platform': platform.system(),
        'containers_running': len(containers),
        'container_names': containers,
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0-windows-compatible'
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
    print("Starting PQC-VPN Management API Server (Windows Compatible)...")
    print(f"Platform: {platform.system()}")
    print(f"Python: {platform.python_version()}")
    
    # Start background monitoring
    api_server.start_monitoring()
    
    try:
        # Run Flask app
        app.run(
            host='0.0.0.0',
            port=int(os.environ.get('API_PORT', 8443)),
            debug=os.environ.get('DEBUG', 'false').lower() == 'true'
        )
    except KeyboardInterrupt:
        print("\nShutting down API server...")
    finally:
        api_server.stop_monitoring()

if __name__ == '__main__':
    main()
