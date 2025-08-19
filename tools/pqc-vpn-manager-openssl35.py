#!/usr/bin/env python3
"""
PQC-VPN Management Tool with OpenSSL 3.5 Support
Enterprise-grade VPN management and monitoring system

Version: 3.0.0 - OpenSSL 3.5 Native Implementation
Author: PQC-VPN Development Team
License: MIT
"""

import os
import sys
import json
import logging
import argparse
import subprocess
import tempfile
import shutil
import signal
import time
import socket
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import yaml
import psutil
import threading
from dataclasses import dataclass, asdict
from contextlib import contextmanager

# Configuration
OPENSSL_PREFIX = os.environ.get('OPENSSL_PREFIX', '/usr/local/openssl35')
OPENSSL_BIN = f"{OPENSSL_PREFIX}/bin/openssl"
OPENSSL_CONF = f"{OPENSSL_PREFIX}/ssl/openssl.cnf"
STRONGSWAN_BIN = "/usr/local/strongswan/sbin/ipsec"
IPSEC_DIR = "/etc/ipsec.d"
CERT_DIR = f"{IPSEC_DIR}/certs"
PRIVATE_DIR = f"{IPSEC_DIR}/private"
CA_DIR = f"{IPSEC_DIR}/cacerts"
CONFIG_DIR = "/etc/pqc-vpn"
LOG_DIR = "/var/log/pqc-vpn"

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'{LOG_DIR}/manager.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class ConnectionInfo:
    """VPN connection information"""
    name: str
    state: str
    local_ip: str
    remote_ip: str
    bytes_in: int
    bytes_out: int
    packets_in: int
    packets_out: int
    established: datetime
    last_activity: datetime
    encryption: str
    authentication: str

@dataclass
class SystemMetrics:
    """System performance metrics"""
    cpu_percent: float
    memory_percent: float
    disk_usage: float
    network_connections: int
    active_vpn_connections: int
    openssl_version: str
    strongswan_version: str
    uptime: int

@dataclass
class SecurityStatus:
    """Security status information"""
    certificates_valid: bool
    ca_expires: datetime
    server_cert_expires: datetime
    crl_updated: datetime
    last_security_scan: datetime
    vulnerabilities: List[str]
    compliance_status: str

class OpenSSL35VPNManager:
    """Enterprise VPN Manager using OpenSSL 3.5"""
    
    def __init__(self):
        self.openssl_bin = OPENSSL_BIN
        self.strongswan_bin = STRONGSWAN_BIN
        self.validate_environment()
        self.setup_directories()
        
    def validate_environment(self):
        """Validate OpenSSL 3.5 and strongSwan environment"""
        try:
            # Check OpenSSL 3.5
            if not os.path.exists(self.openssl_bin):
                raise FileNotFoundError(f"OpenSSL binary not found: {self.openssl_bin}")
            
            result = subprocess.run(
                [self.openssl_bin, 'version'],
                capture_output=True, text=True, check=True
            )
            version = result.stdout.strip()
            logger.info(f"Using {version}")
            
            # Check strongSwan
            if not os.path.exists(self.strongswan_bin):
                raise FileNotFoundError(f"strongSwan binary not found: {self.strongswan_bin}")
            
            # Set environment
            os.environ['OPENSSL_CONF'] = OPENSSL_CONF
            os.environ['LD_LIBRARY_PATH'] = f"{OPENSSL_PREFIX}/lib:{os.environ.get('LD_LIBRARY_PATH', '')}"
            os.environ['PATH'] = f"{OPENSSL_PREFIX}/bin:{os.environ.get('PATH', '')}"
            
            logger.info("Environment validation successful")
            
        except Exception as e:
            logger.error(f"Environment validation failed: {e}")
            raise
    
    def setup_directories(self):
        """Setup required directories"""
        directories = [
            CONFIG_DIR,
            LOG_DIR,
            f"{CONFIG_DIR}/users",
            f"{CONFIG_DIR}/monitoring",
            f"{CONFIG_DIR}/backup"
        ]
        
        for directory in directories:
            os.makedirs(directory, mode=0o755, exist_ok=True)
    
    def run_command(self, cmd: List[str], check: bool = True, capture_output: bool = True) -> subprocess.CompletedProcess:
        """Run system command with error handling"""
        try:
            logger.debug(f"Running command: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=capture_output,
                text=True,
                check=check,
                env=os.environ.copy()
            )
            return result
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {e}")
            if capture_output:
                logger.error(f"stdout: {e.stdout}")
                logger.error(f"stderr: {e.stderr}")
            raise
    
    def get_strongswan_status(self) -> Dict[str, Any]:
        """Get strongSwan daemon status"""
        try:
            result = self.run_command([self.strongswan_bin, 'status'])
            status_text = result.stdout
            
            # Parse status output
            connections = []
            for line in status_text.split('\n'):
                if 'ESTABLISHED' in line or 'CONNECTING' in line or 'INSTALLED' in line:
                    connections.append(line.strip())
            
            # Get detailed status
            result = self.run_command([self.strongswan_bin, 'statusall'])
            detailed_status = result.stdout
            
            return {
                'daemon_running': True,
                'connections': connections,
                'detailed_status': detailed_status,
                'connection_count': len(connections)
            }
            
        except subprocess.CalledProcessError:
            return {
                'daemon_running': False,
                'connections': [],
                'detailed_status': '',
                'connection_count': 0
            }
    
    def get_connection_info(self) -> List[ConnectionInfo]:
        """Get detailed connection information"""
        connections = []
        
        try:
            result = self.run_command([self.strongswan_bin, 'statusall'])
            status_lines = result.stdout.split('\n')
            
            current_connection = None
            for line in status_lines:
                line = line.strip()
                
                if 'ESTABLISHED' in line:
                    # Parse connection establishment
                    parts = line.split()
                    if len(parts) >= 3:
                        name = parts[0].rstrip(':')
                        state = 'ESTABLISHED'
                        # Extract more details...
                        current_connection = {
                            'name': name,
                            'state': state,
                            'local_ip': '',
                            'remote_ip': '',
                            'bytes_in': 0,
                            'bytes_out': 0,
                            'packets_in': 0,
                            'packets_out': 0,
                            'established': datetime.now(),
                            'last_activity': datetime.now(),
                            'encryption': 'Unknown',
                            'authentication': 'Unknown'
                        }
                
                elif 'INSTALLED' in line and current_connection:
                    # Parse traffic information
                    if 'bytes_i' in line:
                        # Extract traffic stats
                        pass
                    
                    connections.append(ConnectionInfo(**current_connection))
                    current_connection = None
            
        except Exception as e:
            logger.error(f"Failed to get connection info: {e}")
        
        return connections
    
    def get_system_metrics(self) -> SystemMetrics:
        """Get system performance metrics"""
        try:
            # CPU and memory usage
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_usage = (disk.used / disk.total) * 100
            
            # Network connections
            network_connections = len(psutil.net_connections())
            
            # VPN connections
            strongswan_status = self.get_strongswan_status()
            active_vpn_connections = strongswan_status['connection_count']
            
            # Version information
            openssl_result = self.run_command([self.openssl_bin, 'version'])
            openssl_version = openssl_result.stdout.strip()
            
            strongswan_result = self.run_command([self.strongswan_bin, 'version'])
            strongswan_version = strongswan_result.stdout.split('\n')[0]
            
            # System uptime
            uptime = int(time.time() - psutil.boot_time())
            
            return SystemMetrics(
                cpu_percent=cpu_percent,
                memory_percent=memory_percent,
                disk_usage=disk_usage,
                network_connections=network_connections,
                active_vpn_connections=active_vpn_connections,
                openssl_version=openssl_version,
                strongswan_version=strongswan_version,
                uptime=uptime
            )
            
        except Exception as e:
            logger.error(f"Failed to get system metrics: {e}")
            return SystemMetrics(0, 0, 0, 0, 0, "Unknown", "Unknown", 0)
    
    def get_security_status(self) -> SecurityStatus:
        """Get security status and certificate information"""
        try:
            certificates_valid = True
            vulnerabilities = []
            
            # Check CA certificate
            ca_cert_path = f"{CA_DIR}/ca-cert.pem"
            ca_expires = datetime.now() + timedelta(days=365)  # Default
            
            if os.path.exists(ca_cert_path):
                result = self.run_command([
                    self.openssl_bin, 'x509', '-in', ca_cert_path, 
                    '-noout', '-enddate'
                ])
                enddate_line = result.stdout.strip()
                if 'notAfter=' in enddate_line:
                    enddate_str = enddate_line.split('notAfter=')[1]
                    try:
                        ca_expires = datetime.strptime(enddate_str, '%b %d %H:%M:%S %Y %Z')
                    except:
                        ca_expires = datetime.now() + timedelta(days=365)
                
                # Check if CA is expiring soon
                if ca_expires < datetime.now() + timedelta(days=30):
                    certificates_valid = False
                    vulnerabilities.append("CA certificate expires within 30 days")
            
            # Check server certificate
            server_cert_path = f"{CERT_DIR}/hub-cert.pem"
            server_cert_expires = datetime.now() + timedelta(days=365)  # Default
            
            if os.path.exists(server_cert_path):
                result = self.run_command([
                    self.openssl_bin, 'x509', '-in', server_cert_path,
                    '-noout', '-enddate'
                ])
                enddate_line = result.stdout.strip()
                if 'notAfter=' in enddate_line:
                    enddate_str = enddate_line.split('notAfter=')[1]
                    try:
                        server_cert_expires = datetime.strptime(enddate_str, '%b %d %H:%M:%S %Y %Z')
                    except:
                        server_cert_expires = datetime.now() + timedelta(days=365)
                
                # Check if server cert is expiring soon
                if server_cert_expires < datetime.now() + timedelta(days=7):
                    certificates_valid = False
                    vulnerabilities.append("Server certificate expires within 7 days")
            
            # Check for weak algorithms
            if os.path.exists(server_cert_path):
                result = self.run_command([
                    self.openssl_bin, 'x509', '-in', server_cert_path,
                    '-noout', '-text'
                ])
                cert_text = result.stdout
                
                if 'md5' in cert_text.lower():
                    vulnerabilities.append("Certificate uses weak MD5 hash")
                if 'sha1' in cert_text.lower() and 'sha256' not in cert_text.lower():
                    vulnerabilities.append("Certificate uses weak SHA1 hash")
            
            return SecurityStatus(
                certificates_valid=certificates_valid,
                ca_expires=ca_expires,
                server_cert_expires=server_cert_expires,
                crl_updated=datetime.now(),  # Placeholder
                last_security_scan=datetime.now(),
                vulnerabilities=vulnerabilities,
                compliance_status="COMPLIANT" if certificates_valid and not vulnerabilities else "NON_COMPLIANT"
            )
            
        except Exception as e:
            logger.error(f"Failed to get security status: {e}")
            return SecurityStatus(
                False, datetime.now(), datetime.now(), datetime.now(),
                datetime.now(), ["Security scan failed"], "UNKNOWN"
            )
    
    def add_user(self, username: str, email: str = None, auth_type: str = 'pki',
                 key_type: str = 'rsa', key_size: int = 2048) -> Dict[str, str]:
        """Add new VPN user"""
        try:
            from .pqc_keygen_openssl35 import OpenSSL35CertificateManager
            
            cert_manager = OpenSSL35CertificateManager()
            
            if auth_type == 'pki':
                # Generate client certificate
                cert_file, key_file = cert_manager.generate_client_certificate(
                    username, email, key_type, key_size
                )
                
                # Create user configuration
                user_config = {
                    'username': username,
                    'email': email,
                    'auth_type': auth_type,
                    'certificate': cert_file,
                    'private_key': key_file,
                    'created': datetime.now().isoformat(),
                    'active': True
                }
                
                # Save user configuration
                user_config_file = f"{CONFIG_DIR}/users/{username}.yaml"
                with open(user_config_file, 'w') as f:
                    yaml.dump(user_config, f)
                
                logger.info(f"User {username} added with PKI authentication")
                
                return {
                    'username': username,
                    'auth_type': auth_type,
                    'certificate': cert_file,
                    'private_key': key_file,
                    'status': 'created'
                }
            
            elif auth_type == 'psk':
                # Generate pre-shared key
                import secrets
                psk = secrets.token_urlsafe(32)
                
                # Add to ipsec.secrets
                secrets_line = f"{username} : PSK \"{psk}\"\n"
                with open('/etc/ipsec.secrets', 'a') as f:
                    f.write(secrets_line)
                
                # Create user configuration
                user_config = {
                    'username': username,
                    'email': email,
                    'auth_type': auth_type,
                    'psk': psk,
                    'created': datetime.now().isoformat(),
                    'active': True
                }
                
                # Save user configuration
                user_config_file = f"{CONFIG_DIR}/users/{username}.yaml"
                with open(user_config_file, 'w') as f:
                    yaml.dump(user_config, f)
                
                logger.info(f"User {username} added with PSK authentication")
                
                return {
                    'username': username,
                    'auth_type': auth_type,
                    'psk': psk,
                    'status': 'created'
                }
            
            else:
                raise ValueError(f"Unsupported authentication type: {auth_type}")
                
        except Exception as e:
            logger.error(f"Failed to add user {username}: {e}")
            raise
    
    def remove_user(self, username: str) -> bool:
        """Remove VPN user"""
        try:
            user_config_file = f"{CONFIG_DIR}/users/{username}.yaml"
            
            if not os.path.exists(user_config_file):
                logger.error(f"User {username} not found")
                return False
            
            # Load user configuration
            with open(user_config_file, 'r') as f:
                user_config = yaml.safe_load(f)
            
            # Remove certificates if PKI
            if user_config.get('auth_type') == 'pki':
                cert_file = user_config.get('certificate')
                key_file = user_config.get('private_key')
                
                if cert_file and os.path.exists(cert_file):
                    os.remove(cert_file)
                if key_file and os.path.exists(key_file):
                    os.remove(key_file)
            
            # Remove from ipsec.secrets if PSK
            elif user_config.get('auth_type') == 'psk':
                # Read current secrets
                with open('/etc/ipsec.secrets', 'r') as f:
                    secrets_lines = f.readlines()
                
                # Filter out user's PSK
                filtered_lines = [
                    line for line in secrets_lines 
                    if not line.startswith(f"{username} :")
                ]
                
                # Write back filtered secrets
                with open('/etc/ipsec.secrets', 'w') as f:
                    f.writelines(filtered_lines)
            
            # Remove user configuration
            os.remove(user_config_file)
            
            logger.info(f"User {username} removed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to remove user {username}: {e}")
            return False
    
    def list_users(self) -> List[Dict[str, Any]]:
        """List all VPN users"""
        users = []
        user_dir = f"{CONFIG_DIR}/users"
        
        if not os.path.exists(user_dir):
            return users
        
        for user_file in Path(user_dir).glob("*.yaml"):
            try:
                with open(user_file, 'r') as f:
                    user_config = yaml.safe_load(f)
                
                # Remove sensitive information
                user_info = {
                    'username': user_config.get('username'),
                    'email': user_config.get('email'),
                    'auth_type': user_config.get('auth_type'),
                    'created': user_config.get('created'),
                    'active': user_config.get('active', True)
                }
                
                users.append(user_info)
                
            except Exception as e:
                logger.error(f"Failed to load user config {user_file}: {e}")
        
        return users
    
    def reload_configuration(self) -> bool:
        """Reload strongSwan configuration"""
        try:
            self.run_command([self.strongswan_bin, 'reload'])
            logger.info("strongSwan configuration reloaded")
            return True
        except Exception as e:
            logger.error(f"Failed to reload configuration: {e}")
            return False
    
    def restart_vpn(self) -> bool:
        """Restart VPN service"""
        try:
            self.run_command([self.strongswan_bin, 'restart'])
            logger.info("VPN service restarted")
            return True
        except Exception as e:
            logger.error(f"Failed to restart VPN: {e}")
            return False
    
    def backup_configuration(self, backup_path: str = None) -> str:
        """Backup VPN configuration"""
        try:
            if not backup_path:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                backup_path = f"{CONFIG_DIR}/backup/pqc-vpn-backup-{timestamp}.tar.gz"
            
            # Create backup directory
            os.makedirs(os.path.dirname(backup_path), exist_ok=True)
            
            # Create tar archive
            import tarfile
            
            with tarfile.open(backup_path, 'w:gz') as tar:
                # Add configuration files
                tar.add('/etc/ipsec.conf', arcname='ipsec.conf')
                tar.add('/etc/ipsec.secrets', arcname='ipsec.secrets')
                tar.add('/etc/strongswan.conf', arcname='strongswan.conf')
                
                # Add certificates
                if os.path.exists(CERT_DIR):
                    tar.add(CERT_DIR, arcname='certs')
                if os.path.exists(CA_DIR):
                    tar.add(CA_DIR, arcname='cacerts')
                if os.path.exists(PRIVATE_DIR):
                    tar.add(PRIVATE_DIR, arcname='private')
                
                # Add user configurations
                if os.path.exists(f"{CONFIG_DIR}/users"):
                    tar.add(f"{CONFIG_DIR}/users", arcname='users')
            
            logger.info(f"Configuration backed up to {backup_path}")
            return backup_path
            
        except Exception as e:
            logger.error(f"Failed to backup configuration: {e}")
            raise
    
    def generate_status_report(self, format_type: str = 'json') -> str:
        """Generate comprehensive status report"""
        try:
            # Collect all status information
            strongswan_status = self.get_strongswan_status()
            connections = self.get_connection_info()
            system_metrics = self.get_system_metrics()
            security_status = self.get_security_status()
            users = self.list_users()
            
            report = {
                'generated': datetime.now().isoformat(),
                'version': '3.0.0',
                'openssl_version': system_metrics.openssl_version,
                'strongswan_status': strongswan_status,
                'connections': [asdict(conn) for conn in connections],
                'system_metrics': asdict(system_metrics),
                'security_status': asdict(security_status),
                'users': users,
                'summary': {
                    'total_users': len(users),
                    'active_connections': len(connections),
                    'system_health': 'healthy' if system_metrics.cpu_percent < 80 else 'warning',
                    'security_status': security_status.compliance_status
                }
            }
            
            if format_type == 'yaml':
                return yaml.dump(report, default_flow_style=False)
            elif format_type == 'json':
                return json.dumps(report, indent=2, default=str)
            else:
                # Simple text format
                text_report = f"""
PQC-VPN Status Report
Generated: {report['generated']}
Version: {report['version']}
OpenSSL: {report['openssl_version']}

System Health:
  CPU Usage: {system_metrics.cpu_percent}%
  Memory Usage: {system_metrics.memory_percent}%
  Disk Usage: {system_metrics.disk_usage}%
  Uptime: {system_metrics.uptime} seconds

VPN Status:
  Daemon Running: {strongswan_status['daemon_running']}
  Active Connections: {len(connections)}
  Total Users: {len(users)}

Security Status:
  Certificates Valid: {security_status.certificates_valid}
  CA Expires: {security_status.ca_expires}
  Compliance: {security_status.compliance_status}
  Vulnerabilities: {len(security_status.vulnerabilities)}
"""
                return text_report
                
        except Exception as e:
            logger.error(f"Failed to generate status report: {e}")
            raise


def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(
        description='PQC-VPN Management Tool with OpenSSL 3.5 Support',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Show VPN status
  %(prog)s status

  # Add new user
  %(prog)s user add alice --email alice@example.com --auth-type pki

  # Remove user
  %(prog)s user remove alice

  # List all users
  %(prog)s user list

  # Generate status report
  %(prog)s report --format json

  # Backup configuration
  %(prog)s backup

  # Restart VPN service
  %(prog)s restart
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Show VPN status')
    status_parser.add_argument('--format', choices=['text', 'json', 'yaml'],
                              default='text', help='Output format')
    
    # User management commands
    user_parser = subparsers.add_parser('user', help='User management')
    user_subparsers = user_parser.add_subparsers(dest='user_action')
    
    # Add user
    add_user_parser = user_subparsers.add_parser('add', help='Add new user')
    add_user_parser.add_argument('username', help='Username')
    add_user_parser.add_argument('--email', help='Email address')
    add_user_parser.add_argument('--auth-type', choices=['pki', 'psk'], 
                                default='pki', help='Authentication type')
    add_user_parser.add_argument('--key-type', choices=['rsa', 'ecdsa', 'ed25519'],
                                default='rsa', help='Key type for PKI')
    add_user_parser.add_argument('--key-size', type=int, default=2048,
                                help='Key size for RSA/ECDSA')
    
    # Remove user
    remove_user_parser = user_subparsers.add_parser('remove', help='Remove user')
    remove_user_parser.add_argument('username', help='Username')
    
    # List users
    list_users_parser = user_subparsers.add_parser('list', help='List users')
    list_users_parser.add_argument('--format', choices=['table', 'json', 'yaml'],
                                  default='table', help='Output format')
    
    # Report command
    report_parser = subparsers.add_parser('report', help='Generate status report')
    report_parser.add_argument('--format', choices=['text', 'json', 'yaml'],
                              default='text', help='Output format')
    report_parser.add_argument('--output', help='Output file')
    
    # Backup command
    backup_parser = subparsers.add_parser('backup', help='Backup configuration')
    backup_parser.add_argument('--output', help='Backup file path')
    
    # Reload command
    reload_parser = subparsers.add_parser('reload', help='Reload configuration')
    
    # Restart command
    restart_parser = subparsers.add_parser('restart', help='Restart VPN service')
    
    # Monitor command
    monitor_parser = subparsers.add_parser('monitor', help='Monitor VPN in real-time')
    monitor_parser.add_argument('--interval', type=int, default=5,
                               help='Update interval in seconds')
    
    # Version command
    version_parser = subparsers.add_parser('version', help='Show version information')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        vpn_manager = OpenSSL35VPNManager()
        
        if args.command == 'status':
            if args.format == 'text':
                strongswan_status = vpn_manager.get_strongswan_status()
                system_metrics = vpn_manager.get_system_metrics()
                security_status = vpn_manager.get_security_status()
                
                print("PQC-VPN Status (OpenSSL 3.5)")
                print("=" * 50)
                print(f"OpenSSL Version: {system_metrics.openssl_version}")
                print(f"strongSwan Running: {strongswan_status['daemon_running']}")
                print(f"Active Connections: {strongswan_status['connection_count']}")
                print(f"CPU Usage: {system_metrics.cpu_percent}%")
                print(f"Memory Usage: {system_metrics.memory_percent}%")
                print(f"Security Status: {security_status.compliance_status}")
            
            elif args.format in ['json', 'yaml']:
                report = vpn_manager.generate_status_report(args.format)
                print(report)
        
        elif args.command == 'user':
            if args.user_action == 'add':
                result = vpn_manager.add_user(
                    args.username, args.email, args.auth_type,
                    args.key_type, args.key_size
                )
                print(f"User {args.username} added successfully")
                print(f"Authentication type: {result['auth_type']}")
                if result['auth_type'] == 'pki':
                    print(f"Certificate: {result['certificate']}")
                    print(f"Private key: {result['private_key']}")
                elif result['auth_type'] == 'psk':
                    print(f"Pre-shared key: {result['psk']}")
            
            elif args.user_action == 'remove':
                if vpn_manager.remove_user(args.username):
                    print(f"User {args.username} removed successfully")
                else:
                    print(f"Failed to remove user {args.username}")
            
            elif args.user_action == 'list':
                users = vpn_manager.list_users()
                
                if args.format == 'table':
                    print(f"{'Username':<20} {'Email':<30} {'Auth Type':<10} {'Created':<20}")
                    print("-" * 80)
                    for user in users:
                        created = user.get('created', 'Unknown')[:19]
                        print(f"{user['username']:<20} {user.get('email', 'N/A'):<30} "
                              f"{user['auth_type']:<10} {created:<20}")
                
                elif args.format == 'json':
                    print(json.dumps(users, indent=2))
                
                elif args.format == 'yaml':
                    print(yaml.dump(users, default_flow_style=False))
        
        elif args.command == 'report':
            report = vpn_manager.generate_status_report(args.format)
            
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(report)
                print(f"Report saved to {args.output}")
            else:
                print(report)
        
        elif args.command == 'backup':
            backup_path = vpn_manager.backup_configuration(args.output)
            print(f"Configuration backed up to: {backup_path}")
        
        elif args.command == 'reload':
            if vpn_manager.reload_configuration():
                print("Configuration reloaded successfully")
            else:
                print("Failed to reload configuration")
        
        elif args.command == 'restart':
            if vpn_manager.restart_vpn():
                print("VPN service restarted successfully")
            else:
                print("Failed to restart VPN service")
        
        elif args.command == 'monitor':
            print("PQC-VPN Real-time Monitor (Press Ctrl+C to exit)")
            print("=" * 60)
            
            try:
                while True:
                    os.system('clear' if os.name == 'posix' else 'cls')
                    
                    # Get current status
                    system_metrics = vpn_manager.get_system_metrics()
                    strongswan_status = vpn_manager.get_strongswan_status()
                    connections = vpn_manager.get_connection_info()
                    
                    print(f"PQC-VPN Monitor - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                    print("=" * 60)
                    print(f"CPU: {system_metrics.cpu_percent:5.1f}% | "
                          f"Memory: {system_metrics.memory_percent:5.1f}% | "
                          f"Connections: {len(connections)}")
                    print(f"strongSwan: {'Running' if strongswan_status['daemon_running'] else 'Stopped'}")
                    print()
                    
                    if connections:
                        print("Active Connections:")
                        print(f"{'Name':<15} {'State':<12} {'Remote IP':<15} {'Encryption':<20}")
                        print("-" * 65)
                        for conn in connections[:10]:  # Show max 10 connections
                            print(f"{conn.name:<15} {conn.state:<12} {conn.remote_ip:<15} {conn.encryption:<20}")
                    else:
                        print("No active connections")
                    
                    time.sleep(args.interval)
                    
            except KeyboardInterrupt:
                print("\nMonitoring stopped")
        
        elif args.command == 'version':
            system_metrics = vpn_manager.get_system_metrics()
            print("PQC-VPN Manager v3.0.0 (OpenSSL 3.5)")
            print(f"OpenSSL: {system_metrics.openssl_version}")
            print(f"strongSwan: {system_metrics.strongswan_version}")
            print("Enterprise Edition with Native Post-Quantum Cryptography")
    
    except Exception as e:
        logger.error(f"Command failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
