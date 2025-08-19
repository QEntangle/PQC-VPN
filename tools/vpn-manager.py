#!/usr/bin/env python3
"""
PQC-VPN Manager
Comprehensive management tool for PQC-VPN infrastructure
"""

import os
import sys
import json
import argparse
import subprocess
import logging
from pathlib import Path
from datetime import datetime
import yaml
import tempfile

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class PQCVPNManager:
    """Complete PQC-VPN management interface"""
    
    def __init__(self, config_file=None):
        self.base_dir = Path('/opt/pqc-vpn')
        self.config_file = config_file or self.base_dir / 'config.yaml'
        self.scripts_dir = self.base_dir / 'scripts'
        self.certs_dir = self.base_dir / 'certs'
        self.logs_dir = Path('/var/log/pqc-vpn')
        
        # Load configuration
        self.config = self.load_config()
        
        # Ensure directories exist
        for dir_path in [self.base_dir, self.scripts_dir, self.certs_dir, self.logs_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
    
    def load_config(self):
        """Load configuration from YAML file"""
        default_config = {
            'hub': {
                'ip': '10.10.0.1',
                'network': '10.10.0.0/16',
                'port': 500,
                'nat_port': 4500
            },
            'certificates': {
                'algorithm': 'dilithium5',
                'ca_validity': 3650,
                'cert_validity': 365,
                'country': 'US',
                'state': 'CA',
                'locality': 'San Francisco',
                'organization': 'PQC-VPN'
            },
            'security': {
                'ike_algorithms': 'aes256gcm16-prfsha256-kyber1024',
                'esp_algorithms': 'aes256gcm16-kyber1024',
                'lifetime': '24h',
                'margintime': '3m'
            },
            'monitoring': {
                'enabled': True,
                'interval': 30,
                'retention_days': 30
            }
        }
        
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    user_config = yaml.safe_load(f)
                    # Merge with defaults
                    return self._merge_configs(default_config, user_config)
            except Exception as e:
                logger.warning(f"Error loading config file: {e}, using defaults")
        
        return default_config
    
    def _merge_configs(self, default, user):
        """Recursively merge configuration dictionaries"""
        for key, value in user.items():
            if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                default[key] = self._merge_configs(default[key], value)
            else:
                default[key] = value
        return default
    
    def save_config(self):
        """Save current configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False, indent=2)
            logger.info(f"Configuration saved to {self.config_file}")
            return True
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
            return False
    
    def initialize_hub(self, hub_ip=None, force=False):
        """Initialize PQC-VPN hub"""
        if hub_ip:
            self.config['hub']['ip'] = hub_ip
            self.save_config()
        
        logger.info("Initializing PQC-VPN Hub...")
        
        # Check if already initialized
        ca_cert = self.certs_dir / 'ca' / 'ca-cert.pem'
        hub_cert = self.certs_dir / 'hub' / 'hub-cert.pem'
        
        if ca_cert.exists() and hub_cert.exists() and not force:
            logger.warning("Hub already initialized. Use --force to reinitialize.")
            return False
        
        try:
            # Generate CA certificate
            logger.info("Generating CA certificate...")
            result = self._run_script('generate-pqc-certs.sh', ['--ca'])
            if result.returncode != 0:
                logger.error("Failed to generate CA certificate")
                return False
            
            # Generate hub certificate
            logger.info(f"Generating hub certificate for IP: {self.config['hub']['ip']}")
            result = self._run_script('generate-pqc-certs.sh', 
                                    ['--hub', self.config['hub']['ip']])
            if result.returncode != 0:
                logger.error("Failed to generate hub certificate")
                return False
            
            # Configure strongSwan
            logger.info("Configuring strongSwan...")
            self._configure_strongswan_hub()
            
            # Start services
            logger.info("Starting strongSwan service...")
            subprocess.run(['systemctl', 'enable', 'strongswan'], check=True)
            subprocess.run(['systemctl', 'start', 'strongswan'], check=True)
            
            logger.info("Hub initialization completed successfully!")
            return True
            
        except Exception as e:
            logger.error(f"Hub initialization failed: {e}")
            return False
    
    def add_user(self, username, email=None, group='users', ip_address=None):
        """Add a new VPN user"""
        logger.info(f"Adding user: {username}")
        
        try:
            args = [username]
            if email:
                args.extend(['--email', email])
            if group:
                args.extend(['--group', group])
            if ip_address:
                args.extend(['--ip', ip_address])
            
            result = self._run_script('add-spoke-user.sh', args)
            
            if result.returncode == 0:
                logger.info(f"User {username} added successfully")
                return True
            else:
                logger.error(f"Failed to add user {username}")
                return False
                
        except Exception as e:
            logger.error(f"Error adding user {username}: {e}")
            return False
    
    def remove_user(self, username):
        """Remove a VPN user"""
        logger.info(f"Removing user: {username}")
        
        try:
            result = self._run_script('add-spoke-user.sh', ['--remove', username])
            
            if result.returncode == 0:
                logger.info(f"User {username} removed successfully")
                return True
            else:
                logger.error(f"Failed to remove user {username}")
                return False
                
        except Exception as e:
            logger.error(f"Error removing user {username}: {e}")
            return False
    
    def list_users(self, format='table'):
        """List all VPN users"""
        try:
            result = self._run_script('add-spoke-user.sh', ['--list'])
            
            if result.returncode == 0:
                if format == 'json':
                    # Parse the output and convert to JSON
                    users = self._parse_user_list(result.stdout)
                    return json.dumps(users, indent=2)
                else:
                    return result.stdout
            else:
                logger.error("Failed to list users")
                return None
                
        except Exception as e:
            logger.error(f"Error listing users: {e}")
            return None
    
    def get_user_info(self, username):
        """Get detailed information about a user"""
        try:
            result = self._run_script('add-spoke-user.sh', ['--info', username])
            
            if result.returncode == 0:
                return result.stdout
            else:
                logger.error(f"User {username} not found")
                return None
                
        except Exception as e:
            logger.error(f"Error getting user info: {e}")
            return None
    
    def create_user_package(self, username, output_dir=None):
        """Create certificate package for user"""
        if not output_dir:
            output_dir = Path.cwd()
        
        package_path = self.certs_dir / 'packages' / f'{username}-package.zip'
        
        if package_path.exists():
            output_path = Path(output_dir) / package_path.name
            try:
                import shutil
                shutil.copy2(package_path, output_path)
                logger.info(f"User package copied to: {output_path}")
                return str(output_path)
            except Exception as e:
                logger.error(f"Error copying package: {e}")
                return None
        else:
            logger.error(f"Package not found for user: {username}")
            return None
    
    def monitor_status(self, format='text'):
        """Get current VPN status"""
        try:
            # Use the connection monitor tool
            monitor_script = self.base_dir / 'tools' / 'connection-monitor.py'
            
            if monitor_script.exists():
                result = subprocess.run([
                    'python3', str(monitor_script), 'status', '--format', format
                ], capture_output=True, text=True)
                
                if result.returncode == 0:
                    return result.stdout
                else:
                    logger.error("Failed to get status from monitor")
                    return None
            else:
                # Fallback to basic status
                return self._get_basic_status()
                
        except Exception as e:
            logger.error(f"Error getting status: {e}")
            return None
    
    def start_monitoring(self, interval=30):
        """Start continuous monitoring"""
        try:
            monitor_script = self.base_dir / 'tools' / 'connection-monitor.py'
            
            if monitor_script.exists():
                subprocess.run([
                    'python3', str(monitor_script), 'monitor', 
                    '--interval', str(interval)
                ])
            else:
                logger.error("Monitoring script not found")
                
        except KeyboardInterrupt:
            logger.info("Monitoring stopped by user")
        except Exception as e:
            logger.error(f"Monitoring error: {e}")
    
    def backup_configuration(self, backup_path=None):
        """Backup VPN configuration and certificates"""
        if not backup_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_path = f'/tmp/pqc-vpn-backup-{timestamp}.tar.gz'
        
        try:
            import tarfile
            
            with tarfile.open(backup_path, 'w:gz') as tar:
                # Add configuration files
                tar.add('/etc/ipsec.conf', arcname='ipsec.conf')
                tar.add('/etc/ipsec.secrets', arcname='ipsec.secrets')
                tar.add('/etc/strongswan.conf', arcname='strongswan.conf')
                
                # Add certificates
                if self.certs_dir.exists():
                    tar.add(str(self.certs_dir), arcname='certs')
                
                # Add user database
                user_db = self.base_dir / 'users.db'
                if user_db.exists():
                    tar.add(str(user_db), arcname='users.db')
                
                # Add configuration
                if self.config_file.exists():
                    tar.add(str(self.config_file), arcname='config.yaml')
            
            logger.info(f"Backup created: {backup_path}")
            return backup_path
            
        except Exception as e:
            logger.error(f"Backup failed: {e}")
            return None
    
    def restore_configuration(self, backup_path, force=False):
        """Restore VPN configuration from backup"""
        if not Path(backup_path).exists():
            logger.error(f"Backup file not found: {backup_path}")
            return False
        
        if not force:
            response = input("This will overwrite current configuration. Continue? (y/N): ")
            if response.lower() != 'y':
                logger.info("Restore cancelled")
                return False
        
        try:
            import tarfile
            
            # Stop strongSwan
            subprocess.run(['systemctl', 'stop', 'strongswan'], check=False)
            
            with tarfile.open(backup_path, 'r:gz') as tar:
                # Extract to temporary directory first
                with tempfile.TemporaryDirectory() as temp_dir:
                    tar.extractall(temp_dir)
                    temp_path = Path(temp_dir)
                    
                    # Restore configuration files
                    config_files = {
                        'ipsec.conf': '/etc/ipsec.conf',
                        'ipsec.secrets': '/etc/ipsec.secrets',
                        'strongswan.conf': '/etc/strongswan.conf'
                    }
                    
                    for src, dst in config_files.items():
                        src_path = temp_path / src
                        if src_path.exists():
                            import shutil
                            shutil.copy2(src_path, dst)
                            logger.info(f"Restored {dst}")
                    
                    # Restore certificates
                    certs_backup = temp_path / 'certs'
                    if certs_backup.exists():
                        if self.certs_dir.exists():
                            import shutil
                            shutil.rmtree(self.certs_dir)
                        shutil.copytree(certs_backup, self.certs_dir)
                        logger.info("Restored certificates")
                    
                    # Restore user database
                    user_db_backup = temp_path / 'users.db'
                    if user_db_backup.exists():
                        import shutil
                        shutil.copy2(user_db_backup, self.base_dir / 'users.db')
                        logger.info("Restored user database")
                    
                    # Restore configuration
                    config_backup = temp_path / 'config.yaml'
                    if config_backup.exists():
                        import shutil
                        shutil.copy2(config_backup, self.config_file)
                        logger.info("Restored configuration")
            
            # Restart strongSwan
            subprocess.run(['systemctl', 'start', 'strongswan'], check=True)
            
            logger.info("Configuration restored successfully")
            return True
            
        except Exception as e:
            logger.error(f"Restore failed: {e}")
            return False
    
    def update_certificates(self, renew_all=False):
        """Update or renew certificates"""
        logger.info("Updating certificates...")
        
        try:
            # Check certificate expiry
            monitor_script = self.base_dir / 'tools' / 'connection-monitor.py'
            
            if monitor_script.exists():
                result = subprocess.run([
                    'python3', str(monitor_script), 'certificates', '--format', 'json'
                ], capture_output=True, text=True)
                
                if result.returncode == 0:
                    cert_status = json.loads(result.stdout)
                    
                    # Check which certificates need renewal
                    certs_to_renew = []
                    
                    # Check CA
                    if cert_status.get('ca', {}).get('status') in ['expired', 'expiring_soon']:
                        certs_to_renew.append('ca')
                    
                    # Check hub
                    if cert_status.get('hub', {}).get('status') in ['expired', 'expiring_soon']:
                        certs_to_renew.append('hub')
                    
                    # Check spokes
                    for username, info in cert_status.get('spokes', {}).items():
                        if info.get('status') in ['expired', 'expiring_soon']:
                            certs_to_renew.append(f'spoke:{username}')
                    
                    if not certs_to_renew and not renew_all:
                        logger.info("No certificates need renewal")
                        return True
                    
                    # Renew certificates
                    for cert in certs_to_renew:
                        if cert == 'ca':
                            logger.info("Renewing CA certificate...")
                            self._run_script('generate-pqc-certs.sh', ['--ca'])
                        elif cert == 'hub':
                            logger.info("Renewing hub certificate...")
                            self._run_script('generate-pqc-certs.sh', 
                                           ['--hub', self.config['hub']['ip']])
                        elif cert.startswith('spoke:'):
                            username = cert.split(':', 1)[1]
                            logger.info(f"Renewing certificate for user: {username}")
                            self._run_script('generate-pqc-certs.sh', 
                                           ['--spoke', username])
                    
                    # Reload strongSwan
                    subprocess.run(['ipsec', 'reload'], check=True)
                    
                    logger.info("Certificate update completed")
                    return True
                    
            return False
            
        except Exception as e:
            logger.error(f"Certificate update failed: {e}")
            return False
    
    def _configure_strongswan_hub(self):
        """Configure strongSwan for hub"""
        # This would update the strongSwan configuration files
        # with the current settings from the config
        pass
    
    def _run_script(self, script_name, args=None):
        """Run a management script"""
        script_path = self.scripts_dir / script_name
        
        if not script_path.exists():
            raise FileNotFoundError(f"Script not found: {script_path}")
        
        cmd = ['bash', str(script_path)]
        if args:
            cmd.extend(args)
        
        return subprocess.run(cmd, capture_output=True, text=True)
    
    def _parse_user_list(self, output):
        """Parse user list output into structured format"""
        users = []
        lines = output.strip().split('\n')
        
        # Skip header lines
        data_started = False
        for line in lines:
            if '--------' in line:
                data_started = True
                continue
            
            if data_started and line.strip():
                parts = line.split()
                if len(parts) >= 6:
                    users.append({
                        'username': parts[0],
                        'ip_address': parts[1],
                        'group': parts[2],
                        'email': parts[3],
                        'status': parts[4],
                        'created': ' '.join(parts[5:])
                    })
        
        return users
    
    def _get_basic_status(self):
        """Get basic status without monitoring tool"""
        status = {
            'timestamp': datetime.now().isoformat(),
            'strongswan_running': False,
            'connections': []
        }
        
        # Check if strongSwan is running
        try:
            result = subprocess.run(['systemctl', 'is-active', 'strongswan'], 
                                  capture_output=True, text=True)
            status['strongswan_running'] = result.returncode == 0
        except:
            pass
        
        # Get connection status
        try:
            result = subprocess.run(['ipsec', 'status'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                # Parse basic connection info
                for line in result.stdout.split('\n'):
                    if 'ESTABLISHED' in line:
                        status['connections'].append(line.strip())
        except:
            pass
        
        return json.dumps(status, indent=2)

def main():
    parser = argparse.ArgumentParser(description='PQC-VPN Management Tool')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Initialize command
    init_parser = subparsers.add_parser('init', help='Initialize PQC-VPN hub')
    init_parser.add_argument('--hub-ip', help='Hub IP address')
    init_parser.add_argument('--force', action='store_true', help='Force reinitialization')
    
    # User management commands
    user_parser = subparsers.add_parser('user', help='User management')
    user_subparsers = user_parser.add_subparsers(dest='user_action')
    
    add_user_parser = user_subparsers.add_parser('add', help='Add user')
    add_user_parser.add_argument('username', help='Username')
    add_user_parser.add_argument('--email', help='User email')
    add_user_parser.add_argument('--group', default='users', help='User group')
    add_user_parser.add_argument('--ip', help='Specific IP address')
    
    remove_user_parser = user_subparsers.add_parser('remove', help='Remove user')
    remove_user_parser.add_argument('username', help='Username')
    
    list_users_parser = user_subparsers.add_parser('list', help='List users')
    list_users_parser.add_argument('--format', choices=['table', 'json'], default='table')
    
    info_user_parser = user_subparsers.add_parser('info', help='User information')
    info_user_parser.add_argument('username', help='Username')
    
    package_parser = user_subparsers.add_parser('package', help='Create user package')
    package_parser.add_argument('username', help='Username')
    package_parser.add_argument('--output-dir', help='Output directory')
    
    # Status and monitoring
    status_parser = subparsers.add_parser('status', help='Show VPN status')
    status_parser.add_argument('--format', choices=['text', 'json'], default='text')
    
    monitor_parser = subparsers.add_parser('monitor', help='Start monitoring')
    monitor_parser.add_argument('--interval', type=int, default=30, help='Monitoring interval')
    
    # Configuration management
    config_parser = subparsers.add_parser('config', help='Configuration management')
    config_subparsers = config_parser.add_subparsers(dest='config_action')
    
    show_config_parser = config_subparsers.add_parser('show', help='Show configuration')
    
    # Backup and restore
    backup_parser = subparsers.add_parser('backup', help='Backup configuration')
    backup_parser.add_argument('--output', help='Backup file path')
    
    restore_parser = subparsers.add_parser('restore', help='Restore configuration')
    restore_parser.add_argument('backup_file', help='Backup file path')
    restore_parser.add_argument('--force', action='store_true', help='Force restore')
    
    # Certificate management
    cert_parser = subparsers.add_parser('certificates', help='Certificate management')
    cert_parser.add_argument('--renew-all', action='store_true', help='Renew all certificates')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Check if running as root for operations that require it
    if args.command in ['init', 'user', 'backup', 'restore', 'certificates'] and os.geteuid() != 0:
        logger.error("This operation requires root privileges")
        sys.exit(1)
    
    manager = PQCVPNManager(config_file=args.config)
    
    if not args.command:
        parser.print_help()
        return
    
    # Execute commands
    if args.command == 'init':
        success = manager.initialize_hub(hub_ip=args.hub_ip, force=args.force)
        sys.exit(0 if success else 1)
    
    elif args.command == 'user':
        if args.user_action == 'add':
            success = manager.add_user(args.username, email=args.email, 
                                     group=args.group, ip_address=args.ip)
            sys.exit(0 if success else 1)
        
        elif args.user_action == 'remove':
            success = manager.remove_user(args.username)
            sys.exit(0 if success else 1)
        
        elif args.user_action == 'list':
            users = manager.list_users(format=args.format)
            if users:
                print(users)
            else:
                sys.exit(1)
        
        elif args.user_action == 'info':
            info = manager.get_user_info(args.username)
            if info:
                print(info)
            else:
                sys.exit(1)
        
        elif args.user_action == 'package':
            package_path = manager.create_user_package(args.username, args.output_dir)
            if package_path:
                print(f"Package created: {package_path}")
            else:
                sys.exit(1)
    
    elif args.command == 'status':
        status = manager.monitor_status(format=args.format)
        if status:
            print(status)
        else:
            sys.exit(1)
    
    elif args.command == 'monitor':
        manager.start_monitoring(interval=args.interval)
    
    elif args.command == 'config':
        if args.config_action == 'show':
            print(yaml.dump(manager.config, default_flow_style=False, indent=2))
    
    elif args.command == 'backup':
        backup_path = manager.backup_configuration(args.output)
        if backup_path:
            print(f"Backup created: {backup_path}")
        else:
            sys.exit(1)
    
    elif args.command == 'restore':
        success = manager.restore_configuration(args.backup_file, force=args.force)
        sys.exit(0 if success else 1)
    
    elif args.command == 'certificates':
        success = manager.update_certificates(renew_all=args.renew_all)
        sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()