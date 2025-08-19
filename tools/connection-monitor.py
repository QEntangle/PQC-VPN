#!/usr/bin/env python3
"""
PQC-VPN Connection Monitor
Real-time monitoring of PQC-VPN connections and performance
"""

import os
import sys
import time
import json
import socket
import psutil
import argparse
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
import threading
import signal
from collections import defaultdict, deque

class VPNConnectionMonitor:
    """Monitor PQC-VPN connections and system performance"""
    
    def __init__(self, user_db_path='/opt/pqc-vpn/users.db', 
                 log_dir='/var/log/pqc-vpn', strongswan_log='/var/log/syslog'):
        self.user_db_path = Path(user_db_path)
        self.log_dir = Path(log_dir)
        self.strongswan_log = Path(strongswan_log)
        self.monitoring = False
        self.connections = {}
        self.performance_data = deque(maxlen=1000)  # Keep last 1000 samples
        self.traffic_stats = defaultdict(lambda: {'bytes_in': 0, 'bytes_out': 0, 'packets_in': 0, 'packets_out': 0})
        
        # Create log directory if it doesn't exist
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        print(f"\nReceived signal {signum}, shutting down gracefully...")
        self.monitoring = False
    
    def get_strongswan_status(self):
        """Get strongSwan service status"""
        try:
            # Check if strongSwan is running
            result = subprocess.run(['systemctl', 'is-active', 'strongswan'], 
                                  capture_output=True, text=True)
            service_active = result.returncode == 0
            
            # Get detailed status
            result = subprocess.run(['ipsec', 'status'], 
                                  capture_output=True, text=True)
            
            status = {
                'service_active': service_active,
                'ipsec_status': result.stdout if result.returncode == 0 else None,
                'connections': self._parse_ipsec_status(result.stdout) if result.returncode == 0 else [],
                'timestamp': datetime.now().isoformat()
            }
            
            return status
        except Exception as e:
            return {
                'service_active': False,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def _parse_ipsec_status(self, status_output):
        """Parse ipsec status output to extract connection information"""
        connections = []
        current_connection = None
        
        for line in status_output.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            # Look for connection names
            if ':' in line and 'ESTABLISHED' in line:
                parts = line.split(':')
                if len(parts) >= 2:
                    conn_name = parts[0].strip()
                    conn_info = parts[1].strip()
                    
                    current_connection = {
                        'name': conn_name,
                        'status': 'ESTABLISHED',
                        'info': conn_info,
                        'security_associations': []
                    }
                    connections.append(current_connection)
            
            # Look for security associations
            elif 'INSTALLED' in line and current_connection:
                current_connection['security_associations'].append(line.strip())
        
        return connections
    
    def get_user_database(self):
        """Load user database"""
        users = {}
        
        if not self.user_db_path.exists():
            return users
        
        try:
            with open(self.user_db_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('#') or not line:
                        continue
                    
                    parts = line.split(':')
                    if len(parts) >= 7:
                        username, ip_addr, group, email, created, expires, status = parts[:7]
                        users[username] = {
                            'ip_address': ip_addr,
                            'group': group,
                            'email': email,
                            'created': created,
                            'expires': expires,
                            'status': status
                        }
        except Exception as e:
            print(f"Error reading user database: {e}")
        
        return users
    
    def get_system_performance(self):
        """Get system performance metrics"""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()
            load_avg = os.getloadavg()
            
            # Memory usage
            memory = psutil.virtual_memory()
            
            # Disk usage
            disk = psutil.disk_usage('/')
            
            # Network interfaces
            network_stats = psutil.net_io_counters(pernic=True)
            
            # strongSwan process info
            strongswan_processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    if 'ipsec' in proc.info['name'].lower() or 'strongswan' in proc.info['name'].lower():
                        strongswan_processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            performance = {
                'timestamp': datetime.now().isoformat(),
                'cpu': {
                    'percent': cpu_percent,
                    'count': cpu_count,
                    'load_avg': load_avg
                },
                'memory': {
                    'total': memory.total,
                    'available': memory.available,
                    'percent': memory.percent,
                    'used': memory.used
                },
                'disk': {
                    'total': disk.total,
                    'free': disk.free,
                    'used': disk.used,
                    'percent': (disk.used / disk.total) * 100
                },
                'network': dict(network_stats),
                'strongswan_processes': strongswan_processes
            }
            
            return performance
        except Exception as e:
            return {
                'timestamp': datetime.now().isoformat(),
                'error': str(e)
            }
    
    def get_network_traffic(self):
        """Monitor network traffic on VPN interfaces"""
        traffic = {}
        
        try:
            # Get network interface statistics
            net_io = psutil.net_io_counters(pernic=True)
            
            for interface, stats in net_io.items():
                # Look for VPN-related interfaces
                if any(keyword in interface.lower() for keyword in ['tun', 'tap', 'ipsec', 'vpn']):
                    traffic[interface] = {
                        'bytes_sent': stats.bytes_sent,
                        'bytes_recv': stats.bytes_recv,
                        'packets_sent': stats.packets_sent,
                        'packets_recv': stats.packets_recv,
                        'errin': stats.errin,
                        'errout': stats.errout,
                        'dropin': stats.dropin,
                        'dropout': stats.dropout
                    }
            
            return traffic
        except Exception as e:
            return {'error': str(e)}
    
    def parse_strongswan_logs(self, lines=100):
        """Parse recent strongSwan log entries"""
        logs = []
        
        if not self.strongswan_log.exists():
            return logs
        
        try:
            # Use tail to get recent log entries
            result = subprocess.run(['tail', '-n', str(lines), str(self.strongswan_log)], 
                                  capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if any(keyword in line.lower() for keyword in ['ipsec', 'strongswan', 'charon']):
                    # Parse log entry
                    parts = line.split()
                    if len(parts) >= 5:
                        timestamp = ' '.join(parts[:3])
                        hostname = parts[3]
                        service = parts[4].rstrip(':')
                        message = ' '.join(parts[5:])
                        
                        # Determine log level
                        level = 'INFO'
                        if any(keyword in message.lower() for keyword in ['error', 'failed', 'critical']):
                            level = 'ERROR'
                        elif any(keyword in message.lower() for keyword in ['warning', 'warn']):
                            level = 'WARNING'
                        elif any(keyword in message.lower() for keyword in ['established', 'installed']):
                            level = 'SUCCESS'
                        
                        logs.append({
                            'timestamp': timestamp,
                            'hostname': hostname,
                            'service': service,
                            'level': level,
                            'message': message
                        })
            
            return logs[-lines:]  # Return most recent entries
        except Exception as e:
            return [{'error': str(e)}]
    
    def check_certificate_expiry(self):
        """Check certificate expiration dates"""
        cert_status = {}
        cert_dir = Path('/opt/pqc-vpn/certs')
        
        # Check CA certificate
        ca_cert = cert_dir / 'ca' / 'ca-cert.pem'
        if ca_cert.exists():
            cert_status['ca'] = self._check_cert_expiry(ca_cert)
        
        # Check hub certificate
        hub_cert = cert_dir / 'hub' / 'hub-cert.pem'
        if hub_cert.exists():
            cert_status['hub'] = self._check_cert_expiry(hub_cert)
        
        # Check spoke certificates
        spoke_certs = {}
        spokes_dir = cert_dir / 'spokes'
        if spokes_dir.exists():
            for cert_file in spokes_dir.glob('*-cert.pem'):
                username = cert_file.stem.replace('-cert', '')
                spoke_certs[username] = self._check_cert_expiry(cert_file)
        
        cert_status['spokes'] = spoke_certs
        
        return cert_status
    
    def _check_cert_expiry(self, cert_file):
        """Check individual certificate expiry"""
        try:
            # Get certificate expiry date
            result = subprocess.run(['openssl', 'x509', '-in', str(cert_file), 
                                   '-noout', '-enddate'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                expiry_line = result.stdout.strip()
                expiry_str = expiry_line.replace('notAfter=', '')
                
                # Parse expiry date
                expiry_date = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                now = datetime.now()
                days_until_expiry = (expiry_date - now).days
                
                status = 'valid'
                if days_until_expiry < 0:
                    status = 'expired'
                elif days_until_expiry < 7:
                    status = 'expiring_soon'
                elif days_until_expiry < 30:
                    status = 'expiring_warning'
                
                return {
                    'expiry_date': expiry_date.isoformat(),
                    'days_until_expiry': days_until_expiry,
                    'status': status,
                    'valid': days_until_expiry >= 0
                }
            else:
                return {
                    'error': 'Cannot read certificate',
                    'status': 'error',
                    'valid': False
                }
        except Exception as e:
            return {
                'error': str(e),
                'status': 'error',
                'valid': False
            }
    
    def generate_report(self, format='text'):
        """Generate comprehensive monitoring report"""
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'strongswan_status': self.get_strongswan_status(),
            'users': self.get_user_database(),
            'performance': self.get_system_performance(),
            'network_traffic': self.get_network_traffic(),
            'certificate_status': self.check_certificate_expiry(),
            'recent_logs': self.parse_strongswan_logs(50)
        }
        
        if format == 'json':
            return json.dumps(report_data, indent=2)
        elif format == 'text':
            return self._format_text_report(report_data)
        else:
            return report_data
    
    def _format_text_report(self, data):
        """Format report as human-readable text"""
        report = []
        report.append("PQC-VPN Monitoring Report")
        report.append("=" * 50)
        report.append(f"Generated: {data['timestamp']}")
        report.append("")
        
        # strongSwan Status
        sw_status = data['strongswan_status']
        report.append("strongSwan Status:")
        report.append(f"  Service Active: {'Yes' if sw_status.get('service_active') else 'No'}")
        report.append(f"  Active Connections: {len(sw_status.get('connections', []))}")
        
        for conn in sw_status.get('connections', []):
            report.append(f"    {conn['name']}: {conn['status']}")
        
        report.append("")
        
        # User Status
        users = data['users']
        report.append(f"Registered Users: {len(users)}")
        active_users = len([u for u in users.values() if u['status'] == 'active'])
        report.append(f"Active Users: {active_users}")
        report.append("")
        
        # Performance
        perf = data['performance']
        if 'error' not in perf:
            report.append("System Performance:")
            report.append(f"  CPU Usage: {perf['cpu']['percent']:.1f}%")
            report.append(f"  Memory Usage: {perf['memory']['percent']:.1f}%")
            report.append(f"  Disk Usage: {perf['disk']['percent']:.1f}%")
            report.append(f"  Load Average: {', '.join(f'{x:.2f}' for x in perf['cpu']['load_avg'])}")
            report.append("")
        
        # Certificate Status
        cert_status = data['certificate_status']
        report.append("Certificate Status:")
        
        if 'ca' in cert_status:
            ca_status = cert_status['ca']['status']
            report.append(f"  CA Certificate: {ca_status}")
        
        if 'hub' in cert_status:
            hub_status = cert_status['hub']['status']
            report.append(f"  Hub Certificate: {hub_status}")
        
        expiring_certs = []
        for username, cert_info in cert_status.get('spokes', {}).items():
            if cert_info['status'] in ['expired', 'expiring_soon', 'expiring_warning']:
                expiring_certs.append(f"{username} ({cert_info['status']})")
        
        if expiring_certs:
            report.append(f"  Certificates Needing Attention: {', '.join(expiring_certs)}")
        else:
            report.append("  All certificates valid")
        
        report.append("")
        
        # Recent Activity
        logs = data['recent_logs']
        error_logs = [log for log in logs if log.get('level') == 'ERROR']
        if error_logs:
            report.append(f"Recent Errors ({len(error_logs)}):")
            for log in error_logs[-5:]:  # Show last 5 errors
                report.append(f"  {log.get('timestamp', 'Unknown')}: {log.get('message', 'No message')}")
        
        return '\n'.join(report)
    
    def start_monitoring(self, interval=30, output_file=None):
        """Start continuous monitoring"""
        self.monitoring = True
        
        print(f"Starting PQC-VPN monitoring (interval: {interval}s)")
        if output_file:
            print(f"Logging to: {output_file}")
        
        while self.monitoring:
            try:
                # Collect monitoring data
                report_data = self.generate_report(format='dict')
                
                # Save performance data
                self.performance_data.append(report_data['performance'])
                
                # Display summary
                self._display_monitoring_summary(report_data)
                
                # Log to file if specified
                if output_file:
                    self._log_to_file(report_data, output_file)
                
                # Wait for next interval
                time.sleep(interval)
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Monitoring error: {e}")
                time.sleep(5)  # Brief pause before retrying
        
        print("Monitoring stopped")
    
    def _display_monitoring_summary(self, data):
        """Display real-time monitoring summary"""
        os.system('clear' if os.name == 'posix' else 'cls')
        
        print("PQC-VPN Live Monitor")
        print("=" * 60)
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # strongSwan status
        sw_status = data['strongswan_status']
        status_indicator = "🟢" if sw_status.get('service_active') else "🔴"
        print(f"strongSwan: {status_indicator} {'Active' if sw_status.get('service_active') else 'Inactive'}")
        
        connections = sw_status.get('connections', [])
        print(f"Active Connections: {len(connections)}")
        
        # User status
        users = data['users']
        active_users = len([u for u in users.values() if u['status'] == 'active'])
        print(f"Users: {active_users}/{len(users)} active")
        
        # Performance
        perf = data['performance']
        if 'error' not in perf:
            print(f"CPU: {perf['cpu']['percent']:.1f}% | "
                  f"Memory: {perf['memory']['percent']:.1f}% | "
                  f"Disk: {perf['disk']['percent']:.1f}%")
        
        # Certificates
        cert_status = data['certificate_status']
        cert_issues = 0
        for cert_type, cert_info in cert_status.items():
            if cert_type == 'spokes':
                for username, info in cert_info.items():
                    if info['status'] in ['expired', 'expiring_soon']:
                        cert_issues += 1
            elif isinstance(cert_info, dict) and cert_info.get('status') in ['expired', 'expiring_soon']:
                cert_issues += 1
        
        cert_indicator = "🟡" if cert_issues > 0 else "🟢"
        print(f"Certificates: {cert_indicator} {cert_issues} issues")
        
        print("\nPress Ctrl+C to stop monitoring")
    
    def _log_to_file(self, data, output_file):
        """Log monitoring data to file"""
        log_entry = {
            'timestamp': data['timestamp'],
            'service_active': data['strongswan_status'].get('service_active'),
            'active_connections': len(data['strongswan_status'].get('connections', [])),
            'active_users': len([u for u in data['users'].values() if u['status'] == 'active']),
            'total_users': len(data['users']),
            'cpu_percent': data['performance'].get('cpu', {}).get('percent'),
            'memory_percent': data['performance'].get('memory', {}).get('percent'),
            'disk_percent': data['performance'].get('disk', {}).get('percent')
        }
        
        with open(output_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')

def main():
    parser = argparse.ArgumentParser(description='PQC-VPN Connection Monitor')
    parser.add_argument('--user-db', default='/opt/pqc-vpn/users.db',
                       help='Path to user database file')
    parser.add_argument('--log-dir', default='/var/log/pqc-vpn',
                       help='Log directory')
    parser.add_argument('--strongswan-log', default='/var/log/syslog',
                       help='strongSwan log file')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Show current status')
    status_parser.add_argument('--format', choices=['text', 'json'], default='text',
                              help='Output format')
    
    # Monitor command
    monitor_parser = subparsers.add_parser('monitor', help='Start continuous monitoring')
    monitor_parser.add_argument('--interval', type=int, default=30,
                               help='Monitoring interval in seconds')
    monitor_parser.add_argument('--output', help='Output log file')
    
    # Report command
    report_parser = subparsers.add_parser('report', help='Generate detailed report')
    report_parser.add_argument('--format', choices=['text', 'json'], default='text',
                              help='Output format')
    report_parser.add_argument('--output', help='Output file')
    
    # Certificates command
    cert_parser = subparsers.add_parser('certificates', help='Check certificate status')
    cert_parser.add_argument('--format', choices=['text', 'json'], default='text',
                            help='Output format')
    
    args = parser.parse_args()
    
    # Check if running as root for some operations
    if args.command in ['monitor'] and os.geteuid() != 0:
        print("Warning: Some features may require root privileges")
    
    monitor = VPNConnectionMonitor(
        user_db_path=args.user_db,
        log_dir=args.log_dir,
        strongswan_log=args.strongswan_log
    )
    
    if not args.command:
        parser.print_help()
        return
    
    if args.command == 'status':
        report = monitor.generate_report(format=args.format)
        print(report)
    
    elif args.command == 'monitor':
        monitor.start_monitoring(interval=args.interval, output_file=args.output)
    
    elif args.command == 'report':
        report = monitor.generate_report(format=args.format)
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(report)
            print(f"Report saved to: {args.output}")
        else:
            print(report)
    
    elif args.command == 'certificates':
        cert_status = monitor.check_certificate_expiry()
        
        if args.format == 'json':
            print(json.dumps(cert_status, indent=2))
        else:
            print("Certificate Status Report")
            print("=" * 40)
            
            # CA Certificate
            if 'ca' in cert_status:
                ca = cert_status['ca']
                status_emoji = "🟢" if ca['valid'] else "🔴"
                print(f"CA Certificate: {status_emoji} {ca['status']}")
                if 'days_until_expiry' in ca:
                    print(f"  Expires in {ca['days_until_expiry']} days")
            
            # Hub Certificate
            if 'hub' in cert_status:
                hub = cert_status['hub']
                status_emoji = "🟢" if hub['valid'] else "🔴"
                print(f"Hub Certificate: {status_emoji} {hub['status']}")
                if 'days_until_expiry' in hub:
                    print(f"  Expires in {hub['days_until_expiry']} days")
            
            # Spoke Certificates
            if cert_status.get('spokes'):
                print(f"\nSpoke Certificates ({len(cert_status['spokes'])}):")
                for username, cert_info in cert_status['spokes'].items():
                    if cert_info['status'] == 'expired':
                        emoji = "🔴"
                    elif cert_info['status'] in ['expiring_soon', 'expiring_warning']:
                        emoji = "🟡"
                    else:
                        emoji = "🟢"
                    
                    print(f"  {username}: {emoji} {cert_info['status']}")
                    if 'days_until_expiry' in cert_info:
                        print(f"    Expires in {cert_info['days_until_expiry']} days")

if __name__ == '__main__':
    main()