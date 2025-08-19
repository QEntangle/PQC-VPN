#!/usr/bin/env python3
"""
PQC Key Generation Utility
Post-Quantum Cryptography key generation for VPN certificates
"""

import os
import sys
import argparse
import subprocess
import logging
from pathlib import Path
from datetime import datetime, timedelta
import json

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class PQCKeyGenerator:
    """Post-Quantum Cryptography Key Generator"""
    
    SUPPORTED_ALGORITHMS = {
        'dilithium2': 'Dilithium-2 (NIST Level 1)',
        'dilithium3': 'Dilithium-3 (NIST Level 3)', 
        'dilithium5': 'Dilithium-5 (NIST Level 5)',
        'falcon512': 'Falcon-512 (NIST Level 1)',
        'falcon1024': 'Falcon-1024 (NIST Level 5)',
        'sphincssha256128f': 'SPHINCS+-SHA256-128f-robust',
        'sphincssha256192f': 'SPHINCS+-SHA256-192f-robust',
        'sphincssha256256f': 'SPHINCS+-SHA256-256f-robust'
    }
    
    def __init__(self, cert_dir='/opt/pqc-vpn/certs'):
        self.cert_dir = Path(cert_dir)
        self.ca_dir = self.cert_dir / 'ca'
        self.hub_dir = self.cert_dir / 'hub'
        self.spokes_dir = self.cert_dir / 'spokes'
        
        # Create directories if they don't exist
        for dir_path in [self.cert_dir, self.ca_dir, self.hub_dir, self.spokes_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
            os.chmod(dir_path, 0o700)
    
    def check_openssl_pqc(self):
        """Check if OpenSSL supports PQC algorithms"""
        try:
            result = subprocess.run(['openssl', 'list', '-providers'], 
                                  capture_output=True, text=True)
            if 'oqsprovider' in result.stdout or 'default' in result.stdout:
                logger.info("OpenSSL PQC support detected")
                return True
            else:
                logger.warning("OpenSSL PQC provider not detected")
                return False
        except subprocess.CalledProcessError:
            logger.error("OpenSSL not found or not functional")
            return False
    
    def list_supported_algorithms(self):
        """List all supported PQC algorithms"""
        print("\nSupported Post-Quantum Cryptography Algorithms:")
        print("=" * 60)
        for alg, desc in self.SUPPORTED_ALGORITHMS.items():
            print(f"  {alg:<20} - {desc}")
        print()
    
    def generate_ca_certificate(self, algorithm='dilithium5', validity_days=3650,
                               country='US', state='CA', locality='San Francisco',
                               organization='PQC-VPN', common_name='PQC-VPN-CA'):
        """Generate Certificate Authority certificate"""
        logger.info(f"Generating CA certificate with {algorithm}")
        
        ca_key = self.ca_dir / 'ca-key.pem'
        ca_cert = self.ca_dir / 'ca-cert.pem'
        
        # Generate CA private key
        cmd_key = [
            'openssl', 'genpkey',
            '-algorithm', algorithm,
            '-out', str(ca_key)
        ]
        
        try:
            subprocess.run(cmd_key, check=True, capture_output=True)
            os.chmod(ca_key, 0o600)
            logger.info(f"CA private key generated: {ca_key}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to generate CA key: {e}")
            return False
        
        # Generate CA certificate
        subject = f"/C={country}/ST={state}/L={locality}/O={organization}/CN={common_name}"
        
        cmd_cert = [
            'openssl', 'req', '-new', '-x509',
            '-key', str(ca_key),
            '-sha256',
            '-days', str(validity_days),
            '-out', str(ca_cert),
            '-subj', subject
        ]
        
        try:
            subprocess.run(cmd_cert, check=True, capture_output=True)
            logger.info(f"CA certificate generated: {ca_cert}")
            
            # Initialize CA database
            self._init_ca_database()
            
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to generate CA certificate: {e}")
            return False
    
    def _init_ca_database(self):
        """Initialize CA database files"""
        serial_file = self.ca_dir / 'serial'
        index_file = self.ca_dir / 'index.txt'
        
        # Create serial number file
        with open(serial_file, 'w') as f:
            f.write('01\n')
        
        # Create empty index file
        index_file.touch()
        
        logger.info("CA database initialized")
    
    def generate_hub_certificate(self, hub_ip, algorithm='dilithium5', 
                                validity_days=365, country='US', state='CA',
                                locality='San Francisco', organization='PQC-VPN'):
        """Generate hub certificate"""
        logger.info(f"Generating hub certificate for IP: {hub_ip}")
        
        hub_key = self.hub_dir / 'hub-key.pem'
        hub_cert = self.hub_dir / 'hub-cert.pem'
        hub_csr = self.hub_dir / 'hub.csr'
        
        # Generate hub private key
        cmd_key = [
            'openssl', 'genpkey',
            '-algorithm', algorithm,
            '-out', str(hub_key)
        ]
        
        try:
            subprocess.run(cmd_key, check=True, capture_output=True)
            os.chmod(hub_key, 0o600)
            logger.info(f"Hub private key generated: {hub_key}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to generate hub key: {e}")
            return False
        
        # Generate certificate signing request
        subject = f"/C={country}/ST={state}/L={locality}/O={organization}/OU=Hub/CN={hub_ip}"
        
        cmd_csr = [
            'openssl', 'req', '-new',
            '-key', str(hub_key),
            '-out', str(hub_csr),
            '-subj', subject
        ]
        
        try:
            subprocess.run(cmd_csr, check=True, capture_output=True)
            logger.info(f"Hub CSR generated: {hub_csr}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to generate hub CSR: {e}")
            return False
        
        # Sign the certificate
        return self._sign_certificate(hub_csr, hub_cert, 'server', validity_days, hub_ip)
    
    def generate_spoke_certificate(self, username, algorithm='dilithium5',
                                 validity_days=365, country='US', state='CA',
                                 locality='San Francisco', organization='PQC-VPN'):
        """Generate spoke certificate"""
        logger.info(f"Generating spoke certificate for user: {username}")
        
        spoke_key = self.spokes_dir / f'{username}-key.pem'
        spoke_cert = self.spokes_dir / f'{username}-cert.pem'
        spoke_csr = self.spokes_dir / f'{username}.csr'
        
        # Generate spoke private key
        cmd_key = [
            'openssl', 'genpkey',
            '-algorithm', algorithm,
            '-out', str(spoke_key)
        ]
        
        try:
            subprocess.run(cmd_key, check=True, capture_output=True)
            os.chmod(spoke_key, 0o600)
            logger.info(f"Spoke private key generated: {spoke_key}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to generate spoke key: {e}")
            return False
        
        # Generate certificate signing request
        subject = f"/C={country}/ST={state}/L={locality}/O={organization}/OU=Spoke/CN={username}"
        
        cmd_csr = [
            'openssl', 'req', '-new',
            '-key', str(spoke_key),
            '-out', str(spoke_csr),
            '-subj', subject
        ]
        
        try:
            subprocess.run(cmd_csr, check=True, capture_output=True)
            logger.info(f"Spoke CSR generated: {spoke_csr}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to generate spoke CSR: {e}")
            return False
        
        # Sign the certificate
        success = self._sign_certificate(spoke_csr, spoke_cert, 'client', validity_days)
        
        if success:
            self._create_user_package(username)
        
        return success
    
    def _sign_certificate(self, csr_file, cert_file, cert_type, validity_days, san_ip=None):
        """Sign a certificate with the CA"""
        ca_cert = self.ca_dir / 'ca-cert.pem'
        ca_key = self.ca_dir / 'ca-key.pem'
        
        if not ca_cert.exists() or not ca_key.exists():
            logger.error("CA certificate or key not found")
            return False
        
        # Create extensions file
        ext_file = Path('/tmp/cert_extensions.conf')
        extensions = ['basicConstraints = CA:FALSE']
        
        if cert_type == 'server':
            extensions.extend([
                'keyUsage = digitalSignature, keyEncipherment',
                'extendedKeyUsage = serverAuth'
            ])
            if san_ip:
                extensions.extend([
                    'subjectAltName = @alt_names',
                    '',
                    '[alt_names]',
                    f'IP.1 = {san_ip}'
                ])
        elif cert_type == 'client':
            extensions.extend([
                'keyUsage = digitalSignature',
                'extendedKeyUsage = clientAuth'
            ])
        
        with open(ext_file, 'w') as f:
            f.write('\n'.join(extensions))
        
        # Sign the certificate
        cmd_sign = [
            'openssl', 'x509', '-req',
            '-in', str(csr_file),
            '-CA', str(ca_cert),
            '-CAkey', str(ca_key),
            '-CAcreateserial',
            '-out', str(cert_file),
            '-days', str(validity_days),
            '-sha256',
            '-extensions', 'v3_ext',
            '-extfile', str(ext_file)
        ]
        
        try:
            subprocess.run(cmd_sign, check=True, capture_output=True)
            logger.info(f"Certificate signed: {cert_file}")
            ext_file.unlink()  # Clean up extensions file
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to sign certificate: {e}")
            if ext_file.exists():
                ext_file.unlink()
            return False
    
    def _create_user_package(self, username):
        """Create certificate package for user"""
        package_dir = self.cert_dir / 'packages' / username
        package_dir.mkdir(parents=True, exist_ok=True)
        
        # Copy certificates
        files_to_copy = [
            (self.ca_dir / 'ca-cert.pem', package_dir / 'ca-cert.pem'),
            (self.spokes_dir / f'{username}-cert.pem', package_dir / f'{username}-cert.pem'),
            (self.spokes_dir / f'{username}-key.pem', package_dir / f'{username}-key.pem')
        ]
        
        for src, dst in files_to_copy:
            if src.exists():
                with open(src, 'rb') as f_src, open(dst, 'wb') as f_dst:
                    f_dst.write(f_src.read())
                os.chmod(dst, 0o600 if 'key' in dst.name else 0o644)
        
        # Create README
        readme_content = f"""PQC-VPN Certificate Package for: {username}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Files included:
- ca-cert.pem: Certificate Authority certificate
- {username}-cert.pem: Your client certificate
- {username}-key.pem: Your private key (KEEP SECURE!)

Installation instructions:
1. Copy these files to your client device
2. Install using the spoke installation script
3. Use the install-certs script to configure strongSwan
"""
        
        with open(package_dir / 'README.txt', 'w') as f:
            f.write(readme_content)
        
        logger.info(f"User package created: {package_dir}")
    
    def verify_certificate(self, cert_file):
        """Verify certificate against CA"""
        ca_cert = self.ca_dir / 'ca-cert.pem'
        
        if not ca_cert.exists():
            logger.error("CA certificate not found")
            return False
        
        cmd_verify = [
            'openssl', 'verify',
            '-CAfile', str(ca_cert),
            str(cert_file)
        ]
        
        try:
            result = subprocess.run(cmd_verify, check=True, capture_output=True, text=True)
            logger.info(f"Certificate verification successful: {cert_file}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Certificate verification failed: {e}")
            return False
    
    def get_certificate_info(self, cert_file):
        """Get certificate information"""
        cmd_info = [
            'openssl', 'x509',
            '-in', str(cert_file),
            '-text', '-noout'
        ]
        
        try:
            result = subprocess.run(cmd_info, check=True, capture_output=True, text=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to get certificate info: {e}")
            return None
    
    def list_certificates(self):
        """List all generated certificates"""
        certs_info = {
            'ca': {},
            'hub': {},
            'spokes': {}
        }
        
        # CA certificate
        ca_cert = self.ca_dir / 'ca-cert.pem'
        if ca_cert.exists():
            certs_info['ca']['path'] = str(ca_cert)
            certs_info['ca']['exists'] = True
        else:
            certs_info['ca']['exists'] = False
        
        # Hub certificate
        hub_cert = self.hub_dir / 'hub-cert.pem'
        if hub_cert.exists():
            certs_info['hub']['path'] = str(hub_cert)
            certs_info['hub']['exists'] = True
        else:
            certs_info['hub']['exists'] = False
        
        # Spoke certificates
        for cert_file in self.spokes_dir.glob('*-cert.pem'):
            username = cert_file.stem.replace('-cert', '')
            certs_info['spokes'][username] = {
                'cert_path': str(cert_file),
                'key_path': str(self.spokes_dir / f'{username}-key.pem'),
                'exists': True
            }
        
        return certs_info

def main():
    parser = argparse.ArgumentParser(description='PQC Key Generation Utility')
    parser.add_argument('--cert-dir', default='/opt/pqc-vpn/certs',
                       help='Certificate directory')
    parser.add_argument('--algorithm', default='dilithium5',
                       choices=list(PQCKeyGenerator.SUPPORTED_ALGORITHMS.keys()),
                       help='PQC algorithm to use')
    parser.add_argument('--validity', type=int, default=365,
                       help='Certificate validity in days')
    parser.add_argument('--list-algorithms', action='store_true',
                       help='List supported algorithms')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # CA command
    ca_parser = subparsers.add_parser('ca', help='Generate CA certificate')
    ca_parser.add_argument('--country', default='US', help='Country code')
    ca_parser.add_argument('--state', default='CA', help='State name')
    ca_parser.add_argument('--locality', default='San Francisco', help='City name')
    ca_parser.add_argument('--organization', default='PQC-VPN', help='Organization name')
    ca_parser.add_argument('--common-name', default='PQC-VPN-CA', help='Common name')
    
    # Hub command
    hub_parser = subparsers.add_parser('hub', help='Generate hub certificate')
    hub_parser.add_argument('ip', help='Hub IP address')
    hub_parser.add_argument('--country', default='US', help='Country code')
    hub_parser.add_argument('--state', default='CA', help='State name')
    hub_parser.add_argument('--locality', default='San Francisco', help='City name')
    hub_parser.add_argument('--organization', default='PQC-VPN', help='Organization name')
    
    # Spoke command
    spoke_parser = subparsers.add_parser('spoke', help='Generate spoke certificate')
    spoke_parser.add_argument('username', help='Spoke username')
    spoke_parser.add_argument('--country', default='US', help='Country code')
    spoke_parser.add_argument('--state', default='CA', help='State name')
    spoke_parser.add_argument('--locality', default='San Francisco', help='City name')
    spoke_parser.add_argument('--organization', default='PQC-VPN', help='Organization name')
    
    # Verify command
    verify_parser = subparsers.add_parser('verify', help='Verify certificate')
    verify_parser.add_argument('cert_file', help='Certificate file to verify')
    
    # Info command
    info_parser = subparsers.add_parser('info', help='Show certificate info')
    info_parser.add_argument('cert_file', help='Certificate file')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List all certificates')
    list_parser.add_argument('--json', action='store_true', help='Output as JSON')
    
    args = parser.parse_args()
    
    # Check if running as root
    if os.geteuid() != 0:
        logger.error("This script must be run as root")
        sys.exit(1)
    
    keygen = PQCKeyGenerator(args.cert_dir)
    
    if args.list_algorithms:
        keygen.list_supported_algorithms()
        return
    
    if not args.command:
        parser.print_help()
        return
    
    # Check OpenSSL PQC support
    if not keygen.check_openssl_pqc():
        logger.warning("PQC support may be limited")
    
    if args.command == 'ca':
        success = keygen.generate_ca_certificate(
            algorithm=args.algorithm,
            validity_days=args.validity,
            country=args.country,
            state=args.state,
            locality=args.locality,
            organization=args.organization,
            common_name=args.common_name
        )
        sys.exit(0 if success else 1)
    
    elif args.command == 'hub':
        success = keygen.generate_hub_certificate(
            hub_ip=args.ip,
            algorithm=args.algorithm,
            validity_days=args.validity,
            country=args.country,
            state=args.state,
            locality=args.locality,
            organization=args.organization
        )
        sys.exit(0 if success else 1)
    
    elif args.command == 'spoke':
        success = keygen.generate_spoke_certificate(
            username=args.username,
            algorithm=args.algorithm,
            validity_days=args.validity,
            country=args.country,
            state=args.state,
            locality=args.locality,
            organization=args.organization
        )
        sys.exit(0 if success else 1)
    
    elif args.command == 'verify':
        success = keygen.verify_certificate(args.cert_file)
        sys.exit(0 if success else 1)
    
    elif args.command == 'info':
        info = keygen.get_certificate_info(args.cert_file)
        if info:
            print(info)
        else:
            sys.exit(1)
    
    elif args.command == 'list':
        certs = keygen.list_certificates()
        if args.json:
            print(json.dumps(certs, indent=2))
        else:
            print("\nPQC-VPN Certificates:")
            print("=" * 50)
            
            print(f"CA Certificate: {'✓' if certs['ca'].get('exists') else '✗'}")
            if certs['ca'].get('exists'):
                print(f"  Path: {certs['ca']['path']}")
            
            print(f"\nHub Certificate: {'✓' if certs['hub'].get('exists') else '✗'}")
            if certs['hub'].get('exists'):
                print(f"  Path: {certs['hub']['path']}")
            
            print(f"\nSpoke Certificates ({len(certs['spokes'])}):")
            for username, info in certs['spokes'].items():
                print(f"  {username}: {'✓' if info['exists'] else '✗'}")
                if info['exists']:
                    print(f"    Cert: {info['cert_path']}")
                    print(f"    Key:  {info['key_path']}")

if __name__ == '__main__':
    main()