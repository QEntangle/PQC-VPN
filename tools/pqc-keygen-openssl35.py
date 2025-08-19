#!/usr/bin/env python3
"""
PQC-VPN Certificate Generation Tool with OpenSSL 3.5 Support
Enterprise-grade certificate management for post-quantum cryptography readiness

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
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import yaml

# Configuration
OPENSSL_PREFIX = os.environ.get('OPENSSL_PREFIX', '/usr/local/openssl35')
OPENSSL_BIN = f"{OPENSSL_PREFIX}/bin/openssl"
OPENSSL_CONF = f"{OPENSSL_PREFIX}/ssl/openssl.cnf"
IPSEC_DIR = "/etc/ipsec.d"
CERT_DIR = f"{IPSEC_DIR}/certs"
PRIVATE_DIR = f"{IPSEC_DIR}/private"
CA_DIR = f"{IPSEC_DIR}/cacerts"
CRL_DIR = f"{IPSEC_DIR}/crls"

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/pqc-vpn/keygen.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class OpenSSL35CertificateManager:
    """Enterprise certificate manager using OpenSSL 3.5"""
    
    def __init__(self):
        self.openssl_bin = OPENSSL_BIN
        self.openssl_conf = OPENSSL_CONF
        self.validate_environment()
        
    def validate_environment(self):
        """Validate OpenSSL 3.5 environment"""
        try:
            # Check OpenSSL binary exists
            if not os.path.exists(self.openssl_bin):
                raise FileNotFoundError(f"OpenSSL binary not found: {self.openssl_bin}")
            
            # Check OpenSSL version
            result = subprocess.run(
                [self.openssl_bin, 'version'],
                capture_output=True, text=True, check=True
            )
            version = result.stdout.strip()
            logger.info(f"Using {version}")
            
            # Verify it's OpenSSL 3.5+
            version_parts = version.split()[1].split('.')
            major, minor = int(version_parts[0]), int(version_parts[1])
            if major < 3 or (major == 3 and minor < 5):
                logger.warning(f"OpenSSL version {version} may not support all enterprise features")
            
            # Check configuration file
            if not os.path.exists(self.openssl_conf):
                logger.warning(f"OpenSSL configuration not found: {self.openssl_conf}")
                
            # Set environment variables
            os.environ['OPENSSL_CONF'] = self.openssl_conf
            os.environ['LD_LIBRARY_PATH'] = f"{OPENSSL_PREFIX}/lib:{os.environ.get('LD_LIBRARY_PATH', '')}"
            
            logger.info("OpenSSL 3.5 environment validated successfully")
            
        except Exception as e:
            logger.error(f"Environment validation failed: {e}")
            raise
    
    def run_openssl_command(self, args: List[str], input_data: str = None) -> Tuple[str, str]:
        """Run OpenSSL command with proper environment"""
        try:
            cmd = [self.openssl_bin] + args
            logger.debug(f"Running command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                input=input_data,
                capture_output=True,
                text=True,
                check=True,
                env=os.environ.copy()
            )
            
            return result.stdout, result.stderr
        
        except subprocess.CalledProcessError as e:
            logger.error(f"OpenSSL command failed: {e}")
            logger.error(f"stdout: {e.stdout}")
            logger.error(f"stderr: {e.stderr}")
            raise
    
    def ensure_directories(self):
        """Ensure all required directories exist with proper permissions"""
        directories = [
            (CERT_DIR, 0o755),
            (PRIVATE_DIR, 0o700),
            (CA_DIR, 0o755),
            (CRL_DIR, 0o755),
            ("/var/log/pqc-vpn", 0o755)
        ]
        
        for directory, mode in directories:
            os.makedirs(directory, mode=mode, exist_ok=True)
            os.chmod(directory, mode)
            logger.debug(f"Directory {directory} ready with mode {oct(mode)}")
    
    def generate_rsa_key(self, key_size: int = 4096, output_file: str = None) -> str:
        """Generate RSA private key"""
        logger.info(f"Generating RSA-{key_size} private key")
        
        args = ['genrsa', '-out', output_file or '/dev/stdout', str(key_size)]
        
        if output_file:
            self.run_openssl_command(args)
            os.chmod(output_file, 0o600)
            logger.info(f"RSA key saved to {output_file}")
            return output_file
        else:
            stdout, _ = self.run_openssl_command(args)
            return stdout
    
    def generate_ecdsa_key(self, curve: str = 'secp384r1', output_file: str = None) -> str:
        """Generate ECDSA private key"""
        logger.info(f"Generating ECDSA key with curve {curve}")
        
        # Generate parameters first
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as param_file:
            param_args = ['ecparam', '-name', curve, '-out', param_file.name]
            self.run_openssl_command(param_args)
            
            # Generate key
            key_args = ['ecparam', '-in', param_file.name, '-genkey']
            if output_file:
                key_args.extend(['-out', output_file])
                self.run_openssl_command(key_args)
                os.chmod(output_file, 0o600)
                logger.info(f"ECDSA key saved to {output_file}")
                result = output_file
            else:
                stdout, _ = self.run_openssl_command(key_args)
                result = stdout
            
            # Cleanup
            os.unlink(param_file.name)
            return result
    
    def generate_ed25519_key(self, output_file: str = None) -> str:
        """Generate Ed25519 private key"""
        logger.info("Generating Ed25519 private key")
        
        args = ['genpkey', '-algorithm', 'Ed25519']
        if output_file:
            args.extend(['-out', output_file])
            self.run_openssl_command(args)
            os.chmod(output_file, 0o600)
            logger.info(f"Ed25519 key saved to {output_file}")
            return output_file
        else:
            stdout, _ = self.run_openssl_command(args)
            return stdout
    
    def create_certificate_request(self, private_key: str, subject: str, 
                                 san_list: List[str] = None, output_file: str = None) -> str:
        """Create certificate signing request"""
        logger.info(f"Creating certificate request for {subject}")
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as conf_file:
            # Create CSR configuration
            config = f"""[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
{self._parse_subject_to_dn(subject)}

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
"""
            
            if san_list:
                config += "subjectAltName = @alt_names\n\n[alt_names]\n"
                for i, san in enumerate(san_list, 1):
                    if san.startswith('IP:'):
                        config += f"IP.{i} = {san[3:]}\n"
                    else:
                        config += f"DNS.{i} = {san}\n"
            
            conf_file.write(config)
            conf_file.flush()
            
            args = ['req', '-new', '-key', private_key, '-config', conf_file.name]
            if output_file:
                args.extend(['-out', output_file])
                self.run_openssl_command(args)
                logger.info(f"CSR saved to {output_file}")
                result = output_file
            else:
                stdout, _ = self.run_openssl_command(args)
                result = stdout
            
            # Cleanup
            os.unlink(conf_file.name)
            return result
    
    def _parse_subject_to_dn(self, subject: str) -> str:
        """Convert subject string to distinguished name format"""
        # Handle subjects like "/C=US/ST=CA/O=Company/CN=example.com"
        if subject.startswith('/'):
            parts = subject[1:].split('/')
            dn_parts = []
            for part in parts:
                if '=' in part:
                    key, value = part.split('=', 1)
                    dn_parts.append(f"{key} = {value}")
            return '\n'.join(dn_parts)
        else:
            # Assume it's already in proper format or just a CN
            if '=' not in subject:
                return f"CN = {subject}"
            return subject.replace('/', '\n').replace('=', ' = ')
    
    def sign_certificate(self, csr: str, ca_cert: str, ca_key: str, 
                        days: int = 365, extensions: str = None, 
                        output_file: str = None) -> str:
        """Sign certificate with CA"""
        logger.info(f"Signing certificate for {days} days")
        
        args = ['x509', '-req', '-in', csr, '-CA', ca_cert, '-CAkey', ca_key,
                '-CAcreateserial', '-days', str(days)]
        
        if extensions:
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as ext_file:
                ext_file.write(extensions)
                ext_file.flush()
                args.extend(['-extensions', 'cert_ext', '-extfile', ext_file.name])
                
                if output_file:
                    args.extend(['-out', output_file])
                    self.run_openssl_command(args)
                    logger.info(f"Certificate saved to {output_file}")
                    result = output_file
                else:
                    stdout, _ = self.run_openssl_command(args)
                    result = stdout
                
                os.unlink(ext_file.name)
                return result
        else:
            if output_file:
                args.extend(['-out', output_file])
                self.run_openssl_command(args)
                logger.info(f"Certificate saved to {output_file}")
                return output_file
            else:
                stdout, _ = self.run_openssl_command(args)
                return stdout
    
    def create_self_signed_certificate(self, private_key: str, subject: str, 
                                     days: int = 3650, san_list: List[str] = None,
                                     output_file: str = None, is_ca: bool = False) -> str:
        """Create self-signed certificate"""
        logger.info(f"Creating self-signed certificate for {subject}")
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as conf_file:
            config = f"""[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ext
prompt = no

[req_distinguished_name]
{self._parse_subject_to_dn(subject)}

[v3_ext]
"""
            if is_ca:
                config += """basicConstraints = critical,CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
"""
            else:
                config += """basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
extendedKeyUsage = serverAuth, clientAuth
"""
            
            if san_list:
                config += "subjectAltName = @alt_names\n\n[alt_names]\n"
                for i, san in enumerate(san_list, 1):
                    if san.startswith('IP:'):
                        config += f"IP.{i} = {san[3:]}\n"
                    else:
                        config += f"DNS.{i} = {san}\n"
            
            conf_file.write(config)
            conf_file.flush()
            
            args = ['req', '-new', '-x509', '-key', private_key, '-config', conf_file.name,
                    '-days', str(days)]
            
            if output_file:
                args.extend(['-out', output_file])
                self.run_openssl_command(args)
                logger.info(f"Self-signed certificate saved to {output_file}")
                result = output_file
            else:
                stdout, _ = self.run_openssl_command(args)
                result = stdout
            
            os.unlink(conf_file.name)
            return result
    
    def get_certificate_info(self, cert_file: str) -> Dict:
        """Get certificate information"""
        try:
            # Get subject
            stdout, _ = self.run_openssl_command(['x509', '-in', cert_file, '-noout', '-subject'])
            subject = stdout.strip().replace('subject=', '')
            
            # Get issuer
            stdout, _ = self.run_openssl_command(['x509', '-in', cert_file, '-noout', '-issuer'])
            issuer = stdout.strip().replace('issuer=', '')
            
            # Get dates
            stdout, _ = self.run_openssl_command(['x509', '-in', cert_file, '-noout', '-dates'])
            dates = {}
            for line in stdout.strip().split('\n'):
                if '=' in line:
                    key, value = line.split('=', 1)
                    dates[key] = value
            
            # Get serial number
            stdout, _ = self.run_openssl_command(['x509', '-in', cert_file, '-noout', '-serial'])
            serial = stdout.strip().replace('serial=', '')
            
            # Get fingerprint
            stdout, _ = self.run_openssl_command(['x509', '-in', cert_file, '-noout', '-fingerprint', '-sha256'])
            fingerprint = stdout.strip().replace('SHA256 Fingerprint=', '')
            
            # Get key usage
            try:
                stdout, _ = self.run_openssl_command(['x509', '-in', cert_file, '-noout', '-ext', 'keyUsage'])
                key_usage = stdout.strip()
            except:
                key_usage = "Not available"
            
            return {
                'subject': subject,
                'issuer': issuer,
                'dates': dates,
                'serial': serial,
                'fingerprint': fingerprint,
                'key_usage': key_usage,
                'file': cert_file
            }
            
        except Exception as e:
            logger.error(f"Failed to get certificate info: {e}")
            return {}
    
    def verify_certificate(self, cert_file: str, ca_file: str = None) -> bool:
        """Verify certificate against CA"""
        try:
            args = ['verify']
            if ca_file:
                args.extend(['-CAfile', ca_file])
            args.append(cert_file)
            
            self.run_openssl_command(args)
            logger.info(f"Certificate {cert_file} verification passed")
            return True
            
        except subprocess.CalledProcessError:
            logger.error(f"Certificate {cert_file} verification failed")
            return False
    
    def generate_ca_certificate(self, key_type: str = 'rsa', key_size: int = 4096,
                              subject: str = None, days: int = 3650) -> Tuple[str, str]:
        """Generate CA certificate and key"""
        self.ensure_directories()
        
        ca_key_file = f"{PRIVATE_DIR}/ca-key.pem"
        ca_cert_file = f"{CA_DIR}/ca-cert.pem"
        
        # Default subject for CA
        if not subject:
            subject = "/C=US/ST=California/L=San Francisco/O=PQC-VPN Enterprise/OU=Certificate Authority/CN=PQC-VPN Root CA"
        
        logger.info("Generating Certificate Authority")
        
        # Generate CA private key
        if key_type.lower() == 'rsa':
            self.generate_rsa_key(key_size, ca_key_file)
        elif key_type.lower() == 'ecdsa':
            curve = 'secp384r1' if key_size >= 384 else 'secp256r1'
            self.generate_ecdsa_key(curve, ca_key_file)
        elif key_type.lower() == 'ed25519':
            self.generate_ed25519_key(ca_key_file)
        else:
            raise ValueError(f"Unsupported key type: {key_type}")
        
        # Generate CA certificate
        self.create_self_signed_certificate(
            ca_key_file, subject, days, is_ca=True, output_file=ca_cert_file
        )
        
        # Set proper permissions
        os.chmod(ca_key_file, 0o600)
        os.chmod(ca_cert_file, 0o644)
        
        logger.info(f"CA certificate generated: {ca_cert_file}")
        return ca_cert_file, ca_key_file
    
    def generate_server_certificate(self, hostname: str, ip_addresses: List[str] = None,
                                   dns_names: List[str] = None, key_type: str = 'rsa',
                                   key_size: int = 4096, days: int = 365) -> Tuple[str, str]:
        """Generate server certificate"""
        self.ensure_directories()
        
        server_key_file = f"{PRIVATE_DIR}/{hostname}-key.pem"
        server_cert_file = f"{CERT_DIR}/{hostname}-cert.pem"
        ca_cert_file = f"{CA_DIR}/ca-cert.pem"
        ca_key_file = f"{PRIVATE_DIR}/ca-key.pem"
        
        # Check if CA exists
        if not os.path.exists(ca_cert_file) or not os.path.exists(ca_key_file):
            logger.info("CA not found, generating new CA")
            self.generate_ca_certificate(key_type, key_size)
        
        subject = f"/C=US/ST=California/L=San Francisco/O=PQC-VPN Enterprise/OU=VPN Server/CN={hostname}"
        
        logger.info(f"Generating server certificate for {hostname}")
        
        # Generate server private key
        if key_type.lower() == 'rsa':
            self.generate_rsa_key(key_size, server_key_file)
        elif key_type.lower() == 'ecdsa':
            curve = 'secp384r1' if key_size >= 384 else 'secp256r1'
            self.generate_ecdsa_key(curve, server_key_file)
        elif key_type.lower() == 'ed25519':
            self.generate_ed25519_key(server_key_file)
        else:
            raise ValueError(f"Unsupported key type: {key_type}")
        
        # Prepare SAN list
        san_list = [hostname, 'localhost']
        if dns_names:
            san_list.extend(dns_names)
        if ip_addresses:
            san_list.extend([f"IP:{ip}" for ip in ip_addresses])
        
        # Create CSR
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csr') as csr_file:
            self.create_certificate_request(server_key_file, subject, san_list, csr_file.name)
            
            # Create certificate extensions
            extensions = f"""[cert_ext]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "PQC-VPN Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment, keyAgreement
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
"""
            for i, san in enumerate(san_list, 1):
                if san.startswith('IP:'):
                    extensions += f"IP.{i} = {san[3:]}\n"
                else:
                    extensions += f"DNS.{i} = {san}\n"
            
            # Sign certificate
            self.sign_certificate(
                csr_file.name, ca_cert_file, ca_key_file, 
                days, extensions, server_cert_file
            )
            
            # Cleanup
            os.unlink(csr_file.name)
        
        # Set proper permissions
        os.chmod(server_key_file, 0o600)
        os.chmod(server_cert_file, 0o644)
        
        logger.info(f"Server certificate generated: {server_cert_file}")
        return server_cert_file, server_key_file
    
    def generate_client_certificate(self, username: str, email: str = None,
                                   key_type: str = 'rsa', key_size: int = 2048,
                                   days: int = 365) -> Tuple[str, str]:
        """Generate client certificate"""
        self.ensure_directories()
        
        client_key_file = f"{PRIVATE_DIR}/{username}-key.pem"
        client_cert_file = f"{CERT_DIR}/{username}-cert.pem"
        ca_cert_file = f"{CA_DIR}/ca-cert.pem"
        ca_key_file = f"{PRIVATE_DIR}/ca-key.pem"
        
        # Check if CA exists
        if not os.path.exists(ca_cert_file) or not os.path.exists(ca_key_file):
            logger.info("CA not found, generating new CA")
            self.generate_ca_certificate()
        
        subject = f"/C=US/ST=California/L=San Francisco/O=PQC-VPN Enterprise/OU=VPN Client/CN={username}"
        if email:
            subject += f"/emailAddress={email}"
        
        logger.info(f"Generating client certificate for {username}")
        
        # Generate client private key
        if key_type.lower() == 'rsa':
            self.generate_rsa_key(key_size, client_key_file)
        elif key_type.lower() == 'ecdsa':
            curve = 'secp256r1' if key_size <= 256 else 'secp384r1'
            self.generate_ecdsa_key(curve, client_key_file)
        elif key_type.lower() == 'ed25519':
            self.generate_ed25519_key(client_key_file)
        else:
            raise ValueError(f"Unsupported key type: {key_type}")
        
        # Create CSR
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csr') as csr_file:
            self.create_certificate_request(client_key_file, subject, output_file=csr_file.name)
            
            # Create certificate extensions
            extensions = f"""[cert_ext]
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "PQC-VPN Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth, emailProtection
"""
            
            # Sign certificate
            self.sign_certificate(
                csr_file.name, ca_cert_file, ca_key_file,
                days, extensions, client_cert_file
            )
            
            # Cleanup
            os.unlink(csr_file.name)
        
        # Set proper permissions
        os.chmod(client_key_file, 0o600)
        os.chmod(client_cert_file, 0o644)
        
        logger.info(f"Client certificate generated: {client_cert_file}")
        return client_cert_file, client_key_file
    
    def list_certificates(self) -> List[Dict]:
        """List all certificates with information"""
        certificates = []
        
        # Check certificate directory
        if os.path.exists(CERT_DIR):
            for cert_file in Path(CERT_DIR).glob("*.pem"):
                cert_info = self.get_certificate_info(str(cert_file))
                if cert_info:
                    certificates.append(cert_info)
        
        # Check CA directory
        if os.path.exists(CA_DIR):
            for cert_file in Path(CA_DIR).glob("*.pem"):
                cert_info = self.get_certificate_info(str(cert_file))
                if cert_info:
                    cert_info['type'] = 'CA'
                    certificates.append(cert_info)
        
        return certificates
    
    def export_certificate_bundle(self, cert_name: str, output_format: str = 'p12',
                                 password: str = None) -> str:
        """Export certificate bundle"""
        cert_file = f"{CERT_DIR}/{cert_name}-cert.pem"
        key_file = f"{PRIVATE_DIR}/{cert_name}-key.pem"
        ca_file = f"{CA_DIR}/ca-cert.pem"
        
        if not all(os.path.exists(f) for f in [cert_file, key_file]):
            raise FileNotFoundError(f"Certificate or key not found for {cert_name}")
        
        output_file = f"{CERT_DIR}/{cert_name}.{output_format}"
        
        if output_format.lower() == 'p12':
            args = ['pkcs12', '-export', '-in', cert_file, '-inkey', key_file]
            if os.path.exists(ca_file):
                args.extend(['-certfile', ca_file])
            args.extend(['-out', output_file])
            
            if password:
                args.extend(['-passout', f'pass:{password}'])
            else:
                args.append('-nodes')
            
            self.run_openssl_command(args)
            logger.info(f"PKCS#12 bundle exported: {output_file}")
            
        elif output_format.lower() == 'pem':
            # Combine cert, key, and CA into single PEM file
            with open(output_file, 'w') as outf:
                with open(cert_file, 'r') as inf:
                    outf.write(inf.read())
                with open(key_file, 'r') as inf:
                    outf.write(inf.read())
                if os.path.exists(ca_file):
                    with open(ca_file, 'r') as inf:
                        outf.write(inf.read())
            
            logger.info(f"PEM bundle exported: {output_file}")
        
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
        
        return output_file


def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(
        description='PQC-VPN Certificate Generator with OpenSSL 3.5 Support',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate CA certificate
  %(prog)s ca --key-type rsa --key-size 4096

  # Generate server certificate
  %(prog)s server hub.example.com --ip 192.168.1.100 --dns hub.local

  # Generate client certificate
  %(prog)s client alice --email alice@example.com

  # List all certificates
  %(prog)s list

  # Export certificate bundle
  %(prog)s export alice --format p12 --password secret123
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # CA command
    ca_parser = subparsers.add_parser('ca', help='Generate CA certificate')
    ca_parser.add_argument('--key-type', choices=['rsa', 'ecdsa', 'ed25519'], 
                          default='rsa', help='Key type (default: rsa)')
    ca_parser.add_argument('--key-size', type=int, default=4096,
                          help='Key size in bits (default: 4096)')
    ca_parser.add_argument('--days', type=int, default=3650,
                          help='Certificate validity in days (default: 3650)')
    ca_parser.add_argument('--subject', help='Certificate subject')
    
    # Server command
    server_parser = subparsers.add_parser('server', help='Generate server certificate')
    server_parser.add_argument('hostname', help='Server hostname')
    server_parser.add_argument('--ip', action='append', dest='ip_addresses',
                              help='IP addresses (can be used multiple times)')
    server_parser.add_argument('--dns', action='append', dest='dns_names',
                              help='DNS names (can be used multiple times)')
    server_parser.add_argument('--key-type', choices=['rsa', 'ecdsa', 'ed25519'],
                              default='rsa', help='Key type (default: rsa)')
    server_parser.add_argument('--key-size', type=int, default=4096,
                              help='Key size in bits (default: 4096)')
    server_parser.add_argument('--days', type=int, default=365,
                              help='Certificate validity in days (default: 365)')
    
    # Client command
    client_parser = subparsers.add_parser('client', help='Generate client certificate')
    client_parser.add_argument('username', help='Username')
    client_parser.add_argument('--email', help='Email address')
    client_parser.add_argument('--key-type', choices=['rsa', 'ecdsa', 'ed25519'],
                              default='rsa', help='Key type (default: rsa)')
    client_parser.add_argument('--key-size', type=int, default=2048,
                              help='Key size in bits (default: 2048)')
    client_parser.add_argument('--days', type=int, default=365,
                              help='Certificate validity in days (default: 365)')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List certificates')
    list_parser.add_argument('--format', choices=['table', 'json', 'yaml'],
                            default='table', help='Output format (default: table)')
    
    # Export command
    export_parser = subparsers.add_parser('export', help='Export certificate bundle')
    export_parser.add_argument('cert_name', help='Certificate name')
    export_parser.add_argument('--format', choices=['p12', 'pem'], default='p12',
                               help='Export format (default: p12)')
    export_parser.add_argument('--password', help='Password for PKCS#12 export')
    
    # Info command
    info_parser = subparsers.add_parser('info', help='Show certificate information')
    info_parser.add_argument('cert_file', help='Certificate file path')
    
    # Verify command
    verify_parser = subparsers.add_parser('verify', help='Verify certificate')
    verify_parser.add_argument('cert_file', help='Certificate file path')
    verify_parser.add_argument('--ca', help='CA certificate file')
    
    # Version command
    version_parser = subparsers.add_parser('version', help='Show version information')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        cert_manager = OpenSSL35CertificateManager()
        
        if args.command == 'ca':
            cert_file, key_file = cert_manager.generate_ca_certificate(
                args.key_type, args.key_size, args.subject, args.days
            )
            print(f"CA certificate generated:")
            print(f"  Certificate: {cert_file}")
            print(f"  Private key: {key_file}")
        
        elif args.command == 'server':
            cert_file, key_file = cert_manager.generate_server_certificate(
                args.hostname, args.ip_addresses, args.dns_names,
                args.key_type, args.key_size, args.days
            )
            print(f"Server certificate generated:")
            print(f"  Certificate: {cert_file}")
            print(f"  Private key: {key_file}")
        
        elif args.command == 'client':
            cert_file, key_file = cert_manager.generate_client_certificate(
                args.username, args.email, args.key_type, args.key_size, args.days
            )
            print(f"Client certificate generated:")
            print(f"  Certificate: {cert_file}")
            print(f"  Private key: {key_file}")
        
        elif args.command == 'list':
            certificates = cert_manager.list_certificates()
            
            if args.format == 'json':
                print(json.dumps(certificates, indent=2, default=str))
            elif args.format == 'yaml':
                print(yaml.dump(certificates, default_flow_style=False))
            else:
                # Table format
                print(f"{'Type':<8} {'Subject':<50} {'Expires':<20} {'File':<30}")
                print("-" * 120)
                for cert in certificates:
                    cert_type = cert.get('type', 'Cert')
                    subject = cert.get('subject', 'Unknown')[:48]
                    expires = cert.get('dates', {}).get('notAfter', 'Unknown')[:18]
                    filename = os.path.basename(cert.get('file', ''))[:28]
                    print(f"{cert_type:<8} {subject:<50} {expires:<20} {filename:<30}")
        
        elif args.command == 'export':
            output_file = cert_manager.export_certificate_bundle(
                args.cert_name, args.format, args.password
            )
            print(f"Certificate bundle exported: {output_file}")
        
        elif args.command == 'info':
            cert_info = cert_manager.get_certificate_info(args.cert_file)
            if cert_info:
                print(f"Certificate Information:")
                print(f"  Subject: {cert_info.get('subject')}")
                print(f"  Issuer: {cert_info.get('issuer')}")
                print(f"  Serial: {cert_info.get('serial')}")
                print(f"  Valid from: {cert_info.get('dates', {}).get('notBefore')}")
                print(f"  Valid until: {cert_info.get('dates', {}).get('notAfter')}")
                print(f"  Fingerprint: {cert_info.get('fingerprint')}")
            else:
                print("Failed to get certificate information")
        
        elif args.command == 'verify':
            ca_file = args.ca or f"{CA_DIR}/ca-cert.pem"
            is_valid = cert_manager.verify_certificate(args.cert_file, ca_file)
            print(f"Certificate verification: {'PASSED' if is_valid else 'FAILED'}")
        
        elif args.command == 'version':
            # Get OpenSSL version
            stdout, _ = cert_manager.run_openssl_command(['version', '-a'])
            print("PQC-VPN Certificate Generator v3.0.0")
            print("OpenSSL 3.5 Native Implementation")
            print("\nOpenSSL Information:")
            print(stdout)
    
    except Exception as e:
        logger.error(f"Command failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
