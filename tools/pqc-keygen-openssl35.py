#!/usr/bin/env python3
"""
PQC-VPN Certificate Generation Tool with OpenSSL 3.5 Support
Enterprise-grade certificate management for post-quantum readiness

Author: PQC-VPN Team
Version: 3.0.0
License: MIT
"""

import os
import sys
import subprocess
import argparse
import json
import logging
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import yaml

# Configuration
OPENSSL_PREFIX = "/usr/local/openssl35"
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
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class OpenSSLError(Exception):
    """Custom exception for OpenSSL operations"""
    pass

class PQCCertificateManager:
    """
    Enterprise certificate manager with OpenSSL 3.5 support
    Handles CA, server, and client certificate generation
    """
    
    def __init__(self, openssl_bin: str = OPENSSL_BIN, openssl_conf: str = OPENSSL_CONF):
        self.openssl_bin = openssl_bin
        self.openssl_conf = openssl_conf
        self.validate_environment()
        
    def validate_environment(self) -> None:
        """Validate OpenSSL 3.5 installation and environment"""
        if not os.path.exists(self.openssl_bin):
            raise OpenSSLError(f"OpenSSL binary not found: {self.openssl_bin}")
            
        if not os.path.exists(self.openssl_conf):
            raise OpenSSLError(f"OpenSSL config not found: {self.openssl_conf}")
            
        # Check OpenSSL version
        try:
            result = self._run_openssl_command(['version'])
            version = result.split()[1]
            if not version.startswith('3.'):
                raise OpenSSLError(f"OpenSSL 3.x required, found: {version}")
            logger.info(f"OpenSSL version validated: {version}")
        except Exception as e:
            raise OpenSSLError(f"Failed to validate OpenSSL: {e}")
    
    def _run_openssl_command(self, args: List[str], input_data: Optional[str] = None) -> str:
        """Execute OpenSSL command with proper environment"""
        env = os.environ.copy()
        env.update({
            'OPENSSL_CONF': self.openssl_conf,
            'LD_LIBRARY_PATH': f"{OPENSSL_PREFIX}/lib:{env.get('LD_LIBRARY_PATH', '')}",
            'PATH': f"{OPENSSL_PREFIX}/bin:{env.get('PATH', '')}"
        })
        
        cmd = [self.openssl_bin] + args
        logger.debug(f"Executing: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                input=input_data,
                text=True,
                capture_output=True,
                check=True,
                env=env
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            logger.error(f"OpenSSL command failed: {e.stderr}")
            raise OpenSSLError(f"Command failed: {' '.join(cmd)}\nError: {e.stderr}")
    
    def _ensure_directories(self) -> None:
        """Ensure all required directories exist with proper permissions"""
        directories = [
            (CERT_DIR, 0o755),
            (PRIVATE_DIR, 0o700),
            (CA_DIR, 0o755),
            (CRL_DIR, 0o755),
            ('/var/log/pqc-vpn', 0o755)
        ]
        
        for directory, mode in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)
            os.chmod(directory, mode)
            logger.debug(f"Directory ensured: {directory} (mode: {oct(mode)})")
    
    def generate_ca_certificate(self, 
                              subject: str = "/C=US/ST=CA/L=San Francisco/O=PQC-VPN Enterprise/OU=Certificate Authority/CN=PQC-VPN Root CA",
                              key_type: str = "rsa",
                              key_size: int = 4096,
                              validity_days: int = 3650,
                              force: bool = False) -> Tuple[str, str]:
        """
        Generate Certificate Authority certificate with OpenSSL 3.5
        
        Args:
            subject: Certificate subject DN
            key_type: Key type (rsa, ec)
            key_size: Key size for RSA (2048, 3072, 4096) or EC curve name
            validity_days: Certificate validity period
            force: Overwrite existing CA
            
        Returns:
            Tuple of (ca_cert_path, ca_key_path)
        """
        self._ensure_directories()
        
        ca_key_path = f"{PRIVATE_DIR}/ca-key.pem"
        ca_cert_path = f"{CA_DIR}/ca-cert.pem"
        
        # Check if CA already exists
        if os.path.exists(ca_cert_path) and not force:
            logger.info("CA certificate already exists. Use --force to overwrite.")
            return ca_cert_path, ca_key_path
        
        logger.info(f"Generating CA certificate with {key_type} key...")
        
        try:
            # Generate CA private key
            if key_type.lower() == "rsa":
                self._run_openssl_command([
                    'genrsa', '-out', ca_key_path, str(key_size)
                ])
                logger.info(f"Generated RSA-{key_size} CA private key")
            elif key_type.lower() == "ec":
                curve_name = key_size if isinstance(key_size, str) else "secp384r1"
                self._run_openssl_command([
                    'ecparam', '-genkey', '-name', curve_name, '-out', ca_key_path
                ])
                logger.info(f"Generated EC {curve_name} CA private key")
            else:
                raise OpenSSLError(f"Unsupported key type: {key_type}")
            
            # Generate CA certificate
            ca_config = self._create_ca_config(subject, validity_days)
            
            self._run_openssl_command([
                'req', '-new', '-x509',
                '-key', ca_key_path,
                '-out', ca_cert_path,
                '-days', str(validity_days),
                '-config', ca_config,
                '-extensions', 'v3_ca',
                '-subj', subject
            ])
            
            # Set proper permissions
            os.chmod(ca_key_path, 0o600)
            os.chmod(ca_cert_path, 0o644)
            
            # Verify certificate
            cert_info = self._get_certificate_info(ca_cert_path)
            logger.info(f"CA certificate generated successfully")
            logger.info(f"Subject: {cert_info['subject']}")
            logger.info(f"Valid until: {cert_info['not_after']}")
            
            # Initialize CA database
            self._initialize_ca_database()
            
            return ca_cert_path, ca_key_path
            
        except Exception as e:
            logger.error(f"Failed to generate CA certificate: {e}")
            raise
    
    def generate_server_certificate(self,
                                  hostname: str,
                                  subject: str = None,
                                  san_list: List[str] = None,
                                  key_type: str = "rsa",
                                  key_size: int = 4096,
                                  validity_days: int = 365) -> Tuple[str, str]:
        """
        Generate server certificate signed by CA
        
        Args:
            hostname: Server hostname (used in CN and SAN)
            subject: Certificate subject DN (auto-generated if None)
            san_list: List of Subject Alternative Names
            key_type: Key type (rsa, ec)
            key_size: Key size or curve name
            validity_days: Certificate validity period
            
        Returns:
            Tuple of (cert_path, key_path)
        """
        self._ensure_directories()
        
        if subject is None:
            subject = f"/C=US/ST=CA/L=San Francisco/O=PQC-VPN Enterprise/OU=VPN Server/CN={hostname}"
        
        if san_list is None:
            san_list = ['localhost', hostname, f'*.{hostname}']
        
        cert_path = f"{CERT_DIR}/{hostname}-cert.pem"
        key_path = f"{PRIVATE_DIR}/{hostname}-key.pem"
        csr_path = f"/tmp/{hostname}-csr.pem"
        
        logger.info(f"Generating server certificate for {hostname}...")
        
        try:
            # Generate server private key
            if key_type.lower() == "rsa":
                self._run_openssl_command([
                    'genrsa', '-out', key_path, str(key_size)
                ])
            elif key_type.lower() == "ec":
                curve_name = key_size if isinstance(key_size, str) else "secp384r1"
                self._run_openssl_command([
                    'ecparam', '-genkey', '-name', curve_name, '-out', key_path
                ])
            
            # Generate certificate signing request
            self._run_openssl_command([
                'req', '-new',
                '-key', key_path,
                '-out', csr_path,
                '-subj', subject,
                '-config', self.openssl_conf
            ])
            
            # Create server certificate extension config
            ext_config = self._create_server_ext_config(san_list)
            
            # Sign certificate with CA
            ca_cert_path = f"{CA_DIR}/ca-cert.pem"
            ca_key_path = f"{PRIVATE_DIR}/ca-key.pem"
            
            if not os.path.exists(ca_cert_path):
                raise OpenSSLError("CA certificate not found. Generate CA first.")
            
            self._run_openssl_command([
                'x509', '-req',
                '-in', csr_path,
                '-CA', ca_cert_path,
                '-CAkey', ca_key_path,
                '-CAcreateserial',
                '-out', cert_path,
                '-days', str(validity_days),
                '-extensions', 'server_cert',
                '-extfile', ext_config
            ])
            
            # Set proper permissions
            os.chmod(key_path, 0o600)
            os.chmod(cert_path, 0o644)
            
            # Clean up
            os.unlink(csr_path)
            os.unlink(ext_config)
            
            # Verify certificate
            cert_info = self._get_certificate_info(cert_path)
            logger.info(f"Server certificate generated successfully")
            logger.info(f"Subject: {cert_info['subject']}")
            logger.info(f"SAN: {', '.join(san_list)}")
            logger.info(f"Valid until: {cert_info['not_after']}")
            
            return cert_path, key_path
            
        except Exception as e:
            logger.error(f"Failed to generate server certificate: {e}")
            # Clean up on failure
            for path in [csr_path, cert_path, key_path]:
                if os.path.exists(path):
                    os.unlink(path)
            raise
    
    def generate_client_certificate(self,
                                   client_name: str,
                                   email: str = None,
                                   subject: str = None,
                                   key_type: str = "rsa",
                                   key_size: int = 4096,
                                   validity_days: int = 365) -> Tuple[str, str]:
        """
        Generate client certificate for VPN authentication
        
        Args:
            client_name: Client identifier
            email: Client email address
            subject: Certificate subject DN (auto-generated if None)
            key_type: Key type (rsa, ec)
            key_size: Key size or curve name
            validity_days: Certificate validity period
            
        Returns:
            Tuple of (cert_path, key_path)
        """
        self._ensure_directories()
        
        if subject is None:
            email_part = f"/emailAddress={email}" if email else ""
            subject = f"/C=US/ST=CA/L=San Francisco/O=PQC-VPN Enterprise/OU=VPN Client/CN={client_name}{email_part}"
        
        cert_path = f"{CERT_DIR}/{client_name}-cert.pem"
        key_path = f"{PRIVATE_DIR}/{client_name}-key.pem"
        csr_path = f"/tmp/{client_name}-csr.pem"
        
        logger.info(f"Generating client certificate for {client_name}...")
        
        try:
            # Generate client private key
            if key_type.lower() == "rsa":
                self._run_openssl_command([
                    'genrsa', '-out', key_path, str(key_size)
                ])
            elif key_type.lower() == "ec":
                curve_name = key_size if isinstance(key_size, str) else "secp256r1"
                self._run_openssl_command([
                    'ecparam', '-genkey', '-name', curve_name, '-out', key_path
                ])
            
            # Generate certificate signing request
            self._run_openssl_command([
                'req', '-new',
                '-key', key_path,
                '-out', csr_path,
                '-subj', subject,
                '-config', self.openssl_conf
            ])
            
            # Create client certificate extension config
            ext_config = self._create_client_ext_config(email)
            
            # Sign certificate with CA
            ca_cert_path = f"{CA_DIR}/ca-cert.pem"
            ca_key_path = f"{PRIVATE_DIR}/ca-key.pem"
            
            if not os.path.exists(ca_cert_path):
                raise OpenSSLError("CA certificate not found. Generate CA first.")
            
            self._run_openssl_command([
                'x509', '-req',
                '-in', csr_path,
                '-CA', ca_cert_path,
                '-CAkey', ca_key_path,
                '-CAcreateserial',
                '-out', cert_path,
                '-days', str(validity_days),
                '-extensions', 'client_cert',
                '-extfile', ext_config
            ])
            
            # Set proper permissions
            os.chmod(key_path, 0o600)
            os.chmod(cert_path, 0o644)
            
            # Clean up
            os.unlink(csr_path)
            os.unlink(ext_config)
            
            # Verify certificate
            cert_info = self._get_certificate_info(cert_path)
            logger.info(f"Client certificate generated successfully")
            logger.info(f"Subject: {cert_info['subject']}")
            logger.info(f"Valid until: {cert_info['not_after']}")
            
            return cert_path, key_path
            
        except Exception as e:
            logger.error(f"Failed to generate client certificate: {e}")
            # Clean up on failure
            for path in [csr_path, cert_path, key_path]:
                if os.path.exists(path):
                    os.unlink(path)
            raise
    
    def create_pkcs12(self, cert_path: str, key_path: str, 
                      ca_cert_path: str = None, password: str = None) -> str:
        """
        Create PKCS#12 bundle for client distribution
        
        Args:
            cert_path: Client certificate path
            key_path: Client private key path
            ca_cert_path: CA certificate path (optional)
            password: PKCS#12 password (optional)
            
        Returns:
            Path to PKCS#12 file
        """
        if ca_cert_path is None:
            ca_cert_path = f"{CA_DIR}/ca-cert.pem"
        
        basename = os.path.basename(cert_path).replace('-cert.pem', '')
        p12_path = f"{CERT_DIR}/{basename}.p12"
        
        cmd = [
            'pkcs12', '-export',
            '-out', p12_path,
            '-inkey', key_path,
            '-in', cert_path
        ]
        
        if os.path.exists(ca_cert_path):
            cmd.extend(['-certfile', ca_cert_path])
        
        if password:
            cmd.extend(['-passout', f'pass:{password}'])
        else:
            cmd.extend(['-passout', 'pass:'])
        
        self._run_openssl_command(cmd)
        
        logger.info(f"PKCS#12 bundle created: {p12_path}")
        return p12_path
    
    def revoke_certificate(self, cert_path: str, reason: str = "unspecified") -> None:
        """
        Revoke a certificate and update CRL
        
        Args:
            cert_path: Path to certificate to revoke
            reason: Revocation reason
        """
        ca_key_path = f"{PRIVATE_DIR}/ca-key.pem"
        ca_cert_path = f"{CA_DIR}/ca-cert.pem"
        crl_path = f"{CRL_DIR}/ca.crl"
        
        # Add certificate to revocation database
        self._run_openssl_command([
            'ca', '-revoke', cert_path,
            '-keyfile', ca_key_path,
            '-cert', ca_cert_path,
            '-config', self.openssl_conf,
            '-crl_reason', reason
        ])
        
        # Generate updated CRL
        self._run_openssl_command([
            'ca', '-gencrl',
            '-keyfile', ca_key_path,
            '-cert', ca_cert_path,
            '-out', crl_path,
            '-config', self.openssl_conf
        ])
        
        logger.info(f"Certificate revoked and CRL updated: {cert_path}")
    
    def verify_certificate(self, cert_path: str, ca_cert_path: str = None) -> bool:
        """
        Verify certificate against CA
        
        Args:
            cert_path: Certificate to verify
            ca_cert_path: CA certificate (optional)
            
        Returns:
            True if valid, False otherwise
        """
        if ca_cert_path is None:
            ca_cert_path = f"{CA_DIR}/ca-cert.pem"
        
        try:
            self._run_openssl_command([
                'verify', '-CAfile', ca_cert_path, cert_path
            ])
            logger.info(f"Certificate verification successful: {cert_path}")
            return True
        except OpenSSLError:
            logger.error(f"Certificate verification failed: {cert_path}")
            return False
    
    def _create_ca_config(self, subject: str, validity_days: int) -> str:
        """Create CA configuration file"""
        config_content = f"""
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_ca
prompt = no

[req_distinguished_name]

[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
certificatePolicies = @ca_policy

[ca_policy]
policyIdentifier = 2.23.140.1.2.1
CPS.1 = "https://pqc-vpn.local/cps"
"""
        
        fd, config_path = tempfile.mkstemp(suffix='.cnf', text=True)
        with os.fdopen(fd, 'w') as f:
            f.write(config_content)
        
        return config_path
    
    def _create_server_ext_config(self, san_list: List[str]) -> str:
        """Create server certificate extension configuration"""
        san_entries = []
        dns_count = 1
        ip_count = 1
        
        for san in san_list:
            if self._is_ip_address(san):
                san_entries.append(f"IP.{ip_count} = {san}")
                ip_count += 1
            else:
                san_entries.append(f"DNS.{dns_count} = {san}")
                dns_count += 1
        
        config_content = f"""
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "PQC-VPN Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment, keyAgreement
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
{chr(10).join(san_entries)}
"""
        
        fd, config_path = tempfile.mkstemp(suffix='.cnf', text=True)
        with os.fdopen(fd, 'w') as f:
            f.write(config_content)
        
        return config_path
    
    def _create_client_ext_config(self, email: str = None) -> str:
        """Create client certificate extension configuration"""
        email_san = f"email.1 = {email}" if email else ""
        
        config_content = f"""
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "PQC-VPN Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth, emailProtection
{f'subjectAltName = @alt_names' if email else ''}

{f'[alt_names]' if email else ''}
{email_san}
"""
        
        fd, config_path = tempfile.mkstemp(suffix='.cnf', text=True)
        with os.fdopen(fd, 'w') as f:
            f.write(config_content)
        
        return config_path
    
    def _initialize_ca_database(self) -> None:
        """Initialize CA database files"""
        ca_dir = f"{OPENSSL_PREFIX}/ssl"
        
        # Create index file
        index_file = f"{ca_dir}/index.txt"
        if not os.path.exists(index_file):
            Path(index_file).touch()
        
        # Create serial file
        serial_file = f"{ca_dir}/serial"
        if not os.path.exists(serial_file):
            with open(serial_file, 'w') as f:
                f.write('1000\n')
        
        # Create CRL number file
        crlnumber_file = f"{ca_dir}/crlnumber"
        if not os.path.exists(crlnumber_file):
            with open(crlnumber_file, 'w') as f:
                f.write('1000\n')
    
    def _get_certificate_info(self, cert_path: str) -> Dict[str, str]:
        """Get certificate information"""
        try:
            # Get subject
            subject = self._run_openssl_command([
                'x509', '-in', cert_path, '-noout', '-subject'
            ]).strip().replace('subject=', '')
            
            # Get issuer
            issuer = self._run_openssl_command([
                'x509', '-in', cert_path, '-noout', '-issuer'
            ]).strip().replace('issuer=', '')
            
            # Get dates
            dates = self._run_openssl_command([
                'x509', '-in', cert_path, '-noout', '-dates'
            ]).strip().split('\n')
            
            not_before = dates[0].replace('notBefore=', '')
            not_after = dates[1].replace('notAfter=', '')
            
            return {
                'subject': subject,
                'issuer': issuer,
                'not_before': not_before,
                'not_after': not_after
            }
        except Exception as e:
            logger.error(f"Failed to get certificate info: {e}")
            return {}
    
    def _is_ip_address(self, address: str) -> bool:
        """Check if string is an IP address"""
        import ipaddress
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False
    
    def list_certificates(self) -> List[Dict[str, str]]:
        """List all certificates with their information"""
        certificates = []
        
        for cert_file in Path(CERT_DIR).glob("*.pem"):
            if cert_file.name.endswith('-cert.pem'):
                cert_info = self._get_certificate_info(str(cert_file))
                cert_info['file'] = str(cert_file)
                cert_info['name'] = cert_file.name.replace('-cert.pem', '')
                certificates.append(cert_info)
        
        return certificates
    
    def export_certificate_bundle(self, output_dir: str, client_name: str = None) -> str:
        """Export certificate bundle for distribution"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        ca_cert_path = f"{CA_DIR}/ca-cert.pem"
        
        if client_name:
            # Export specific client bundle
            cert_path = f"{CERT_DIR}/{client_name}-cert.pem"
            key_path = f"{PRIVATE_DIR}/{client_name}-key.pem"
            
            if not os.path.exists(cert_path):
                raise OpenSSLError(f"Client certificate not found: {cert_path}")
            
            bundle_dir = output_path / client_name
            bundle_dir.mkdir(exist_ok=True)
            
            # Copy files
            shutil.copy2(ca_cert_path, bundle_dir / "ca-cert.pem")
            shutil.copy2(cert_path, bundle_dir / f"{client_name}-cert.pem")
            shutil.copy2(key_path, bundle_dir / f"{client_name}-key.pem")
            
            # Create PKCS#12
            p12_path = self.create_pkcs12(cert_path, key_path, ca_cert_path)
            shutil.copy2(p12_path, bundle_dir / f"{client_name}.p12")
            
            # Create connection script
            self._create_connection_script(bundle_dir, client_name)
            
            logger.info(f"Client bundle exported: {bundle_dir}")
            return str(bundle_dir)
        else:
            # Export CA bundle
            shutil.copy2(ca_cert_path, output_path / "ca-cert.pem")
            logger.info(f"CA bundle exported: {output_path}")
            return str(output_path)
    
    def _create_connection_script(self, bundle_dir: Path, client_name: str) -> None:
        """Create connection script for client"""
        script_content = f"""#!/bin/bash
# PQC-VPN Connection Script for {client_name}
# Generated by PQC-VPN Certificate Manager

BUNDLE_DIR="$(dirname "$0")"
IPSEC_CONF="/etc/ipsec.conf"
IPSEC_SECRETS="/etc/ipsec.secrets"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

echo "Setting up PQC-VPN connection for {client_name}..."

# Install certificates
cp "$BUNDLE_DIR/ca-cert.pem" /etc/ipsec.d/cacerts/
cp "$BUNDLE_DIR/{client_name}-cert.pem" /etc/ipsec.d/certs/
cp "$BUNDLE_DIR/{client_name}-key.pem" /etc/ipsec.d/private/

# Set permissions
chmod 644 /etc/ipsec.d/cacerts/ca-cert.pem
chmod 644 /etc/ipsec.d/certs/{client_name}-cert.pem
chmod 600 /etc/ipsec.d/private/{client_name}-key.pem

# Add connection configuration
cat >> "$IPSEC_CONF" << 'EOF'

# PQC-VPN Client Connection for {client_name}
conn pqc-vpn-{client_name}
    keyexchange=ikev2
    left=%defaultroute
    leftcert={client_name}-cert.pem
    leftauth=pubkey
    leftfirewall=yes
    
    right=%any
    rightauth=pubkey
    rightca="C=US, ST=CA, L=San Francisco, O=PQC-VPN Enterprise, OU=Certificate Authority, CN=PQC-VPN Root CA"
    
    ike=aes256gcm16-sha384-ecp384,aes256-sha384-ecp384!
    esp=aes256gcm16-sha384,aes256-sha384!
    
    auto=start
    closeaction=restart
    dpdaction=restart
    dpddelay=30s
    dpdtimeout=120s
EOF

# Add secrets
echo ": RSA {client_name}-key.pem" >> "$IPSEC_SECRETS"

echo "Connection configured. Starting strongSwan..."
systemctl restart strongswan

echo "PQC-VPN connection setup complete for {client_name}"
echo "Check status with: ipsec status"
"""
        
        script_path = bundle_dir / f"connect-{client_name}.sh"
        with open(script_path, 'w') as f:
            f.write(script_content)
        
        os.chmod(script_path, 0o755)


def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(
        description="PQC-VPN Certificate Manager with OpenSSL 3.5 Support",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate CA certificate
  %(prog)s ca --key-type rsa --key-size 4096
  
  # Generate server certificate
  %(prog)s server hub.pqc-vpn.local --san localhost,10.10.0.1
  
  # Generate client certificate
  %(prog)s client alice --email alice@company.com
  
  # List all certificates
  %(prog)s list
  
  # Export client bundle
  %(prog)s export alice /tmp/vpn-clients/
        """
    )
    
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--openssl-bin', default=OPENSSL_BIN, help='OpenSSL binary path')
    parser.add_argument('--openssl-conf', default=OPENSSL_CONF, help='OpenSSL config path')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # CA command
    ca_parser = subparsers.add_parser('ca', help='Generate Certificate Authority')
    ca_parser.add_argument('--subject', help='CA subject DN')
    ca_parser.add_argument('--key-type', choices=['rsa', 'ec'], default='rsa', help='Key type')
    ca_parser.add_argument('--key-size', default='4096', help='Key size or curve name')
    ca_parser.add_argument('--validity-days', type=int, default=3650, help='Validity period')
    ca_parser.add_argument('--force', action='store_true', help='Overwrite existing CA')
    
    # Server command
    server_parser = subparsers.add_parser('server', help='Generate server certificate')
    server_parser.add_argument('hostname', help='Server hostname')
    server_parser.add_argument('--subject', help='Certificate subject DN')
    server_parser.add_argument('--san', help='Comma-separated list of SANs')
    server_parser.add_argument('--key-type', choices=['rsa', 'ec'], default='rsa', help='Key type')
    server_parser.add_argument('--key-size', default='4096', help='Key size or curve name')
    server_parser.add_argument('--validity-days', type=int, default=365, help='Validity period')
    
    # Client command
    client_parser = subparsers.add_parser('client', help='Generate client certificate')
    client_parser.add_argument('client_name', help='Client name')
    client_parser.add_argument('--email', help='Client email address')
    client_parser.add_argument('--subject', help='Certificate subject DN')
    client_parser.add_argument('--key-type', choices=['rsa', 'ec'], default='rsa', help='Key type')
    client_parser.add_argument('--key-size', default='4096', help='Key size or curve name')
    client_parser.add_argument('--validity-days', type=int, default=365, help='Validity period')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List certificates')
    list_parser.add_argument('--format', choices=['table', 'json', 'yaml'], default='table', help='Output format')
    
    # Export command
    export_parser = subparsers.add_parser('export', help='Export certificate bundle')
    export_parser.add_argument('client_name', nargs='?', help='Client name (optional for CA bundle)')
    export_parser.add_argument('output_dir', help='Output directory')
    
    # Verify command
    verify_parser = subparsers.add_parser('verify', help='Verify certificate')
    verify_parser.add_argument('cert_path', help='Certificate file path')
    verify_parser.add_argument('--ca-cert', help='CA certificate path')
    
    # Revoke command
    revoke_parser = subparsers.add_parser('revoke', help='Revoke certificate')
    revoke_parser.add_argument('cert_path', help='Certificate file path')
    revoke_parser.add_argument('--reason', default='unspecified', help='Revocation reason')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if not args.command:
        parser.print_help()
        return 1
    
    try:
        cert_manager = PQCCertificateManager(args.openssl_bin, args.openssl_conf)
        
        if args.command == 'ca':
            key_size = int(args.key_size) if args.key_size.isdigit() else args.key_size
            cert_manager.generate_ca_certificate(
                subject=args.subject,
                key_type=args.key_type,
                key_size=key_size,
                validity_days=args.validity_days,
                force=args.force
            )
            
        elif args.command == 'server':
            san_list = args.san.split(',') if args.san else None
            key_size = int(args.key_size) if args.key_size.isdigit() else args.key_size
            cert_manager.generate_server_certificate(
                hostname=args.hostname,
                subject=args.subject,
                san_list=san_list,
                key_type=args.key_type,
                key_size=key_size,
                validity_days=args.validity_days
            )
            
        elif args.command == 'client':
            key_size = int(args.key_size) if args.key_size.isdigit() else args.key_size
            cert_manager.generate_client_certificate(
                client_name=args.client_name,
                email=args.email,
                subject=args.subject,
                key_type=args.key_type,
                key_size=key_size,
                validity_days=args.validity_days
            )
            
        elif args.command == 'list':
            certificates = cert_manager.list_certificates()
            
            if args.format == 'json':
                print(json.dumps(certificates, indent=2))
            elif args.format == 'yaml':
                print(yaml.dump(certificates, default_flow_style=False))
            else:
                # Table format
                from tabulate import tabulate
                table_data = []
                for cert in certificates:
                    table_data.append([
                        cert['name'],
                        cert['subject'].split('CN=')[1].split(',')[0] if 'CN=' in cert['subject'] else 'N/A',
                        cert['not_after']
                    ])
                
                print(tabulate(table_data, headers=['Name', 'Common Name', 'Expires'], tablefmt='grid'))
            
        elif args.command == 'export':
            bundle_path = cert_manager.export_certificate_bundle(args.output_dir, args.client_name)
            print(f"Bundle exported to: {bundle_path}")
            
        elif args.command == 'verify':
            is_valid = cert_manager.verify_certificate(args.cert_path, args.ca_cert)
            if is_valid:
                print("Certificate is valid")
                return 0
            else:
                print("Certificate is invalid")
                return 1
                
        elif args.command == 'revoke':
            cert_manager.revoke_certificate(args.cert_path, args.reason)
            print(f"Certificate revoked: {args.cert_path}")
        
        return 0
        
    except OpenSSLError as e:
        logger.error(f"OpenSSL error: {e}")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
