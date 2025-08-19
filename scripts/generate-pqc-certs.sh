#!/bin/bash
#
# PQC Certificate Generation Script for strongSwan VPN
# Supports Post-Quantum Cryptography using Dilithium signatures
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
CERT_DIR="/opt/pqc-vpn/certs"
CA_NAME="PQC-VPN-CA"
KEY_ALGORITHM="dilithium5"
CERT_VALIDITY="3650"  # 10 years for CA
SPOKE_VALIDITY="365"  # 1 year for spokes
COUNTRY="US"
STATE="CA"
LOCALITY="San Francisco"
ORGANIZATION="PQC-VPN"

# Logging functions
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Help function
show_help() {
    cat << EOF
PQC Certificate Generation Script

Usage: $0 [OPTIONS] --ca | --hub | --spoke <username>

OPTIONS:
    --ca                    Generate Certificate Authority (CA) certificate
    --hub [ip]             Generate hub certificate (optional IP)
    --spoke <username>     Generate spoke certificate for user
    --sign <csr_file>      Sign a certificate signing request
    --revoke <cert_file>   Revoke a certificate
    --list                 List all certificates
    --verify <cert_file>   Verify a certificate
    
    --cert-dir <path>      Certificate directory (default: $CERT_DIR)
    --algorithm <alg>      Key algorithm (default: $KEY_ALGORITHM)
    --ca-validity <days>   CA certificate validity (default: $CERT_VALIDITY)
    --validity <days>      Certificate validity (default: $SPOKE_VALIDITY)
    --country <code>       Country code (default: $COUNTRY)
    --state <state>        State name (default: $STATE)
    --locality <city>      City name (default: $LOCALITY)
    --org <name>           Organization name (default: $ORGANIZATION)
    
    -h, --help             Show this help message
    -v, --verbose          Verbose output

Examples:
    $0 --ca                                    # Generate CA certificate
    $0 --hub 192.168.1.1                     # Generate hub certificate
    $0 --spoke alice                          # Generate spoke certificate for 'alice'
    $0 --sign alice.csr                       # Sign alice's certificate request
    $0 --list                                 # List all certificates
    $0 --verify hub-cert.pem                 # Verify hub certificate

EOF
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Check dependencies
check_dependencies() {
    local missing_deps=()
    
    # Check for OpenSSL with PQC support
    if ! command -v openssl >/dev/null 2>&1; then
        missing_deps+=("openssl")
    fi
    
    # Check if liboqs is available (for PQC algorithms)
    if ! openssl list -providers 2>/dev/null | grep -q "oqsprovider\|default"; then
        log_warning "OpenSSL PQC provider not detected. Falling back to RSA."
        KEY_ALGORITHM="rsa"
    fi
    
    if [[ ${#missing_deps[@]} -ne 0 ]]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        log_info "Please install missing dependencies first"
        exit 1
    fi
}

# Create directory structure
create_directories() {
    local dirs=(
        "$CERT_DIR"
        "$CERT_DIR/ca"
        "$CERT_DIR/hub"
        "$CERT_DIR/spokes"
        "$CERT_DIR/csr"
        "$CERT_DIR/crl"
        "$CERT_DIR/private"
    )
    
    for dir in "${dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
            chmod 700 "$dir"
            log_info "Created directory: $dir"
        fi
    done
}

# Generate Certificate Authority
generate_ca() {
    log_info "Generating Certificate Authority (CA) with $KEY_ALGORITHM..."
    
    local ca_key="$CERT_DIR/ca/ca-key.pem"
    local ca_cert="$CERT_DIR/ca/ca-cert.pem"
    local ca_serial="$CERT_DIR/ca/serial"
    local ca_index="$CERT_DIR/ca/index.txt"
    
    # Check if CA already exists
    if [[ -f "$ca_cert" ]]; then
        log_warning "CA certificate already exists: $ca_cert"
        read -p "Overwrite existing CA? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "CA generation cancelled"
            return 0
        fi
    fi
    
    # Generate CA private key
    case "$KEY_ALGORITHM" in
        "dilithium"*|"falcon"*|"sphincs"*)
            openssl genpkey -algorithm "$KEY_ALGORITHM" -out "$ca_key"
            ;;
        "rsa")
            openssl genpkey -algorithm RSA -pkcs8 -out "$ca_key" -pkeyopt rsa_keygen_bits:4096
            ;;
        *)
            log_error "Unsupported key algorithm: $KEY_ALGORITHM"
            exit 1
            ;;
    esac
    
    chmod 600 "$ca_key"
    
    # Generate CA certificate
    openssl req -new -x509 -key "$ca_key" -sha256 -days "$CERT_VALIDITY" -out "$ca_cert" \
        -subj "/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORGANIZATION/OU=Certificate Authority/CN=$CA_NAME"
    
    # Initialize CA database
    echo "01" > "$ca_serial"
    touch "$ca_index"
    
    # Create CRL
    openssl ca -config <(generate_openssl_config) -gencrl -out "$CERT_DIR/crl/ca-crl.pem" \
        -cert "$ca_cert" -keyfile "$ca_key" -batch 2>/dev/null || true
    
    log_success "CA certificate generated: $ca_cert"
    log_info "CA key stored securely: $ca_key"
    
    # Display CA information
    log_info "CA Certificate Information:"
    openssl x509 -in "$ca_cert" -text -noout | grep -E "(Subject:|Not Before|Not After|Public Key Algorithm|Signature Algorithm)"
}

# Generate hub certificate
generate_hub() {
    local hub_ip="$1"
    
    log_info "Generating hub certificate..."
    
    if [[ -z "$hub_ip" ]]; then
        read -p "Enter hub IP address: " hub_ip
    fi
    
    if [[ -z "$hub_ip" ]]; then
        log_error "Hub IP address is required"
        exit 1
    fi
    
    local hub_key="$CERT_DIR/hub/hub-key.pem"
    local hub_cert="$CERT_DIR/hub/hub-cert.pem"
    local hub_csr="$CERT_DIR/csr/hub.csr"
    
    # Generate hub private key
    case "$KEY_ALGORITHM" in
        "dilithium"*|"falcon"*|"sphincs"*)
            openssl genpkey -algorithm "$KEY_ALGORITHM" -out "$hub_key"
            ;;
        "rsa")
            openssl genpkey -algorithm RSA -pkcs8 -out "$hub_key" -pkeyopt rsa_keygen_bits:4096
            ;;
    esac
    
    chmod 600 "$hub_key"
    
    # Generate certificate request
    openssl req -new -key "$hub_key" -out "$hub_csr" \
        -subj "/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORGANIZATION/OU=Hub/CN=$hub_ip"
    
    # Sign the certificate
    sign_certificate "$hub_csr" "$hub_cert" "server"
    
    log_success "Hub certificate generated: $hub_cert"
    log_info "Hub key: $hub_key"
    log_info "Hub IP: $hub_ip"
}

# Generate spoke certificate
generate_spoke() {
    local username="$1"
    
    if [[ -z "$username" ]]; then
        log_error "Username is required for spoke certificate"
        exit 1
    fi
    
    log_info "Generating spoke certificate for user: $username"
    
    local spoke_key="$CERT_DIR/spokes/${username}-key.pem"
    local spoke_cert="$CERT_DIR/spokes/${username}-cert.pem"
    local spoke_csr="$CERT_DIR/csr/${username}.csr"
    
    # Generate spoke private key
    case "$KEY_ALGORITHM" in
        "dilithium"*|"falcon"*|"sphincs"*)
            openssl genpkey -algorithm "$KEY_ALGORITHM" -out "$spoke_key"
            ;;
        "rsa")
            openssl genpkey -algorithm RSA -pkcs8 -out "$spoke_key" -pkeyopt rsa_keygen_bits:4096
            ;;
    esac
    
    chmod 600 "$spoke_key"
    
    # Generate certificate request
    openssl req -new -key "$spoke_key" -out "$spoke_csr" \
        -subj "/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORGANIZATION/OU=Spoke/CN=$username"
    
    # Sign the certificate
    sign_certificate "$spoke_csr" "$spoke_cert" "client"
    
    log_success "Spoke certificate generated: $spoke_cert"
    log_info "Spoke key: $spoke_key"
    log_info "Username: $username"
    
    # Create client package
    create_client_package "$username"
}

# Sign a certificate signing request
sign_certificate() {
    local csr_file="$1"
    local cert_file="$2"
    local cert_type="$3"  # server or client
    
    local ca_cert="$CERT_DIR/ca/ca-cert.pem"
    local ca_key="$CERT_DIR/ca/ca-key.pem"
    
    if [[ ! -f "$ca_cert" || ! -f "$ca_key" ]]; then
        log_error "CA certificate or key not found. Generate CA first."
        exit 1
    fi
    
    if [[ ! -f "$csr_file" ]]; then
        log_error "CSR file not found: $csr_file"
        exit 1
    fi
    
    # Create extensions file based on certificate type
    local ext_file="/tmp/cert_extensions.conf"
    case "$cert_type" in
        "server")
            cat > "$ext_file" << EOF
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
IP.1 = $(openssl req -in "$csr_file" -noout -subject | sed -n 's/.*CN=\([^/]*\).*/\1/p')
EOF
            ;;
        "client")
            cat > "$ext_file" << EOF
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
EOF
            ;;
        *)
            log_error "Invalid certificate type: $cert_type"
            exit 1
            ;;
    esac
    
    # Sign the certificate
    openssl x509 -req -in "$csr_file" -CA "$ca_cert" -CAkey "$ca_key" \
        -CAcreateserial -out "$cert_file" -days "$SPOKE_VALIDITY" -sha256 \
        -extensions v3_ext -extfile "$ext_file"
    
    rm -f "$ext_file"
    
    log_success "Certificate signed: $cert_file"
}

# Sign external CSR file
sign_external_csr() {
    local csr_file="$1"
    
    if [[ ! -f "$csr_file" ]]; then
        log_error "CSR file not found: $csr_file"
        exit 1
    fi
    
    # Extract username from CSR
    local username=$(openssl req -in "$csr_file" -noout -subject | sed -n 's/.*CN=\([^/]*\).*/\1/p')
    
    if [[ -z "$username" ]]; then
        log_error "Could not extract username from CSR"
        exit 1
    fi
    
    log_info "Signing CSR for user: $username"
    
    local cert_file="$CERT_DIR/spokes/${username}-cert.pem"
    
    sign_certificate "$csr_file" "$cert_file" "client"
    create_client_package "$username"
}

# Create client package
create_client_package() {
    local username="$1"
    local package_dir="$CERT_DIR/packages/${username}"
    
    mkdir -p "$package_dir"
    
    # Copy certificates
    cp "$CERT_DIR/ca/ca-cert.pem" "$package_dir/"
    cp "$CERT_DIR/spokes/${username}-cert.pem" "$package_dir/"
    cp "$CERT_DIR/spokes/${username}-key.pem" "$package_dir/"
    
    # Create README
    cat > "$package_dir/README.txt" << EOF
PQC-VPN Client Certificate Package for: $username
===================================================

Files included:
- ca-cert.pem: Certificate Authority certificate
- ${username}-cert.pem: Your client certificate
- ${username}-key.pem: Your private key (KEEP SECURE!)

Installation instructions:
1. Copy these files to your client device
2. Install using the spoke installation script
3. Use the install-certs script to configure strongSwan

Generated on: $(date)
Certificate Algorithm: $KEY_ALGORITHM
Certificate Expires: $(openssl x509 -in "$CERT_DIR/spokes/${username}-cert.pem" -noout -enddate | cut -d= -f2)
EOF
    
    # Create ZIP package
    if command -v zip >/dev/null 2>&1; then
        local zip_file="$CERT_DIR/packages/${username}-certificates.zip"
        cd "$package_dir"
        zip -r "$zip_file" . >/dev/null
        cd - >/dev/null
        log_success "Client package created: $zip_file"
    else
        log_success "Client package created: $package_dir"
    fi
}

# List all certificates
list_certificates() {
    log_info "Certificate Authority:"
    if [[ -f "$CERT_DIR/ca/ca-cert.pem" ]]; then
        echo "  ✅ CA Certificate: $CERT_DIR/ca/ca-cert.pem"
        echo "     Expires: $(openssl x509 -in "$CERT_DIR/ca/ca-cert.pem" -noout -enddate | cut -d= -f2)"
    else
        echo "  ❌ CA Certificate not found"
    fi
    
    echo
    log_info "Hub Certificates:"
    if [[ -f "$CERT_DIR/hub/hub-cert.pem" ]]; then
        echo "  ✅ Hub Certificate: $CERT_DIR/hub/hub-cert.pem"
        echo "     Subject: $(openssl x509 -in "$CERT_DIR/hub/hub-cert.pem" -noout -subject | cut -d= -f2-)"
        echo "     Expires: $(openssl x509 -in "$CERT_DIR/hub/hub-cert.pem" -noout -enddate | cut -d= -f2)"
    else
        echo "  ❌ Hub Certificate not found"
    fi
    
    echo
    log_info "Spoke Certificates:"
    local spoke_certs=("$CERT_DIR/spokes/"*-cert.pem)
    if [[ -f "${spoke_certs[0]}" ]]; then
        for cert in "${spoke_certs[@]}"; do
            if [[ -f "$cert" ]]; then
                local basename=$(basename "$cert" -cert.pem)
                echo "  ✅ $basename"
                echo "     File: $cert"
                echo "     Expires: $(openssl x509 -in "$cert" -noout -enddate | cut -d= -f2)"
                echo
            fi
        done
    else
        echo "  ❌ No spoke certificates found"
    fi
}

# Verify certificate
verify_certificate() {
    local cert_file="$1"
    
    if [[ ! -f "$cert_file" ]]; then
        log_error "Certificate file not found: $cert_file"
        exit 1
    fi
    
    local ca_cert="$CERT_DIR/ca/ca-cert.pem"
    
    if [[ ! -f "$ca_cert" ]]; then
        log_error "CA certificate not found: $ca_cert"
        exit 1
    fi
    
    log_info "Verifying certificate: $cert_file"
    
    # Verify against CA
    if openssl verify -CAfile "$ca_cert" "$cert_file" >/dev/null 2>&1; then
        log_success "Certificate is valid"
    else
        log_error "Certificate verification failed"
        return 1
    fi
    
    # Show certificate details
    echo
    log_info "Certificate Details:"
    openssl x509 -in "$cert_file" -text -noout | grep -E "(Subject:|Issuer:|Not Before|Not After|Public Key Algorithm|Signature Algorithm)"
}

# Revoke certificate
revoke_certificate() {
    local cert_file="$1"
    
    if [[ ! -f "$cert_file" ]]; then
        log_error "Certificate file not found: $cert_file"
        exit 1
    fi
    
    local ca_cert="$CERT_DIR/ca/ca-cert.pem"
    local ca_key="$CERT_DIR/ca/ca-key.pem"
    
    if [[ ! -f "$ca_cert" || ! -f "$ca_key" ]]; then
        log_error "CA certificate or key not found"
        exit 1
    fi
    
    log_warning "Revoking certificate: $cert_file"
    
    # Add to revocation list
    openssl ca -config <(generate_openssl_config) -revoke "$cert_file" \
        -cert "$ca_cert" -keyfile "$ca_key" -batch
    
    # Update CRL
    openssl ca -config <(generate_openssl_config) -gencrl -out "$CERT_DIR/crl/ca-crl.pem" \
        -cert "$ca_cert" -keyfile "$ca_key" -batch
    
    log_success "Certificate revoked and CRL updated"
}

# Generate OpenSSL configuration
generate_openssl_config() {
    cat << EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = $CERT_DIR/ca
certs             = \$dir
crl_dir           = $CERT_DIR/crl
new_certs_dir     = \$dir
database          = \$dir/index.txt
serial            = \$dir/serial
RANDFILE          = \$dir/.rand
private_key       = \$dir/ca-key.pem
certificate       = \$dir/ca-cert.pem
crlnumber         = \$dir/crlnumber
crl               = \$dir/ca-crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30
default_md        = sha256
name_opt          = ca_default
cert_opt          = ca_default
default_days      = $SPOKE_VALIDITY
preserve          = no
policy            = policy_loose

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ crl_ext ]
authorityKeyIdentifier=keyid:always,issuer:always
EOF
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --ca)
                ACTION="ca"
                shift
                ;;
            --hub)
                ACTION="hub"
                if [[ $2 && $2 != -* ]]; then
                    HUB_IP="$2"
                    shift
                fi
                shift
                ;;
            --spoke)
                ACTION="spoke"
                if [[ $2 && $2 != -* ]]; then
                    SPOKE_USER="$2"
                    shift
                else
                    log_error "Username required for --spoke"
                    exit 1
                fi
                shift
                ;;
            --sign)
                ACTION="sign"
                if [[ $2 && $2 != -* ]]; then
                    CSR_FILE="$2"
                    shift
                else
                    log_error "CSR file required for --sign"
                    exit 1
                fi
                shift
                ;;
            --revoke)
                ACTION="revoke"
                if [[ $2 && $2 != -* ]]; then
                    CERT_FILE="$2"
                    shift
                else
                    log_error "Certificate file required for --revoke"
                    exit 1
                fi
                shift
                ;;
            --list)
                ACTION="list"
                shift
                ;;
            --verify)
                ACTION="verify"
                if [[ $2 && $2 != -* ]]; then
                    CERT_FILE="$2"
                    shift
                else
                    log_error "Certificate file required for --verify"
                    exit 1
                fi
                shift
                ;;
            --cert-dir)
                CERT_DIR="$2"
                shift 2
                ;;
            --algorithm)
                KEY_ALGORITHM="$2"
                shift 2
                ;;
            --ca-validity)
                CERT_VALIDITY="$2"
                shift 2
                ;;
            --validity)
                SPOKE_VALIDITY="$2"
                shift 2
                ;;
            --country)
                COUNTRY="$2"
                shift 2
                ;;
            --state)
                STATE="$2"
                shift 2
                ;;
            --locality)
                LOCALITY="$2"
                shift 2
                ;;
            --org)
                ORGANIZATION="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--verbose)
                set -x
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    if [[ -z "$ACTION" ]]; then
        log_error "No action specified"
        show_help
        exit 1
    fi
}

# Main function
main() {
    parse_arguments "$@"
    check_root
    check_dependencies
    create_directories
    
    case "$ACTION" in
        "ca")
            generate_ca
            ;;
        "hub")
            generate_hub "$HUB_IP"
            ;;
        "spoke")
            generate_spoke "$SPOKE_USER"
            ;;
        "sign")
            sign_external_csr "$CSR_FILE"
            ;;
        "revoke")
            revoke_certificate "$CERT_FILE"
            ;;
        "list")
            list_certificates
            ;;
        "verify")
            verify_certificate "$CERT_FILE"
            ;;
        *)
            log_error "Invalid action: $ACTION"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"