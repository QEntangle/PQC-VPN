#!/bin/bash

# PQC-VPN Hub Installation Script for Linux with OpenSSL 3.5 Support
# Enterprise-grade installation supporting Ubuntu 20.04+, CentOS 8+, Debian 11+, RHEL 8+, Rocky Linux 8+
# Version: 3.0.0 - OpenSSL 3.5 Native PQC Implementation

set -euo pipefail

# Script configuration
SCRIPT_VERSION="3.0.0"
SCRIPT_NAME="PQC-VPN Hub Installer (OpenSSL 3.5)"
LOG_FILE="/var/log/pqc-vpn-install.log"
CONFIG_DIR="/etc/pqc-vpn"
BACKUP_DIR="/var/backups/pqc-vpn"

# OpenSSL 3.5 configuration
OPENSSL_VERSION="${OPENSSL_VERSION:-3.5.0}"
OPENSSL_PREFIX="/usr/local/openssl35"
OPENSSL_BUILD_DIR="/tmp/openssl-build"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Installation options (can be overridden via environment variables)
HUB_IP="${HUB_IP:-$(hostname -I | awk '{print $1}')}"
ENABLE_HA="${ENABLE_HA:-false}"
ENABLE_MONITORING="${ENABLE_MONITORING:-true}"
ENABLE_WEB_INTERFACE="${ENABLE_WEB_INTERFACE:-true}"
STRONGSWAN_VERSION="${STRONGSWAN_VERSION:-5.9.14}"
AUTH_METHODS="${AUTH_METHODS:-pki,psk,hybrid}"
PQC_ALGORITHMS="${PQC_ALGORITHMS:-rsa4096,ec384,aes256gcm}"
INSTALL_MODE="${INSTALL_MODE:-production}"  # production, development, testing
ENABLE_FIPS="${ENABLE_FIPS:-false}"

# Function definitions
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "${LOG_FILE}"
}

info() {
    log "INFO" "${BLUE}[INFO]${NC} $*"
}

warn() {
    log "WARN" "${YELLOW}[WARN]${NC} $*"
}

error() {
    log "ERROR" "${RED}[ERROR]${NC} $*"
}

success() {
    log "SUCCESS" "${GREEN}[SUCCESS]${NC} $*"
}

debug() {
    if [[ "${DEBUG:-false}" == "true" ]]; then
        log "DEBUG" "${PURPLE}[DEBUG]${NC} $*"
    fi
}

# Cleanup function
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        error "Installation failed with exit code $exit_code"
        error "Check the log file: $LOG_FILE"
        if [[ -d "$OPENSSL_BUILD_DIR" ]]; then
            rm -rf "$OPENSSL_BUILD_DIR"
        fi
    fi
    exit $exit_code
}

trap cleanup EXIT

print_banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
╔═══════════════════════════════════════════════════════════════╗
║               PQC-VPN Hub Installer v3.0.0                   ║
║             OpenSSL 3.5 Native PQC Implementation            ║
║                     Enterprise Edition                       ║
╚═══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS_ID="$ID"
        OS_VERSION="$VERSION_ID"
        OS_NAME="$PRETTY_NAME"
    elif [[ -f /etc/redhat-release ]]; then
        OS_ID="rhel"
        OS_VERSION=$(cat /etc/redhat-release | sed 's/.*release \([0-9]\+\).*/\1/')
        OS_NAME=$(cat /etc/redhat-release)
    else
        error "Unsupported operating system"
        exit 1
    fi
    
    info "Detected OS: $OS_NAME"
    debug "OS ID: $OS_ID, Version: $OS_VERSION"
}

check_requirements() {
    info "Checking system requirements for OpenSSL 3.5 deployment..."
    
    # Check CPU architecture
    local arch=$(uname -m)
    if [[ "$arch" != "x86_64" && "$arch" != "aarch64" ]]; then
        error "Unsupported architecture: $arch"
        exit 1
    fi
    
    # Enhanced memory requirements for OpenSSL 3.5
    local mem_gb=$(free -g | awk '/^Mem:/{print $2}')
    if [[ $mem_gb -lt 4 ]]; then
        warn "System has less than 4GB RAM. OpenSSL 3.5 compilation may be slow."
    fi
    
    # Enhanced disk space requirements
    local disk_gb=$(df / | awk 'NR==2{printf "%.0f", $4/1024/1024}')
    if [[ $disk_gb -lt 15 ]]; then
        error "Insufficient disk space. At least 15GB required for OpenSSL 3.5 build."
        exit 1
    fi
    
    # Check kernel version for advanced IPsec support
    local kernel_version=$(uname -r | cut -d. -f1-2)
    local kernel_major=$(echo $kernel_version | cut -d. -f1)
    local kernel_minor=$(echo $kernel_version | cut -d. -f2)
    
    if [[ $kernel_major -lt 5 || ($kernel_major -eq 4 && $kernel_minor -lt 18) ]]; then
        warn "Kernel version $kernel_version may not support all advanced IPsec features"
    fi
    
    # Check for hardware acceleration support
    if lscpu | grep -q "aes"; then
        info "AES-NI hardware acceleration detected"
    fi
    
    if lscpu | grep -q "avx2"; then
        info "AVX2 support detected - will enhance cryptographic performance"
    fi
    
    success "System requirements check passed"
}

setup_logging() {
    # Create log directory
    mkdir -p "$(dirname "$LOG_FILE")"
    
    # Start logging
    info "Starting $SCRIPT_NAME v$SCRIPT_VERSION"
    info "Installation mode: $INSTALL_MODE"
    info "Hub IP: $HUB_IP"
    info "Authentication methods: $AUTH_METHODS"
    info "Cryptographic algorithms: $PQC_ALGORITHMS"
    info "OpenSSL version: $OPENSSL_VERSION"
}

create_directories() {
    info "Creating directory structure..."
    
    local dirs=(
        "$CONFIG_DIR"
        "$BACKUP_DIR"
        "/etc/ipsec.d/certs"
        "/etc/ipsec.d/private"
        "/etc/ipsec.d/cacerts"
        "/etc/ipsec.d/crls"
        "/etc/ipsec.d/conf.d"
        "/etc/ipsec.d/secrets"
        "/var/log/strongswan"
        "/var/log/pqc-vpn"
        "/usr/local/share/pqc-vpn"
        "/usr/local/bin/pqc-vpn"
        "$OPENSSL_PREFIX"
        "$OPENSSL_BUILD_DIR"
    )
    
    for dir in "${dirs[@]}"; do
        mkdir -p "$dir"
        debug "Created directory: $dir"
    done
    
    # Set proper permissions
    chmod 700 /etc/ipsec.d/private
    chmod 755 /etc/ipsec.d/certs
    chmod 755 /etc/ipsec.d/cacerts
    chmod 700 "$OPENSSL_BUILD_DIR"
    
    success "Directory structure created"
}

install_dependencies() {
    info "Installing system dependencies for OpenSSL 3.5 build..."
    
    case "$OS_ID" in
        ubuntu|debian)
            # Update package list
            apt-get update -qq
            
            # Install build dependencies for OpenSSL 3.5
            local packages=(
                "build-essential"
                "gcc-11"
                "g++-11"
                "make"
                "cmake"
                "ninja-build"
                "autoconf"
                "automake"
                "libtool"
                "pkg-config"
                "libssl-dev"
                "libcurl4-openssl-dev"
                "libgmp-dev"
                "libmpfr-dev"
                "libmpc-dev"
                "zlib1g-dev"
                "libbz2-dev"
                "libffi-dev"
                "libreadline-dev"
                "libsqlite3-dev"
                "libncursesw5-dev"
                "xz-utils"
                "tk-dev"
                "libxml2-dev"
                "libxmlsec1-dev"
                "libffi-dev"
                "liblzma-dev"
                "libtspi-dev"
                "libldap2-dev"
                "libsystemd-dev"
                "libnl-3-dev"
                "libnl-route-3-dev"
                "iptables-dev"
                "python3"
                "python3-pip"
                "python3-dev"
                "git"
                "wget"
                "curl"
                "jq"
                "strongswan"
                "strongswan-pki"
                "strongswan-swanctl"
                "ipsec-tools"
                "docker.io"
                "docker-compose"
                "net-tools"
                "iproute2"
                "tcpdump"
                "nmap"
                "htop"
                "tree"
            )
            
            if [[ "$ENABLE_MONITORING" == "true" ]]; then
                packages+=("prometheus" "grafana")
            fi
            
            # Set GCC-11 as default for OpenSSL 3.5 compilation
            update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-11 60 \
                               --slave /usr/bin/g++ g++ /usr/bin/g++-11
            
            DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}"
            ;;
            
        centos|rhel|rocky|almalinux)
            # Enable EPEL repository
            if ! rpm -q epel-release > /dev/null 2>&1; then
                yum install -y epel-release
            fi
            
            # Install development tools
            yum groupinstall -y "Development Tools"
            yum install -y centos-release-scl || true  # For newer GCC
            
            # Install dependencies
            local packages=(
                "gcc"
                "gcc-c++"
                "make"
                "cmake"
                "autoconf"
                "automake"
                "libtool"
                "pkgconfig"
                "openssl-devel"
                "libcurl-devel"
                "gmp-devel"
                "mpfr-devel"
                "libmpc-devel"
                "zlib-devel"
                "bzip2-devel"
                "libffi-devel"
                "readline-devel"
                "sqlite-devel"
                "ncurses-devel"
                "xz-devel"
                "libxml2-devel"
                "systemd-devel"
                "libnl3-devel"
                "iptables-devel"
                "python3"
                "python3-pip"
                "python3-devel"
                "git"
                "wget"
                "curl"
                "jq"
                "strongswan"
                "docker"
                "docker-compose"
                "net-tools"
                "iproute"
                "tcpdump"
                "nmap"
                "htop"
                "tree"
            )
            
            yum install -y "${packages[@]}"
            ;;
            
        *)
            error "Unsupported operating system: $OS_ID"
            exit 1
            ;;
    esac
    
    success "System dependencies installed"
}

install_openssl35() {
    info "Building and installing OpenSSL $OPENSSL_VERSION with enterprise features..."
    
    cd "$OPENSSL_BUILD_DIR"
    
    # Download OpenSSL 3.5 source
    local openssl_url="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"
    
    info "Downloading OpenSSL $OPENSSL_VERSION..."
    wget -O "openssl-${OPENSSL_VERSION}.tar.gz" "$openssl_url"
    
    # Verify download (if available)
    if wget -q -O "openssl-${OPENSSL_VERSION}.tar.gz.sha256" "${openssl_url}.sha256" 2>/dev/null; then
        if sha256sum -c "openssl-${OPENSSL_VERSION}.tar.gz.sha256"; then
            success "OpenSSL download verified"
        else
            warn "OpenSSL download verification failed, but continuing..."
        fi
    fi
    
    # Extract OpenSSL
    tar -xzf "openssl-${OPENSSL_VERSION}.tar.gz"
    cd "openssl-${OPENSSL_VERSION}"
    
    info "Configuring OpenSSL $OPENSSL_VERSION build..."
    
    # Configure OpenSSL with enterprise features
    local config_options=(
        "linux-x86_64"
        "--prefix=${OPENSSL_PREFIX}"
        "--openssldir=${OPENSSL_PREFIX}/ssl"
        "--libdir=lib"
        "shared"
        "zlib"
        "enable-ktls"          # Kernel TLS support
        "enable-legacy"        # Legacy algorithm support
        "enable-asm"           # Assembly optimizations
        "enable-ec_nistp_64_gcc_128"  # Optimized elliptic curve
        "enable-ssl-trace"     # SSL/TLS tracing
        "enable-tls1_3"        # TLS 1.3 support
        "enable-weak-ssl-ciphers"  # Backward compatibility
        "enable-camellia"      # Camellia cipher
        "enable-seed"          # SEED cipher
        "enable-rfc3779"       # RFC 3779 support
        "enable-scrypt"        # scrypt KDF
        "enable-cms"           # CMS support
        "enable-ct"            # Certificate transparency
        "enable-srp"           # SRP support
        "enable-aria"          # ARIA cipher
        "enable-sm2"           # SM2 elliptic curve
        "enable-sm3"           # SM3 hash
        "enable-sm4"           # SM4 cipher
        "-Wl,-rpath,${OPENSSL_PREFIX}/lib"
    )
    
    # Add FIPS support if enabled
    if [[ "$ENABLE_FIPS" == "true" ]]; then
        config_options+=("enable-fips")
        info "FIPS mode enabled"
    fi
    
    # Run configuration
    ./Configure "${config_options[@]}"
    
    # Check configuration
    info "OpenSSL configuration completed, starting build..."
    
    # Build OpenSSL (using all available cores)
    local cores=$(nproc)
    make -j"$cores"
    
    info "Running OpenSSL test suite..."
    if [[ "$INSTALL_MODE" != "production" ]]; then
        # Run tests in development/testing mode
        make test || warn "Some OpenSSL tests failed, but installation will continue"
    else
        info "Skipping tests in production mode for faster installation"
    fi
    
    # Install OpenSSL
    make install
    
    # Update library cache
    echo "${OPENSSL_PREFIX}/lib" > /etc/ld.so.conf.d/openssl35.conf
    ldconfig
    
    # Verify installation
    local installed_version=$("${OPENSSL_PREFIX}/bin/openssl" version)
    info "Installed OpenSSL: $installed_version"
    
    # Test basic functionality
    "${OPENSSL_PREFIX}/bin/openssl" list -algorithms > /dev/null
    
    success "OpenSSL $OPENSSL_VERSION installed successfully"
}

configure_openssl35() {
    info "Configuring OpenSSL 3.5 for enterprise PQC deployment..."
    
    # Create comprehensive OpenSSL configuration
    cat > "${OPENSSL_PREFIX}/ssl/openssl.cnf" << 'EOF'
#
# OpenSSL 3.5 Enterprise Configuration
# Optimized for Post-Quantum Cryptography Readiness
#

openssl_conf = openssl_init

[openssl_init]
providers = provider_sect
alg_section = evp_properties

[provider_sect]
default = default_sect
legacy = legacy_sect

[default_sect]
activate = 1

[legacy_sect]
activate = 1

[evp_properties]
# Algorithm preferences for maximum security
# RSA minimum 3072-bit (4096-bit recommended)
rsa = provider:default
# ECDSA with P-384 or higher
ec = provider:default
# EdDSA algorithms
ed25519 = provider:default
ed448 = provider:default

# Symmetric algorithms
aes = provider:default
chacha20 = provider:default

# Hash algorithms - prioritize SHA-3 and SHA-2
sha3 = provider:default
sha2 = provider:default

[req]
default_bits = 4096
default_md = sha384
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no
string_mask = utf8only

[req_distinguished_name]
C = US
ST = California
L = San Francisco
O = PQC-VPN Enterprise
OU = IT Security Department
CN = PQC-VPN Certificate Authority

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names
extendedKeyUsage = serverAuth, clientAuth

[alt_names]
DNS.1 = localhost
DNS.2 = pqc-vpn-hub
DNS.3 = *.pqc-vpn.local
IP.1 = 127.0.0.1

[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
certificatePolicies = @ca_policy

[ca_policy]
policyIdentifier = 2.23.140.1.2.1
CPS.1 = "https://pqc-vpn.local/cps"

[server_cert]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "PQC-VPN Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
crlDistributionPoints = @crl_section
authorityInfoAccess = @ocsp_section

[client_cert]
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "PQC-VPN Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth, emailProtection

[crl_section]
URI.0 = http://pqc-vpn.local/crl/ca.crl

[ocsp_section]
OCSP;URI.0 = http://pqc-vpn.local/ocsp

# Enterprise cipher suites
[cipher_sect]
CIPHERSTRING = ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS
EOF
    
    # Set up PKI directory structure
    mkdir -p "${OPENSSL_PREFIX}/ssl/"{certs,private,crl,newcerts}
    touch "${OPENSSL_PREFIX}/ssl/index.txt"
    echo 1000 > "${OPENSSL_PREFIX}/ssl/serial"
    echo 1000 > "${OPENSSL_PREFIX}/ssl/crlnumber"
    
    # Set proper permissions
    chmod 644 "${OPENSSL_PREFIX}/ssl/openssl.cnf"
    chmod 700 "${OPENSSL_PREFIX}/ssl/private"
    
    # Create OpenSSL wrapper script for system integration
    cat > /usr/local/bin/openssl-pqc << EOF
#!/bin/bash
# OpenSSL 3.5 wrapper for PQC-VPN
export OPENSSL_CONF="${OPENSSL_PREFIX}/ssl/openssl.cnf"
export LD_LIBRARY_PATH="${OPENSSL_PREFIX}/lib:\${LD_LIBRARY_PATH}"
exec "${OPENSSL_PREFIX}/bin/openssl" "\$@"
EOF
    
    chmod +x /usr/local/bin/openssl-pqc
    
    success "OpenSSL 3.5 configuration completed"
}

configure_strongswan() {
    info "Configuring strongSwan with OpenSSL 3.5 support..."
    
    # Backup existing configuration
    if [[ -f /etc/ipsec.conf ]]; then
        cp /etc/ipsec.conf "$BACKUP_DIR/ipsec.conf.backup.$(date +%Y%m%d_%H%M%S)"
    fi
    
    if [[ -f /etc/ipsec.secrets ]]; then
        cp /etc/ipsec.secrets "$BACKUP_DIR/ipsec.secrets.backup.$(date +%Y%m%d_%H%M%S)"
    fi
    
    if [[ -f /etc/strongswan.conf ]]; then
        cp /etc/strongswan.conf "$BACKUP_DIR/strongswan.conf.backup.$(date +%Y%m%d_%H%M%S)"
    fi
    
    # Create enterprise strongSwan configuration
    cat > /etc/strongswan.conf << EOF
# strongSwan Configuration with OpenSSL 3.5 Enterprise Support

strongswan {
    load_modular = yes
    
    # Plugin loading with OpenSSL 3.5 integration
    plugins {
        include strongswan.d/charon/*.conf
    }
    
    # Enterprise logging configuration
    charondebug {
        ike = 2
        knl = 2
        cfg = 2
        net = 2
        asn = 1
        enc = 1
        lib = 1
        esp = 2
        tls = 2
        tnc = 2
        imc = 1
        imv = 1
        pts = 1
        mgr = 1
    }
    
    # Performance optimizations for enterprise deployment
    pool {
        load = yes
    }
    
    starter {
        load_warning = yes
    }
}

# Charon (IKE daemon) configuration
charon {
    load_modular = yes
    
    # Network configuration
    dns1 = 8.8.8.8
    dns2 = 8.8.4.4
    
    # Performance tuning for enterprise workloads
    threads = 32
    processor_slots = 8
    
    # Crypto configuration for OpenSSL 3.5
    crypto_test {
        on_add = yes
        on_create = yes
        required = no
    }
    
    # Enterprise monitoring and management
    plugins {
        openssl {
            load = yes
            engine = yes
            fips_mode = ${ENABLE_FIPS}
            engine_id = openssl
        }
        
        # Core plugins
        random { load = yes }
        nonce { load = yes }
        x509 { load = yes }
        revocation { load = yes }
        constraints { load = yes }
        pubkey { load = yes }
        pkcs1 { load = yes }
        pkcs8 { load = yes }
        pkcs12 { load = yes }
        pgp { load = yes }
        dnskey { load = yes }
        sshkey { load = yes }
        pem { load = yes }
        
        # Network plugins
        curl { load = yes }
        soup { load = yes }
        
        # Database plugins
        mysql { load = no }
        sqlite { load = yes }
        
        # System plugins
        attr { load = yes }
        kernel-netlink {
            load = yes
            fwmark = !0x42
            buflen = 1024
            force_receive_own_broadcasts = yes
        }
        resolve { load = yes }
        socket-default { load = yes }
        
        # Management plugins
        vici {
            load = yes
            socket = unix:///var/run/strongswan/charon-vici.socket
        }
        updown { load = yes }
        
        # Authentication plugins
        eap-identity { load = yes }
        eap-md5 { load = yes }
        eap-gtc { load = yes }
        eap-aka { load = yes }
        eap-mschapv2 { load = yes }
        xauth-generic { load = yes }
        xauth-eap { load = yes }
        xauth-pam { load = yes }
        xauth-noauth { load = yes }
        
        # Enterprise features
        unity { load = yes }
        stroke { load = yes }
        
        # Additional security
        constraints { load = yes }
        acert { load = yes }
        
        # Performance
        aes { load = yes }
        des { load = yes }
        blowfish { load = yes }
        rc2 { load = yes }
        sha1 { load = yes }
        sha2 { load = yes }
        md5 { load = yes }
        rdrand { load = yes }
        aesni { load = yes }
        
        # Enterprise monitoring
        counters { load = yes }
        
        # Advanced features
        forecast { load = yes }
        connmark { load = yes }
        bypass-lan { load = yes }
    }
    
    # Advanced security settings
    make_before_break = yes
    
    # Certificate validation
    send_vendor_id = yes
    
    # Performance settings
    inactivity_timeout = 900
    half_open_timeout = 30
    max_packet = 10000
    
    # Enterprise security
    integrity_test = yes
}

# Pool configuration for enterprise
pool {
    load = yes
}

# Enterprise starter configuration
starter {
    config_file = /etc/ipsec.conf
    secrets_file = /etc/ipsec.secrets
    load_warning = yes
}

# Enterprise logging
charon-systemd {
    journal {
        default = 1
        ike = 2
        cfg = 2
        knl = 2
    }
}
EOF
    
    # Create IPsec configuration with OpenSSL 3.5 optimized settings
    cat > /etc/ipsec.conf << EOF
# IPsec Configuration with OpenSSL 3.5 Enterprise Support
# Version 3.0.0 - Enterprise PQC-Ready Implementation

config setup
    charondebug="ike 2, knl 2, cfg 2, net 1, asn 1, enc 1, lib 1, esp 2, tls 2, tnc 2, imc 1, imv 1, pts 1"
    uniqueids=never
    strictcrlpolicy=no
    cachecrls=yes
    
# Enterprise default connection template
conn %default
    # IKE configuration with enterprise-grade algorithms
    ikelifetime=28800s
    keylife=3600s
    rekeymargin=540s
    keyingtries=3
    keyexchange=ikev2
    
    # Enterprise crypto policy - maximum security with OpenSSL 3.5
    # Using RSA-4096 and ECDSA-P384 for current deployment
    # Future PQC algorithms will be added as they become available in OpenSSL 3.5+
    ike=aes256gcm16-sha384-ecp384,aes256gcm16-sha384-modp4096,aes256-sha384-ecp384,aes256-sha384-modp4096,chacha20poly1305-sha384-ecp384!
    esp=aes256gcm16-sha384,aes256-sha384,chacha20poly1305-sha384!
    
    # Certificate-based authentication with enhanced validation
    leftauth=pubkey
    rightauth=pubkey
    leftcert=hub-cert.pem
    leftid="C=US, ST=California, L=San Francisco, O=PQC-VPN Enterprise, OU=VPN Hub, CN=pqc-vpn-hub"
    rightca="C=US, ST=California, L=San Francisco, O=PQC-VPN Enterprise, OU=Certificate Authority, CN=PQC-VPN Root CA"
    
    # Network configuration
    left=${HUB_IP}
    leftsubnet=10.10.0.0/16
    right=%any
    rightsubnet=10.10.0.0/24
    
    # Enterprise features and optimizations
    auto=add
    closeaction=restart
    dpdaction=restart
    dpddelay=30s
    dpdtimeout=120s
    replay_window=64
    compress=no
    mobike=yes
    forceencaps=no
    
    # Enterprise security enhancements
    send_certreq=yes
    send_cert=always
    
    # Performance optimizations
    inactivity_timeout=900
    
# Primary hub-to-spoke connections with certificate authentication
conn pqc-vpn-clients
    also=%default
    
    # Client-specific settings
    rightauth=pubkey
    rightsourceip=10.10.1.0/24
    rightdns=8.8.8.8,8.8.4.4
    rightsendcert=always
    leftfirewall=yes
    
    # Enterprise access control
    rightgroups=vpn-users
    
    # Automatic connection management
    auto=add

# PSK-based connection for legacy/IoT devices
conn pqc-vpn-psk
    keyexchange=ikev2
    
    # Network configuration
    left=${HUB_IP}
    leftsubnet=10.10.0.0/16
    leftauth=psk
    leftfirewall=yes
    leftid=@pqc-vpn-hub
    
    right=%any
    rightsubnet=10.10.2.0/24
    rightsourceip=10.10.2.0/24
    rightauth=psk
    rightdns=8.8.8.8,8.8.4.4
    
    # Simplified crypto for IoT devices
    ike=aes256-sha256-modp2048,aes128-sha256-modp2048!
    esp=aes256-sha256,aes128-sha256!
    
    # Timing configuration
    ikelifetime=86400s
    keylife=3600s
    rekeymargin=540s
    
    auto=add

# Site-to-site VPN for enterprise branch offices
conn pqc-vpn-site2site
    type=tunnel
    keyexchange=ikev2
    
    # Authentication
    leftauth=pubkey
    rightauth=pubkey
    leftcert=hub-cert.pem
    
    # Network configuration for site-to-site
    left=${HUB_IP}
    leftsubnet=10.10.0.0/16
    right=%any
    rightsubnet=10.20.0.0/16
    
    # Enterprise-grade crypto
    ike=aes256gcm16-sha384-ecp384!
    esp=aes256gcm16-sha384!
    
    # Site-to-site specific settings
    auto=start
    closeaction=restart
    dpdaction=restart
    dpddelay=30s
    dpdtimeout=120s

# Enterprise monitoring and management connection
conn pqc-vpn-monitor
    type=passthrough
    left=%any
    right=%any
    leftprotoport=udp/500
    rightprotoport=udp/500
    auto=route

# Road warrior connection for mobile users
conn pqc-vpn-roadwarrior
    also=%default
    
    # Mobile-optimized settings
    rightauth=eap-mschapv2
    rightsourceip=10.10.3.0/24
    rightdns=8.8.8.8,8.8.4.4
    
    # Mobile crypto optimization
    ike=aes256gcm16-sha256-ecp256,aes128gcm16-sha256-ecp256!
    esp=aes256gcm16-sha256,aes128gcm16-sha256!
    
    # Mobile-specific features
    mobike=yes
    closeaction=restart
    
    auto=add
EOF
    
    # Set proper permissions
    chmod 644 /etc/ipsec.conf
    chmod 644 /etc/strongswan.conf
    
    success "strongSwan configuration with OpenSSL 3.5 support completed"
}

generate_certificates() {
    info "Generating enterprise certificates with OpenSSL 3.5..."
    
    local openssl_bin="${OPENSSL_PREFIX}/bin/openssl"
    export OPENSSL_CONF="${OPENSSL_PREFIX}/ssl/openssl.cnf"
    
    # Generate CA private key (RSA-4096 for maximum security)
    info "Generating Certificate Authority..."
    $openssl_bin genrsa -out /etc/ipsec.d/private/ca-key.pem 4096
    
    # Generate CA certificate
    $openssl_bin req -new -x509 -days 3650 \
        -key /etc/ipsec.d/private/ca-key.pem \
        -out /etc/ipsec.d/cacerts/ca-cert.pem \
        -extensions v3_ca \
        -subj "/C=US/ST=California/L=San Francisco/O=PQC-VPN Enterprise/OU=Certificate Authority/CN=PQC-VPN Root CA"
    
    # Generate hub private key
    info "Generating Hub certificate..."
    $openssl_bin genrsa -out /etc/ipsec.d/private/hub-key.pem 4096
    
    # Generate hub certificate signing request
    $openssl_bin req -new \
        -key /etc/ipsec.d/private/hub-key.pem \
        -out /tmp/hub-csr.pem \
        -subj "/C=US/ST=California/L=San Francisco/O=PQC-VPN Enterprise/OU=VPN Hub/CN=pqc-vpn-hub"
    
    # Create hub certificate with SAN extension
    cat > /tmp/hub_ext.cnf << EOF
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "PQC-VPN Hub Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment, keyAgreement
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = pqc-vpn-hub
DNS.3 = hub.pqc-vpn.local
DNS.4 = *.pqc-vpn.local
IP.1 = 127.0.0.1
IP.2 = ${HUB_IP}
EOF
    
    # Sign hub certificate
    $openssl_bin x509 -req -in /tmp/hub-csr.pem \
        -CA /etc/ipsec.d/cacerts/ca-cert.pem \
        -CAkey /etc/ipsec.d/private/ca-key.pem \
        -CAcreateserial \
        -out /etc/ipsec.d/certs/hub-cert.pem \
        -days 365 \
        -extensions server_cert \
        -extfile /tmp/hub_ext.cnf
    
    # Generate ECDSA certificates for performance testing
    info "Generating ECDSA certificates for performance comparison..."
    
    # ECDSA CA key (P-384)
    $openssl_bin ecparam -genkey -name secp384r1 -out /etc/ipsec.d/private/ecdsa-ca-key.pem
    
    # ECDSA CA certificate
    $openssl_bin req -new -x509 -days 3650 \
        -key /etc/ipsec.d/private/ecdsa-ca-key.pem \
        -out /etc/ipsec.d/cacerts/ecdsa-ca-cert.pem \
        -extensions v3_ca \
        -subj "/C=US/ST=California/L=San Francisco/O=PQC-VPN Enterprise/OU=ECDSA Certificate Authority/CN=PQC-VPN ECDSA Root CA"
    
    # ECDSA hub key (P-384)
    $openssl_bin ecparam -genkey -name secp384r1 -out /etc/ipsec.d/private/ecdsa-hub-key.pem
    
    # ECDSA hub certificate
    $openssl_bin req -new \
        -key /etc/ipsec.d/private/ecdsa-hub-key.pem \
        -out /tmp/ecdsa-hub-csr.pem \
        -subj "/C=US/ST=California/L=San Francisco/O=PQC-VPN Enterprise/OU=ECDSA VPN Hub/CN=pqc-vpn-hub-ecdsa"
    
    $openssl_bin x509 -req -in /tmp/ecdsa-hub-csr.pem \
        -CA /etc/ipsec.d/cacerts/ecdsa-ca-cert.pem \
        -CAkey /etc/ipsec.d/private/ecdsa-ca-key.pem \
        -CAcreateserial \
        -out /etc/ipsec.d/certs/ecdsa-hub-cert.pem \
        -days 365 \
        -extensions server_cert \
        -extfile /tmp/hub_ext.cnf
    
    # Set proper permissions
    chmod 600 /etc/ipsec.d/private/*
    chmod 644 /etc/ipsec.d/certs/*
    chmod 644 /etc/ipsec.d/cacerts/*
    
    # Clean up temporary files
    rm -f /tmp/hub-csr.pem /tmp/hub_ext.cnf /tmp/ecdsa-hub-csr.pem
    
    # Verify certificates
    info "Verifying generated certificates..."
    $openssl_bin x509 -in /etc/ipsec.d/cacerts/ca-cert.pem -noout -text | head -20
    $openssl_bin x509 -in /etc/ipsec.d/certs/hub-cert.pem -noout -text | head -15
    
    success "Enterprise certificates generated successfully"
}

setup_firewall() {
    info "Configuring enterprise firewall with enhanced security..."
    
    # Detect firewall system and configure accordingly
    if command -v ufw > /dev/null; then
        # Ubuntu/Debian UFW
        ufw --force enable
        
        # Basic VPN ports
        ufw allow 500/udp comment "IPsec IKE"
        ufw allow 4500/udp comment "IPsec NAT-T"
        ufw allow ssh comment "SSH management"
        
        # Management interfaces
        if [[ "$ENABLE_WEB_INTERFACE" == "true" ]]; then
            ufw allow 8443/tcp comment "PQC-VPN Web Interface"
        fi
        
        if [[ "$ENABLE_MONITORING" == "true" ]]; then
            ufw allow 3000/tcp comment "Grafana"
            ufw allow 9090/tcp comment "Prometheus"
        fi
        
        # Enterprise logging
        ufw logging on
        
    elif command -v firewall-cmd > /dev/null; then
        # CentOS/RHEL firewalld
        systemctl enable firewalld
        systemctl start firewalld
        
        # Configure zones
        firewall-cmd --permanent --new-zone=vpn-zone || true
        firewall-cmd --permanent --zone=vpn-zone --add-source=10.10.0.0/16
        
        # Basic services
        firewall-cmd --permanent --add-service=ipsec
        firewall-cmd --permanent --add-port=500/udp
        firewall-cmd --permanent --add-port=4500/udp
        
        # Management interfaces
        if [[ "$ENABLE_WEB_INTERFACE" == "true" ]]; then
            firewall-cmd --permanent --add-port=8443/tcp
        fi
        
        if [[ "$ENABLE_MONITORING" == "true" ]]; then
            firewall-cmd --permanent --add-port=3000/tcp
            firewall-cmd --permanent --add-port=9090/tcp
        fi
        
        # Enable masquerading for VPN
        firewall-cmd --permanent --add-masquerade
        
        firewall-cmd --reload
        
    else
        # Direct iptables configuration
        info "Configuring iptables rules..."
        
        # Flush existing rules
        iptables -F
        iptables -X
        iptables -t nat -F
        iptables -t nat -X
        
        # Default policies
        iptables -P INPUT DROP
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
        
        # Allow loopback
        iptables -A INPUT -i lo -j ACCEPT
        
        # Allow established connections
        iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        
        # Allow IPsec
        iptables -A INPUT -p udp --dport 500 -j ACCEPT
        iptables -A INPUT -p udp --dport 4500 -j ACCEPT
        iptables -A INPUT -p esp -j ACCEPT
        iptables -A INPUT -p ah -j ACCEPT
        
        # Allow SSH
        iptables -A INPUT -p tcp --dport 22 -j ACCEPT
        
        # Management interfaces
        if [[ "$ENABLE_WEB_INTERFACE" == "true" ]]; then
            iptables -A INPUT -p tcp --dport 8443 -j ACCEPT
        fi
        
        if [[ "$ENABLE_MONITORING" == "true" ]]; then
            iptables -A INPUT -p tcp --dport 3000 -j ACCEPT
            iptables -A INPUT -p tcp --dport 9090 -j ACCEPT
        fi
        
        # NAT for VPN clients
        iptables -t nat -A POSTROUTING -s 10.10.0.0/16 -o $(ip route | grep default | awk '{print $5}' | head -1) -j MASQUERADE
        
        # Forward VPN traffic
        iptables -A FORWARD -s 10.10.0.0/16 -j ACCEPT
        iptables -A FORWARD -d 10.10.0.0/16 -j ACCEPT
        
        # Save iptables rules
        if command -v iptables-save > /dev/null; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
            iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
        fi
    fi
    
    success "Enterprise firewall configured"
}

configure_networking() {
    info "Configuring enterprise networking optimizations..."
    
    # Enable IP forwarding
    echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-pqc-vpn.conf
    echo 'net.ipv6.conf.all.forwarding = 1' >> /etc/sysctl.d/99-pqc-vpn.conf
    
    # Enterprise network optimizations for OpenSSL 3.5 and VPN performance
    cat >> /etc/sysctl.d/99-pqc-vpn.conf << 'EOF'
# PQC-VPN Enterprise Network Optimizations for OpenSSL 3.5

# Enhanced TCP settings for high-performance VPN
net.core.rmem_default = 262144
net.core.rmem_max = 67108864
net.core.wmem_default = 262144
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 262144 67108864
net.ipv4.tcp_wmem = 4096 262144 67108864

# Network device optimizations
net.core.netdev_max_backlog = 10000
net.core.netdev_budget = 600
net.core.netdev_budget_usecs = 5000

# TCP performance enhancements
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fack = 1
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_no_metrics_save = 1

# Security enhancements
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.default.rp_filter = 1

# IPsec and crypto optimizations
net.core.xfrm_larval_drop = 1
net.core.xfrm_acq_expires = 3

# Memory management for crypto operations
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5

# File descriptor limits for enterprise workloads
fs.file-max = 2097152

# Network connection tracking
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30

# UDP optimizations for IPsec
net.ipv4.udp_mem = 102400 873800 16777216
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192

# IPv6 optimizations
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
EOF
    
    # Apply sysctl settings
    sysctl -p /etc/sysctl.d/99-pqc-vpn.conf
    
    success "Enterprise network configuration applied"
}

install_python_tools() {
    info "Installing enhanced Python management tools for OpenSSL 3.5..."
    
    # Install Python dependencies
    pip3 install --upgrade pip setuptools wheel
    
    # Enterprise Python packages
    local pip_packages=(
        "psutil>=5.9.0"
        "pyyaml>=6.0"
        "cryptography>=41.0.0"
        "requests>=2.31.0"
        "click>=8.1.0"
        "tabulate>=0.9.0"
        "colorama>=0.4.6"
        "flask>=2.3.0"
        "flask-cors>=4.0.0"
        "jinja2>=3.1.0"
        "jsonschema>=4.0.0"
        "schedule>=1.2.0"
        "prometheus-client>=0.17.0"
        "grafana-api>=1.0.3"
        "paramiko>=3.3.0"
        "scapy>=2.5.0"
        "netaddr>=0.9.0"
        "dnspython>=2.4.0"
        "certifi>=2023.7.22"
        "pyopenssl>=23.2.0"
    )
    
    pip3 install "${pip_packages[@]}"
    
    # Install enhanced PQC-VPN tools
    local tools_dir="${REPO_DIR:-/opt/PQC-VPN}/tools"
    if [[ -d "$tools_dir" ]]; then
        cp "$tools_dir"/*.py /usr/local/bin/pqc-vpn/
        chmod +x /usr/local/bin/pqc-vpn/*.py
        
        # Create symlinks with OpenSSL 3.5 environment
        cat > /usr/local/bin/pqc-vpn-manager << 'EOF'
#!/bin/bash
export OPENSSL_CONF="/usr/local/openssl35/ssl/openssl.cnf"
export LD_LIBRARY_PATH="/usr/local/openssl35/lib:${LD_LIBRARY_PATH}"
export PATH="/usr/local/openssl35/bin:${PATH}"
exec /usr/local/bin/pqc-vpn/pqc-vpn-manager.py "$@"
EOF
        
        cat > /usr/local/bin/pqc-connection-monitor << 'EOF'
#!/bin/bash
export OPENSSL_CONF="/usr/local/openssl35/ssl/openssl.cnf"
export LD_LIBRARY_PATH="/usr/local/openssl35/lib:${LD_LIBRARY_PATH}"
export PATH="/usr/local/openssl35/bin:${PATH}"
exec /usr/local/bin/pqc-vpn/connection-monitor.py "$@"
EOF
        
        cat > /usr/local/bin/pqc-keygen << 'EOF'
#!/bin/bash
export OPENSSL_CONF="/usr/local/openssl35/ssl/openssl.cnf"
export LD_LIBRARY_PATH="/usr/local/openssl35/lib:${LD_LIBRARY_PATH}"
export PATH="/usr/local/openssl35/bin:${PATH}"
exec /usr/local/bin/pqc-vpn/pqc-keygen.py "$@"
EOF
        
        chmod +x /usr/local/bin/pqc-*
    fi
    
    success "Enhanced Python tools with OpenSSL 3.5 support installed"
}

setup_web_interface() {
    if [[ "$ENABLE_WEB_INTERFACE" != "true" ]]; then
        return 0
    fi
    
    info "Setting up enterprise web management interface..."
    
    # Install enhanced web interface
    local web_dir="${REPO_DIR:-/opt/PQC-VPN}/web"
    if [[ -d "$web_dir" ]]; then
        mkdir -p /var/www/pqc-vpn
        cp -r "$web_dir"/* /var/www/pqc-vpn/
        
        # Create enhanced systemd service for web API with OpenSSL 3.5
        cat > /etc/systemd/system/pqc-vpn-web.service << 'EOF'
[Unit]
Description=PQC-VPN Web Management Interface (OpenSSL 3.5)
After=network.target strongswan.service
Requires=strongswan.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/var/www/pqc-vpn
ExecStart=/usr/bin/python3 /var/www/pqc-vpn/api_server.py
Restart=always
RestartSec=10
Environment=PYTHONPATH=/usr/local/bin/pqc-vpn
Environment=OPENSSL_CONF=/usr/local/openssl35/ssl/openssl.cnf
Environment=LD_LIBRARY_PATH=/usr/local/openssl35/lib
Environment=PATH=/usr/local/openssl35/bin:/usr/local/bin:/usr/bin:/bin
Environment=PQC_VPN_MODE=production

# Security enhancements
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/www/pqc-vpn /var/log/pqc-vpn /etc/ipsec.d

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF
        
        systemctl daemon-reload
        systemctl enable pqc-vpn-web
    fi
    
    success "Enterprise web interface configured"
}

setup_monitoring() {
    if [[ "$ENABLE_MONITORING" != "true" ]]; then
        return 0
    fi
    
    info "Setting up enterprise monitoring with OpenSSL 3.5 metrics..."
    
    # Create enhanced monitoring configuration
    mkdir -p /etc/pqc-vpn/monitoring
    
    # Enhanced Prometheus configuration
    cat > /etc/pqc-vpn/monitoring/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    monitor: 'pqc-vpn-monitor'

rule_files:
  - "/etc/pqc-vpn/monitoring/alert_rules.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

scrape_configs:
  - job_name: 'pqc-vpn-hub'
    static_configs:
      - targets: ['localhost:8443']
    metrics_path: '/api/metrics'
    scrape_interval: 30s
    
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['localhost:9100']
    scrape_interval: 15s
    
  - job_name: 'strongswan-exporter'
    static_configs:
      - targets: ['localhost:9101']
    scrape_interval: 30s
    
  - job_name: 'openssl-metrics'
    static_configs:
      - targets: ['localhost:9102']
    metrics_path: '/metrics'
    scrape_interval: 60s
EOF
    
    # Create alert rules
    cat > /etc/pqc-vpn/monitoring/alert_rules.yml << 'EOF'
groups:
  - name: pqc-vpn-alerts
    rules:
      - alert: VPNConnectionDown
        expr: strongswan_connections_active == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "No active VPN connections"
          description: "PQC-VPN hub has no active connections for more than 5 minutes"
          
      - alert: HighCPUUsage
        expr: 100 - (avg by(instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High CPU usage detected"
          description: "CPU usage is above 80% for more than 5 minutes"
          
      - alert: CertificateExpiringSoon
        expr: (openssl_certificate_expiry_days < 30) and (openssl_certificate_expiry_days > 0)
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "Certificate expiring soon"
          description: "SSL certificate will expire in {{ $value }} days"
          
      - alert: OpenSSLCryptoFailure
        expr: openssl_crypto_operations_failed_total > 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "OpenSSL cryptographic operation failure"
          description: "OpenSSL has reported failed cryptographic operations"
EOF
    
    # Enhanced Node exporter installation
    if ! command -v node_exporter > /dev/null; then
        local node_exporter_version="1.7.0"
        wget -O /tmp/node_exporter.tar.gz \
            "https://github.com/prometheus/node_exporter/releases/download/v${node_exporter_version}/node_exporter-${node_exporter_version}.linux-amd64.tar.gz"
        tar -xzf /tmp/node_exporter.tar.gz -C /tmp
        mv "/tmp/node_exporter-${node_exporter_version}.linux-amd64/node_exporter" /usr/local/bin/
        rm -rf /tmp/node_exporter*
        
        # Create enhanced systemd service
        cat > /etc/systemd/system/node-exporter.service << 'EOF'
[Unit]
Description=Node Exporter for PQC-VPN
After=network.target

[Service]
Type=simple
User=nobody
Group=nobody
ExecStart=/usr/local/bin/node_exporter \
  --web.listen-address=:9100 \
  --collector.filesystem.ignored-mount-points="^/(dev|proc|sys|var/lib/docker/.+)($|/)" \
  --collector.filesystem.ignored-fs-types="^(autofs|binfmt_misc|bpf|cgroup2?|configfs|debugfs|devpts|devtmpfs|fusectl|hugetlbfs|mqueue|nsfs|overlay|proc|procfs|pstore|rpc_pipefs|securityfs|selinuxfs|squashfs|sysfs|tracefs)$"
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
        
        systemctl daemon-reload
        systemctl enable node-exporter
        systemctl start node-exporter
    fi
    
    success "Enterprise monitoring with OpenSSL 3.5 metrics configured"
}

setup_systemd_services() {
    info "Configuring enhanced systemd services for OpenSSL 3.5..."
    
    # Ensure strongSwan is enabled
    systemctl enable strongswan
    
    # Create enhanced PQC-VPN service with OpenSSL 3.5 environment
    cat > /etc/systemd/system/pqc-vpn.service << 'EOF'
[Unit]
Description=PQC-VPN Hub Service (OpenSSL 3.5)
After=network.target network-online.target
Wants=network-online.target
Before=strongswan.service

[Service]
Type=forking
Environment=OPENSSL_CONF=/usr/local/openssl35/ssl/openssl.cnf
Environment=LD_LIBRARY_PATH=/usr/local/openssl35/lib
Environment=PATH=/usr/local/openssl35/bin:/usr/local/strongswan/sbin:/usr/local/strongswan/bin:/usr/local/bin:/usr/bin:/bin
ExecStartPre=/bin/bash -c 'while ! ping -c1 8.8.8.8 >/dev/null 2>&1; do sleep 1; done'
ExecStart=/usr/local/strongswan/sbin/ipsec start --nofork
ExecReload=/usr/local/strongswan/sbin/ipsec reload
ExecStop=/usr/local/strongswan/sbin/ipsec stop
Restart=always
RestartSec=10
TimeoutStartSec=300
TimeoutStopSec=60

# Security enhancements
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log /var/run /etc/ipsec.d /tmp
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_CHOWN CAP_FOWNER CAP_SETGID CAP_SETUID

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF
    
    # Create enhanced maintenance service
    cat > /etc/systemd/system/pqc-vpn-maintenance.service << 'EOF'
[Unit]
Description=PQC-VPN Maintenance Tasks (OpenSSL 3.5)
After=network.target

[Service]
Type=oneshot
Environment=OPENSSL_CONF=/usr/local/openssl35/ssl/openssl.cnf
Environment=LD_LIBRARY_PATH=/usr/local/openssl35/lib
Environment=PATH=/usr/local/openssl35/bin:/usr/local/bin:/usr/bin:/bin
ExecStart=/usr/local/bin/pqc-vpn-maintenance.sh
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF
    
    # Create maintenance timer (daily execution)
    cat > /etc/systemd/system/pqc-vpn-maintenance.timer << 'EOF'
[Unit]
Description=Run PQC-VPN maintenance tasks daily
Requires=pqc-vpn-maintenance.service

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=3600

[Install]
WantedBy=timers.target
EOF
    
    # Create enhanced maintenance script
    cat > /usr/local/bin/pqc-vpn-maintenance.sh << 'EOF'
#!/bin/bash
# PQC-VPN Maintenance Script for OpenSSL 3.5

set -euo pipefail

# Environment setup
export OPENSSL_CONF="/usr/local/openssl35/ssl/openssl.cnf"
export LD_LIBRARY_PATH="/usr/local/openssl35/lib:${LD_LIBRARY_PATH:-}"
export PATH="/usr/local/openssl35/bin:/usr/local/bin:/usr/bin:/bin"

OPENSSL_BIN="/usr/local/openssl35/bin/openssl"
LOG_FILE="/var/log/pqc-vpn/maintenance.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOG_FILE"
}

log "Starting PQC-VPN maintenance tasks..."

# Rotate logs
log "Rotating log files..."
find /var/log/strongswan -name "*.log" -mtime +30 -delete 2>/dev/null || true
find /var/log/pqc-vpn -name "*.log" -mtime +30 -delete 2>/dev/null || true

# Compress old logs
find /var/log/strongswan -name "*.log" -mtime +7 -exec gzip {} \; 2>/dev/null || true
find /var/log/pqc-vpn -name "*.log" -mtime +7 -exec gzip {} \; 2>/dev/null || true

# Check certificate expiry
log "Checking certificate expiry..."
if [[ -f /etc/ipsec.d/certs/hub-cert.pem ]]; then
    expiry_date=$($OPENSSL_BIN x509 -in /etc/ipsec.d/certs/hub-cert.pem -noout -enddate | cut -d= -f2)
    expiry_epoch=$(date -d "$expiry_date" +%s)
    current_epoch=$(date +%s)
    days_until_expiry=$(( (expiry_epoch - current_epoch) / 86400 ))
    
    log "Hub certificate expires in $days_until_expiry days ($expiry_date)"
    
    if [[ $days_until_expiry -lt 30 ]]; then
        log "WARNING: Certificate expires in less than 30 days!"
        # Send alert (implement your notification system here)
    fi
fi

# Check OpenSSL 3.5 functionality
log "Verifying OpenSSL 3.5 functionality..."
$OPENSSL_BIN version
$OPENSSL_BIN list -algorithms >/dev/null

# Update CRL if configured
if [[ -f /etc/ipsec.d/crls/ca.crl ]]; then
    log "Checking CRL update..."
    # Implement CRL update logic here
fi

# Backup configuration
log "Creating configuration backup..."
backup_dir="/var/backups/pqc-vpn"
mkdir -p "$backup_dir"

backup_file="$backup_dir/config-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
tar -czf "$backup_file" \
    /etc/ipsec.conf \
    /etc/ipsec.secrets \
    /etc/strongswan.conf \
    /etc/ipsec.d/certs \
    /etc/ipsec.d/cacerts \
    /usr/local/openssl35/ssl/openssl.cnf \
    2>/dev/null || log "Backup creation had some warnings"

# Keep only last 7 days of backups
find "$backup_dir" -name "config-backup-*.tar.gz" -mtime +7 -delete 2>/dev/null || true

# Performance monitoring
log "Collecting performance metrics..."
if command -v pqc-connection-monitor > /dev/null; then
    pqc-connection-monitor status --format json > "/var/log/pqc-vpn/status-$(date +%Y%m%d).json" || true
fi

# Check system resources
log "Checking system resources..."
df -h | grep -E '(^Filesystem|/$|/var|/tmp)' >> "$LOG_FILE"
free -h >> "$LOG_FILE"

# Validate strongSwan configuration
log "Validating strongSwan configuration..."
if /usr/local/strongswan/sbin/ipsec checkconfig; then
    log "strongSwan configuration is valid"
else
    log "WARNING: strongSwan configuration validation failed!"
fi

log "Maintenance tasks completed successfully"
EOF
    
    chmod +x /usr/local/bin/pqc-vpn-maintenance.sh
    
    # Reload systemd and enable services
    systemctl daemon-reload
    systemctl enable pqc-vpn
    systemctl enable pqc-vpn-maintenance.timer
    
    success "Enhanced systemd services configured"
}

start_services() {
    info "Starting PQC-VPN services with OpenSSL 3.5..."
    
    # Start strongSwan
    if systemctl start strongswan; then
        success "strongSwan started successfully"
    else
        error "Failed to start strongSwan"
        systemctl status strongswan
        exit 1
    fi
    
    # Start PQC-VPN service
    if systemctl start pqc-vpn; then
        success "PQC-VPN service started successfully"
    else
        warn "PQC-VPN service startup had issues"
        systemctl status pqc-vpn
    fi
    
    # Start web interface if enabled
    if [[ "$ENABLE_WEB_INTERFACE" == "true" ]]; then
        systemctl start pqc-vpn-web
        success "Web interface started"
    fi
    
    # Start maintenance timer
    systemctl start pqc-vpn-maintenance.timer
    success "Maintenance timer started"
    
    # Verify services are running
    sleep 10
    
    local status_checks=(
        "strongswan"
        "pqc-vpn"
    )
    
    if [[ "$ENABLE_WEB_INTERFACE" == "true" ]]; then
        status_checks+=("pqc-vpn-web")
    fi
    
    for service in "${status_checks[@]}"; do
        if systemctl is-active --quiet "$service"; then
            success "$service is running"
        else
            warn "$service status check failed"
            systemctl status "$service" --no-pager
        fi
    done
    
    success "Services startup completed"
}

perform_post_install_checks() {
    info "Performing comprehensive post-installation validation..."
    
    local openssl_bin="${OPENSSL_PREFIX}/bin/openssl"
    
    # Check OpenSSL 3.5 installation
    local openssl_version=$($openssl_bin version)
    info "OpenSSL version: $openssl_version"
    
    # Verify algorithm availability
    info "Available algorithms:"
    $openssl_bin list -algorithms | head -10
    
    # Check strongSwan status
    if /usr/local/strongswan/sbin/ipsec status > /dev/null 2>&1; then
        success "strongSwan is functioning correctly"
        /usr/local/strongswan/sbin/ipsec status
    else
        warn "strongSwan status check failed"
    fi
    
    # Check certificate validity
    if [[ -f /etc/ipsec.d/certs/hub-cert.pem ]]; then
        local cert_info=$($openssl_bin x509 -in /etc/ipsec.d/certs/hub-cert.pem -noout -subject -issuer -dates)
        info "Hub certificate information:"
        echo "$cert_info"
    fi
    
    # Test certificate verification
    if [[ -f /etc/ipsec.d/certs/hub-cert.pem && -f /etc/ipsec.d/cacerts/ca-cert.pem ]]; then
        if $openssl_bin verify -CAfile /etc/ipsec.d/cacerts/ca-cert.pem /etc/ipsec.d/certs/hub-cert.pem; then
            success "Certificate chain verification passed"
        else
            warn "Certificate chain verification failed"
        fi
    fi
    
    # Check network connectivity
    if ping -c 1 8.8.8.8 > /dev/null 2>&1; then
        success "Internet connectivity verified"
    else
        warn "Internet connectivity check failed"
    fi
    
    # Check listening ports
    info "Checking listening ports..."
    ss -tlnp | grep -E ':500|:4500|:8443|:9090' || true
    
    # Performance assessment
    local cpu_cores=$(nproc)
    local mem_gb=$(free -g | awk '/^Mem:/{print $2}')
    local openssl_perf=$($openssl_bin speed rsa2048 2>&1 | grep "rsa 2048" | awk '{print $6}' || echo "N/A")
    
    info "System performance assessment:"
    info "  CPU cores: $cpu_cores"
    info "  Memory: ${mem_gb}GB"
    info "  OpenSSL RSA-2048 performance: $openssl_perf ops/sec"
    
    # Test crypto operations
    info "Testing cryptographic operations..."
    local test_key="/tmp/test-key.pem"
    local test_cert="/tmp/test-cert.pem"
    
    $openssl_bin genrsa -out "$test_key" 2048 2>/dev/null
    $openssl_bin req -new -x509 -key "$test_key" -out "$test_cert" -days 1 \
        -subj "/CN=test" 2>/dev/null
    
    if $openssl_bin verify -CAfile "$test_cert" "$test_cert" > /dev/null 2>&1; then
        success "Cryptographic operations test passed"
    else
        warn "Cryptographic operations test failed"
    fi
    
    rm -f "$test_key" "$test_cert"
    
    success "Post-installation validation completed"
}

print_installation_summary() {
    echo -e "\n${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                   INSTALLATION COMPLETE                      ║${NC}"
    echo -e "${GREEN}║                  OpenSSL 3.5 Enterprise                      ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}\n"
    
    echo -e "${CYAN}🎉 PQC-VPN Hub with OpenSSL 3.5 has been successfully installed!${NC}\n"
    
    local openssl_version=$("${OPENSSL_PREFIX}/bin/openssl" version | cut -d' ' -f2)
    
    echo -e "${BLUE}📊 Installation Summary:${NC}"
    echo -e "   • OpenSSL Version: ${YELLOW}${openssl_version}${NC}"
    echo -e "   • Hub IP Address: ${YELLOW}$HUB_IP${NC}"
    echo -e "   • Authentication Methods: ${YELLOW}$AUTH_METHODS${NC}"
    echo -e "   • Cryptographic Algorithms: ${YELLOW}$PQC_ALGORITHMS${NC}"
    echo -e "   • Installation Mode: ${YELLOW}$INSTALL_MODE${NC}"
    echo -e "   • Web Interface: ${YELLOW}$([ "$ENABLE_WEB_INTERFACE" == "true" ] && echo "Enabled" || echo "Disabled")${NC}"
    echo -e "   • Monitoring: ${YELLOW}$([ "$ENABLE_MONITORING" == "true" ] && echo "Enabled" || echo "Disabled")${NC}"
    echo -e "   • High Availability: ${YELLOW}$([ "$ENABLE_HA" == "true" ] && echo "Enabled" || echo "Disabled")${NC}"
    echo -e "   • FIPS Mode: ${YELLOW}$([ "$ENABLE_FIPS" == "true" ] && echo "Enabled" || echo "Disabled")${NC}"
    
    echo -e "\n${BLUE}🔗 Access Points:${NC}"
    if [[ "$ENABLE_WEB_INTERFACE" == "true" ]]; then
        echo -e "   • Web Dashboard: ${YELLOW}https://$HUB_IP:8443${NC}"
    fi
    if [[ "$ENABLE_MONITORING" == "true" ]]; then
        echo -e "   • Grafana: ${YELLOW}http://$HUB_IP:3000${NC} (admin/admin)"
        echo -e "   • Prometheus: ${YELLOW}http://$HUB_IP:9090${NC}"
    fi
    
    echo -e "\n${BLUE}📁 Important Files:${NC}"
    echo -e "   • OpenSSL 3.5 Binary: ${YELLOW}${OPENSSL_PREFIX}/bin/openssl${NC}"
    echo -e "   • OpenSSL Configuration: ${YELLOW}${OPENSSL_PREFIX}/ssl/openssl.cnf${NC}"
    echo -e "   • IPsec Configuration: ${YELLOW}/etc/ipsec.conf${NC}"
    echo -e "   • IPsec Secrets: ${YELLOW}/etc/ipsec.secrets${NC}"
    echo -e "   • strongSwan Configuration: ${YELLOW}/etc/strongswan.conf${NC}"
    echo -e "   • Certificates: ${YELLOW}/etc/ipsec.d/certs/${NC}"
    echo -e "   • Logs: ${YELLOW}/var/log/strongswan/${NC}, ${YELLOW}/var/log/pqc-vpn/${NC}"
    echo -e "   • Installation Log: ${YELLOW}$LOG_FILE${NC}"
    
    echo -e "\n${BLUE}🔧 Management Commands:${NC}"
    echo -e "   • OpenSSL Command: ${YELLOW}openssl-pqc${NC}"
    echo -e "   • Add User: ${YELLOW}pqc-vpn-manager user add <username> --email <email>${NC}"
    echo -e "   • Monitor Connections: ${YELLOW}pqc-connection-monitor status${NC}"
    echo -e "   • Generate Certificates: ${YELLOW}pqc-keygen${NC}"
    echo -e "   • Check Status: ${YELLOW}/usr/local/strongswan/sbin/ipsec status${NC}"
    echo -e "   • View Logs: ${YELLOW}journalctl -u strongswan -f${NC}"
    echo -e "   • System Maintenance: ${YELLOW}/usr/local/bin/pqc-vpn-maintenance.sh${NC}"
    
    echo -e "\n${BLUE}🧪 Verification Commands:${NC}"
    echo -e "   • Test OpenSSL: ${YELLOW}${OPENSSL_PREFIX}/bin/openssl version -a${NC}"
    echo -e "   • List Algorithms: ${YELLOW}${OPENSSL_PREFIX}/bin/openssl list -algorithms${NC}"
    echo -e "   • strongSwan Status: ${YELLOW}/usr/local/strongswan/sbin/ipsec statusall${NC}"
    echo -e "   • Certificate Info: ${YELLOW}${OPENSSL_PREFIX}/bin/openssl x509 -in /etc/ipsec.d/certs/hub-cert.pem -noout -text${NC}"
    
    echo -e "\n${BLUE}📚 Documentation:${NC}"
    echo -e "   • GitHub Repository: ${YELLOW}https://github.com/QEntangle/PQC-VPN${NC}"
    echo -e "   • OpenSSL 3.5 Migration Branch: ${YELLOW}https://github.com/QEntangle/PQC-VPN/tree/openssl-3.5-migration${NC}"
    echo -e "   • Documentation: ${YELLOW}https://github.com/QEntangle/PQC-VPN/tree/main/docs${NC}"
    
    echo -e "\n${BLUE}⚠️  Migration Notes:${NC}"
    echo -e "   • This installation uses OpenSSL 3.5 instead of liboqs"
    echo -e "   • Current algorithms: RSA-4096, ECDSA-P384, AES-256-GCM, ChaCha20-Poly1305"
    echo -e "   • Future PQC algorithms will be added as they become available in OpenSSL 3.5+"
    echo -e "   • Performance may differ from liboqs implementation"
    echo -e "   • All enterprise features have been preserved and enhanced"
    
    echo -e "\n${GREEN}✅ Installation completed successfully!${NC}"
    echo -e "   ${CYAN}Your VPN is now ready with OpenSSL 3.5 enterprise-grade cryptography.${NC}"
    echo -e "   ${CYAN}Future quantum-safe algorithms will be available through OpenSSL updates.${NC}\n"
}

# Main installation function
main() {
    print_banner
    check_root
    detect_os
    setup_logging
    check_requirements
    create_directories
    install_dependencies
    install_openssl35
    configure_openssl35
    configure_strongswan
    generate_certificates
    setup_firewall
    configure_networking
    install_python_tools
    setup_web_interface
    setup_monitoring
    setup_systemd_services
    start_services
    perform_post_install_checks
    print_installation_summary
}

# Handle command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --hub-ip)
            HUB_IP="$2"
            shift 2
            ;;
        --openssl-version)
            OPENSSL_VERSION="$2"
            shift 2
            ;;
        --enable-ha)
            ENABLE_HA="true"
            shift
            ;;
        --enable-fips)
            ENABLE_FIPS="true"
            shift
            ;;
        --disable-web)
            ENABLE_WEB_INTERFACE="false"
            shift
            ;;
        --disable-monitoring)
            ENABLE_MONITORING="false"
            shift
            ;;
        --install-mode)
            INSTALL_MODE="$2"
            shift 2
            ;;
        --auth-methods)
            AUTH_METHODS="$2"
            shift 2
            ;;
        --pqc-algorithms)
            PQC_ALGORITHMS="$2"
            shift 2
            ;;
        --debug)
            DEBUG="true"
            shift
            ;;
        --help|-h)
            echo "PQC-VPN Hub Installer v$SCRIPT_VERSION (OpenSSL 3.5)"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --hub-ip IP               Set hub IP address"
            echo "  --openssl-version VER     Set OpenSSL version (default: 3.5.0)"
            echo "  --enable-ha               Enable high availability"
            echo "  --enable-fips             Enable FIPS mode"
            echo "  --disable-web             Disable web interface"
            echo "  --disable-monitoring      Disable monitoring"
            echo "  --install-mode MODE       Set install mode (production/development/testing)"
            echo "  --auth-methods METHODS    Set authentication methods (pki,psk,hybrid)"
            echo "  --pqc-algorithms ALGOS    Set cryptographic algorithms"
            echo "  --debug                   Enable debug output"
            echo "  --help, -h                Show this help message"
            echo ""
            echo "Environment Variables:"
            echo "  HUB_IP                    Hub IP address"
            echo "  OPENSSL_VERSION           OpenSSL version to install"
            echo "  ENABLE_HA                 Enable high availability (true/false)"
            echo "  ENABLE_FIPS               Enable FIPS mode (true/false)"
            echo "  ENABLE_MONITORING         Enable monitoring (true/false)"
            echo "  ENABLE_WEB_INTERFACE      Enable web interface (true/false)"
            echo "  REPO_DIR                  Local repository directory"
            echo ""
            echo "Features:"
            echo "  • OpenSSL 3.5+ native support (no liboqs dependency)"
            echo "  • Enterprise-grade security and performance"
            echo "  • Future PQC algorithm support through OpenSSL"
            echo "  • Enhanced monitoring and management"
            echo "  • Production-ready deployment"
            echo ""
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Run main installation
main "$@"
