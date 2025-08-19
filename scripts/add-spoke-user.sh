#!/bin/bash
#
# Add Spoke User Script for PQC-VPN Hub
# Automates the process of adding new spoke users to the VPN
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default configuration
CERT_DIR="/opt/pqc-vpn/certs"
CONFIG_DIR="/etc"
IPSEC_CONF="$CONFIG_DIR/ipsec.conf"
IPSEC_SECRETS="$CONFIG_DIR/ipsec.secrets"
SPOKE_NETWORK_BASE="10.10"
SPOKE_NETWORK_START=10
MAX_SPOKES=1000
USER_DB="/opt/pqc-vpn/users.db"

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
Add Spoke User Script for PQC-VPN Hub

Usage: $0 <username> [OPTIONS]

Arguments:
    username                Username for the new spoke client

Options:
    --ip <ip>              Assign specific IP address
    --email <email>        User email for notifications
    --group <group>        User group (default: users)
    --expires <days>       Certificate expiry in days (default: 365)
    --no-cert             Skip certificate generation
    --batch               Non-interactive mode
    --cert-dir <path>     Certificate directory (default: $CERT_DIR)
    
    -h, --help            Show this help message
    -v, --verbose         Verbose output

Examples:
    $0 alice                          # Add user 'alice' with auto-assigned IP
    $0 bob --ip 10.10.1.50           # Add user 'bob' with specific IP
    $0 charlie --group admins         # Add user 'charlie' to 'admins' group
    $0 david --expires 730            # Add user 'david' with 2-year certificate

User Management:
    $0 --list                        # List all users
    $0 --remove <username>           # Remove user
    $0 --info <username>             # Show user information
    $0 --renew <username>            # Renew user certificate
    $0 --disable <username>          # Disable user temporarily
    $0 --enable <username>           # Re-enable disabled user

EOF
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Initialize user database
init_user_db() {
    if [[ ! -f "$USER_DB" ]]; then
        log_info "Creating user database..."
        cat > "$USER_DB" << 'EOF'
# PQC-VPN User Database
# Format: username:ip_address:group:email:created_date:expires_date:status:cert_path
# Status: active, disabled, expired
# This file is automatically managed by add-spoke-user.sh
EOF
        chmod 600 "$USER_DB"
        log_success "User database created: $USER_DB"
    fi
}

# Get next available IP address
get_next_ip() {
    local subnet_start=$SPOKE_NETWORK_START
    local subnet_current=$subnet_start
    
    # Read existing IP assignments
    local used_ips=()
    if [[ -f "$USER_DB" ]]; then
        while IFS=':' read -r username ip_addr group email created expires status cert_path; do
            if [[ ! "$username" =~ ^# ]] && [[ -n "$ip_addr" ]] && [[ "$status" != "removed" ]]; then
                used_ips+=("$ip_addr")
            fi
        done < "$USER_DB"
    fi
    
    # Find next available IP
    for ((i=1; i<=254; i++)); do
        local test_ip="$SPOKE_NETWORK_BASE.$subnet_current.$i"
        
        # Skip network and broadcast addresses
        if [[ $i -eq 1 || $i -eq 255 ]]; then
            continue
        fi
        
        # Check if IP is already used
        local ip_used=false
        for used_ip in "${used_ips[@]}"; do
            if [[ "$used_ip" == "$test_ip" ]]; then
                ip_used=true
                break
            fi
        done
        
        if [[ "$ip_used" == false ]]; then
            echo "$test_ip"
            return 0
        fi
    done
    
    # If current subnet is full, try next subnet
    ((subnet_current++))
    if [[ $subnet_current -le 255 ]]; then
        for ((i=1; i<=254; i++)); do
            local test_ip="$SPOKE_NETWORK_BASE.$subnet_current.$i"
            
            if [[ $i -eq 1 || $i -eq 255 ]]; then
                continue
            fi
            
            local ip_used=false
            for used_ip in "${used_ips[@]}"; do
                if [[ "$used_ip" == "$test_ip" ]]; then
                    ip_used=true
                    break
                fi
            done
            
            if [[ "$ip_used" == false ]]; then
                echo "$test_ip"
                return 0
            fi
        done
    fi
    
    log_error "No available IP addresses in the range"
    exit 1
}

# Validate IP address
validate_ip() {
    local ip="$1"
    
    if [[ ! $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 1
    fi
    
    local IFS='.'
    local parts=($ip)
    
    for part in "${parts[@]}"; do
        if [[ $part -gt 255 ]]; then
            return 1
        fi
    done
    
    return 0
}

# Check if user exists
user_exists() {
    local username="$1"
    
    if [[ ! -f "$USER_DB" ]]; then
        return 1
    fi
    
    grep -q "^$username:" "$USER_DB"
}

# Check if IP is available
ip_available() {
    local ip="$1"
    
    if [[ ! -f "$USER_DB" ]]; then
        return 0
    fi
    
    ! grep -q ":$ip:" "$USER_DB"
}

# Add user to database
add_user_to_db() {
    local username="$1"
    local ip_addr="$2"
    local group="$3"
    local email="$4"
    local expires_date="$5"
    local cert_path="$6"
    
    local created_date=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "$username:$ip_addr:$group:$email:$created_date:$expires_date:active:$cert_path" >> "$USER_DB"
    
    log_success "User added to database: $username"
}

# Generate spoke certificate for user
generate_user_certificate() {
    local username="$1"
    local expires_days="$2"
    
    log_info "Generating certificate for user: $username"
    
    # Use the generate-pqc-certs.sh script
    local cert_script="$(dirname "$0")/generate-pqc-certs.sh"
    
    if [[ ! -f "$cert_script" ]]; then
        log_error "Certificate generation script not found: $cert_script"
        exit 1
    fi
    
    # Generate certificate with custom validity period
    "$cert_script" --spoke "$username" --validity "$expires_days" --cert-dir "$CERT_DIR"
    
    local cert_file="$CERT_DIR/spokes/${username}-cert.pem"
    
    if [[ ! -f "$cert_file" ]]; then
        log_error "Certificate generation failed for user: $username"
        exit 1
    fi
    
    echo "$cert_file"
}

# Update ipsec.conf with new spoke connection
update_ipsec_conf() {
    local username="$1"
    local ip_addr="$2"
    
    log_info "Updating IPsec configuration for user: $username"
    
    # Backup original configuration
    cp "$IPSEC_CONF" "$IPSEC_CONF.backup.$(date +%Y%m%d_%H%M%S)"
    
    # Add spoke connection configuration
    cat >> "$IPSEC_CONF" << EOF

# Spoke connection for user: $username
conn $username
    keyexchange=ikev2
    authby=pubkey
    left=%defaultroute
    leftid=@hub.pqc-vpn.local
    leftcert=hub-cert.pem
    leftsubnet=10.10.0.0/16
    right=%any
    rightid=@$username
    rightsubnet=$ip_addr/32
    rightcert=${username}-cert.pem
    auto=add
    ike=aes256gcm16-prfsha256-kyber1024!
    esp=aes256gcm16-kyber1024!
    lifetime=24h
    ikelifetime=24h
    margintime=3m
    keyingtries=3
    rekeymargin=3m
    type=tunnel
    compress=no
    mobike=yes
    fragmentation=yes
    forceencaps=yes
EOF

    log_success "IPsec configuration updated for user: $username"
}

# Update ipsec.secrets with user certificate
update_ipsec_secrets() {
    local username="$1"
    
    log_info "Updating IPsec secrets for user: $username"
    
    # Backup original secrets
    cp "$IPSEC_SECRETS" "$IPSEC_SECRETS.backup.$(date +%Y%m%d_%H%M%S)"
    
    # Add certificate entry
    echo ": RSA ${username}-key.pem" >> "$IPSEC_SECRETS"
    
    log_success "IPsec secrets updated for user: $username"
}

# Copy certificates to strongSwan directory
install_certificates() {
    local username="$1"
    local cert_path="$2"
    
    log_info "Installing certificates for user: $username"
    
    # Copy certificate to strongSwan directory
    cp "$CERT_DIR/spokes/${username}-cert.pem" "/etc/ipsec.d/certs/"
    cp "$CERT_DIR/spokes/${username}-key.pem" "/etc/ipsec.d/private/"
    
    # Set proper permissions
    chmod 644 "/etc/ipsec.d/certs/${username}-cert.pem"
    chmod 600 "/etc/ipsec.d/private/${username}-key.pem"
    
    log_success "Certificates installed for user: $username"
}

# Reload strongSwan configuration
reload_strongswan() {
    log_info "Reloading strongSwan configuration..."
    
    if systemctl is-active --quiet strongswan; then
        ipsec reload
        log_success "strongSwan configuration reloaded"
    else
        log_warning "strongSwan is not running. Configuration will be loaded on next start."
    fi
}

# Create user package
create_user_package() {
    local username="$1"
    local ip_addr="$2"
    local email="$3"
    
    log_info "Creating user package for: $username"
    
    local package_dir="/opt/pqc-vpn/packages/$username"
    mkdir -p "$package_dir"
    
    # Copy necessary files
    cp "$CERT_DIR/ca/ca-cert.pem" "$package_dir/"
    cp "$CERT_DIR/spokes/${username}-cert.pem" "$package_dir/"
    cp "$CERT_DIR/spokes/${username}-key.pem" "$package_dir/"
    
    # Create configuration template
    cat > "$package_dir/ipsec.conf" << EOF
# PQC-VPN Spoke Configuration for $username
config setup
    charondebug="ike 2, knl 2, cfg 2, net 2, esp 2, dmn 2, mgr 2"
    strictcrlpolicy=no
    uniqueids=never

conn %default
    keyexchange=ikev2
    ike=aes256gcm16-prfsha256-kyber1024!
    esp=aes256gcm16-kyber1024!
    authby=pubkey
    compress=no
    type=tunnel

conn pqc-vpn
    left=%defaultroute
    leftid=@$username
    leftcert=${username}-cert.pem
    leftsubnet=$ip_addr/32
    right=%any
    rightid=@hub.pqc-vpn.local
    rightsubnet=10.10.0.0/16
    auto=start
    lifetime=24h
    ikelifetime=24h
    margintime=3m
    keyingtries=3
    rekeymargin=3m
    mobike=yes
    fragmentation=yes
    forceencaps=yes
EOF

    # Create secrets file
    cat > "$package_dir/ipsec.secrets" << EOF
# PQC-VPN Spoke Secrets for $username
: RSA ${username}-key.pem
EOF

    # Create README
    cat > "$package_dir/README.txt" << EOF
PQC-VPN Configuration Package for: $username
============================================

Your assigned IP address: $ip_addr
Email: $email
Generated: $(date)

Files included:
- ca-cert.pem: Certificate Authority certificate
- ${username}-cert.pem: Your client certificate  
- ${username}-key.pem: Your private key (KEEP SECURE!)
- ipsec.conf: strongSwan configuration
- ipsec.secrets: strongSwan secrets configuration

Installation Instructions:
=========================

Linux:
1. Install strongSwan with PQC support using install-spoke-linux.sh
2. Copy certificates to /etc/ipsec.d/:
   sudo cp ca-cert.pem /etc/ipsec.d/cacerts/
   sudo cp ${username}-cert.pem /etc/ipsec.d/certs/
   sudo cp ${username}-key.pem /etc/ipsec.d/private/
3. Copy configuration files:
   sudo cp ipsec.conf /etc/
   sudo cp ipsec.secrets /etc/
4. Start the connection:
   sudo ipsec start
   sudo ipsec up pqc-vpn

Windows:
1. Run install-spoke-windows.ps1 
2. Use the certificate installation script provided

Connection Details:
==================
- Your VPN IP: $ip_addr
- Hub Network: 10.10.0.0/16
- Encryption: Post-Quantum (Kyber-1024 + AES-256-GCM)
- Authentication: Digital Signatures (Dilithium-5)

Support:
========
Contact your VPN administrator for support.
EOF

    # Create ZIP package if zip is available
    if command -v zip >/dev/null 2>&1; then
        local zip_file="/opt/pqc-vpn/packages/${username}-package.zip"
        cd "$package_dir"
        zip -r "$zip_file" . >/dev/null 2>&1
        cd - >/dev/null
        log_success "User package created: $zip_file"
    else
        log_success "User package created: $package_dir"
    fi
}

# Send notification email (if configured)
send_notification() {
    local username="$1"
    local email="$2"
    local ip_addr="$3"
    
    if [[ -n "$email" ]] && command -v mail >/dev/null 2>&1; then
        log_info "Sending notification email to: $email"
        
        cat << EOF | mail -s "PQC-VPN Account Created: $username" "$email"
Hello,

Your PQC-VPN account has been created successfully.

Username: $username
Assigned IP: $ip_addr
Created: $(date)

Please download your certificate package and follow the installation instructions.

Your VPN administrator will provide you with the certificate package and hub connection details.

Best regards,
PQC-VPN Administrator
EOF
        
        log_success "Notification email sent to: $email"
    fi
}

# List all users
list_users() {
    if [[ ! -f "$USER_DB" ]]; then
        log_warning "No users found (database doesn't exist)"
        return 0
    fi
    
    log_info "PQC-VPN Users:"
    echo
    printf "%-15s %-15s %-10s %-25s %-10s %-19s\n" "Username" "IP Address" "Group" "Email" "Status" "Created"
    printf "%-15s %-15s %-10s %-25s %-10s %-19s\n" "--------" "----------" "-----" "-----" "------" "-------"
    
    while IFS=':' read -r username ip_addr group email created expires status cert_path; do
        if [[ ! "$username" =~ ^# ]] && [[ -n "$username" ]]; then
            local short_email="${email:0:24}"
            if [[ ${#email} -gt 24 ]]; then
                short_email="${short_email}..."
            fi
            printf "%-15s %-15s %-10s %-25s %-10s %-19s\n" "$username" "$ip_addr" "$group" "$short_email" "$status" "$created"
        fi
    done < "$USER_DB"
}

# Show user information
show_user_info() {
    local username="$1"
    
    if ! user_exists "$username"; then
        log_error "User not found: $username"
        exit 1
    fi
    
    local line=$(grep "^$username:" "$USER_DB")
    IFS=':' read -r user ip_addr group email created expires status cert_path <<< "$line"
    
    log_info "User Information: $username"
    echo
    echo "Username: $user"
    echo "IP Address: $ip_addr"
    echo "Group: $group"
    echo "Email: $email"
    echo "Created: $created"
    echo "Expires: $expires"
    echo "Status: $status"
    echo "Certificate: $cert_path"
    
    # Check certificate validity
    if [[ -f "$cert_path" ]]; then
        local cert_expires=$(openssl x509 -in "$cert_path" -noout -enddate 2>/dev/null | cut -d= -f2)
        echo "Certificate Expires: $cert_expires"
        
        # Check if certificate is still valid
        if openssl x509 -in "$cert_path" -checkend 0 >/dev/null 2>&1; then
            echo "Certificate Status: Valid"
        else
            echo "Certificate Status: Expired"
        fi
    else
        echo "Certificate Status: Not found"
    fi
}

# Remove user
remove_user() {
    local username="$1"
    
    if ! user_exists "$username"; then
        log_error "User not found: $username"
        exit 1
    fi
    
    log_warning "Removing user: $username"
    
    # Remove from database
    sed -i "/^$username:/d" "$USER_DB"
    
    # Remove from ipsec.conf
    sed -i "/^# Spoke connection for user: $username$/,/^$/d" "$IPSEC_CONF"
    
    # Remove from ipsec.secrets
    sed -i "/: RSA ${username}-key.pem/d" "$IPSEC_SECRETS"
    
    # Remove certificates
    rm -f "/etc/ipsec.d/certs/${username}-cert.pem"
    rm -f "/etc/ipsec.d/private/${username}-key.pem"
    rm -f "$CERT_DIR/spokes/${username}-cert.pem"
    rm -f "$CERT_DIR/spokes/${username}-key.pem"
    
    # Remove package
    rm -rf "/opt/pqc-vpn/packages/$username"
    
    reload_strongswan
    
    log_success "User removed: $username"
}

# Add new spoke user
add_spoke_user() {
    local username="$1"
    local ip_addr="$2"
    local group="$3"
    local email="$4"
    local expires_days="$5"
    local skip_cert="$6"
    
    log_info "Adding new spoke user: $username"
    
    # Validate username
    if [[ ! "$username" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        log_error "Invalid username. Use only alphanumeric characters, hyphens, and underscores."
        exit 1
    fi
    
    # Check if user already exists
    if user_exists "$username"; then
        log_error "User already exists: $username"
        exit 1
    fi
    
    # Get IP address if not provided
    if [[ -z "$ip_addr" ]]; then
        ip_addr=$(get_next_ip)
        log_info "Assigned IP address: $ip_addr"
    else
        # Validate provided IP
        if ! validate_ip "$ip_addr"; then
            log_error "Invalid IP address: $ip_addr"
            exit 1
        fi
        
        if ! ip_available "$ip_addr"; then
            log_error "IP address already in use: $ip_addr"
            exit 1
        fi
    fi
    
    # Set default group if not provided
    if [[ -z "$group" ]]; then
        group="users"
    fi
    
    # Calculate expiry date
    local expires_date=$(date -d "+${expires_days} days" '+%Y-%m-%d %H:%M:%S')
    
    # Generate certificate if not skipped
    local cert_path=""
    if [[ "$skip_cert" != "true" ]]; then
        cert_path=$(generate_user_certificate "$username" "$expires_days")
    fi
    
    # Add user to database
    add_user_to_db "$username" "$ip_addr" "$group" "$email" "$expires_date" "$cert_path"
    
    # Update configurations
    update_ipsec_conf "$username" "$ip_addr"
    update_ipsec_secrets "$username"
    
    # Install certificates
    if [[ "$skip_cert" != "true" ]]; then
        install_certificates "$username" "$cert_path"
    fi
    
    # Create user package
    create_user_package "$username" "$ip_addr" "$email"
    
    # Reload strongSwan
    reload_strongswan
    
    # Send notification
    send_notification "$username" "$email" "$ip_addr"
    
    log_success "User added successfully: $username"
    log_info "IP Address: $ip_addr"
    log_info "Group: $group"
    log_info "Certificate expires: $expires_date"
    log_info "User package: /opt/pqc-vpn/packages/${username}-package.zip"
}

# Parse command line arguments
parse_arguments() {
    local action=""
    local username=""
    local ip_addr=""
    local group=""
    local email=""
    local expires_days="365"
    local skip_cert="false"
    local batch_mode="false"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --list)
                action="list"
                shift
                ;;
            --remove)
                action="remove"
                if [[ $2 && $2 != -* ]]; then
                    username="$2"
                    shift
                else
                    log_error "Username required for --remove"
                    exit 1
                fi
                shift
                ;;
            --info)
                action="info"
                if [[ $2 && $2 != -* ]]; then
                    username="$2"
                    shift
                else
                    log_error "Username required for --info"
                    exit 1
                fi
                shift
                ;;
            --ip)
                ip_addr="$2"
                shift 2
                ;;
            --email)
                email="$2"
                shift 2
                ;;
            --group)
                group="$2"
                shift 2
                ;;
            --expires)
                expires_days="$2"
                shift 2
                ;;
            --no-cert)
                skip_cert="true"
                shift
                ;;
            --batch)
                batch_mode="true"
                shift
                ;;
            --cert-dir)
                CERT_DIR="$2"
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
            -*)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
            *)
                if [[ -z "$username" ]]; then
                    username="$1"
                    action="add"
                else
                    log_error "Unexpected argument: $1"
                    exit 1
                fi
                shift
                ;;
        esac
    done
    
    case "$action" in
        "add")
            if [[ -z "$username" ]]; then
                log_error "Username is required"
                show_help
                exit 1
            fi
            add_spoke_user "$username" "$ip_addr" "$group" "$email" "$expires_days" "$skip_cert"
            ;;
        "list")
            list_users
            ;;
        "remove")
            remove_user "$username"
            ;;
        "info")
            show_user_info "$username"
            ;;
        "")
            log_error "No action specified"
            show_help
            exit 1
            ;;
        *)
            log_error "Invalid action: $action"
            exit 1
            ;;
    esac
}

# Main function
main() {
    check_root
    init_user_db
    parse_arguments "$@"
}

# Run main function
main "$@"