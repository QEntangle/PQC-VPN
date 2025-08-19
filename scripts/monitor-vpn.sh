#!/bin/bash
#
# PQC-VPN Monitoring Script
# Real-time monitoring and management of PQC-VPN connections
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
LOG_DIR="/var/log/pqc-vpn"
USER_DB="/opt/pqc-vpn/users.db"
STRONGSWAN_LOG="/var/log/syslog"
REFRESH_INTERVAL=5
MAX_LOG_LINES=100

# Create log directory if it doesn't exist
mkdir -p "$LOG_DIR"

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
PQC-VPN Monitoring Script

Usage: $0 [COMMAND] [OPTIONS]

Commands:
    status              Show VPN status overview (default)
    connections         Show active connections
    users              Show user connection status
    logs               Show recent logs
    stats              Show statistics and performance metrics
    health             Health check of all components
    dashboard          Interactive dashboard
    export             Export monitoring data
    alerts             Check for alerts and issues
    
Options:
    --refresh <sec>    Refresh interval for dashboard (default: 5)
    --lines <num>      Number of log lines to show (default: 100)
    --format <fmt>     Output format: text, json, csv
    --watch            Continuous monitoring mode
    --output <file>    Output to file
    
    -h, --help         Show this help message
    -v, --verbose      Verbose output

Examples:
    $0 status                    # Show current status
    $0 dashboard                 # Interactive monitoring dashboard
    $0 connections --watch       # Watch connections in real-time
    $0 logs --lines 50          # Show last 50 log entries
    $0 stats --format json      # Export stats as JSON
    $0 health                   # Comprehensive health check

EOF
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Get system information
get_system_info() {
    echo "System Information:"
    echo "=================="
    echo "Hostname: $(hostname)"
    echo "Uptime: $(uptime -p 2>/dev/null || uptime)"
    echo "Load Average: $(uptime | awk -F'load average:' '{print $2}')"
    echo "Memory Usage: $(free -h | awk '/^Mem:/ {printf "%s/%s (%.1f%%)", $3, $2, $3/$2*100}')"
    echo "Disk Usage: $(df -h / | awk 'NR==2 {printf "%s/%s (%s)", $3, $2, $5}')"
    echo
}

# Get strongSwan status
get_strongswan_status() {
    echo "strongSwan Status:"
    echo "=================="
    
    if systemctl is-active --quiet strongswan; then
        echo -e "Service Status: ${GREEN}Active${NC}"
        echo "PID: $(systemctl show --property MainPID --value strongswan)"
        echo "Started: $(systemctl show --property ActiveEnterTimestamp --value strongswan)"
    else
        echo -e "Service Status: ${RED}Inactive${NC}"
        return 1
    fi
    
    # Get version information
    local version=$(ipsec --version 2>/dev/null | head -1)
    echo "Version: $version"
    
    # Check if PQC is supported
    if ipsec listpubkeys 2>/dev/null | grep -q "Dilithium\|Kyber"; then
        echo -e "PQC Support: ${GREEN}Enabled${NC}"
    else
        echo -e "PQC Support: ${YELLOW}Unknown/Disabled${NC}"
    fi
    
    echo
}

# Get active connections
get_connections() {
    echo "Active Connections:"
    echo "==================="
    
    local connections=$(ipsec status 2>/dev/null)
    
    if [[ -z "$connections" ]]; then
        echo "No active connections"
        return 0
    fi
    
    echo "$connections"
    echo
    
    # Parse and count connections
    local total_conns=$(echo "$connections" | grep -c "ESTABLISHED" || echo "0")
    local security_assocs=$(echo "$connections" | grep -c "INSTALLED" || echo "0")
    
    echo "Summary:"
    echo "  Total Connections: $total_conns"
    echo "  Security Associations: $security_assocs"
    echo
}

# Get user connection status
get_user_status() {
    echo "User Connection Status:"
    echo "======================"
    
    if [[ ! -f "$USER_DB" ]]; then
        echo "User database not found"
        return 0
    fi
    
    printf "%-15s %-15s %-10s %-12s %-20s\n" "Username" "IP Address" "Status" "Connection" "Last Seen"
    printf "%-15s %-15s %-10s %-12s %-20s\n" "--------" "----------" "------" "----------" "---------"
    
    while IFS=':' read -r username ip_addr group email created expires status cert_path; do
        if [[ ! "$username" =~ ^# ]] && [[ -n "$username" ]]; then
            local conn_status="Disconnected"
            local last_seen="Never"
            
            # Check if user is currently connected
            if ipsec status 2>/dev/null | grep -q "$username.*ESTABLISHED"; then
                conn_status="Connected"
                last_seen="Active"
            else
                # Check logs for last connection
                local last_log=$(grep "$username" "$STRONGSWAN_LOG" 2>/dev/null | tail -1)
                if [[ -n "$last_log" ]]; then
                    last_seen=$(echo "$last_log" | awk '{print $1" "$2" "$3}')
                fi
            fi
            
            # Color code the connection status
            local colored_status=""
            case "$conn_status" in
                "Connected")
                    colored_status="${GREEN}$conn_status${NC}"
                    ;;
                "Disconnected")
                    colored_status="${RED}$conn_status${NC}"
                    ;;
                *)
                    colored_status="${YELLOW}$conn_status${NC}"
                    ;;
            esac
            
            printf "%-15s %-15s %-10s %-20s %-20s\n" "$username" "$ip_addr" "$status" "$colored_status" "$last_seen"
        fi
    done < "$USER_DB"
    
    echo
}

# Get recent logs
get_logs() {
    local lines="${1:-$MAX_LOG_LINES}"
    
    echo "Recent Logs (last $lines entries):"
    echo "=================================="
    
    # Filter strongSwan related logs
    if [[ -f "$STRONGSWAN_LOG" ]]; then
        grep -i "ipsec\|strongswan\|charon" "$STRONGSWAN_LOG" | tail -n "$lines" | while read -r line; do
            # Color code different log levels
            if echo "$line" | grep -qi "error"; then
                echo -e "${RED}$line${NC}"
            elif echo "$line" | grep -qi "warning\|warn"; then
                echo -e "${YELLOW}$line${NC}"
            elif echo "$line" | grep -qi "established\|installed"; then
                echo -e "${GREEN}$line${NC}"
            else
                echo "$line"
            fi
        done
    else
        echo "No log file found"
    fi
    
    echo
}

# Get statistics
get_statistics() {
    echo "Performance Statistics:"
    echo "======================"
    
    # Connection statistics
    local total_users=0
    local active_connections=0
    local disabled_users=0
    
    if [[ -f "$USER_DB" ]]; then
        total_users=$(grep -v "^#" "$USER_DB" | grep -c ":" || echo "0")
        disabled_users=$(grep -v "^#" "$USER_DB" | grep -c ":disabled:" || echo "0")
    fi
    
    active_connections=$(ipsec status 2>/dev/null | grep -c "ESTABLISHED" || echo "0")
    
    echo "Users:"
    echo "  Total Registered: $total_users"
    echo "  Currently Connected: $active_connections"
    echo "  Disabled: $disabled_users"
    echo
    
    # Traffic statistics (if available)
    echo "Traffic Statistics:"
    if command -v iptables >/dev/null 2>&1; then
        local vpn_in=$(iptables -L INPUT -n -v 2>/dev/null | grep "udp dpt:500\|udp dpt:4500" | awk '{sum+=$2} END {print sum+0}')
        local vpn_out=$(iptables -L OUTPUT -n -v 2>/dev/null | grep "udp dpt:500\|udp dpt:4500" | awk '{sum+=$2} END {print sum+0}')
        
        echo "  Packets In: $vpn_in"
        echo "  Packets Out: $vpn_out"
    else
        echo "  Traffic statistics not available (iptables not found)"
    fi
    echo
    
    # Resource usage
    echo "Resource Usage:"
    local strongswan_pid=$(pgrep -f "ipsec|strongswan|charon" | head -1)
    if [[ -n "$strongswan_pid" ]]; then
        local cpu_usage=$(ps -p "$strongswan_pid" -o %cpu --no-headers 2>/dev/null || echo "0")
        local mem_usage=$(ps -p "$strongswan_pid" -o %mem --no-headers 2>/dev/null || echo "0")
        echo "  strongSwan CPU: ${cpu_usage}%"
        echo "  strongSwan Memory: ${mem_usage}%"
    else
        echo "  strongSwan not running"
    fi
    echo
    
    # Certificate statistics
    echo "Certificate Statistics:"
    local total_certs=0
    local expired_certs=0
    local expiring_soon=0
    
    if [[ -d "/opt/pqc-vpn/certs/spokes" ]]; then
        for cert in /opt/pqc-vpn/certs/spokes/*-cert.pem; do
            if [[ -f "$cert" ]]; then
                ((total_certs++))
                
                # Check if certificate is expired
                if ! openssl x509 -in "$cert" -checkend 0 >/dev/null 2>&1; then
                    ((expired_certs++))
                # Check if certificate expires within 30 days
                elif ! openssl x509 -in "$cert" -checkend 2592000 >/dev/null 2>&1; then
                    ((expiring_soon++))
                fi
            fi
        done
    fi
    
    echo "  Total Certificates: $total_certs"
    echo "  Expired: $expired_certs"
    echo "  Expiring Soon (30 days): $expiring_soon"
    echo
}

# Health check
health_check() {
    echo "PQC-VPN Health Check:"
    echo "===================="
    
    local issues=0
    
    # Check strongSwan service
    echo -n "strongSwan Service: "
    if systemctl is-active --quiet strongswan; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAILED${NC}"
        ((issues++))
    fi
    
    # Check configuration files
    echo -n "Configuration Files: "
    if [[ -f "/etc/ipsec.conf" && -f "/etc/ipsec.secrets" ]]; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}MISSING${NC}"
        ((issues++))
    fi
    
    # Check certificates
    echo -n "CA Certificate: "
    if [[ -f "/opt/pqc-vpn/certs/ca/ca-cert.pem" ]]; then
        if openssl x509 -in "/opt/pqc-vpn/certs/ca/ca-cert.pem" -checkend 0 >/dev/null 2>&1; then
            echo -e "${GREEN}OK${NC}"
        else
            echo -e "${RED}EXPIRED${NC}"
            ((issues++))
        fi
    else
        echo -e "${RED}MISSING${NC}"
        ((issues++))
    fi
    
    echo -n "Hub Certificate: "
    if [[ -f "/opt/pqc-vpn/certs/hub/hub-cert.pem" ]]; then
        if openssl x509 -in "/opt/pqc-vpn/certs/hub/hub-cert.pem" -checkend 0 >/dev/null 2>&1; then
            echo -e "${GREEN}OK${NC}"
        else
            echo -e "${RED}EXPIRED${NC}"
            ((issues++))
        fi
    else
        echo -e "${RED}MISSING${NC}"
        ((issues++))
    fi
    
    # Check network connectivity
    echo -n "Network Ports: "
    local port_500=$(netstat -ulpn 2>/dev/null | grep ":500 " | wc -l)
    local port_4500=$(netstat -ulpn 2>/dev/null | grep ":4500 " | wc -l)
    
    if [[ $port_500 -gt 0 && $port_4500 -gt 0 ]]; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAILED${NC} (Ports 500/4500 not listening)"
        ((issues++))
    fi
    
    # Check log file permissions
    echo -n "Log Files: "
    if [[ -r "$STRONGSWAN_LOG" ]]; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${YELLOW}WARNING${NC} (Cannot read log file)"
    fi
    
    # Check disk space
    echo -n "Disk Space: "
    local disk_usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    if [[ $disk_usage -lt 90 ]]; then
        echo -e "${GREEN}OK${NC} (${disk_usage}% used)"
    else
        echo -e "${RED}WARNING${NC} (${disk_usage}% used)"
        ((issues++))
    fi
    
    echo
    echo "Health Check Summary:"
    if [[ $issues -eq 0 ]]; then
        echo -e "${GREEN}All systems operational${NC}"
    else
        echo -e "${RED}$issues issue(s) detected${NC}"
    fi
    echo
}

# Check for alerts
check_alerts() {
    echo "Alert Check:"
    echo "============"
    
    local alerts=0
    
    # Check for failed authentication attempts
    local failed_auth=$(grep -i "authentication failed\|auth failed" "$STRONGSWAN_LOG" 2>/dev/null | tail -10 | wc -l)
    if [[ $failed_auth -gt 5 ]]; then
        echo -e "${RED}ALERT: Multiple authentication failures detected ($failed_auth recent failures)${NC}"
        ((alerts++))
    fi
    
    # Check for certificate expiry
    local expiring_certs=0
    if [[ -d "/opt/pqc-vpn/certs/spokes" ]]; then
        for cert in /opt/pqc-vpn/certs/spokes/*-cert.pem; do
            if [[ -f "$cert" ]]; then
                # Check if certificate expires within 7 days
                if ! openssl x509 -in "$cert" -checkend 604800 >/dev/null 2>&1; then
                    ((expiring_certs++))
                fi
            fi
        done
    fi
    
    if [[ $expiring_certs -gt 0 ]]; then
        echo -e "${YELLOW}WARNING: $expiring_certs certificate(s) expiring within 7 days${NC}"
        ((alerts++))
    fi
    
    # Check system resources
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{print $1}' | tr -d ' ')
    local cpu_count=$(nproc)
    local load_threshold=$((cpu_count * 2))
    
    if (( $(echo "$load_avg > $load_threshold" | bc -l 2>/dev/null || echo "0") )); then
        echo -e "${RED}ALERT: High system load ($load_avg)${NC}"
        ((alerts++))
    fi
    
    # Check memory usage
    local mem_usage=$(free | awk '/^Mem:/ {printf "%.0f", $3/$2*100}')
    if [[ $mem_usage -gt 90 ]]; then
        echo -e "${RED}ALERT: High memory usage (${mem_usage}%)${NC}"
        ((alerts++))
    fi
    
    if [[ $alerts -eq 0 ]]; then
        echo -e "${GREEN}No alerts detected${NC}"
    else
        echo -e "${RED}$alerts alert(s) detected${NC}"
    fi
    echo
}

# Interactive dashboard
dashboard() {
    local refresh_interval="${1:-$REFRESH_INTERVAL}"
    
    while true; do
        clear
        echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
        echo -e "${CYAN}                           PQC-VPN MONITORING DASHBOARD                    ${NC}"
        echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
        echo -e "${CYAN}Refresh: ${refresh_interval}s | $(date) | Press Ctrl+C to exit${NC}"
        echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
        echo
        
        get_strongswan_status
        get_connections
        get_user_status
        check_alerts
        
        echo -e "${CYAN}Refreshing in ${refresh_interval} seconds...${NC}"
        sleep "$refresh_interval"
    done
}

# Export data
export_data() {
    local format="${1:-text}"
    local output_file="$2"
    
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    local default_file="/tmp/pqc-vpn-export-${timestamp}.${format}"
    
    if [[ -z "$output_file" ]]; then
        output_file="$default_file"
    fi
    
    case "$format" in
        "json")
            export_json "$output_file"
            ;;
        "csv")
            export_csv "$output_file"
            ;;
        "text")
            export_text "$output_file"
            ;;
        *)
            log_error "Unsupported format: $format"
            exit 1
            ;;
    esac
    
    log_success "Data exported to: $output_file"
}

# Export as JSON
export_json() {
    local output_file="$1"
    
    cat > "$output_file" << EOF
{
  "timestamp": "$(date -Iseconds)",
  "system": {
    "hostname": "$(hostname)",
    "uptime": "$(uptime -p 2>/dev/null || uptime)",
    "load_average": "$(uptime | awk -F'load average:' '{print $2}')"
  },
  "strongswan": {
    "active": $(systemctl is-active --quiet strongswan && echo "true" || echo "false"),
    "version": "$(ipsec --version 2>/dev/null | head -1)"
  },
  "connections": {
    "total": $(ipsec status 2>/dev/null | grep -c "ESTABLISHED" || echo "0"),
    "security_associations": $(ipsec status 2>/dev/null | grep -c "INSTALLED" || echo "0")
  },
  "users": [
$(if [[ -f "$USER_DB" ]]; then
    first=true
    while IFS=':' read -r username ip_addr group email created expires status cert_path; do
        if [[ ! "$username" =~ ^# ]] && [[ -n "$username" ]]; then
            if [[ "$first" == "true" ]]; then
                first=false
            else
                echo ","
            fi
            connected=$(ipsec status 2>/dev/null | grep -q "$username.*ESTABLISHED" && echo "true" || echo "false")
            echo -n "    {\"username\": \"$username\", \"ip\": \"$ip_addr\", \"group\": \"$group\", \"status\": \"$status\", \"connected\": $connected}"
        fi
    done < "$USER_DB"
fi)
  ]
}
EOF
}

# Export as CSV
export_csv() {
    local output_file="$1"
    
    echo "username,ip_address,group,email,created,expires,status,connected" > "$output_file"
    
    if [[ -f "$USER_DB" ]]; then
        while IFS=':' read -r username ip_addr group email created expires status cert_path; do
            if [[ ! "$username" =~ ^# ]] && [[ -n "$username" ]]; then
                local connected="false"
                if ipsec status 2>/dev/null | grep -q "$username.*ESTABLISHED"; then
                    connected="true"
                fi
                echo "$username,$ip_addr,$group,$email,$created,$expires,$status,$connected" >> "$output_file"
            fi
        done < "$USER_DB"
    fi
}

# Export as text
export_text() {
    local output_file="$1"
    
    {
        echo "PQC-VPN Status Report"
        echo "Generated: $(date)"
        echo "===================="
        echo
        get_system_info
        get_strongswan_status
        get_connections
        get_user_status
        get_statistics
        health_check
        check_alerts
    } > "$output_file"
}

# Parse command line arguments
parse_arguments() {
    local command="status"
    local format="text"
    local output_file=""
    local watch_mode=false
    local refresh_interval="$REFRESH_INTERVAL"
    local lines="$MAX_LOG_LINES"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            status|connections|users|logs|stats|health|dashboard|export|alerts)
                command="$1"
                shift
                ;;
            --refresh)
                refresh_interval="$2"
                shift 2
                ;;
            --lines)
                lines="$2"
                shift 2
                ;;
            --format)
                format="$2"
                shift 2
                ;;
            --output)
                output_file="$2"
                shift 2
                ;;
            --watch)
                watch_mode=true
                shift
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
    
    # Execute command
    case "$command" in
        "status")
            if [[ "$watch_mode" == "true" ]]; then
                while true; do
                    clear
                    get_system_info
                    get_strongswan_status
                    get_connections
                    echo "Refreshing in ${refresh_interval} seconds... (Press Ctrl+C to exit)"
                    sleep "$refresh_interval"
                done
            else
                get_system_info
                get_strongswan_status
                get_connections
            fi
            ;;
        "connections")
            if [[ "$watch_mode" == "true" ]]; then
                while true; do
                    clear
                    get_connections
                    echo "Refreshing in ${refresh_interval} seconds... (Press Ctrl+C to exit)"
                    sleep "$refresh_interval"
                done
            else
                get_connections
            fi
            ;;
        "users")
            if [[ "$watch_mode" == "true" ]]; then
                while true; do
                    clear
                    get_user_status
                    echo "Refreshing in ${refresh_interval} seconds... (Press Ctrl+C to exit)"
                    sleep "$refresh_interval"
                done
            else
                get_user_status
            fi
            ;;
        "logs")
            get_logs "$lines"
            ;;
        "stats")
            if [[ "$format" != "text" ]]; then
                export_data "$format" "$output_file"
            else
                get_statistics
            fi
            ;;
        "health")
            health_check
            ;;
        "dashboard")
            dashboard "$refresh_interval"
            ;;
        "export")
            export_data "$format" "$output_file"
            ;;
        "alerts")
            check_alerts
            ;;
        *)
            log_error "Invalid command: $command"
            exit 1
            ;;
    esac
}

# Main function
main() {
    # Create monitoring log entry
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Monitor script executed with args: $*" >> "$LOG_DIR/monitor.log"
    
    if [[ $# -eq 0 ]]; then
        parse_arguments "status"
    else
        parse_arguments "$@"
    fi
}

# Handle Ctrl+C gracefully
trap 'echo -e "\n${YELLOW}Monitoring stopped${NC}"; exit 0' INT

# Run main function
main "$@"