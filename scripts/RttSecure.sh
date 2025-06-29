#!/bin/bash

# RTT-Secure Management Script v2.0
# Designed and Developed by RmnJL
# Advanced Enterprise Stealth Tunnel Management
# Zero-Log | High Performance | Maximum Security

set -euo pipefail  # Enhanced error handling

# Color definitions for enhanced UI
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m' 
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[0;37m'
readonly NC='\033[0m' # No Color

# Security constants
readonly SECURE_TMP_DIR="/tmp/rtt-secure-$(date +%s)-$$"
readonly LOG_FILE="/var/log/rtt-secure-install.log"
readonly BACKUP_DIR="/opt/rtt-secure/backup"
readonly CONFIG_DIR="/etc/rtt-secure"
readonly SERVICE_NAME="rtt-secure"

# Security Banner
show_banner() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                    RTT-Secure v2.0                           ║${NC}"
    echo -e "${CYAN}║           Advanced Enterprise Stealth Tunnel                 ║${NC}"
    echo -e "${CYAN}║                                                              ║${NC}"
    echo -e "${CYAN}║               Designed & Developed by RmnJL                  ║${NC}"
    echo -e "${CYAN}║                                                              ║${NC}"
    echo -e "${CYAN}║    🔒 Maximum Security | ⚡ High Performance | 👻 Stealth    ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo
}

# Enhanced security check
secure_root_access() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[SECURITY] This script requires root access for secure installation.${NC}"
        echo -e "${YELLOW}Please run: sudo bash $0${NC}"
        exit 1
    fi
    
    # Create secure directories
    mkdir -p "$SECURE_TMP_DIR" && chmod 700 "$SECURE_TMP_DIR"
    mkdir -p "$CONFIG_DIR" && chmod 750 "$CONFIG_DIR"
    mkdir -p "$BACKUP_DIR" && chmod 750 "$BACKUP_DIR"
    
    # Initialize logging
    mkdir -p "$(dirname "$LOG_FILE")"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] RTT-Secure session started" >> "$LOG_FILE"
}

# Enhanced dependency check
check_dependencies() {
    echo -e "${BLUE}🔍 Checking system dependencies...${NC}"
    
    local deps=("curl" "wget" "unzip" "systemctl" "openssl")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [ ${#missing[@]} -ne 0 ]; then
        echo -e "${YELLOW}Installing missing dependencies: ${missing[*]}${NC}"
        apt-get update -qq
        apt-get install -y "${missing[@]}"
    fi
    
    echo -e "${GREEN}✅ All dependencies satisfied${NC}"
}

# System information
get_system_info() {
    local myip=$(hostname -I | awk '{print $1}' 2>/dev/null || echo "Unknown")
    local version=""
    
    if [ -f "/opt/rtt-secure/RTT-Secure" ]; then
        version=$(/opt/rtt-secure/RTT-Secure -v 2>&1 | grep -o 'version="[0-9.]*"' 2>/dev/null || echo 'version="Unknown"')
    else
        version='version="Not Installed"'
    fi
    
    echo "$myip:$version"
}

# Generate secure password
generate_secure_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-25
}

# Secure installation
secure_install() {
    echo -e "${GREEN}🚀 Starting RTT-Secure installation...${NC}"
    
    check_dependencies
    
    # Download latest secure version
    local latest_version=$(curl -s https://api.github.com/repos/RmnJL/RTT-Secure/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    
    if [ -z "$latest_version" ]; then
        latest_version="v2.0"  # Fallback version
    fi
    
    echo -e "${BLUE}📦 Downloading RTT-Secure ${latest_version}...${NC}"
    
    case $(uname -m) in
        x86_64)  local arch="amd64" ;;
        aarch64) local arch="arm64" ;;
        arm*)    local arch="arm64" ;;
        *)       echo -e "${RED}❌ Unsupported architecture: $(uname -m)${NC}"; exit 1 ;;
    esac
    
    local download_url="https://github.com/RmnJL/RTT-Secure/releases/download/${latest_version}/rtt-secure_${latest_version}_linux_${arch}.tar.gz"
    
    cd "$SECURE_TMP_DIR"
    if wget -q "$download_url" -O rtt-secure.tar.gz; then
        tar -xzf rtt-secure.tar.gz
        
        # Install with enhanced security
        mkdir -p /opt/rtt-secure
        cp RTT-Secure /opt/rtt-secure/
        chmod 750 /opt/rtt-secure/RTT-Secure
        chown root:root /opt/rtt-secure/RTT-Secure
        
        echo -e "${GREEN}✅ RTT-Secure installed successfully${NC}"
        configure_service
    else
        echo -e "${RED}❌ Download failed. Please check your internet connection.${NC}"
        exit 1
    fi
}

# Service configuration
configure_service() {
    echo -e "${BLUE}⚙️ Configuring RTT-Secure service...${NC}"
    
    # Get configuration from user
    read -p "$(echo -e ${CYAN}🏠 Server type [iran/kharej]: ${NC})" server_type
    read -p "$(echo -e ${CYAN}🌐 SNI domain [aparat.com]: ${NC})" sni_domain
    sni_domain=${sni_domain:-aparat.com}
    
    local secure_password=$(generate_secure_password)
    echo -e "${GREEN}🔑 Generated secure password: ${YELLOW}$secure_password${NC}"
    echo -e "${RED}⚠️  Please save this password securely!${NC}"
    
    if [ "$server_type" = "iran" ]; then
        configure_iran_server "$sni_domain" "$secure_password"
    elif [ "$server_type" = "kharej" ]; then
        configure_kharej_server "$sni_domain" "$secure_password"
    else
        echo -e "${RED}❌ Invalid server type${NC}"
        return 1
    fi
}

# Iran server configuration
configure_iran_server() {
    local sni="$1"
    local password="$2"
    
    read -p "$(echo -e ${CYAN}🔌 Listen port [443]: ${NC})" listen_port
    listen_port=${listen_port:-443}
    
    # Create service file
    cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=RTT-Secure Advanced Stealth Tunnel by RmnJL
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/rtt-secure
ExecStart=/opt/rtt-secure/RTT-Secure --iran --lport:${listen_port} --sni:${sni} --password:"${password}" --stealth-mode --zero-logs --anti-detection
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=3
KillMode=mixed
TimeoutStopSec=5

# Security enhancements
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/rtt-secure
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}"
    
    echo -e "${GREEN}✅ Iran server configured successfully${NC}"
}

# Kharej server configuration
configure_kharej_server() {
    local sni="$1"
    local password="$2"
    
    read -p "$(echo -e ${CYAN}🌍 Iran server IP: ${NC})" iran_ip
    read -p "$(echo -e ${CYAN}🔌 Iran server port [443]: ${NC})" iran_port
    iran_port=${iran_port:-443}
    
    read -p "$(echo -e ${CYAN}🏠 Local target IP [127.0.0.1]: ${NC})" target_ip
    target_ip=${target_ip:-127.0.0.1}
    
    read -p "$(echo -e ${CYAN}🔌 Local target port: ${NC})" target_port
    
    # Create service file
    cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=RTT-Secure Advanced Stealth Tunnel by RmnJL
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/rtt-secure
ExecStart=/opt/rtt-secure/RTT-Secure --kharej --iran-ip:${iran_ip} --iran-port:${iran_port} --toip:${target_ip} --toport:${target_port} --password:"${password}" --sni:${sni} --stealth-mode --zero-logs
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=3
KillMode=mixed
TimeoutStopSec=5

# Security enhancements
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/rtt-secure

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}"
    
    echo -e "${GREEN}✅ Kharej server configured successfully${NC}"
}

# Service management functions
start_service() {
    echo -e "${BLUE}🚀 Starting RTT-Secure service...${NC}"
    if systemctl start "${SERVICE_NAME}"; then
        echo -e "${GREEN}✅ Service started successfully${NC}"
    else
        echo -e "${RED}❌ Failed to start service${NC}"
    fi
}

stop_service() {
    echo -e "${BLUE}🛑 Stopping RTT-Secure service...${NC}"
    if systemctl stop "${SERVICE_NAME}"; then
        echo -e "${GREEN}✅ Service stopped successfully${NC}"
    else
        echo -e "${RED}❌ Failed to stop service${NC}"
    fi
}

check_service_status() {
    echo -e "${BLUE}📊 Checking service status...${NC}"
    
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        echo -e "${GREEN}✅ RTT-Secure is running${NC}"
        
        # Show detailed status
        echo -e "\n${CYAN}📋 Service Details:${NC}"
        systemctl status "${SERVICE_NAME}" --no-pager -l
        
        # Show network connections
        echo -e "\n${CYAN}🌐 Network Connections:${NC}"
        ss -tulnp | grep RTT-Secure || echo "No active connections found"
        
    else
        echo -e "${RED}❌ RTT-Secure is not running${NC}"
    fi
}

# Security audit
security_audit() {
    echo -e "${BLUE}🔍 Running security audit...${NC}"
    
    echo -e "\n${CYAN}🔒 Security Check Results:${NC}"
    
    # Check file permissions
    if [ -f "/opt/rtt-secure/RTT-Secure" ]; then
        local perms=$(stat -c "%a" /opt/rtt-secure/RTT-Secure)
        if [ "$perms" = "750" ]; then
            echo -e "${GREEN}✅ File permissions: Secure ($perms)${NC}"
        else
            echo -e "${YELLOW}⚠️  File permissions: $perms (recommended: 750)${NC}"
        fi
    fi
    
    # Check service security settings
    if systemctl cat "${SERVICE_NAME}" | grep -q "NoNewPrivileges=true"; then
        echo -e "${GREEN}✅ Service hardening: Enabled${NC}"
    else
        echo -e "${RED}❌ Service hardening: Disabled${NC}"
    fi
    
    # Check firewall status
    if command -v ufw &> /dev/null; then
        if ufw status | grep -q "Status: active"; then
            echo -e "${GREEN}✅ Firewall: Active${NC}"
        else
            echo -e "${YELLOW}⚠️  Firewall: Inactive${NC}"
        fi
    fi
    
    echo -e "\n${GREEN}🛡️ Security audit completed${NC}"
}

# Performance test
performance_test() {
    echo -e "${BLUE}⚡ Running performance test...${NC}"
    
    if ! systemctl is-active --quiet "${SERVICE_NAME}"; then
        echo -e "${RED}❌ Service not running. Please start the service first.${NC}"
        return 1
    fi
    
    echo -e "\n${CYAN}📊 Performance Metrics:${NC}"
    
    # CPU usage
    local cpu_usage=$(ps -o pcpu= -p $(pgrep RTT-Secure) 2>/dev/null | awk '{print $1"%"}')
    echo -e "CPU Usage: ${cpu_usage:-N/A}"
    
    # Memory usage
    local mem_usage=$(ps -o pmem= -p $(pgrep RTT-Secure) 2>/dev/null | awk '{print $1"%"}')
    echo -e "Memory Usage: ${mem_usage:-N/A}"
    
    # Network connections
    local connections=$(ss -tn | grep -c "$(pgrep RTT-Secure)" 2>/dev/null || echo "0")
    echo -e "Active Connections: $connections"
    
    echo -e "\n${GREEN}⚡ Performance test completed${NC}"
}

# Uninstall function
secure_uninstall() {
    echo -e "${YELLOW}⚠️  This will completely remove RTT-Secure from your system.${NC}"
    read -p "$(echo -e ${RED}Are you sure? [y/N]: ${NC})" confirm
    
    if [[ $confirm =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}🗑️ Uninstalling RTT-Secure...${NC}"
        
        # Stop and disable service
        systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
        systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
        
        # Remove files
        rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
        rm -rf "/opt/rtt-secure"
        rm -rf "$CONFIG_DIR"
        
        systemctl daemon-reload
        systemctl reset-failed 2>/dev/null || true
        
        echo -e "${GREEN}✅ RTT-Secure uninstalled successfully${NC}"
    else
        echo -e "${BLUE}Uninstallation cancelled${NC}"
    fi
}

# Enhanced main menu
main_menu() {
    show_banner
    
    local system_info=$(get_system_info)
    local myip=$(echo "$system_info" | cut -d: -f1)
    local version=$(echo "$system_info" | cut -d: -f2)
    
    echo -e "${BLUE}🌐 Server IP: ${CYAN}$myip${NC}"
    echo -e "${BLUE}📦 Version: ${CYAN}$version${NC}"
    echo
    echo -e "${YELLOW}════════════════════════════════════════${NC}"
    
    # Check service status
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        echo -e "${GREEN}🟢 RTT-Secure Status: Running${NC}"
    else
        echo -e "${RED}🔴 RTT-Secure Status: Stopped${NC}"
    fi
    
    echo -e "${YELLOW}════════════════════════════════════════${NC}"
    echo -e "${PURPLE}           🚀 RTT-Secure Manager v2.0           ${NC}"
    echo -e "${YELLOW}════════════════════════════════════════${NC}"
    
    echo -e "${GREEN}📦 Installation & Management:${NC}"
    echo -e "  ${GREEN}1)${NC} Install RTT-Secure"
    echo -e "  ${RED}2)${NC} Uninstall RTT-Secure"
    echo -e "  ${BLUE}3)${NC} Start Service"
    echo -e "  ${BLUE}4)${NC} Stop Service"
    echo -e "  ${CYAN}5)${NC} Check Status"
    
    echo -e "\n${GREEN}🔧 Advanced Operations:${NC}"
    echo -e "  ${YELLOW}6)${NC} Security Audit"
    echo -e "  ${YELLOW}7)${NC} Performance Test"
    echo -e "  ${CYAN}8)${NC} View Logs"
    echo -e "  ${PURPLE}9)${NC} System Information"
    
    echo -e "\n  ${RED}0)${NC} Exit"
    
    echo -e "${YELLOW}════════════════════════════════════════${NC}"
    echo -e "${PURPLE}Powered by RmnJL | Maximum Security${NC}"
    echo -e "${YELLOW}════════════════════════════════════════${NC}"
    
    read -p "$(echo -e ${CYAN}🎯 Please choose an option: ${NC})" choice
}

# View logs
view_logs() {
    echo -e "${BLUE}📋 Viewing RTT-Secure logs...${NC}"
    
    if [ -f "$LOG_FILE" ]; then
        echo -e "\n${CYAN}Installation Logs:${NC}"
        tail -20 "$LOG_FILE"
    fi
    
    echo -e "\n${CYAN}Service Logs:${NC}"
    journalctl -u "${SERVICE_NAME}" --no-pager -n 20
}

# System information
show_system_info() {
    echo -e "${BLUE}💻 System Information${NC}"
    echo -e "\n${CYAN}System:${NC}"
    uname -a
    
    echo -e "\n${CYAN}Memory Usage:${NC}"
    free -h
    
    echo -e "\n${CYAN}Disk Usage:${NC}"
    df -h /
    
    echo -e "\n${CYAN}Network Interfaces:${NC}"
    ip addr show | grep -E "^[0-9]+:|inet "
}

# Enhanced menu handler
handle_menu_choice() {
    case $choice in
        1) secure_install ;;
        2) secure_uninstall ;;
        3) start_service ;;
        4) stop_service ;;
        5) check_service_status ;;
        6) security_audit ;;
        7) performance_test ;;
        8) view_logs ;;
        9) show_system_info ;;
        0) 
            echo -e "${GREEN}✅ Thank you for using RTT-Secure!${NC}"
            cleanup_temp
            exit 0
            ;;
        *)
            echo -e "${RED}❌ Invalid option. Please try again.${NC}"
            sleep 2
            ;;
    esac
}

# Cleanup function
cleanup_temp() {
    if [ -d "$SECURE_TMP_DIR" ]; then
        rm -rf "$SECURE_TMP_DIR"
    fi
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] RTT-Secure session ended" >> "$LOG_FILE"
}

# Trap for cleanup on exit
trap cleanup_temp EXIT

# Main execution
main() {
    secure_root_access
    
    while true; do
        main_menu
        handle_menu_choice
        
        if [ "$choice" != "0" ]; then
            echo -e "\n${YELLOW}Press Enter to continue...${NC}"
            read
        fi
    done
}

# Execute main function
main "$@"
