#!/bin/bash

# RTT-Secure Installation Script
# Designed and Developed by RmnJL
# Enterprise Grade Security Installation
# Version: 2.0

set -euo pipefail

# Color definitions
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# Constants
readonly INSTALL_DIR="/opt/rtt-secure"
readonly CONFIG_DIR="/etc/rtt-secure"
readonly LOG_FILE="/var/log/rtt-secure-install.log"
readonly SERVICE_NAME="rtt-secure"

# Banner
show_banner() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                RTT-Secure Installation v2.0                  ║${NC}"
    echo -e "${CYAN}║                                                              ║${NC}"
    echo -e "${CYAN}║           🔒 Maximum Security Installation 🔒                ║${NC}"
    echo -e "${CYAN}║                                                              ║${NC}"
    echo -e "${CYAN}║               Designed & Developed by RmnJL                  ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo
}

# Logging function
log_message() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $message" >> "$LOG_FILE"
    echo -e "${BLUE}[$timestamp]${NC} $message"
}

# Root check
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}❌ This script must be run as root${NC}"
        echo -e "${YELLOW}Please run: sudo bash $0${NC}"
        exit 1
    fi
}

# System detection
detect_system() {
    log_message "Detecting system architecture..."
    
    local os=""
    local arch=""
    
    # Detect OS
    if [ -f /etc/os-release ]; then
        os=$(grep '^ID=' /etc/os-release | cut -d'=' -f2 | tr -d '"')
    else
        echo -e "${RED}❌ Unable to detect operating system${NC}"
        exit 1
    fi
    
    # Detect architecture
    case $(uname -m) in
        x86_64)  arch="amd64" ;;
        aarch64) arch="arm64" ;;
        arm*)    arch="arm64" ;;
        *)       
            echo -e "${RED}❌ Unsupported architecture: $(uname -m)${NC}"
            exit 1
            ;;
    esac
    
    log_message "System: $os | Architecture: $arch"
    echo "$os:$arch"
}

# Install dependencies
install_dependencies() {
    log_message "Installing system dependencies..."
    
    local system_info=$(detect_system)
    local os=$(echo "$system_info" | cut -d: -f1)
    
    case $os in
        ubuntu|debian)
            apt-get update -qq
            apt-get install -y curl wget unzip tar openssl ufw systemd
            ;;
        centos|rhel|fedora)
            yum update -y
            yum install -y curl wget unzip tar openssl firewalld systemd
            ;;
        *)
            echo -e "${YELLOW}⚠️ Unknown OS: $os. Attempting generic installation...${NC}"
            ;;
    esac
    
    log_message "Dependencies installed successfully"
}

# Create directories
create_directories() {
    log_message "Creating secure directories..."
    
    # Create installation directory
    mkdir -p "$INSTALL_DIR"
    chmod 750 "$INSTALL_DIR"
    chown root:root "$INSTALL_DIR"
    
    # Create configuration directory
    mkdir -p "$CONFIG_DIR"
    chmod 750 "$CONFIG_DIR"
    chown root:root "$CONFIG_DIR"
    
    # Create log directory
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    chmod 640 "$LOG_FILE"
    
    log_message "Directories created successfully"
}

# Download RTT-Secure
download_rtt_secure() {
    log_message "Downloading RTT-Secure..."
    
    local system_info=$(detect_system)
    local arch=$(echo "$system_info" | cut -d: -f2)
    
    # Get latest version
    local latest_version
    latest_version=$(curl -s https://api.github.com/repos/RmnJL/RTT-Secure/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' 2>/dev/null || echo "v2.0")
    
    log_message "Latest version: $latest_version"
    
    local download_url="https://github.com/RmnJL/RTT-Secure/releases/download/${latest_version}/rtt-secure_${latest_version}_linux_${arch}.tar.gz"
    local temp_dir=$(mktemp -d)
    
    cd "$temp_dir"
    
    if wget -q --show-progress "$download_url" -O rtt-secure.tar.gz; then
        log_message "Download completed successfully"
        
        # Extract and install
        tar -xzf rtt-secure.tar.gz
        
        if [ -f "RTT-Secure" ]; then
            cp RTT-Secure "$INSTALL_DIR/"
            chmod 750 "$INSTALL_DIR/RTT-Secure"
            chown root:root "$INSTALL_DIR/RTT-Secure"
            
            log_message "RTT-Secure installed to $INSTALL_DIR"
        else
            echo -e "${RED}❌ RTT-Secure binary not found in archive${NC}"
            exit 1
        fi
    else
        echo -e "${RED}❌ Failed to download RTT-Secure${NC}"
        echo -e "${YELLOW}Please check your internet connection and try again${NC}"
        exit 1
    fi
    
    # Cleanup
    rm -rf "$temp_dir"
}

# Create systemd service
create_service() {
    log_message "Creating systemd service..."
    
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" << 'EOF'
[Unit]
Description=RTT-Secure Advanced Stealth Tunnel by RmnJL
Documentation=https://github.com/RmnJL/RTT-Secure
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/rtt-secure
ExecStart=/opt/rtt-secure/RTT-Secure
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=3
KillMode=mixed
TimeoutStopSec=5

# Security enhancements
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/rtt-secure /var/log
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN

# Resource limits
LimitNOFILE=65536
LimitNPROC=32768

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    log_message "Systemd service created"
}

# Configure firewall
configure_firewall() {
    log_message "Configuring firewall..."
    
    if command -v ufw >/dev/null 2>&1; then
        # UFW configuration
        ufw --force reset >/dev/null 2>&1
        ufw default deny incoming >/dev/null 2>&1
        ufw default allow outgoing >/dev/null 2>&1
        
        # Allow essential ports
        ufw allow 22/tcp comment 'SSH' >/dev/null 2>&1
        ufw allow 443/tcp comment 'RTT-Secure' >/dev/null 2>&1
        
        ufw --force enable >/dev/null 2>&1
        log_message "UFW firewall configured"
        
    elif command -v firewalld >/dev/null 2>&1; then
        # Firewalld configuration
        systemctl enable firewalld >/dev/null 2>&1
        systemctl start firewalld >/dev/null 2>&1
        
        firewall-cmd --permanent --add-port=22/tcp >/dev/null 2>&1
        firewall-cmd --permanent --add-port=443/tcp >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
        
        log_message "Firewalld configured"
    else
        echo -e "${YELLOW}⚠️ No firewall detected. Please configure manually.${NC}"
    fi
}

# System optimization
optimize_system() {
    log_message "Applying system optimizations..."
    
    # Network optimizations
    cat >> /etc/sysctl.conf << 'EOF'

# RTT-Secure Network Optimizations
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_congestion_control = bbr
EOF
    
    sysctl -p >/dev/null 2>&1
    
    # File limits
    cat >> /etc/security/limits.conf << 'EOF'

# RTT-Secure limits
root soft nofile 65536
root hard nofile 65536
EOF
    
    log_message "System optimizations applied"
}

# Create configuration template
create_config_template() {
    log_message "Creating configuration templates..."
    
    # Iran server template
    cat > "$CONFIG_DIR/iran-server.conf" << 'EOF'
# RTT-Secure Iran Server Configuration
# Edit this file and run: systemctl start rtt-secure

--iran
--lport:443
--sni:aparat.com
--password:CHANGE_THIS_PASSWORD
--stealth-mode
--zero-logs
--anti-detection
--high-performance
EOF
    
    # Kharej server template
    cat > "$CONFIG_DIR/kharej-server.conf" << 'EOF'
# RTT-Secure Kharej Server Configuration
# Edit this file and run: systemctl start rtt-secure

--kharej
--iran-ip:YOUR_IRAN_SERVER_IP
--iran-port:443
--toip:127.0.0.1
--toport:YOUR_LOCAL_PORT
--password:CHANGE_THIS_PASSWORD
--sni:aparat.com
--stealth-mode
--zero-logs
EOF
    
    chmod 640 "$CONFIG_DIR"/*.conf
    log_message "Configuration templates created in $CONFIG_DIR"
}

# Generate secure password
generate_password() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 32 | tr -d "=+/" | cut -c1-25
    else
        cat /dev/urandom | tr -dc 'a-zA-Z0-9!@#$%^&*' | fold -w 25 | head -n 1
    fi
}

# Post installation setup
post_install_setup() {
    log_message "Running post-installation setup..."
    
    echo -e "\n${GREEN}🎉 RTT-Secure installed successfully!${NC}\n"
    
    echo -e "${CYAN}📁 Installation Directory:${NC} $INSTALL_DIR"
    echo -e "${CYAN}⚙️ Configuration Directory:${NC} $CONFIG_DIR"
    echo -e "${CYAN}📋 Log File:${NC} $LOG_FILE"
    echo -e "${CYAN}🔧 Service Name:${NC} $SERVICE_NAME"
    
    echo -e "\n${YELLOW}🔑 Generated Secure Password:${NC}"
    local secure_password=$(generate_password)
    echo -e "${GREEN}$secure_password${NC}"
    echo -e "${RED}⚠️ Please save this password securely!${NC}"
    
    echo -e "\n${BLUE}📝 Next Steps:${NC}"
    echo -e "1. Edit configuration: ${CYAN}nano $CONFIG_DIR/iran-server.conf${NC}"
    echo -e "2. Update password in config file"
    echo -e "3. Start service: ${CYAN}systemctl start $SERVICE_NAME${NC}"
    echo -e "4. Enable auto-start: ${CYAN}systemctl enable $SERVICE_NAME${NC}"
    echo -e "5. Check status: ${CYAN}systemctl status $SERVICE_NAME${NC}"
    
    echo -e "\n${PURPLE}🛠️ Management Script:${NC}"
    echo -e "Run the management script: ${CYAN}bash <(curl -fsSL https://raw.githubusercontent.com/RmnJL/RTT-Secure/master/scripts/RttSecure.sh)${NC}"
    
    echo -e "\n${GREEN}✅ Installation completed successfully!${NC}"
}

# Main installation function
main() {
    show_banner
    
    echo -e "${BLUE}🚀 Starting RTT-Secure installation...${NC}\n"
    
    check_root
    
    # Installation steps
    install_dependencies
    create_directories
    download_rtt_secure
    create_service
    configure_firewall
    optimize_system
    create_config_template
    post_install_setup
    
    log_message "Installation completed successfully"
}

# Execute main function
main "$@"
