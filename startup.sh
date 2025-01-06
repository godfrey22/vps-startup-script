#!/bin/bash

# Version
sh_v="1.1.0"

# Define Colors for Output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging Functions
log_success() { echo -e "${GREEN}[+]${NC} $1"; }
log_error() { echo -e "${RED}[-]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[!]${NC} $1"; }

# Check if Running as Root
if [ "$EUID" -ne 0 ]; then
    log_error "Please run as root"
    exit 1
fi

# System Update Function
update_system() {
    log_warning "Updating system packages..."
    if command -v apt >/dev/null 2>&1; then
        apt update && apt upgrade -y
    elif command -v yum >/dev/null 2>&1; then
        yum update -y
    elif command -v dnf >/dev/null 2>&1; then
        dnf update -y
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Syu --noconfirm
    else
        log_error "Unsupported package manager. Update manually."
        return 1
    fi
    log_success "System updated successfully."
    return 0
}

# Install Dependencies
install_dependencies() {
    local dependencies=("sudo" "net-tools")

    if ! command -v ufw >/dev/null 2>&1 && ! command -v firewall-cmd >/dev/null 2>&1; then
        read -p "No firewall detected. Install UFW? (y/n): " install_firewall
        if [[ "$install_firewall" =~ ^[Yy]$ ]]; then
            dependencies+=("ufw")
        fi
    fi

    log_warning "Installing dependencies..."
    if command -v apt >/dev/null 2>&1; then
        apt install -y "${dependencies[@]}"
    elif command -v yum >/dev/null 2>&1; then
        yum install -y "${dependencies[@]}"
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y "${dependencies[@]}"
    elif command -v pacman >/dev/null 2>&1; then
        pacman -S --noconfirm "${dependencies[@]}"
    else
        log_error "Unsupported package manager. Install dependencies manually."
        return 1
    fi
    log_success "Dependencies installed."
    return 0
}

# Validate SSH Port
validate_port() {
    local port=$1
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -le 0 ] || [ "$port" -gt 65535 ]; then
        log_error "Invalid port number. Enter a value between 1 and 65535."
        return 1
    fi
    if netstat -tuln | grep ":$port " >/dev/null 2>&1; then
        log_error "Port $port is already in use."
        return 1
    fi
    return 0
}

# Validate Username
validate_username() {
    local username=$1
    if ! [[ "$username" =~ ^[a-z][-a-z0-9]*$ ]]; then
        log_error "Username must start with a letter and contain only lowercase letters, numbers, and hyphens."
        return 1
    fi
    if id "$username" >/dev/null 2>&1; then
        log_error "User $username already exists."
        return 1
    fi
    return 0
}

# Rollback SSH Config on Failure
rollback_ssh_config() {
    if [ -f /etc/ssh/sshd_config.bak ]; then
        cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
        log_warning "SSH configuration restored from backup."
    fi
}

# Main Menu
while true; do
    echo -e "${YELLOW}=== Secure User & SSH Setup ===${NC}"
    echo "1) Update system packages"
    echo "2) Install dependencies"
    echo "3) Create a new user"
    echo "4) Configure SSH"
    echo "5) Exit"
    read -p "Choose an option: " choice

    case $choice in
        1)
            update_system
            ;;
        
        2)
            install_dependencies
            ;;
        
        3)
            while true; do
                read -p "Enter new username: " USERNAME
                validate_username "$USERNAME" && break
            done

            read -s -p "Enter password: " PASSWORD
            echo

            useradd -m -s /bin/bash "$USERNAME"
            echo "$USERNAME:$PASSWORD" | chpasswd
            usermod -aG sudo "$USERNAME"
            mkdir -p "/home/$USERNAME/.ssh"

            echo "Paste your public SSH key:"
            read SSH_KEY
            echo "$SSH_KEY" > "/home/$USERNAME/.ssh/authorized_keys"
            chmod 700 "/home/$USERNAME/.ssh"
            chmod 600 "/home/$USERNAME/.ssh/authorized_keys"
            chown -R "$USERNAME:$USERNAME" "/home/$USERNAME/.ssh"
            log_success "User $USERNAME created successfully!"
            ;;
        
        4)
            cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
            while true; do
                read -p "Enter desired SSH port: " SSH_PORT
                validate_port "$SSH_PORT" && break
            done

            sed -i "/^#Port 22/c\Port $SSH_PORT" /etc/ssh/sshd_config
            sed -i "/^Port /c\Port $SSH_PORT" /etc/ssh/sshd_config
            sed -i 's/#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
            sed -i 's/#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
            sed -i 's/#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

            sshd -t
            if [ $? -ne 0 ]; then
                log_error "SSH configuration test failed."
                rollback_ssh_config
                continue
            fi

            if command -v ufw >/dev/null 2>&1; then
                ufw allow "$SSH_PORT/tcp"
                log_success "Firewall configured with UFW for SSH port $SSH_PORT."
            elif command -v firewall-cmd >/dev/null 2>&1; then
                firewall-cmd --permanent --add-port="$SSH_PORT/tcp"
                firewall-cmd --reload
                log_success "Firewall configured with Firewalld for SSH port $SSH_PORT."
            else
                log_warning "No firewall installed. Please configure manually."
            fi

            systemctl restart sshd
            if [ $? -ne 0 ]; then
                log_error "Failed to restart SSH service."
                rollback_ssh_config
                continue
            fi

            log_success "SSH configured on port $SSH_PORT!"
            echo "Test your SSH connection before closing this session:"
            echo -e "${GREEN}ssh -p $SSH_PORT $USERNAME@<server-ip>${NC}"
            ;;
        
        5)
            log_success "Exiting..."
            exit 0
            ;;
        
        *)
            log_error "Invalid option. Please select a valid menu option."
            ;;
    esac
done