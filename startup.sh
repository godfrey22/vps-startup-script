#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Set up logging
LOG_FILE="/var/log/vps_setup.log"
exec > >(tee -a "$LOG_FILE") 2>&1

# Cleanup on exit
cleanup() {
    if [ -d "/tmp/ssh_setup" ]; then
        rm -rf "/tmp/ssh_setup"
    fi
}
trap cleanup EXIT

# Function to print colored output
print_message() {
    echo -e "${GREEN}[+] $1${NC}"
    logger -t "vps-setup" "$1"
}

print_warning() {
    echo -e "${YELLOW}[!] $1${NC}"
    logger -t "vps-setup" "WARNING: $1"
}

print_error() {
    echo -e "${RED}[-] $1${NC}"
    logger -t "vps-setup" "ERROR: $1"
}

# Function to check command status
check_status() {
    if [ $? -ne 0 ]; then
        print_error "$1"
        exit 1
    fi
}

# Parse command line arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --username) USERNAME="$2"; shift ;;
        --ssh-port) SSH_PORT="$2"; shift ;;
        --non-interactive) NON_INTERACTIVE=true ;;
        --help) 
            echo "Usage: $0 [--username USERNAME] [--ssh-port PORT] [--non-interactive]"
            exit 0
            ;;
        *) print_error "Unknown parameter: $1"; exit 1 ;;
    esac
    shift
done

# Detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VERSION=$VERSION_ID
    else
        print_error "Cannot detect OS"
        exit 1
    fi
}

# Function to check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "Please run as root"
        exit 1
    fi
}

# Validate username
validate_username() {
    local username=$1
    if ! [[ "$username" =~ ^[a-zA-Z0-9._-]+$ ]]; then
        print_error "Invalid username. Use only letters, numbers, underscores, dashes, or periods."
        exit 1
    fi
    
    # Check username length
    if [ ${#username} -lt 1 ] || [ ${#username} -gt 32 ]; then
        print_error "Username must be between 1 and 32 characters"
        exit 1
    fi
}

# Validate SSH port
validate_ssh_port() {
    local port=$1
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -le 0 ] || [ "$port" -gt 65535 ]; then
        print_error "Invalid port number. Please enter a value between 1 and 65535."
        exit 1
    fi
    
    # Check if port is already in use
    if netstat -tuln | grep ":$port " >/dev/null 2>&1; then
        print_error "Port $port is already in use"
        exit 1
    fi
}

# Update system packages based on OS
update_system() {
    print_message "Updating system packages..."
    case "$OS" in
        *"Ubuntu"*|*"Debian"*)
            apt update && apt upgrade -y
            check_status "Failed to update packages"
            ;;
        *"CentOS"*|*"Red Hat"*)
            # Add --nobest flag to handle package conflicts
            dnf update -y --nobest
            check_status "Failed to update packages"
            ;;
        *"Fedora"*)
            dnf update -y
            check_status "Failed to update packages"
            ;;
        *"Arch"*)
            pacman -Syu --noconfirm
            check_status "Failed to update packages"
            ;;
        *)
            print_error "Unsupported OS for package update"
            exit 1
            ;;
    esac
}

# Install required packages
enable_repos() {
    print_message "Enabling required repositories..."
    case "$OS" in
        *"CentOS"*|*"Red Hat"*)
            # Install EPEL repository
            dnf install -y epel-release
            dnf config-manager --set-enabled crb  # Enable CRB repo (needed for some EPEL packages)
            check_status "Failed to enable repositories"
            ;;
    esac
}
install_packages() {
    print_message "Installing required packages..."
    case "$OS" in
        *"Ubuntu"*|*"Debian"*)
            apt install -y sudo ufw fail2ban
            ;;
        *"CentOS"*|*"Red Hat"*)
            # First enable required repos
            enable_repos
            # Install packages
            dnf install -y sudo firewalld fail2ban
            ;;
        *"Fedora"*)
            dnf install -y sudo firewalld fail2ban
            ;;
        *"Arch"*)
            pacman -S --noconfirm sudo ufw fail2ban
            ;;
    esac
    check_status "Failed to install required packages"
}

# Create new user
create_user() {
    print_message "Creating new user..."
    
    if [ -z "$USERNAME" ] && [ "$NON_INTERACTIVE" != "true" ]; then
        read -p "Enter username: " USERNAME
    fi
    
    validate_username "$USERNAME"
    
    if id "$USERNAME" &>/dev/null; then
        print_error "User already exists"
        exit 1
    fi
    
    # Create user with home directory
    useradd -m -s /bin/bash "$USERNAME"
    check_status "Failed to create user"
    
    if [ "$NON_INTERACTIVE" != "true" ]; then
        # Set password
        print_message "Setting password for $USERNAME"
        passwd "$USERNAME"
        check_status "Failed to set password"
    fi
    
    # Add to sudo group
    case "$OS" in
        *"Ubuntu"*|*"Debian"*)
            usermod -aG sudo "$USERNAME"
            ;;
        *)
            usermod -aG wheel "$USERNAME"
            ;;
    esac
    check_status "Failed to add user to sudo group"
}

# Add this function to handle SSH service
restart_ssh() {
    print_message "Restarting SSH service..."
    if [[ $OS == *"Ubuntu"* ]] || [[ $OS == *"Debian"* ]]; then
        systemctl restart sshd
    elif [[ $OS == *"CentOS"* ]] || [[ $OS == *"Red Hat"* ]] || [[ $OS == *"Fedora"* ]]; then
        systemctl restart sshd
    fi
    check_status "Failed to restart SSH service"
}

# Update the configure_ssh function to immediately apply changes
configure_ssh() {
    print_message "Configuring SSH..."
    
    # Backup original sshd_config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    check_status "Failed to backup sshd_config"
    
    # Get SSH port
    if [ -z "$SSH_PORT" ] && [ "$NON_INTERACTIVE" != "true" ]; then
        read -p "Enter SSH port (default 2222): " SSH_PORT
    fi
    SSH_PORT=${SSH_PORT:-2222}
    validate_ssh_port "$SSH_PORT"
    
    # Get public key
    if [ "$NON_INTERACTIVE" != "true" ]; then
        print_message "Enter your public key (paste and press Enter, then Ctrl+D):"
        mkdir -p /home/$USERNAME/.ssh
        touch /home/$USERNAME/.ssh/authorized_keys
        cat > /home/$USERNAME/.ssh/authorized_keys
        check_status "Failed to save public key"
    fi
    
    # Set proper permissions
    chmod 700 /home/$USERNAME/.ssh
    chmod 600 /home/$USERNAME/.ssh/authorized_keys
    chown -R $USERNAME:$USERNAME /home/$USERNAME/.ssh
    check_status "Failed to set SSH directory permissions"
    
    # Modify sshd_config
    sed -i "s/^#*Port .*/Port $SSH_PORT/" /etc/ssh/sshd_config
    sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#*PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/^#*PubkeyAuthentication .*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
    echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
    echo "AllowUsers $USERNAME" >> /etc/ssh/sshd_config
    check_status "Failed to modify sshd_config"
    
    # Test SSH config
    sshd -t
    check_status "SSH configuration test failed"
    
    # Apply changes
    restart_ssh
}

# Configure firewall
configure_firewall() {
    print_message "Configuring firewall..."
    case "$OS" in
        *"Ubuntu"*|*"Debian"*|*"Arch"*)
            # First allow the new port before blocking the old one
            ufw allow $SSH_PORT/tcp
            ufw --force enable
            # Only block port 22 if it's different from new SSH port
            if [ "$SSH_PORT" != "22" ]; then
                ufw deny 22/tcp
            fi
            ufw status
            check_status "Failed to configure UFW"
            ;;
        *"CentOS"*|*"Red Hat"*|*"Fedora"*)
            systemctl start firewalld
            systemctl enable firewalld
            # First add the new port
            firewall-cmd --permanent --add-port=$SSH_PORT/tcp
            # Only remove ssh service if using non-standard port
            if [ "$SSH_PORT" != "22" ]; then
                firewall-cmd --permanent --remove-service=ssh
            fi
            firewall-cmd --reload
            firewall-cmd --list-all
            check_status "Failed to configure firewalld"
            ;;
    esac
}

# Configure fail2ban
configure_fail2ban() {
    print_message "Configuring fail2ban..."
    
    # Create fail2ban custom config
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = %(sshd_log)s
maxretry = 3
bantime = 3600
EOF
    check_status "Failed to create fail2ban configuration"
    
    systemctl enable fail2ban
    systemctl start fail2ban
    check_status "Failed to start fail2ban"
}

# Update main execution order
print_message "Starting VPS setup at $(date)"
check_root
detect_os
update_system
enable_repos
install_packages
create_user
# Configure firewall first
configure_firewall
# Then configure SSH and restart it
configure_ssh

print_message "Setup completed! Please test new SSH connection before closing this session."
print_warning "New SSH port: $SSH_PORT"
print_warning "New username: $USERNAME"
print_warning "Make sure you can login with your SSH key before closing this session!"
print_warning "Test with: ssh -p $SSH_PORT $USERNAME@<your-ip>"
print_message "Setup log available at: $LOG_FILE"