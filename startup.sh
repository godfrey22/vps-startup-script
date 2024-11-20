#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
DEFAULT_SSH_PORT=2222
BACKUP_DIR="/var/backups/vps-setup"
LOG_FILE="/var/log/vps_setup.log"

# Create backup directory first
mkdir -p "$BACKUP_DIR"

# Set up logging with timestamps
exec > >(tee -a "$LOG_FILE") 2>&1

# Enhanced cleanup
cleanup() {
    if [ -d "/tmp/ssh_setup" ]; then
        rm -rf "/tmp/ssh_setup"
    fi
    cp "$LOG_FILE" "$BACKUP_DIR/vps_setup_$(date +%Y%m%d_%H%M%S).log"
}
trap cleanup EXIT

# Logging functions
print_message() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${GREEN}[+] [$timestamp] $1${NC}"
    logger -t "vps-setup" "$1"
}

print_warning() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${YELLOW}[!] [$timestamp] $1${NC}"
    logger -t "vps-setup" "WARNING: $1"
}

print_error() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${RED}[-] [$timestamp] $1${NC}"
    logger -t "vps-setup" "ERROR: $1"
}

# Error handling
check_status() {
    if [ $? -ne 0 ]; then
        print_error "Failed on line ${BASH_LINENO[0]}: $1"
        exit 1
    fi
}

# Argument parsing
parse_arguments() {
    while [[ "$#" -gt 0 ]]; do
        case $1 in
            --username)
                if [[ -z "$2" || "$2" == -* ]]; then
                    print_error "Username parameter requires a value"
                    exit 1
                fi
                USERNAME="$2"
                shift
                ;;
            --ssh-port)
                if [[ -z "$2" || "$2" == -* ]]; then
                    print_error "SSH port parameter requires a value"
                    exit 1
                fi
                SSH_PORT="$2"
                shift
                ;;
            --non-interactive)
                NON_INTERACTIVE=true
                ;;
            --help)
                echo "Usage: $0 [--username USERNAME] [--ssh-port PORT] [--non-interactive]"
                echo "Options:"
                echo "  --username USERNAME    Specify the username to create"
                echo "  --ssh-port PORT       Specify the SSH port to use (default: 2222)"
                echo "  --non-interactive     Run without interactive prompts"
                echo "  --help                Show this help message"
                exit 0
                ;;
            *)
                print_error "Unknown parameter: $1"
                exit 1
                ;;
        esac
        shift
    done

    # Set default values if not provided
    SSH_PORT=${SSH_PORT:-$DEFAULT_SSH_PORT}
    
    # If not in non-interactive mode and username is not set, prompt for it
    if [ -z "$USERNAME" ] && [ "$NON_INTERACTIVE" != "true" ]; then
        read -p "Enter username: " USERNAME
    fi
}

# OS detection using ID instead of NAME
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION_ID=$VERSION_ID
        print_message "Detected OS: $OS $VERSION_ID"
        
        case "$OS" in
            ubuntu|debian|centos|rhel|fedora|arch)
                print_message "Operating system is supported"
                ;;
            *)
                print_error "Unsupported operating system: $OS"
                exit 1
                ;;
        esac
    else
        print_error "Cannot detect OS"
        exit 1
    fi
}

# Root check
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

# Username validation
validate_username() {
    local username=$1

    if [ -z "$username" ]; then
        print_error "Username cannot be empty"
        exit 1
    fi

    if [ ${#username} -lt 1 ] || [ ${#username} -gt 32 ]; then
        print_error "Username must be between 1 and 32 characters"
        exit 1
    fi

    if ! [[ "$username" =~ ^[a-zA-Z][a-zA-Z0-9._-]*$ ]]; then
        print_error "Username must start with a letter and contain only letters, numbers, underscores, dashes, or periods"
        exit 1
    fi
}

# SSH port validation
validate_ssh_port() {
    local port=$1

    # Remove any non-numeric characters
    port=$(echo "$port" | tr -dc '0-9')

    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -le 0 ] || [ "$port" -gt 65535 ]; then
        print_error "Invalid port number. Please enter a value between 1 and 65535"
        exit 1
    fi

    # Check if port is already in use (using ss if available, falling back to netstat)
    if command -v ss >/dev/null 2>&1; then
        if ss -tuln | grep ":$port " >/dev/null 2>&1; then
            print_error "Port $port is already in use"
            exit 1
        fi
    elif command -v netstat >/dev/null 2>&1; then
        if netstat -tuln | grep ":$port " >/dev/null 2>&1; then
            print_error "Port $port is already in use"
            exit 1
        fi
    else
        print_warning "Neither ss nor netstat available. Skipping port check"
    fi

    SSH_PORT=$port
}

# System update with better package conflict handling
update_system() {
    print_message "Updating system packages..."
    case "$OS" in
        ubuntu|debian)
            apt update && apt upgrade -y
            check_status "Failed to update packages"
            ;;
        centos|rhel)
            if command -v dnf >/dev/null 2>&1; then
                # Try normal update first
                if ! dnf update -y; then
                    print_warning "Normal update failed, attempting with --nobest option..."
                    if ! dnf update -y --nobest; then
                        print_warning "Update with --nobest failed, trying with --skip-broken..."
                        if ! dnf update -y --skip-broken; then
                            print_warning "Update with --skip-broken failed, attempting critical updates only..."
                            # Update only security and critical packages
                            if ! dnf update -y --security; then
                                print_error "All update attempts failed"
                                exit 1
                            fi
                        fi
                    fi
                fi
            else
                # For older systems using yum
                if ! yum update -y; then
                    print_warning "Normal update failed, attempting with --skip-broken..."
                    if ! yum update -y --skip-broken; then
                        print_error "All update attempts failed"
                        exit 1
                    fi
                fi
            fi
            ;;
        fedora)
            if ! dnf update -y; then
                print_warning "Normal update failed, attempting with --skip-broken..."
                dnf update -y --skip-broken
            fi
            check_status "Failed to update packages"
            ;;
        arch)
            pacman -Syu --noconfirm
            check_status "Failed to update packages"
            ;;
    esac
}

# Repository enablement
enable_repos() {
    print_message "Enabling required repositories..."
    case "$OS" in
        centos|rhel)
            # Backup repo configuration
            cp -r /etc/yum.repos.d/ "$BACKUP_DIR/repos.backup/"
            
            if [[ $VERSION_ID == 8* ]]; then
                dnf install -y "https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm"
                dnf config-manager --set-enabled powertools
            else
                if command -v dnf >/dev/null 2>&1; then
                    dnf install -y epel-release
                    dnf config-manager --set-enabled crb
                else
                    yum install -y epel-release
                fi
            fi
            check_status "Failed to enable repositories"
            ;;
    esac
}

# Package installation with proper package names per distribution
install_packages() {
    print_message "Installing required packages..."
    
    case "$OS" in
        ubuntu|debian)
            local deps=(curl wget iproute2 sudo ufw fail2ban)
            apt update
            apt install -y "${deps[@]}"
            ;;
        centos|rhel)
            local deps=(curl wget iproute sudo firewalld fail2ban)
            enable_repos
            if command -v dnf >/dev/null 2>&1; then
                # First check which packages need to be installed
                local to_install=()
                for pkg in "${deps[@]}"; do
                    if ! rpm -q "$pkg" &>/dev/null; then
                        to_install+=("$pkg")
                    else
                        print_message "Package $pkg is already installed"
                    fi
                done
                
                # Install only missing packages
                if [ ${#to_install[@]} -gt 0 ]; then
                    dnf install -y "${to_install[@]}"
                else
                    print_message "All required packages are already installed"
                fi
            else
                yum install -y "${deps[@]}"
            fi
            ;;
        fedora)
            local deps=(curl wget iproute sudo firewalld fail2ban)
            dnf install -y "${deps[@]}"
            ;;
        arch)
            local deps=(curl wget iproute2 sudo ufw fail2ban)
            pacman -S --noconfirm "${deps[@]}"
            ;;
    esac
    check_status "Failed to install required packages"

    # Verify critical commands are available
    local required_commands=(curl wget ip sudo)
    local missing_commands=()
    
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_commands+=("$cmd")
        fi
    done
    
    if [ ${#missing_commands[@]} -gt 0 ]; then
        print_error "Some required commands are still missing: ${missing_commands[*]}"
        exit 1
    fi
}

# User creation
create_user() {
    print_message "Setting up user $USERNAME..."
    
    if id "$USERNAME" >/dev/null 2>&1; then
        print_message "User $USERNAME already exists"
    else
        useradd -m -s /bin/bash "$USERNAME"
        check_status "Failed to create user"

        if [ "$NON_INTERACTIVE" != "true" ]; then
            print_message "Setting password for $USERNAME"
            passwd "$USERNAME"
            check_status "Failed to set password"
        fi
    fi

    # Add to sudo group
    case "$OS" in
        ubuntu|debian)
            usermod -aG sudo "$USERNAME"
            ;;
        *)
            usermod -aG wheel "$USERNAME"
            ;;
    esac
    check_status "Failed to add user to sudo group"
}

# SSH configuration
configure_ssh() {
    print_message "Configuring SSH..."
    
    # Backup original config
    cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.backup"
    check_status "Failed to backup SSH config"
    
    # Set up SSH directory and permissions
    local ssh_dir="/home/$USERNAME/.ssh"
    local auth_keys="$ssh_dir/authorized_keys"
    
    mkdir -p "$ssh_dir"
    touch "$auth_keys"
    
    # Set proper permissions
    chmod 700 "$ssh_dir"
    chmod 600 "$auth_keys"
    chown -R "$USERNAME:$USERNAME" "$ssh_dir"
    
    # Collect SSH public key
    if [ "$NON_INTERACTIVE" != "true" ]; then
        while true; do
            print_message "Please paste your SSH public key (it should start with 'ssh-rsa' or 'ssh-ed25519'):"
            local pubkey
            read -r pubkey
            
            # Validate the SSH key format
            if [[ "$pubkey" =~ ^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521)[[:space:]] ]]; then
                echo "$pubkey" >> "$auth_keys"
                check_status "Failed to add SSH key"
                print_message "SSH public key added successfully"
                break
            else
                print_error "Invalid SSH key format. It should start with 'ssh-rsa', 'ssh-ed25519', or 'ecdsa-sha2-*'"
                print_message "Example of a valid key:"
                print_message "ssh-rsa AAAAB3NzaC1yc2E... user@host"
                read -p "Try again? (y/n): " retry
                if [[ ! "$retry" =~ ^[Yy] ]]; then
                    print_error "SSH key setup aborted. You won't be able to log in without a valid key."
                    exit 1
                fi
            fi
        done
    fi
    
    # Configure sshd_config
    print_message "Configuring SSH daemon..."
    sed -i.bak "
        s/^#*Port .*/Port $SSH_PORT/
        s/^#*PermitRootLogin .*/PermitRootLogin no/
        s/^#*PasswordAuthentication .*/PasswordAuthentication no/
        s/^#*PubkeyAuthentication .*/PubkeyAuthentication yes/
        s/^#*AuthorizedKeysFile.*/AuthorizedKeysFile .ssh\/authorized_keys/
        s/^#*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/
    " /etc/ssh/sshd_config
    
    # Add or update AllowUsers directive
    if grep -q "^AllowUsers" /etc/ssh/sshd_config; then
        sed -i "s/^AllowUsers.*/& $USERNAME/" /etc/ssh/sshd_config
    else
        echo "AllowUsers $USERNAME" >> /etc/ssh/sshd_config
    fi
    
    # Add additional security configurations
    cat >> /etc/ssh/sshd_config << EOF

# Additional security settings
PermitEmptyPasswords no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
    
    # Test SSH configuration
    print_message "Testing SSH configuration..."
    sshd -t
    check_status "SSH configuration test failed"
    
    # Restart SSH service
    print_message "Restarting SSH service..."
    if systemctl is-active --quiet ssh; then
        systemctl restart ssh
    elif systemctl is-active --quiet sshd; then
        systemctl restart sshd
    else
        print_error "SSH service not found"
        exit 1
    fi
    check_status "Failed to restart SSH service"
    
    # Verify the key was properly set
    if [ -s "$auth_keys" ]; then
        print_message "SSH configuration completed successfully"
        print_message "You can now connect using: ssh -p $SSH_PORT $USERNAME@<server-ip>"
    else
        print_warning "No SSH key was added to authorized_keys"
        print_warning "You will need to add a key manually to connect"
    fi
    
    # Display current SSH port and settings
    print_message "Current SSH settings:"
    echo "Port: $SSH_PORT"
    echo "User: $USERNAME"
    echo "Public key authentication: enabled"
    echo "Password authentication: disabled"
}


# Firewall configuration
configure_firewall() {
    print_message "Configuring firewall..."
    case "$OS" in
        ubuntu|debian|arch)
            ufw allow "$SSH_PORT"/tcp
            ufw --force enable
            if [ "$SSH_PORT" != "22" ]; then
                ufw deny 22/tcp
            fi
            check_status "Failed to configure UFW"
            ;;
        centos|rhel|fedora)
            # Stop firewalld first to avoid conflicts
            systemctl stop firewalld
            systemctl disable firewalld
            
            # Clean up any existing iptables rules for SSH
            iptables -D INPUT -p tcp --dport "$SSH_PORT" -j DROP 2>/dev/null || true
            iptables -D INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT 2>/dev/null || true
            
            # Add new ACCEPT rule for SSH port
            iptables -I INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT
            
            # If using non-standard port, remove access to port 22
            if [ "$SSH_PORT" != "22" ]; then
                iptables -D INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || true
                iptables -A INPUT -p tcp --dport 22 -j DROP
            fi
            
            # Make iptables rules persistent
            if command -v iptables-save >/dev/null 2>&1; then
                iptables-save > /etc/sysconfig/iptables
            else
                print_warning "iptables-save not found. Firewall rules may not persist after reboot"
            fi
            
            print_message "Verifying firewall rules..."
            iptables -L -n -v | grep "$SSH_PORT"
            check_status "Failed to verify firewall rules"
            ;;
    esac
}

# Fail2ban configuration
configure_fail2ban() {
    print_message "Configuring fail2ban..."
    
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
    systemctl restart fail2ban
    check_status "Failed to start fail2ban"
}

# Main execution
main() {
    print_message "Starting VPS setup at $(date)"
    
    parse_arguments "$@"
    check_root
    detect_os
    
    # Validate inputs
    validate_username "$USERNAME"
    validate_ssh_port "$SSH_PORT"
    
    # System setup
    update_system
    install_packages
    
    # User and security setup
    create_user
    configure_firewall
    configure_ssh
    configure_fail2ban
    
    print_message "Setup completed successfully!"
    print_warning "New SSH port: $SSH_PORT"
    print_warning "New username: $USERNAME"
    print_warning "Make sure you can login with your SSH key before closing this session!"
    print_warning "Test with: ssh -p $SSH_PORT $USERNAME@<your-ip>"
    print_message "Setup log available at: $LOG_FILE"
    print_message "Backup files available at: $BACKUP_DIR"
}

# Execute main function
main "$@"