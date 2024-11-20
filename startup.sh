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
MINIMUM_DISK_SPACE=500000  # 500MB in KB
TIMEOUT_DURATION=300       # 5 minutes

# Create backup directory first
mkdir -p "$BACKUP_DIR"

# Set up logging with timestamps
exec > >(tee -a "$LOG_FILE") 2>&1

# Enhanced logging
log_operation() {
    local operation="$1"
    local result="$2"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $operation: $result" >> "$LOG_FILE"
}

# Enhanced cleanup with rollback capability
cleanup() {
    local exit_code=$?
    if [ -d "/tmp/ssh_setup" ]; then
        rm -rf "/tmp/ssh_setup"
    fi
    
    # Copy log file to backup directory
    cp "$LOG_FILE" "$BACKUP_DIR/vps_setup_$(date +%Y%m%d_%H%M%S).log"
    
    if [ $exit_code -ne 0 ]; then
        print_error "Script failed with exit code $exit_code"
        # Attempt rollback of critical configurations
        rollback_changes
    fi
}

rollback_changes() {
    print_warning "Attempting to rollback changes..."
    
    # Restore SSH config if backup exists
    if [ -f "$BACKUP_DIR/sshd_config.backup" ]; then
        cp "$BACKUP_DIR/sshd_config.backup" /etc/ssh/sshd_config
        systemctl restart sshd
    fi
    
    # Restore firewall rules if backup exists
    case "$OS" in
        ubuntu|debian|arch)
            if [ -f "$BACKUP_DIR/ufw.backup" ]; then
                ufw reset --force
                . "$BACKUP_DIR/ufw.backup"
            fi
            ;;
        centos|rhel|fedora)
            if [ -f "$BACKUP_DIR/iptables.backup" ]; then
                iptables-restore < "$BACKUP_DIR/iptables.backup"
            fi
            ;;
    esac
    
    log_operation "Rollback" "Completed"
}

trap cleanup EXIT

# Logging functions
print_message() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${GREEN}[+] [$timestamp] $1${NC}"
    log_operation "INFO" "$1"
}

print_warning() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${YELLOW}[!] [$timestamp] $1${NC}"
    log_operation "WARNING" "$1"
}

print_error() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${RED}[-] [$timestamp] $1${NC}"
    log_operation "ERROR" "$1"
}

# Enhanced error handling with retry capability
execute_with_retry() {
    local cmd="$1"
    local max_attempts=${2:-3}
    local attempt=1
    local result
    
    while [ $attempt -le $max_attempts ]; do
        result=$(eval "$cmd")
        local status=$?
        if [ $status -eq 0 ]; then
            return 0
        fi
        print_warning "Command failed (attempt $attempt/$max_attempts): $cmd"
        attempt=$((attempt + 1))
        sleep 5
    done
    return 1
}

check_status() {
    local status=$?
    local message="$1"
    if [ $status -ne 0 ]; then
        print_error "Failed on line ${BASH_LINENO[0]}: $message"
        exit 1
    fi
}

# System resource monitoring
monitor_disk_space() {
    local available=$(df / | awk 'NR==2 {print $4}')
    if [ "$available" -lt "$MINIMUM_DISK_SPACE" ]; then
        print_error "Low disk space: ${available}KB available"
        return 1
    fi
    return 0
}

check_system_resources() {
    # Check available disk space
    monitor_disk_space || exit 1
    
    # Check if package manager is locked
    case "$OS" in
        ubuntu|debian)
            if [ -f /var/lib/dpkg/lock-frontend ] || [ -f /var/lib/apt/lists/lock ]; then
                print_error "Package manager is locked. Please wait or check system status"
                exit 1
            fi
            ;;
        centos|rhel|fedora)
            if [ -f /var/run/yum.pid ] || [ -f /var/run/dnf.pid ]; then
                print_error "Package manager is locked. Please wait or check system status"
                exit 1
            fi
            ;;
    esac
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

# Enhanced OS detection
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

# Enhanced username validation
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

    # Check if username is in list of system users or common service accounts
    local system_users="root bin daemon adm lp sync shutdown halt mail news uucp operator games man"
    for sys_user in $system_users; do
        if [ "$username" = "$sys_user" ]; then
            print_error "Username cannot be a system account"
            exit 1
        fi
    done
}

# Enhanced SSH key validation
validate_ssh_key() {
    local key="$1"
    
    # Check minimum length
    if [ ${#key} -lt 256 ]; then
        return 1
    fi
    
    # Validate format thoroughly
    if ! echo "$key" | grep -qE '^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp[256|384|521]) [A-Za-z0-9+/]+[=]{0,2}( [^@]+@[^@]+)?$'; then
        return 1
    fi
    
    # Check for common issues
    if echo "$key" | grep -q "^ssh-rsa.*1024 "; then
        print_warning "RSA keys shorter than 2048 bits are not recommended"
        return 1
    fi
    
    return 0
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

    # Check if port is already in use
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

    # Check if port is in reserved range
    if [ "$port" -lt 1024 ] && [ "$port" -ne 22 ]; then
        print_warning "Port $port is in the privileged port range"
    fi

    SSH_PORT=$port
}

# Enhanced system update
update_system() {
    print_message "Updating system packages..."
    
    # Check system resources before update
    check_system_resources
    
    case "$OS" in
        ubuntu|debian)
            # Backup sources
            cp -r /etc/apt/sources.list* "$BACKUP_DIR/"
            
            # Update with timeout and retry
            if ! timeout "$TIMEOUT_DURATION" apt-get update; then
                print_error "apt-get update timed out"
                exit 1
            fi
            
            if ! timeout "$TIMEOUT_DURATION" apt-get upgrade -y; then
                print_warning "Full upgrade failed, attempting minimal upgrade..."
                apt-get upgrade -y --minimal
            fi
            ;;
        centos|rhel)
            # Backup repo configuration
            cp -r /etc/yum.repos.d/ "$BACKUP_DIR/repos.backup/"
            
            if command -v dnf >/dev/null 2>&1; then
                execute_with_retry "dnf update -y" 3
                if [ $? -ne 0 ]; then
                    print_warning "Normal update failed, attempting with --nobest..."
                    execute_with_retry "dnf update -y --nobest" 2
                    if [ $? -ne 0 ]; then
                        print_warning "Update with --nobest failed, trying security updates only..."
                        if ! dnf update -y --security; then
                            print_error "All update attempts failed"
                            exit 1
                        fi
                    fi
                fi
            else
                execute_with_retry "yum update -y" 3
            fi
            ;;
        fedora)
            execute_with_retry "dnf update -y" 3
            ;;
        arch)
            execute_with_retry "pacman -Syu --noconfirm" 3
            ;;
    esac
    
    monitor_disk_space
}

# Enhanced package installation
install_packages() {
    print_message "Installing required packages..."
    
    check_system_resources
    
    case "$OS" in
        ubuntu|debian)
            local deps=(curl wget iproute2 sudo ufw fail2ban)
            apt update
            for pkg in "${deps[@]}"; do
                if ! dpkg -l "$pkg" >/dev/null 2>&1; then
                    execute_with_retry "apt install -y $pkg" 3
                fi
            done
            ;;
        centos|rhel)
            local deps=(curl wget iproute sudo firewalld fail2ban)
            for pkg in "${deps[@]}"; do
                if ! rpm -q "$pkg" >/dev/null 2>&1; then
                    execute_with_retry "dnf install -y $pkg" 3
                fi
            done
            ;;
        fedora)
            local deps=(curl wget iproute sudo firewalld fail2ban)
            for pkg in "${deps[@]}"; do
                execute_with_retry "dnf install -y $pkg" 3
            done
            ;;
        arch)
            local deps=(curl wget iproute2 sudo ufw fail2ban)
            execute_with_retry "pacman -S --noconfirm ${deps[*]}" 3
            ;;
    esac

    # Verify critical commands
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

# Enhanced user creation
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

    # Add to sudo group with backup of sudoers
    cp /etc/sudoers "$BACKUP_DIR/sudoers.backup"
    case "$OS" in
        ubuntu|debian)
            usermod -aG sudo "$USERNAME"
            ;;
        *)
            usermod -aG wheel "$USERNAME"
            ;;
    esac
    check_status "Failed to add user to sudo group"
    
    # Verify sudo access
    if ! sudo -l -u "$USERNAME" >/dev/null 2>&1; then
        print_error "Failed to verify sudo access for $USERNAME"
        exit 1
    else
        print_message "$USERNAME has been successfully added to the sudo group"
    fi
}

# Enhanced SSH configuration
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
            
            if validate_ssh_key "$pubkey"; then
                echo "$pubkey" >> "$auth_keys"
                check_status "Failed to add SSH key"
                print_message "SSH public key added successfully"
                break
            else
                print_error "Invalid SSH key format. Please try again."
            fi
        done
    fi
    
    # Update SSH configuration
    print_message "Configuring SSH daemon..."
    sed -i.bak "
        s/^#*Port .*/Port $SSH_PORT/
        s/^#*PermitRootLogin .*/PermitRootLogin no/
        s/^#*PasswordAuthentication .*/PasswordAuthentication no/
        s/^#*PubkeyAuthentication .*/PubkeyAuthentication yes/
        s/^#*AuthorizedKeysFile.*/AuthorizedKeysFile .ssh\/authorized_keys/
        s/^#*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/
    " /etc/ssh/sshd_config
    
    # Add AllowUsers directive
    if grep -q "^AllowUsers" /etc/ssh/sshd_config; then
        sed -i "s/^AllowUsers.*/& $USERNAME/" /etc/ssh/sshd_config
    else
        echo "AllowUsers $USERNAME" >> /etc/ssh/sshd_config
    fi
    
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
    
    print_message "SSH configuration completed successfully"
    print_message "You can now connect using: ssh -p $SSH_PORT $USERNAME@<server-ip>"
}

# Main execution
main() {
    print_message "Starting VPS setup at $(date)"
    
    parse_arguments "$@"
    check_root
    detect_os
    validate_username "$USERNAME"
    validate_ssh_port "$SSH_PORT"
    check_system_resources
    
    update_system
    install_packages
    create_user
    configure_firewall
    configure_ssh
    configure_fail2ban
    
    print_message "Setup completed successfully!"
    print_warning "New SSH port: $SSH_PORT"
    print_warning "New username: $USERNAME"
    print_warning "Make sure you can log in with your SSH key before closing this session!"
    print_message "Setup log available at: $LOG_FILE"
    print_message "Backup files available at: $BACKUP_DIR"
}

# Execute main function
main "$@"
