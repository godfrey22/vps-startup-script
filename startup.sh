#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Set up logging with timestamps
LOG_FILE="/var/log/vps_setup.log"
exec > >(tee -a "$LOG_FILE") 2>&1

# Enhanced cleanup with backup
BACKUP_DIR="/var/backups/vps-setup"
cleanup() {
    if [ -d "/tmp/ssh_setup" ]; then
        rm -rf "/tmp/ssh_setup"
    fi
    # Keep backup files for potential recovery
    mkdir -p "$BACKUP_DIR"
    cp "$LOG_FILE" "$BACKUP_DIR/vps_setup_$(date +%Y%m%d_%H%M%S).log"
}
trap cleanup EXIT

# Enhanced logging functions with timestamps
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

# Enhanced error checking with line number reporting
check_status() {
    if [ $? -ne 0 ]; then
        print_error "Failed on line ${BASH_LINENO[0]}: $1"
        exit 1
    fi
}

# Enhanced command line argument parsing with validation
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
                echo "  --ssh-port PORT       Specify the SSH port to use"
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
}

# Enhanced OS detection with version validation
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VERSION=$VERSION_ID
        print_message "Detected OS: $OS $VERSION"
    else
        print_error "Cannot detect OS"
        exit 1
    fi

    # Validate supported OS
    case "$OS" in
        *"Ubuntu"*|*"Debian"*|*"CentOS"*|*"Red Hat"*|*"Fedora"*|*"Arch"*)
            print_message "Operating system is supported"
            ;;
        *)
            print_error "Unsupported operating system: $OS"
            exit 1
            ;;
    esac
}

# Enhanced root check with detailed message
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This script must be run as root or with sudo privileges"
        exit 1
    fi
}

# Enhanced username validation with better pattern matching
validate_username() {
    local username=$1
    
    # Check for empty username
    if [ -z "$username" ]; then
        print_error "Username cannot be empty"
        exit 1
    }
    
    # Check length
    if [ ${#username} -lt 1 ] || [ ${#username} -gt 32 ]; then
        print_error "Username must be between 1 and 32 characters"
        exit 1
    }
    
    # Check valid characters
    if ! [[ "$username" =~ ^[a-zA-Z0-9._-]+$ ]]; then
        print_error "Invalid username. Use only letters, numbers, underscores, dashes, or periods."
        exit 1
    }
    
    # Check if username starts with valid character
    if ! [[ "$username" =~ ^[a-zA-Z][a-zA-Z0-9._-]*$ ]]; then
        print_error "Username must start with a letter"
        exit 1
    }
}

# Enhanced SSH port validation with connection testing
validate_ssh_port() {
    local port=$1
    
    # Remove any non-numeric characters
    port=$(echo $port | tr -dc '0-9')
    
    # Validate port number
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -le 0 ] || [ "$port" -gt 65535 ]; then
        print_error "Invalid port number. Please enter a value between 1 and 65535."
        exit 1
    fi
    
    # Check if port is already in use
    if netstat -tuln | grep ":$port " >/dev/null 2>&1; then
        print_error "Port $port is already in use"
        exit 1
    }
    
    # Update the global SSH_PORT variable
    SSH_PORT=$port
}

# Enhanced system update with backup
update_system() {
    print_message "Creating package list backup..."
    case "$OS" in
        *"Ubuntu"*|*"Debian"*)
            dpkg --get-selections > "$BACKUP_DIR/package_list.backup"
            ;;
        *"CentOS"*|*"Red Hat"*|*"Fedora"*)
            rpm -qa > "$BACKUP_DIR/package_list.backup"
            ;;
    esac

    print_message "Updating system packages..."
    case "$OS" in
        *"Ubuntu"*|*"Debian"*)
            apt update && apt upgrade -y
            check_status "Failed to update packages"
            ;;
        *"CentOS"*|*"Red Hat"*)
            # Add --nobest flag for better compatibility
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
    esac
}

# Enhanced repository enablement with error handling
enable_repos() {
    print_message "Enabling required repositories..."
    case "$OS" in
        *"CentOS"*|*"Red Hat"*)
            # Backup repo configuration
            cp -r /etc/yum.repos.d/ "$BACKUP_DIR/repos.backup/"
            
            # Install EPEL repository with version check
            if [[ $VERSION_ID == 8* ]]; then
                dnf install -y "https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm"
            else
                dnf install -y epel-release
            fi
            check_status "Failed to install EPEL repository"
            
            # Enable CRB/PowerTools repository based on version
            if [[ $VERSION_ID == 8* ]]; then
                dnf config-manager --set-enabled powertools
            else
                dnf config-manager --set-enabled crb
            fi
            check_status "Failed to enable additional repositories"
            ;;
    esac
}

# Enhanced package installation with dependency checking
install_packages() {
    print_message "Installing required packages..."
    
    # Common dependencies check
    local deps=(curl wget)
    for dep in "${deps[@]}"; do
        if ! command -v $dep &> /dev/null; then
            case "$OS" in
                *"Ubuntu"*|*"Debian"*)
                    apt install -y $dep
                    ;;
                *"CentOS"*|*"Red Hat"*|*"Fedora"*)
                    dnf install -y $dep
                    ;;
                *"Arch"*)
                    pacman -S --noconfirm $dep
                    ;;
            esac
        fi
    done
    
    # Main package installation
    case "$OS" in
        *"Ubuntu"*|*"Debian"*)
            apt install -y sudo ufw fail2ban
            ;;
        *"CentOS"*|*"Red Hat"*)
            enable_repos
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

# Rest of the original functions...
# (create_user, restart_ssh, configure_ssh, configure_firewall, configure_fail2ban)
# These remain largely unchanged but benefit from the enhanced error handling
# and logging provided by the improved check_status and print_* functions

# Enhanced main execution with better flow control
main() {
    print_message "Starting VPS setup at $(date)"
    
    # Create backup directory
    mkdir -p "$BACKUP_DIR"
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Basic checks
    check_root
    detect_os
    
    # System preparation
    update_system
    install_packages
    
    # User management
    create_user
    
    # Security configuration
    configure_firewall
    configure_ssh
    configure_fail2ban
    
    # Final verification
    print_message "Running final verification checks..."
    
    # Test SSH configuration
    sshd -t
    check_status "SSH configuration test failed"
    
    # Verify services are running
    systemctl is-active --quiet sshd
    check_status "SSH service is not running"
    
    systemctl is-active --quiet fail2ban
    check_status "Fail2ban service is not running"
    
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