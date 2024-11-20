#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Logging functions
log_success() { echo -e "${GREEN}[+]${NC} $1"; }
log_error() { echo -e "${RED}[-]${NC} $1"; }

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log_error "Please run as root"
    exit 1
fi

# Validate SSH port
validate_port() {
    local port=$1
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -le 0 ] || [ "$port" -gt 65535 ]; then
        log_error "Invalid port number. Please enter a value between 1 and 65535"
        return 1
    fi
    
    if netstat -tuln | grep ":$port " >/dev/null 2>&1; then
        log_error "Port $port is already in use"
        return 1
    fi
    return 0
}

# Validate username
validate_username() {
    local username=$1
    if ! [[ "$username" =~ ^[a-z][-a-z0-9]*$ ]]; then
        log_error "Username must start with a letter and contain only lowercase letters, numbers, and hyphens"
        return 1
    fi
    if id "$username" >/dev/null 2>&1; then
        log_error "User $username already exists"
        return 1
    fi
    return 0
}

# Get user inputs with validation
while true; do
    read -p "Enter new username: " USERNAME
    validate_username "$USERNAME" && break
done

read -s -p "Enter password: " PASSWORD
echo

while true; do
    read -p "Enter desired SSH port: " SSH_PORT
    validate_port "$SSH_PORT" && break
done

echo "Paste your public SSH key (ending with domain or comment):"
SSH_KEY=$(cat)

if [ -z "$SSH_KEY" ] || ! [[ "$SSH_KEY" =~ ^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp[0-9]+) ]]; then
    log_error "Invalid SSH key format"
    exit 1
fi

# Create new user
useradd -m -s /bin/bash "$USERNAME"
if [ $? -ne 0 ]; then
    log_error "Failed to create user $USERNAME"
    exit 1
fi

echo "$USERNAME:$PASSWORD" | chpasswd
if [ $? -ne 0 ]; then
    log_error "Failed to set password"
    exit 1
fi

# Add user to sudo/wheel group
if getent group sudo >/dev/null; then
    usermod -aG sudo "$USERNAME"
elif getent group wheel >/dev/null; then
    usermod -aG wheel "$USERNAME"
else
    log_error "No sudo/wheel group found"
    exit 1
fi

# Set up SSH for the new user
mkdir -p "/home/$USERNAME/.ssh"
echo "$SSH_KEY" > "/home/$USERNAME/.ssh/authorized_keys"
chmod 700 "/home/$USERNAME/.ssh"
chmod 600 "/home/$USERNAME/.ssh/authorized_keys"
chown -R "$USERNAME:$USERNAME" "/home/$USERNAME/.ssh"

# Backup and configure SSH
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
sed -i "/^#Port 22/c\Port $SSH_PORT" /etc/ssh/sshd_config
sed -i "/^Port /c\Port $SSH_PORT" /etc/ssh/sshd_config
sed -i 's/#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

# Test SSH configuration
sshd -t
if [ $? -ne 0 ]; then
    log_error "SSH configuration test failed. Restoring backup..."
    cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
    exit 1
fi

# Configure firewall
if command -v ufw >/dev/null 2>&1; then
    ufw status | grep -q "Status: active" || ufw --force enable
    ufw allow "$SSH_PORT/tcp"
    log_success "Firewall configured with ufw for SSH port $SSH_PORT"
elif command -v firewall-cmd >/dev/null 2>&1; then
    systemctl is-active --quiet firewalld || systemctl start firewalld
    firewall-cmd --permanent --add-port="$SSH_PORT/tcp"
    firewall-cmd --reload
    log_success "Firewall configured with firewall-cmd for SSH port $SSH_PORT"
else
    log_error "No supported firewall found. Please configure manually."
fi

# Check if SSH service is running before restart
if ! systemctl is-active --quiet sshd; then
    log_error "SSH service is not running"
    exit 1
fi

# Restart SSH service
systemctl restart sshd
if [ $? -ne 0 ]; then
    log_error "Failed to restart SSH service"
    exit 1
fi

log_success "Setup completed!"
log_success "New user: $USERNAME"
log_success "SSH port: $SSH_PORT"
log_success "Root login disabled, password authentication disabled"
log_success "Please test your new SSH connection before closing this session:"
echo "ssh -p $SSH_PORT $USERNAME@<server-ip>"