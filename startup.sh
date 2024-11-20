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

# Get user inputs
read -p "Enter new username: " USERNAME
read -s -p "Enter password: " PASSWORD
echo
read -p "Enter desired SSH port: " SSH_PORT
read -p "Enter your public SSH key: " SSH_KEY

# Create new user
useradd -m -s /bin/bash "$USERNAME"
if [ $? -ne 0 ]; then
    log_error "Failed to create user $USERNAME"
    exit 1
fi
echo "$USERNAME:$PASSWORD" | chpasswd
usermod -aG sudo "$USERNAME"

# Set up SSH for the new user
mkdir -p "/home/$USERNAME/.ssh"
echo "$SSH_KEY" > "/home/$USERNAME/.ssh/authorized_keys"
chmod 700 "/home/$USERNAME/.ssh"
chmod 600 "/home/$USERNAME/.ssh/authorized_keys"
chown -R "$USERNAME:$USERNAME" "/home/$USERNAME/.ssh"

# Configure SSH
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
sed -i "/^#Port 22/c\Port $SSH_PORT" /etc/ssh/sshd_config
sed -i "/^Port /c\Port $SSH_PORT" /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config

# Test SSH configuration before restart
sshd -t
if [ $? -ne 0 ]; then
    log_error "SSH configuration test failed. Please review the changes."
    exit 1
fi

# Configure firewall
if command -v ufw >/dev/null 2>&1; then
    ufw allow "$SSH_PORT/tcp"
    ufw --force enable
    log_success "Firewall configured with ufw for SSH port $SSH_PORT"
elif command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="$SSH_PORT/tcp"
    firewall-cmd --reload
    log_success "Firewall configured with firewall-cmd for SSH port $SSH_PORT"
else
    log_error "No supported firewall found. Please configure manually."
fi

# Restart SSH service
systemctl restart sshd
log_success "SSH service restarted successfully"

log_success "Setup completed!"
log_success "New user: $USERNAME"
log_success "SSH port: $SSH_PORT"
log_success "Root login disabled, password authentication disabled"
log_success "Please test your new SSH connection before closing this session:"
echo "ssh -p $SSH_PORT $USERNAME@<server-ip>"
