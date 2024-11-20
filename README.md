# VPS Startup Security Script

A bash script for quick and secure setup of a new Linux VPS. This script automates essential security configurations to protect your server from common vulnerabilities.

## Features

- 🔑 SSH key authentication only (more secure than passwords)
- 🚫 Disables root SSH login
- 🔒 Disables password authentication
- 🚪 Custom SSH port
- 🛡️ Automatic firewall configuration
- ✅ Works on Ubuntu/Debian (UFW) and CentOS/RHEL (firewalld)

## Quick Start

1. Clone the repository:
```bash
git clone https://github.com/godfrey22/vps-startup-script.git
```

2. Make the script executable:
```bash
chmod +x startup.sh
```

3. Run as root:
```bash
sudo ./startup.sh
```

4. The script will prompt you for:
- New username to create
- Password for the new user
- Desired SSH port
- Your public SSH key

## Verifying the Setup

After running the script, verify your security settings:

Check listening ports:
```bash
ss -tuln
```

Verify SSH configuration:
```bash
sudo grep -E '^(PermitRootLogin|PasswordAuthentication|Port) ' /etc/ssh/sshd_config
```

Check firewall status:
```bash
# For Ubuntu/Debian
sudo ufw status

# For CentOS/RHEL
sudo firewall-cmd --list-all
```

## Important Warning

⚠️ Always test your new SSH connection in a new terminal window before closing your current session to prevent lockouts.

## Requirements

- Root access to your VPS
- A Linux VPS (Ubuntu, Debian, CentOS, or RHEL)
- Your SSH public key

## Security Features

The script implements these security measures:
- Changes SSH port to reduce automated attacks
- Enforces SSH key authentication
- Disables root login via SSH
- Disables password authentication
- Configures basic firewall rules

## Contributing

Issues and pull requests are welcome! Feel free to contribute to improve the script.

## License

MIT License