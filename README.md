# VPS Initial Setup Script

A secure initialization script for Linux VPS servers that automates the setup of a new user, SSH hardening, and basic security configurations.

## Features

- ✅ Creates a new sudo user
- 🔒 Hardens SSH configuration
- 🔥 Configures firewall (UFW/firewalld)
- 🛡️ Sets up fail2ban
- 📝 Comprehensive logging
- 🔄 Supports multiple Linux distributions
- 🤖 Supports both interactive and non-interactive modes

## Supported Operating Systems

- Ubuntu
- Debian
- CentOS
- Red Hat Enterprise Linux
- Fedora
- Arch Linux

## Prerequisites

- Root access to your VPS
- SSH public key ready on your local machine

## Quick Start

1. Download the script:
```bash
wget https://raw.githubusercontent.com/godfrey22/vps-startup-script/main/setup.sh
```

2. Make it executable:
```bash
chmod +x setup.sh
```

3. Run the script:
```bash
./setup.sh
```

## Usage

### Interactive Mode (Recommended)

Run the script without parameters to enter interactive mode:
```bash
./setup.sh
```

The script will prompt you for:
- Username for the new account
- Password for the new user
- SSH port (default: 2222)
- Your public SSH key

### Non-Interactive Mode

For automated deployments, use command-line arguments:
```bash
./setup.sh --username myuser --ssh-port 2222 --non-interactive
```

### Available Options

| Option | Description | Default |
|--------|-------------|---------|
| `--username` | Username for the new account | (Required in non-interactive mode) |
| `--ssh-port` | Custom SSH port | 2222 |
| `--non-interactive` | Run without prompts | false |
| `--help` | Show help message | - |

## Security Features

The script implements the following security measures:

1. **SSH Hardening**
   - Disables root login
   - Disables password authentication
   - Enables public key authentication only
   - Changes default SSH port
   - Restricts SSH access to specific user

2. **Firewall Configuration**
   - Enables UFW/firewalld
   - Opens only the specified SSH port
   - Blocks default SSH port (22)

3. **Fail2ban Setup**
   - Configures bruteforce protection
   - Custom jail rules for SSH
   - 1-hour ban time for failed attempts

## Logging

The script creates detailed logs at `/var/log/vps_setup.log` for troubleshooting.

## Safety Measures

- Creates backup of original SSH configuration
- Validates all user inputs
- Tests SSH configuration before applying
- Checks for command execution status
- Implements proper error handling

## Post-Installation

After running the script:

1. **Keep your current session open**
2. **Test new connection in a new terminal:**
```bash
ssh -p <new_port> <new_username>@your_vps_ip
```
3. **Only close the original session after confirming new connection works**

## Troubleshooting

If you encounter issues:

1. Check the log file:
```bash
cat /var/log/vps_setup.log
```

2. Original SSH config backup is available at:
```bash
/etc/ssh/sshd_config.backup
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Godfrey Gao ([@godfrey22](https://github.com/godfrey22))  
Email: zhuorui.gao@gmail.com

## Acknowledgments

- ChatGPT and Claude for code review and suggestions
- The Linux community for security best practices

## Security Note

While this script implements various security measures, always review the code and adjust configurations according to your specific security requirements.