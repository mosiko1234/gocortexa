# Heimdal Deployment Scripts

This directory contains deployment and maintenance scripts for the Heimdal real-time network monitoring system.

## Installation Scripts

### `install.sh`
Main installation script for Heimdal on Debian-based systems.

**Usage:**
```bash
sudo bash scripts/install.sh
```

**What it does:**
- Checks system compatibility
- Installs system dependencies
- Creates heimdal user and directories
- Sets up Python virtual environment
- Installs Heimdal application
- Configures systemd service
- Sets up logging and permissions
- Generates unique sensor ID

### `raspberry-pi-setup.sh`
Raspberry Pi specific optimization script (run before main installation).

**Usage:**
```bash
sudo bash scripts/raspberry-pi-setup.sh
```

**Optimizations:**
- Memory and GPU settings
- Network buffer optimization
- SD card longevity improvements
- Hardware watchdog setup
- Temperature monitoring
- Performance monitoring
- USB storage configuration

## Configuration Scripts

### `update-config.sh`
Interactive configuration management tool.

**Usage:**
```bash
# Interactive mode
sudo bash scripts/update-config.sh

# Command line options
sudo bash scripts/update-config.sh --interface    # Update network interface
sudo bash scripts/update-config.sh --asgard      # Update Asgard settings
sudo bash scripts/update-config.sh --logging     # Update logging settings
sudo bash scripts/update-config.sh --validate    # Validate configuration
sudo bash scripts/update-config.sh --restart     # Restart service
```

## Service Files

### `heimdal.service`
Systemd service file for Heimdal daemon.

**Features:**
- Runs as heimdal user with minimal privileges
- Security hardening with systemd features
- Network capabilities for packet capture
- Automatic restart on failure
- Proper logging integration

## Maintenance Scripts

### `health-check.sh`
Comprehensive system health monitoring.

**Usage:**
```bash
# Full health check
sudo bash scripts/health-check.sh

# Specific checks
sudo bash scripts/health-check.sh service     # Service status
sudo bash scripts/health-check.sh config      # Configuration validation
sudo bash scripts/health-check.sh network     # Network capabilities
sudo bash scripts/health-check.sh disk        # Disk space
sudo bash scripts/health-check.sh logs        # Log files
sudo bash scripts/health-check.sh baseline    # Baseline data
sudo bash scripts/health-check.sh info        # System information
```

### `backup-restore.sh`
Backup and restore functionality for Heimdal data.

**Usage:**
```bash
# Create backup
sudo bash scripts/backup-restore.sh create

# List backups
sudo bash scripts/backup-restore.sh list

# Restore (interactive)
sudo bash scripts/backup-restore.sh restore

# Restore specific backup
sudo bash scripts/backup-restore.sh restore /path/to/backup.tar.gz

# Cleanup old backups
sudo bash scripts/backup-restore.sh cleanup 30  # Keep 30 days
```

### `uninstall.sh`
Complete removal of Heimdal system.

**Usage:**
```bash
sudo bash scripts/uninstall.sh
```

**What it removes:**
- Systemd service
- Application files
- Configuration files
- Log files (optional)
- Baseline data (optional)
- User account (optional)

## Quick Start

For new installations:

1. **Raspberry Pi users (optional optimization):**
   ```bash
   sudo bash scripts/raspberry-pi-setup.sh
   sudo reboot
   ```

2. **Install Heimdal:**
   ```bash
   sudo bash scripts/install.sh
   ```

3. **Configure:**
   ```bash
   sudo bash scripts/update-config.sh
   ```

4. **Start service:**
   ```bash
   sudo systemctl start heimdal
   ```

5. **Verify:**
   ```bash
   sudo bash scripts/health-check.sh
   ```

## Script Dependencies

All scripts require:
- Bash shell
- Root/sudo privileges (for system operations)
- Standard Linux utilities (systemctl, tar, etc.)

Individual script dependencies:
- `install.sh`: apt-get, python3, pip
- `raspberry-pi-setup.sh`: Raspberry Pi hardware
- `backup-restore.sh`: tar, gzip
- `health-check.sh`: systemctl, journalctl

## Security Notes

- Scripts require root privileges for system operations
- Network capabilities are set using Linux capabilities (not setuid)
- Service runs with restricted permissions
- Configuration files have appropriate ownership and permissions
- Sensitive data (API keys) should be protected

## Troubleshooting

If scripts fail:

1. **Check permissions:**
   ```bash
   ls -la scripts/
   chmod +x scripts/*.sh
   ```

2. **Check system compatibility:**
   ```bash
   # Debian/Ubuntu required
   which apt-get
   
   # Python 3.8+ required
   python3 --version
   ```

3. **Check available space:**
   ```bash
   df -h /opt /etc /var
   ```

4. **Check logs:**
   ```bash
   journalctl -xe
   ```

## Customization

Scripts can be customized by modifying variables at the top of each file:

```bash
# Example customization in install.sh
HEIMDAL_USER="custom-user"
HEIMDAL_HOME="/custom/path"
HEIMDAL_CONFIG_DIR="/custom/config"
```

## Support

For issues with deployment scripts:
1. Check script output for error messages
2. Verify system requirements
3. Check available disk space and permissions
4. Review logs for detailed error information
5. Contact support with script output and system information