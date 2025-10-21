# Heimdal Deployment Guide

This guide covers the complete deployment process for Heimdal real-time network monitoring system on Raspberry Pi and other Linux systems.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Service Management](#service-management)
5. [Monitoring and Maintenance](#monitoring-and-maintenance)
6. [Troubleshooting](#troubleshooting)
7. [Backup and Recovery](#backup-and-recovery)
8. [Uninstallation](#uninstallation)

## Prerequisites

### Hardware Requirements

**Minimum Requirements:**
- Raspberry Pi 4 with 4GB RAM
- 32GB SD card (Class 10 or better)
- Ethernet connection for network monitoring

**Recommended Requirements:**
- Raspberry Pi 5 with 8GB RAM
- 64GB SD card (Class 10 or better)
- Gigabit Ethernet connection
- External USB storage for logs and data (optional)

### Software Requirements

- Raspberry Pi OS (Debian-based) or Ubuntu 20.04+
- Python 3.8 or higher
- Root/sudo access for installation
- Internet connection for package installation

### Network Requirements

- Access to monitor network traffic (typically requires ARP spoofing position)
- Outbound HTTPS access to Asgard API endpoints
- Network interface with promiscuous mode support

## Installation

### Automated Installation

The easiest way to install Heimdal is using the automated installation script:

```bash
# Download and run the installation script
sudo bash scripts/install.sh
```

The installation script will:
1. Check system compatibility
2. Install required system packages
3. Create heimdal user and directories
4. Set up Python virtual environment
5. Install Heimdal application
6. Configure systemd service
7. Set up logging and permissions

### Manual Installation

If you prefer manual installation or need to customize the process:

#### 1. Install System Dependencies

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv python3-dev \
    build-essential libpcap-dev tcpdump net-tools curl wget git \
    systemd logrotate
```

#### 2. Create User and Directories

```bash
sudo useradd --system --home-dir /opt/heimdal --create-home --shell /bin/bash heimdal
sudo mkdir -p /etc/heimdal /var/log/heimdal /var/lib/heimdal
sudo chown -R heimdal:heimdal /opt/heimdal /var/log/heimdal /var/lib/heimdal
```

#### 3. Install Heimdal Application

```bash
cd /path/to/heimdal/source
sudo -u heimdal python3 -m venv /opt/heimdal/venv
sudo -u heimdal /opt/heimdal/venv/bin/pip install -e .
```

#### 4. Set Up Configuration

```bash
sudo cp config/heimdal.yaml /etc/heimdal/
sudo chown root:root /etc/heimdal/heimdal.yaml
sudo chmod 644 /etc/heimdal/heimdal.yaml
```

#### 5. Install Systemd Service

```bash
sudo cp scripts/heimdal.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable heimdal.service
```

#### 6. Set Network Permissions

```bash
sudo setcap cap_net_raw,cap_net_admin=eip /opt/heimdal/venv/bin/python3
```

## Configuration

### Basic Configuration

Edit the main configuration file:

```bash
sudo nano /etc/heimdal/heimdal.yaml
```

Key settings to configure:

#### Network Interface
```yaml
capture:
  interface: "eth0"  # Change to your network interface
```

Find available interfaces:
```bash
ip link show
```

#### Asgard API Settings
```yaml
asgard:
  api_endpoint: "https://api.asgard.cortexa.ai"
  api_key: "your-api-key-here"
```

#### Logging Configuration
```yaml
logging:
  level: "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
  file_path: "/var/log/heimdal/heimdal.log"
```

#### Sensor Information
```yaml
system:
  sensor_id: ""  # Auto-generated if empty
  location: "Home Network"  # Describe sensor location
```

### Advanced Configuration

#### Anomaly Detection Thresholds
```yaml
anomaly_detection:
  thresholds:
    new_destination: 0.7      # Sensitivity for new connections
    unusual_volume: 0.8       # Traffic volume anomaly threshold
    protocol_violation: 0.9   # Protocol anomaly threshold
    timing_anomaly: 0.6       # Timing pattern threshold
    geolocation_violation: 0.85  # Geographic anomaly threshold
```

#### Baseline Management
```yaml
baseline:
  rolling_window_days: 7      # Days of behavior to maintain
  max_baseline_age_days: 30   # Maximum baseline age
  confidence_threshold: 0.5   # Minimum confidence for updates
```

### Environment Variables

You can also configure Heimdal using environment variables:

```bash
export HEIMDAL_CONFIG_PATH="/etc/heimdal/heimdal.yaml"
export HEIMDAL_ASGARD_API_KEY="your-api-key"
export HEIMDAL_LOG_LEVEL="INFO"
```

### Configuration Validation

Use the configuration update script to validate and modify settings:

```bash
# Interactive configuration
sudo bash scripts/update-config.sh

# Validate configuration only
sudo bash scripts/update-config.sh --validate
```

## Service Management

### Starting and Stopping

```bash
# Start the service
sudo systemctl start heimdal

# Stop the service
sudo systemctl stop heimdal

# Restart the service
sudo systemctl restart heimdal

# Check service status
sudo systemctl status heimdal
```

### Enable/Disable Auto-start

```bash
# Enable auto-start on boot
sudo systemctl enable heimdal

# Disable auto-start
sudo systemctl disable heimdal
```

### Viewing Logs

```bash
# View real-time logs
sudo journalctl -u heimdal -f

# View recent logs
sudo journalctl -u heimdal -n 50

# View logs from specific time
sudo journalctl -u heimdal --since "2024-01-01 00:00:00"
```

### Log Files

- **Service logs:** `journalctl -u heimdal`
- **Application logs:** `/var/log/heimdal/heimdal.log`
- **System logs:** `/var/log/syslog`

## Monitoring and Maintenance

### Health Checks

Use the health check script to monitor system status:

```bash
# Full health check
sudo bash scripts/health-check.sh

# Check specific components
sudo bash scripts/health-check.sh service
sudo bash scripts/health-check.sh config
sudo bash scripts/health-check.sh network
```

### Performance Monitoring

Monitor system performance:

```bash
# Check memory usage
ps aux | grep heimdal

# Check disk usage
df -h /var/log/heimdal /var/lib/heimdal

# Check network interface statistics
cat /proc/net/dev
```

### Log Rotation

Logs are automatically rotated using logrotate. Configuration is in `/etc/logrotate.d/heimdal`.

Manual log rotation:
```bash
sudo logrotate -f /etc/logrotate.d/heimdal
```

### Updates

To update Heimdal:

1. Stop the service:
   ```bash
   sudo systemctl stop heimdal
   ```

2. Update the code:
   ```bash
   cd /path/to/heimdal/source
   git pull
   sudo -u heimdal /opt/heimdal/venv/bin/pip install -e .
   ```

3. Start the service:
   ```bash
   sudo systemctl start heimdal
   ```

## Troubleshooting

### Common Issues

#### Service Won't Start

1. Check service status:
   ```bash
   sudo systemctl status heimdal
   ```

2. Check logs:
   ```bash
   sudo journalctl -u heimdal -n 20
   ```

3. Validate configuration:
   ```bash
   sudo bash scripts/update-config.sh --validate
   ```

#### Permission Denied Errors

1. Check network capabilities:
   ```bash
   getcap /opt/heimdal/venv/bin/python3
   ```

2. Re-apply capabilities:
   ```bash
   sudo setcap cap_net_raw,cap_net_admin=eip /opt/heimdal/venv/bin/python3
   ```

#### High Memory Usage

1. Check current usage:
   ```bash
   ps aux | grep heimdal
   ```

2. Adjust configuration:
   ```yaml
   capture:
     max_packet_buffer_size: 5000  # Reduce buffer size
   ```

#### Network Interface Issues

1. List available interfaces:
   ```bash
   ip link show
   ```

2. Check interface status:
   ```bash
   ip link show eth0
   ```

3. Update configuration:
   ```bash
   sudo bash scripts/update-config.sh --interface
   ```

### Debug Mode

Enable debug logging for troubleshooting:

```bash
# Edit configuration
sudo nano /etc/heimdal/heimdal.yaml

# Change log level
logging:
  level: "DEBUG"

# Restart service
sudo systemctl restart heimdal
```

### Getting Help

1. Check the logs first
2. Run health check script
3. Verify configuration
4. Check system resources
5. Review network connectivity

## Backup and Recovery

### Creating Backups

```bash
# Create full backup
sudo bash scripts/backup-restore.sh create

# List existing backups
sudo bash scripts/backup-restore.sh list
```

### Restoring from Backup

```bash
# Interactive restore
sudo bash scripts/backup-restore.sh restore

# Restore specific backup
sudo bash scripts/backup-restore.sh restore /opt/heimdal-backups/backup.tar.gz
```

### Automated Backups

Set up automated backups using cron:

```bash
# Edit crontab
sudo crontab -e

# Add daily backup at 2 AM
0 2 * * * /path/to/scripts/backup-restore.sh create >/dev/null 2>&1

# Add weekly cleanup (keep 30 days)
0 3 * * 0 /path/to/scripts/backup-restore.sh cleanup 30 >/dev/null 2>&1
```

## Uninstallation

To completely remove Heimdal:

```bash
sudo bash scripts/uninstall.sh
```

This will:
1. Stop and disable the service
2. Remove application files
3. Remove configuration files
4. Optionally remove logs and data
5. Optionally remove user account

## Security Considerations

### Network Security

- Heimdal requires network monitoring capabilities
- Uses capabilities instead of running as root
- Encrypts all communication with Asgard
- Anonymizes data before transmission

### File Permissions

- Configuration files: readable by heimdal user
- Log files: writable by heimdal user
- Data files: owned by heimdal user
- Service runs with restricted permissions

### API Security

- Store API keys securely
- Use environment variables for sensitive data
- Rotate API keys regularly
- Monitor API usage

## Performance Tuning

### Raspberry Pi Optimization

1. **SD Card Performance:**
   ```bash
   # Use high-quality SD card (Class 10+)
   # Consider USB 3.0 storage for data
   ```

2. **Memory Management:**
   ```yaml
   capture:
     max_packet_buffer_size: 5000  # Reduce for Pi 4
   ```

3. **CPU Usage:**
   ```yaml
   analysis:
     processing_batch_size: 50     # Reduce batch size
   ```

### Network Optimization

1. **Interface Selection:**
   - Use wired Ethernet when possible
   - Avoid WiFi for packet capture

2. **Capture Filtering:**
   ```yaml
   capture:
     filter_expression: "not port 22"  # Exclude SSH traffic
   ```

## Support and Documentation

- **Documentation:** https://docs.cortexa.ai/heimdal
- **Issues:** https://github.com/cortexa/heimdal/issues
- **Support:** support@cortexa.ai

For additional help, include the following information:
- System information (`scripts/health-check.sh info`)
- Service logs (`journalctl -u heimdal -n 50`)
- Configuration file (with API keys removed)
- Error messages and symptoms