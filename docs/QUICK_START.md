# Heimdal Quick Start Guide

Get Heimdal up and running in minutes with this quick start guide.

## Prerequisites

- Raspberry Pi 4+ with Raspberry Pi OS
- Root/sudo access
- Internet connection
- Network interface for monitoring

## 1. Installation

Run the automated installation script:

```bash
# Clone the repository (or download the scripts)
git clone https://github.com/cortexa/heimdal.git
cd heimdal

# Run installation script
sudo bash scripts/install.sh
```

The installer will:
- Install system dependencies
- Create heimdal user and directories
- Set up the application and service
- Configure permissions

## 2. Basic Configuration

Edit the configuration file:

```bash
sudo nano /etc/heimdal/heimdal.yaml
```

**Minimum required changes:**

1. **Set network interface:**
   ```yaml
   capture:
     interface: "eth0"  # Change to your interface
   ```

2. **Set Asgard API key:**
   ```yaml
   asgard:
     api_key: "your-api-key-here"
   ```

3. **Set sensor location:**
   ```yaml
   system:
     location: "Home Network"  # Describe your location
   ```

**Find your network interface:**
```bash
ip link show
```

## 3. Start the Service

```bash
# Start Heimdal
sudo systemctl start heimdal

# Enable auto-start on boot
sudo systemctl enable heimdal

# Check status
sudo systemctl status heimdal
```

## 4. Verify Operation

Check that everything is working:

```bash
# Run health check
sudo bash scripts/health-check.sh

# View real-time logs
sudo journalctl -u heimdal -f

# Check application logs
sudo tail -f /var/log/heimdal/heimdal.log
```

## 5. Monitor Activity

**View service status:**
```bash
sudo systemctl status heimdal
```

**Check logs for activity:**
```bash
# Recent service logs
sudo journalctl -u heimdal -n 20

# Application logs
sudo tail -20 /var/log/heimdal/heimdal.log
```

**Look for these log messages:**
- `Starting packet capture on interface eth0`
- `Device discovered: [device_info]`
- `Baseline updated for device: [device_id]`
- `Connected to Asgard API`

## Common First-Time Issues

### Service Won't Start

**Check configuration:**
```bash
sudo bash scripts/update-config.sh --validate
```

**Check network interface:**
```bash
ip link show
sudo bash scripts/update-config.sh --interface
```

### Permission Errors

**Re-apply network capabilities:**
```bash
sudo setcap cap_net_raw,cap_net_admin=eip /opt/heimdal/venv/bin/python3
```

### No Network Traffic Detected

1. Verify interface is correct
2. Check if interface is up: `ip link show eth0`
3. Ensure network has traffic to monitor
4. Check for firewall blocking

## Next Steps

Once Heimdal is running:

1. **Monitor for 24-48 hours** to establish baselines
2. **Review logs** for any anomalies or errors
3. **Adjust thresholds** if needed in configuration
4. **Set up automated backups**
5. **Configure monitoring alerts**

## Configuration Quick Reference

**Essential settings in `/etc/heimdal/heimdal.yaml`:**

```yaml
# Network monitoring
capture:
  interface: "eth0"                    # Your network interface

# Asgard connection
asgard:
  api_key: "your-api-key"             # Your API key
  api_endpoint: "https://api.asgard.cortexa.ai"

# Logging
logging:
  level: "INFO"                       # DEBUG for troubleshooting
  file_path: "/var/log/heimdal/heimdal.log"

# System info
system:
  location: "Home Network"            # Sensor description
  sensor_id: ""                       # Auto-generated if empty
```

## Useful Commands

```bash
# Service management
sudo systemctl start heimdal          # Start service
sudo systemctl stop heimdal           # Stop service
sudo systemctl restart heimdal        # Restart service
sudo systemctl status heimdal         # Check status

# Logs
sudo journalctl -u heimdal -f         # Follow service logs
sudo tail -f /var/log/heimdal/heimdal.log  # Follow app logs

# Configuration
sudo bash scripts/update-config.sh    # Interactive config update
sudo bash scripts/health-check.sh     # System health check

# Backup
sudo bash scripts/backup-restore.sh create  # Create backup
sudo bash scripts/backup-restore.sh list    # List backups
```

## Getting Help

If you encounter issues:

1. **Check logs:** `sudo journalctl -u heimdal -n 20`
2. **Run health check:** `sudo bash scripts/health-check.sh`
3. **Validate config:** `sudo bash scripts/update-config.sh --validate`
4. **Check documentation:** `docs/DEPLOYMENT.md`

For support: support@cortexa.ai