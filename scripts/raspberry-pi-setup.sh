#!/bin/bash

# Raspberry Pi Specific Setup Script for Heimdal
# Optimizes Raspberry Pi for network monitoring

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_raspberry_pi() {
    log_info "Checking if running on Raspberry Pi..."
    
    if ! grep -q "Raspberry Pi" /proc/cpuinfo 2>/dev/null; then
        log_error "This script is designed for Raspberry Pi systems"
        exit 1
    fi
    
    # Get Pi model
    local model=$(grep "Model" /proc/cpuinfo | cut -d: -f2 | sed 's/^ *//')
    log_success "Detected: $model"
    
    # Check if Pi 4 or newer (recommended)
    if echo "$model" | grep -qE "(Pi 4|Pi 5|Pi 400)"; then
        log_success "Raspberry Pi model is suitable for Heimdal"
    else
        log_warning "Older Raspberry Pi detected. Pi 4+ recommended for best performance"
    fi
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

update_system() {
    log_info "Updating system packages..."
    
    apt update
    apt upgrade -y
    
    log_success "System updated"
}

optimize_memory() {
    log_info "Optimizing memory settings..."
    
    # Increase GPU memory split for headless operation
    if ! grep -q "gpu_mem=" /boot/config.txt; then
        echo "gpu_mem=16" >> /boot/config.txt
        log_info "Set GPU memory to 16MB (headless optimization)"
    fi
    
    # Disable swap if not needed (optional)
    read -p "Disable swap to improve SD card longevity? (yes/no): " -r
    if [[ $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        dphys-swapfile swapoff
        dphys-swapfile uninstall
        update-rc.d dphys-swapfile remove
        log_success "Swap disabled"
    fi
    
    log_success "Memory optimization completed"
}

optimize_network() {
    log_info "Optimizing network settings..."
    
    # Increase network buffer sizes
    cat >> /etc/sysctl.conf << EOF

# Heimdal network monitoring optimizations
net.core.rmem_max = 134217728
net.core.rmem_default = 65536
net.core.netdev_max_backlog = 5000
net.core.netdev_budget = 600
EOF
    
    # Apply settings
    sysctl -p
    
    log_success "Network optimization completed"
}

setup_usb_storage() {
    log_info "Checking for USB storage..."
    
    # List available USB storage devices
    local usb_devices=$(lsblk -o NAME,SIZE,TYPE,MOUNTPOINT | grep -E "sd[a-z]" || true)
    
    if [[ -n "$usb_devices" ]]; then
        log_info "USB storage devices found:"
        echo "$usb_devices"
        echo
        
        read -p "Set up USB storage for Heimdal data and logs? (yes/no): " -r
        if [[ $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
            setup_usb_mount
        fi
    else
        log_info "No USB storage devices detected"
    fi
}

setup_usb_mount() {
    log_info "Setting up USB storage mount..."
    
    # List available partitions
    local partitions=$(lsblk -o NAME,SIZE,FSTYPE,MOUNTPOINT | grep -E "sd[a-z][0-9]" | grep -v "/" || true)
    
    if [[ -z "$partitions" ]]; then
        log_warning "No unmounted USB partitions found"
        return
    fi
    
    echo "Available partitions:"
    echo "$partitions"
    echo
    
    read -p "Enter partition to use (e.g., sda1): " partition
    
    if [[ ! -b "/dev/$partition" ]]; then
        log_error "Partition /dev/$partition not found"
        return
    fi
    
    # Create mount point
    local mount_point="/mnt/heimdal-storage"
    mkdir -p "$mount_point"
    
    # Get filesystem type
    local fstype=$(lsblk -o FSTYPE -n "/dev/$partition")
    
    # Mount the partition
    mount "/dev/$partition" "$mount_point"
    
    # Get UUID for fstab
    local uuid=$(blkid -s UUID -o value "/dev/$partition")
    
    # Add to fstab for persistent mounting
    echo "UUID=$uuid $mount_point $fstype defaults,noatime 0 2" >> /etc/fstab
    
    # Create directories for Heimdal
    mkdir -p "$mount_point/heimdal-logs"
    mkdir -p "$mount_point/heimdal-data"
    mkdir -p "$mount_point/heimdal-backups"
    
    # Set ownership
    chown -R heimdal:heimdal "$mount_point/heimdal-logs" "$mount_point/heimdal-data"
    
    log_success "USB storage mounted at $mount_point"
    log_info "Update Heimdal configuration to use:"
    log_info "  Log path: $mount_point/heimdal-logs"
    log_info "  Data path: $mount_point/heimdal-data"
}

optimize_sd_card() {
    log_info "Optimizing SD card settings..."
    
    # Reduce writes to SD card
    cat >> /etc/fstab << EOF

# Heimdal SD card optimizations
tmpfs /tmp tmpfs defaults,noatime,nosuid,size=100m 0 0
tmpfs /var/tmp tmpfs defaults,noatime,nosuid,size=30m 0 0
tmpfs /var/log tmpfs defaults,noatime,nosuid,mode=0755,size=100m 0 0
EOF
    
    # Note: This will make logs non-persistent across reboots
    log_warning "Logs will be stored in RAM (non-persistent across reboots)"
    log_info "Consider using USB storage for persistent logs"
    
    log_success "SD card optimization completed"
}

setup_watchdog() {
    log_info "Setting up hardware watchdog..."
    
    # Install watchdog
    apt install -y watchdog
    
    # Configure watchdog
    cat > /etc/watchdog.conf << EOF
# Heimdal watchdog configuration
watchdog-device = /dev/watchdog
watchdog-timeout = 15
realtime = yes
priority = 1

# Test conditions
max-load-1 = 24
max-load-5 = 18
max-load-15 = 12
min-memory = 1
EOF
    
    # Enable hardware watchdog in boot config
    if ! grep -q "dtparam=watchdog=on" /boot/config.txt; then
        echo "dtparam=watchdog=on" >> /boot/config.txt
        log_info "Hardware watchdog enabled in boot config"
    fi
    
    # Enable and start watchdog service
    systemctl enable watchdog
    
    log_success "Hardware watchdog configured"
    log_warning "Watchdog will start after reboot"
}

setup_temperature_monitoring() {
    log_info "Setting up temperature monitoring..."
    
    # Create temperature monitoring script
    cat > /usr/local/bin/pi-temp-monitor.sh << 'EOF'
#!/bin/bash

# Raspberry Pi temperature monitoring for Heimdal

TEMP_THRESHOLD=70  # Celsius
LOG_FILE="/var/log/pi-temperature.log"

# Get current temperature
TEMP=$(vcgencmd measure_temp | cut -d= -f2 | cut -d\' -f1)

# Log temperature
echo "$(date): CPU Temperature: ${TEMP}°C" >> "$LOG_FILE"

# Check if temperature is too high
if (( $(echo "$TEMP > $TEMP_THRESHOLD" | bc -l) )); then
    echo "$(date): WARNING: High temperature detected: ${TEMP}°C" >> "$LOG_FILE"
    logger "Raspberry Pi temperature warning: ${TEMP}°C"
    
    # Optional: throttle Heimdal service if temperature is critical
    if (( $(echo "$TEMP > 80" | bc -l) )); then
        echo "$(date): CRITICAL: Temperature critical, consider throttling" >> "$LOG_FILE"
    fi
fi
EOF
    
    chmod +x /usr/local/bin/pi-temp-monitor.sh
    
    # Add to crontab for regular monitoring
    (crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/pi-temp-monitor.sh") | crontab -
    
    log_success "Temperature monitoring configured"
}

configure_heimdal_for_pi() {
    log_info "Configuring Heimdal for Raspberry Pi..."
    
    local config_file="/etc/heimdal/heimdal.yaml"
    
    if [[ -f "$config_file" ]]; then
        # Create Pi-optimized configuration
        cp "$config_file" "$config_file.backup"
        
        # Adjust settings for Pi performance
        sed -i 's/max_packet_buffer_size: 10000/max_packet_buffer_size: 5000/' "$config_file"
        sed -i 's/processing_batch_size: 100/processing_batch_size: 50/' "$config_file"
        
        log_success "Heimdal configuration optimized for Raspberry Pi"
    else
        log_warning "Heimdal configuration not found. Run main installation first."
    fi
}

setup_performance_monitoring() {
    log_info "Setting up performance monitoring..."
    
    # Create performance monitoring script
    cat > /usr/local/bin/heimdal-performance.sh << 'EOF'
#!/bin/bash

# Heimdal performance monitoring script

LOG_FILE="/var/log/heimdal-performance.log"

# Get system stats
CPU_TEMP=$(vcgencmd measure_temp | cut -d= -f2)
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d% -f1)
MEM_USAGE=$(free | grep Mem | awk '{printf("%.1f", $3/$2 * 100.0)}')
DISK_USAGE=$(df -h / | awk 'NR==2 {print $5}')

# Get Heimdal process stats
HEIMDAL_PID=$(pgrep -f "heimdal.main")
if [[ -n "$HEIMDAL_PID" ]]; then
    HEIMDAL_MEM=$(ps -p "$HEIMDAL_PID" -o rss= | tr -d ' ')
    HEIMDAL_MEM_MB=$((HEIMDAL_MEM / 1024))
    HEIMDAL_CPU=$(ps -p "$HEIMDAL_PID" -o %cpu= | tr -d ' ')
else
    HEIMDAL_MEM_MB="N/A"
    HEIMDAL_CPU="N/A"
fi

# Log performance data
echo "$(date): Temp=$CPU_TEMP, CPU=${CPU_USAGE}%, Mem=${MEM_USAGE}%, Disk=$DISK_USAGE, Heimdal: ${HEIMDAL_MEM_MB}MB, ${HEIMDAL_CPU}%" >> "$LOG_FILE"

# Rotate log if it gets too large
if [[ -f "$LOG_FILE" ]] && [[ $(stat -c%s "$LOG_FILE") -gt 1048576 ]]; then
    mv "$LOG_FILE" "${LOG_FILE}.old"
fi
EOF
    
    chmod +x /usr/local/bin/heimdal-performance.sh
    
    # Add to crontab for regular monitoring
    (crontab -l 2>/dev/null; echo "*/10 * * * * /usr/local/bin/heimdal-performance.sh") | crontab -
    
    log_success "Performance monitoring configured"
}

print_post_setup_info() {
    log_success "Raspberry Pi optimization completed!"
    echo
    echo "Optimizations applied:"
    echo "- System packages updated"
    echo "- Memory settings optimized"
    echo "- Network buffers increased"
    echo "- Hardware watchdog configured"
    echo "- Temperature monitoring enabled"
    echo "- Performance monitoring setup"
    echo
    echo "Next steps:"
    echo "1. Reboot the system: sudo reboot"
    echo "2. Run Heimdal installation: sudo bash scripts/install.sh"
    echo "3. Configure Heimdal: sudo bash scripts/update-config.sh"
    echo "4. Monitor performance: tail -f /var/log/heimdal-performance.log"
    echo
    echo "Monitoring commands:"
    echo "- Temperature: vcgencmd measure_temp"
    echo "- Performance: tail -f /var/log/heimdal-performance.log"
    echo "- System load: htop"
    echo
    log_warning "A reboot is recommended to apply all optimizations"
}

# Main setup process
main() {
    log_info "Starting Raspberry Pi optimization for Heimdal..."
    
    check_root
    check_raspberry_pi
    update_system
    optimize_memory
    optimize_network
    setup_usb_storage
    optimize_sd_card
    setup_watchdog
    setup_temperature_monitoring
    configure_heimdal_for_pi
    setup_performance_monitoring
    print_post_setup_info
}

# Run main function
main "$@"