#!/bin/bash

# Heimdal Real-time Network Monitoring Installation Script
# For Raspberry Pi and Debian-based systems

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
HEIMDAL_USER="heimdal"
HEIMDAL_HOME="/opt/heimdal"
HEIMDAL_CONFIG_DIR="/etc/heimdal"
HEIMDAL_LOG_DIR="/var/log/heimdal"
HEIMDAL_DATA_DIR="/var/lib/heimdal"
PYTHON_VERSION="3.9"

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
PROJECT_ROOT=$( dirname "$SCRIPT_DIR" )

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

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_system() {
    log_info "Checking system compatibility..."
    
    # Check if running on supported system
    if ! command -v apt-get &> /dev/null; then
        log_error "This installer requires a Debian-based system (apt-get not found)"
        exit 1
    fi
    
    # Check Python version
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is required but not installed"
        exit 1
    fi
    
    PYTHON_VER=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    log_info "Found Python $PYTHON_VER"
    
    # Check if Raspberry Pi
    if grep -q "Raspberry Pi" /proc/cpuinfo 2>/dev/null; then
        log_info "Detected Raspberry Pi system"
        export IS_RASPBERRY_PI=1
    else
        log_info "Detected generic Linux system"
        export IS_RASPBERRY_PI=0
    fi
}

install_system_dependencies() {
    log_info "Installing system dependencies..."
    
    # Update package list
    apt-get update
    
    # Install required system packages
    apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        build-essential \
        libpcap-dev \
        tcpdump \
        net-tools \
        curl \
        wget \
        git \
        systemd \
        logrotate
    
    # Install additional packages for Raspberry Pi
    if [[ $IS_RASPBERRY_PI -eq 1 ]]; then
        apt-get install -y \
            raspi-utils-dt \
            raspi-utils-core \
            rpi-update
    fi
    
    log_success "System dependencies installed"
}

create_user() {
    log_info "Creating heimdal user..."
    
    if ! id "$HEIMDAL_USER" &>/dev/null; then
        useradd --system --home-dir "$HEIMDAL_HOME" --create-home --shell /bin/bash "$HEIMDAL_USER"
        log_success "Created user: $HEIMDAL_USER"
    else
        log_info "User $HEIMDAL_USER already exists"
    fi
    
    # Add user to necessary groups for network monitoring
    usermod -a -G netdev "$HEIMDAL_USER" 2>/dev/null || true
    usermod -a -G adm "$HEIMDAL_USER" 2>/dev/null || true
}

create_directories() {
    log_info "Creating directory structure..."

    # Create directories
    mkdir -p "$HEIMDAL_HOME"
    mkdir -p "$HEIMDAL_CONFIG_DIR"
    mkdir -p "$HEIMDAL_LOG_DIR"
    mkdir -p "$HEIMDAL_DATA_DIR"
    mkdir -p "$HEIMDAL_DATA_DIR/baselines"
    mkdir -p "$HEIMDAL_DATA_DIR/cache"

    log_info "Copying application files to $HEIMDAL_HOME..."
    # Copy all project files from the source to the application home
    cp -a "$PROJECT_ROOT/." "$HEIMDAL_HOME/"

    # Set ownership
    chown -R "$HEIMDAL_USER:$HEIMDAL_USER" "$HEIMDAL_HOME"
    chown -R "$HEIMDAL_USER:$HEIMDAL_USER" "$HEIMDAL_LOG_DIR"
    chown -R "$HEIMDAL_USER:$HEIMDAL_USER" "$HEIMDAL_DATA_DIR"

    # Set permissions
    chmod 755 "$HEIMDAL_HOME"
    chmod 755 "$HEIMDAL_CONFIG_DIR"
    chmod 755 "$HEIMDAL_LOG_DIR"
    chmod 755 "$HEIMDAL_DATA_DIR"

    log_success "Directory structure and files created"
}

install_heimdal() {
    log_info "Installing Heimdal application..."

    # Create virtual environment
    sudo -u "$HEIMDAL_USER" python3 -m venv "$HEIMDAL_HOME/venv"

    # Activate virtual environment and install
    # We MUST change directory (cd) to $HEIMDAL_HOME before running pip
    sudo -u "$HEIMDAL_USER" bash -c "
        cd '$HEIMDAL_HOME' &&
        source '$HEIMDAL_HOME/venv/bin/activate' &&
        pip install --upgrade pip setuptools wheel &&
        pip install -e .
    "

    log_success "Heimdal application installed"
}

setup_configuration() {
    log_info "Setting up configuration files..."
    
    # Copy configuration templates
    cp config/heimdal.yaml "$HEIMDAL_CONFIG_DIR/heimdal.yaml"
    cp config/heimdal.json "$HEIMDAL_CONFIG_DIR/heimdal.json"
    
    # Set ownership
    chown root:root "$HEIMDAL_CONFIG_DIR/heimdal.yaml"
    chown root:root "$HEIMDAL_CONFIG_DIR/heimdal.json"
    
    # Set permissions (readable by heimdal user)
    chmod 644 "$HEIMDAL_CONFIG_DIR/heimdal.yaml"
    chmod 644 "$HEIMDAL_CONFIG_DIR/heimdal.json"
    
    # Update configuration for system paths
    sed -i "s|/var/log/heimdal/heimdal.log|$HEIMDAL_LOG_DIR/heimdal.log|g" "$HEIMDAL_CONFIG_DIR/heimdal.yaml"
    
    log_success "Configuration files installed"
}

setup_systemd_service() {
    log_info "Installing systemd service..."
    
    # Copy service file
    cp scripts/heimdal.service /etc/systemd/system/
    
    # Update service file with correct paths
    sed -i "s|/opt/heimdal|$HEIMDAL_HOME|g" /etc/systemd/system/heimdal.service
    sed -i "s|/etc/heimdal|$HEIMDAL_CONFIG_DIR|g" /etc/systemd/system/heimdal.service
    
    # Reload systemd and enable service
    systemctl daemon-reload
    systemctl enable heimdal.service
    
    log_success "Systemd service installed and enabled"
}

setup_logrotate() {
    log_info "Setting up log rotation..."
    
    cat > /etc/logrotate.d/heimdal << EOF
$HEIMDAL_LOG_DIR/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 $HEIMDAL_USER $HEIMDAL_USER
    postrotate
        systemctl reload heimdal.service > /dev/null 2>&1 || true
    endscript
}
EOF
    
    log_success "Log rotation configured"
}

setup_network_permissions() {
    log_info "Setting up network monitoring permissions..."
    
    # Allow heimdal user to capture packets without root
    # This uses capabilities instead of running as root
    PYTHON_EXEC_PATH=$(readlink -f "$HEIMDAL_HOME/venv/bin/python3")
    setcap cap_net_raw,cap_net_admin=eip "$PYTHON_EXEC_PATH"
    
    # Alternative: Add to sudoers for specific commands (commented out)
    # echo "$HEIMDAL_USER ALL=(ALL) NOPASSWD: /usr/sbin/tcpdump" >> /etc/sudoers.d/heimdal
    
    log_success "Network monitoring permissions configured"
}

generate_sensor_id() {
    log_info "Generating unique sensor ID..."
    
    # Generate a unique sensor ID based on system information
    SENSOR_ID=$(cat /proc/cpuinfo /etc/machine-id 2>/dev/null | sha256sum | cut -d' ' -f1 | head -c 16)
    
    # Update configuration with sensor ID
    sed -i "s/sensor_id: \"\"/sensor_id: \"$SENSOR_ID\"/" "$HEIMDAL_CONFIG_DIR/heimdal.yaml"
    
    log_success "Sensor ID generated: $SENSOR_ID"
}

print_post_install_info() {
    log_success "Heimdal installation completed successfully!"
    echo
    echo "Next steps:"
    echo "1. Edit the configuration file: $HEIMDAL_CONFIG_DIR/heimdal.yaml"
    echo "2. Set your Asgard API key in the configuration or environment variable"
    echo "3. Configure the network interface to monitor"
    echo "4. Start the service: sudo systemctl start heimdal"
    echo "5. Check service status: sudo systemctl status heimdal"
    echo "6. View logs: sudo journalctl -u heimdal -f"
    echo
    echo "Configuration file: $HEIMDAL_CONFIG_DIR/heimdal.yaml"
    echo "Log files: $HEIMDAL_LOG_DIR/"
    echo "Data directory: $HEIMDAL_DATA_DIR/"
    echo
    echo "For more information, see the documentation at:"
    echo "https://docs.cortexa.ai/heimdal"
}

# Main installation process
main() {
    log_info "Starting Heimdal installation..."
    
    check_root
    check_system
    install_system_dependencies
    create_user
    create_directories
    install_heimdal
    setup_configuration
    setup_systemd_service
    setup_logrotate
    setup_network_permissions
    generate_sensor_id
    print_post_install_info
}

# Run main function
main "$@"