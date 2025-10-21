#!/bin/bash

# Heimdal Real-time Network Monitoring Uninstall Script

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

confirm_uninstall() {
    echo -e "${YELLOW}WARNING: This will completely remove Heimdal and all its data!${NC}"
    echo "The following will be removed:"
    echo "  - Heimdal application and virtual environment"
    echo "  - Configuration files"
    echo "  - Log files"
    echo "  - Baseline data and cache"
    echo "  - System service"
    echo "  - User account (optional)"
    echo
    read -p "Are you sure you want to continue? (yes/no): " -r
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        log_info "Uninstall cancelled"
        exit 0
    fi
}

stop_and_disable_service() {
    log_info "Stopping and disabling Heimdal service..."
    
    if systemctl is-active --quiet heimdal.service; then
        systemctl stop heimdal.service
        log_info "Service stopped"
    fi
    
    if systemctl is-enabled --quiet heimdal.service; then
        systemctl disable heimdal.service
        log_info "Service disabled"
    fi
    
    # Remove service file
    if [[ -f /etc/systemd/system/heimdal.service ]]; then
        rm -f /etc/systemd/system/heimdal.service
        systemctl daemon-reload
        log_success "Service file removed"
    fi
}

remove_logrotate() {
    log_info "Removing log rotation configuration..."
    
    if [[ -f /etc/logrotate.d/heimdal ]]; then
        rm -f /etc/logrotate.d/heimdal
        log_success "Log rotation configuration removed"
    fi
}

remove_directories() {
    log_info "Removing Heimdal directories..."
    
    # Remove application directory
    if [[ -d "$HEIMDAL_HOME" ]]; then
        rm -rf "$HEIMDAL_HOME"
        log_success "Application directory removed: $HEIMDAL_HOME"
    fi
    
    # Remove configuration directory
    if [[ -d "$HEIMDAL_CONFIG_DIR" ]]; then
        rm -rf "$HEIMDAL_CONFIG_DIR"
        log_success "Configuration directory removed: $HEIMDAL_CONFIG_DIR"
    fi
    
    # Ask about data and logs
    read -p "Remove log files? (yes/no): " -r
    if [[ $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        if [[ -d "$HEIMDAL_LOG_DIR" ]]; then
            rm -rf "$HEIMDAL_LOG_DIR"
            log_success "Log directory removed: $HEIMDAL_LOG_DIR"
        fi
    else
        log_info "Log files preserved: $HEIMDAL_LOG_DIR"
    fi
    
    read -p "Remove baseline data and cache? (yes/no): " -r
    if [[ $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        if [[ -d "$HEIMDAL_DATA_DIR" ]]; then
            rm -rf "$HEIMDAL_DATA_DIR"
            log_success "Data directory removed: $HEIMDAL_DATA_DIR"
        fi
    else
        log_info "Data files preserved: $HEIMDAL_DATA_DIR"
    fi
}

remove_user() {
    log_info "Checking user account..."
    
    if id "$HEIMDAL_USER" &>/dev/null; then
        read -p "Remove user account '$HEIMDAL_USER'? (yes/no): " -r
        if [[ $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
            userdel "$HEIMDAL_USER" 2>/dev/null || true
            log_success "User account removed: $HEIMDAL_USER"
        else
            log_info "User account preserved: $HEIMDAL_USER"
        fi
    fi
}

remove_sudoers() {
    log_info "Removing sudoers configuration..."
    
    if [[ -f /etc/sudoers.d/heimdal ]]; then
        rm -f /etc/sudoers.d/heimdal
        log_success "Sudoers configuration removed"
    fi
}

print_post_uninstall_info() {
    log_success "Heimdal uninstallation completed!"
    echo
    log_info "System packages were not removed (python3, libpcap-dev, etc.)"
    log_info "You may remove them manually if no longer needed"
    echo
    if [[ -d "$HEIMDAL_LOG_DIR" ]] || [[ -d "$HEIMDAL_DATA_DIR" ]]; then
        log_info "Some data was preserved:"
        [[ -d "$HEIMDAL_LOG_DIR" ]] && echo "  - Logs: $HEIMDAL_LOG_DIR"
        [[ -d "$HEIMDAL_DATA_DIR" ]] && echo "  - Data: $HEIMDAL_DATA_DIR"
    fi
}

# Main uninstall process
main() {
    log_info "Starting Heimdal uninstallation..."
    
    check_root
    confirm_uninstall
    stop_and_disable_service
    remove_logrotate
    remove_sudoers
    remove_directories
    remove_user
    print_post_uninstall_info
}

# Run main function
main "$@"