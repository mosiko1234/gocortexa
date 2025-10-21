#!/bin/bash

# Heimdal Configuration Update Script
# Helps users update configuration and restart service

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
HEIMDAL_CONFIG_DIR="/etc/heimdal"
HEIMDAL_CONFIG_FILE="$HEIMDAL_CONFIG_DIR/heimdal.yaml"

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

check_config_exists() {
    if [[ ! -f "$HEIMDAL_CONFIG_FILE" ]]; then
        log_error "Configuration file not found: $HEIMDAL_CONFIG_FILE"
        log_info "Please run the installation script first"
        exit 1
    fi
}

validate_config() {
    log_info "Validating configuration..."
    
    # Basic YAML syntax check
    if command -v python3 &> /dev/null; then
        python3 -c "
import yaml
import sys
try:
    with open('$HEIMDAL_CONFIG_FILE', 'r') as f:
        yaml.safe_load(f)
    print('Configuration syntax is valid')
except yaml.YAMLError as e:
    print(f'Configuration syntax error: {e}')
    sys.exit(1)
except Exception as e:
    print(f'Error reading configuration: {e}')
    sys.exit(1)
"
    else
        log_warning "Python3 not available for configuration validation"
    fi
}

update_network_interface() {
    log_info "Available network interfaces:"
    ip link show | grep -E '^[0-9]+:' | cut -d: -f2 | sed 's/^ */  - /'
    echo
    
    read -p "Enter network interface to monitor (current: $(grep 'interface:' $HEIMDAL_CONFIG_FILE | cut -d'"' -f2)): " interface
    
    if [[ -n "$interface" ]]; then
        # Validate interface exists
        if ip link show "$interface" &>/dev/null; then
            sed -i "s/interface: \".*\"/interface: \"$interface\"/" "$HEIMDAL_CONFIG_FILE"
            log_success "Network interface updated to: $interface"
        else
            log_error "Interface '$interface' not found"
            return 1
        fi
    fi
}

update_asgard_config() {
    log_info "Updating Asgard configuration..."
    
    read -p "Enter Asgard API endpoint (press Enter to keep current): " api_endpoint
    if [[ -n "$api_endpoint" ]]; then
        sed -i "s|api_endpoint: \".*\"|api_endpoint: \"$api_endpoint\"|" "$HEIMDAL_CONFIG_FILE"
        log_success "API endpoint updated"
    fi
    
    read -s -p "Enter Asgard API key (press Enter to keep current): " api_key
    echo
    if [[ -n "$api_key" ]]; then
        sed -i "s/api_key: \".*\"/api_key: \"$api_key\"/" "$HEIMDAL_CONFIG_FILE"
        log_success "API key updated"
    fi
}

update_logging_config() {
    log_info "Updating logging configuration..."
    
    echo "Available log levels: DEBUG, INFO, WARNING, ERROR, CRITICAL"
    read -p "Enter log level (press Enter to keep current): " log_level
    
    if [[ -n "$log_level" ]]; then
        case "$log_level" in
            DEBUG|INFO|WARNING|ERROR|CRITICAL)
                sed -i "s/level: \".*\"/level: \"$log_level\"/" "$HEIMDAL_CONFIG_FILE"
                log_success "Log level updated to: $log_level"
                ;;
            *)
                log_error "Invalid log level: $log_level"
                return 1
                ;;
        esac
    fi
}

update_sensor_location() {
    log_info "Updating sensor location..."
    
    read -p "Enter sensor location description (press Enter to keep current): " location
    if [[ -n "$location" ]]; then
        sed -i "s/location: \".*\"/location: \"$location\"/" "$HEIMDAL_CONFIG_FILE"
        log_success "Sensor location updated"
    fi
}

restart_service() {
    if systemctl is-active --quiet heimdal.service; then
        read -p "Restart Heimdal service to apply changes? (yes/no): " -r
        if [[ $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
            log_info "Restarting Heimdal service..."
            systemctl restart heimdal.service
            sleep 2
            
            if systemctl is-active --quiet heimdal.service; then
                log_success "Service restarted successfully"
            else
                log_error "Service failed to start. Check logs: journalctl -u heimdal -n 20"
                return 1
            fi
        fi
    else
        log_info "Service is not running. Start it with: sudo systemctl start heimdal"
    fi
}

show_current_config() {
    log_info "Current configuration summary:"
    echo
    echo "Network Interface: $(grep 'interface:' $HEIMDAL_CONFIG_FILE | cut -d'"' -f2)"
    echo "Log Level: $(grep 'level:' $HEIMDAL_CONFIG_FILE | cut -d'"' -f2)"
    echo "Sensor ID: $(grep 'sensor_id:' $HEIMDAL_CONFIG_FILE | cut -d'"' -f2)"
    echo "Location: $(grep 'location:' $HEIMDAL_CONFIG_FILE | cut -d'"' -f2)"
    echo "API Endpoint: $(grep 'api_endpoint:' $HEIMDAL_CONFIG_FILE | cut -d'"' -f2)"
    echo
}

interactive_config() {
    while true; do
        echo
        echo "Heimdal Configuration Update Menu:"
        echo "1. Show current configuration"
        echo "2. Update network interface"
        echo "3. Update Asgard settings"
        echo "4. Update logging settings"
        echo "5. Update sensor location"
        echo "6. Validate configuration"
        echo "7. Restart service"
        echo "8. Exit"
        echo
        
        read -p "Select option (1-8): " choice
        
        case $choice in
            1) show_current_config ;;
            2) update_network_interface ;;
            3) update_asgard_config ;;
            4) update_logging_config ;;
            5) update_sensor_location ;;
            6) validate_config ;;
            7) restart_service ;;
            8) log_info "Exiting..."; exit 0 ;;
            *) log_error "Invalid option: $choice" ;;
        esac
    done
}

# Main function
main() {
    log_info "Heimdal Configuration Update Tool"
    
    # Check if running as root for service operations
    if [[ $EUID -ne 0 ]]; then
        log_warning "Not running as root. Service restart will require sudo."
    fi
    
    check_config_exists
    
    if [[ $# -eq 0 ]]; then
        # Interactive mode
        interactive_config
    else
        # Command line mode
        case "$1" in
            --interface)
                update_network_interface
                ;;
            --asgard)
                update_asgard_config
                ;;
            --logging)
                update_logging_config
                ;;
            --location)
                update_sensor_location
                ;;
            --validate)
                validate_config
                ;;
            --restart)
                restart_service
                ;;
            --show)
                show_current_config
                ;;
            *)
                echo "Usage: $0 [--interface|--asgard|--logging|--location|--validate|--restart|--show]"
                echo "Run without arguments for interactive mode"
                exit 1
                ;;
        esac
    fi
}

# Run main function
main "$@"