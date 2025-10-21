#!/bin/bash

# Heimdal Health Check Script
# Monitors system health and provides diagnostics

set -e

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

check_service_status() {
    log_info "Checking Heimdal service status..."
    
    if systemctl is-active --quiet heimdal.service; then
        log_success "Service is running"
        
        # Get service uptime
        uptime=$(systemctl show heimdal.service --property=ActiveEnterTimestamp --value)
        log_info "Service started: $uptime"
        
        # Get process info
        pid=$(systemctl show heimdal.service --property=MainPID --value)
        if [[ "$pid" != "0" ]]; then
            log_info "Process ID: $pid"
            
            # Memory usage
            if command -v ps &> /dev/null; then
                mem_usage=$(ps -p "$pid" -o rss= 2>/dev/null | tr -d ' ')
                if [[ -n "$mem_usage" ]]; then
                    mem_mb=$((mem_usage / 1024))
                    log_info "Memory usage: ${mem_mb}MB"
                fi
            fi
        fi
    else
        log_error "Service is not running"
        
        # Check if service failed
        if systemctl is-failed --quiet heimdal.service; then
            log_error "Service is in failed state"
            log_info "Recent service logs:"
            journalctl -u heimdal.service -n 5 --no-pager
        fi
        return 1
    fi
}

check_configuration() {
    log_info "Checking configuration..."
    
    config_file="$HEIMDAL_CONFIG_DIR/heimdal.yaml"
    if [[ -f "$config_file" ]]; then
        log_success "Configuration file exists: $config_file"
        
        # Check configuration syntax
        if command -v python3 &> /dev/null; then
            if python3 -c "import yaml; yaml.safe_load(open('$config_file'))" 2>/dev/null; then
                log_success "Configuration syntax is valid"
            else
                log_error "Configuration syntax error"
                return 1
            fi
        fi
        
        # Check key configuration values
        interface=$(grep 'interface:' "$config_file" | cut -d'"' -f2)
        if [[ -n "$interface" ]]; then
            if ip link show "$interface" &>/dev/null; then
                log_success "Network interface '$interface' exists"
            else
                log_error "Network interface '$interface' not found"
            fi
        fi
        
    else
        log_error "Configuration file not found: $config_file"
        return 1
    fi
}

check_directories() {
    log_info "Checking directory structure..."
    
    directories=("$HEIMDAL_HOME" "$HEIMDAL_CONFIG_DIR" "$HEIMDAL_LOG_DIR" "$HEIMDAL_DATA_DIR")
    
    for dir in "${directories[@]}"; do
        if [[ -d "$dir" ]]; then
            log_success "Directory exists: $dir"
            
            # Check permissions
            if [[ -r "$dir" ]]; then
                log_success "Directory is readable: $dir"
            else
                log_warning "Directory is not readable: $dir"
            fi
        else
            log_error "Directory missing: $dir"
        fi
    done
}

check_user_account() {
    log_info "Checking user account..."
    
    if id "$HEIMDAL_USER" &>/dev/null; then
        log_success "User account exists: $HEIMDAL_USER"
        
        # Check home directory
        home_dir=$(getent passwd "$HEIMDAL_USER" | cut -d: -f6)
        if [[ "$home_dir" == "$HEIMDAL_HOME" ]]; then
            log_success "Home directory is correct: $home_dir"
        else
            log_warning "Home directory mismatch. Expected: $HEIMDAL_HOME, Got: $home_dir"
        fi
        
        # Check groups
        groups=$(groups "$HEIMDAL_USER" 2>/dev/null | cut -d: -f2)
        log_info "User groups:$groups"
        
    else
        log_error "User account not found: $HEIMDAL_USER"
        return 1
    fi
}

check_network_capabilities() {
    log_info "Checking network monitoring capabilities..."
    
    # Check if tcpdump is available
    if command -v tcpdump &> /dev/null; then
        log_success "tcpdump is available"
    else
        log_warning "tcpdump not found - may affect packet capture"
    fi
    
    # Check network interfaces
    log_info "Available network interfaces:"
    ip link show | grep -E '^[0-9]+:' | cut -d: -f2 | sed 's/^ */  - /'
    
    # Check if running as root or with capabilities
    if [[ $EUID -eq 0 ]]; then
        log_info "Running as root - network access available"
    else
        # Check capabilities on Python binary
        python_bin="$HEIMDAL_HOME/venv/bin/python3"
        if [[ -f "$python_bin" ]]; then
            if command -v getcap &> /dev/null; then
                caps=$(getcap "$python_bin" 2>/dev/null)
                if [[ -n "$caps" ]]; then
                    log_success "Python binary has capabilities: $caps"
                else
                    log_warning "Python binary has no capabilities - may need root or setcap"
                fi
            fi
        fi
    fi
}

check_disk_space() {
    log_info "Checking disk space..."
    
    # Check available space in key directories
    directories=("$HEIMDAL_LOG_DIR" "$HEIMDAL_DATA_DIR" "/tmp")
    
    for dir in "${directories[@]}"; do
        if [[ -d "$dir" ]]; then
            available=$(df -h "$dir" | awk 'NR==2 {print $4}')
            used_percent=$(df -h "$dir" | awk 'NR==2 {print $5}' | tr -d '%')
            
            if [[ $used_percent -lt 80 ]]; then
                log_success "Disk space OK for $dir: $available available ($used_percent% used)"
            elif [[ $used_percent -lt 90 ]]; then
                log_warning "Disk space low for $dir: $available available ($used_percent% used)"
            else
                log_error "Disk space critical for $dir: $available available ($used_percent% used)"
            fi
        fi
    done
}

check_log_files() {
    log_info "Checking log files..."
    
    log_file="$HEIMDAL_LOG_DIR/heimdal.log"
    if [[ -f "$log_file" ]]; then
        log_success "Log file exists: $log_file"
        
        # Check log file size
        size=$(du -h "$log_file" | cut -f1)
        log_info "Log file size: $size"
        
        # Check recent log entries
        if [[ -r "$log_file" ]]; then
            recent_entries=$(tail -n 10 "$log_file" 2>/dev/null | wc -l)
            log_info "Recent log entries: $recent_entries"
            
            # Check for errors in recent logs
            error_count=$(tail -n 100 "$log_file" 2>/dev/null | grep -c "ERROR" || true)
            if [[ $error_count -gt 0 ]]; then
                log_warning "Found $error_count ERROR entries in recent logs"
            else
                log_success "No recent ERROR entries found"
            fi
        fi
    else
        log_warning "Log file not found: $log_file"
    fi
}

check_baseline_data() {
    log_info "Checking baseline data..."
    
    baseline_dir="$HEIMDAL_DATA_DIR/baselines"
    if [[ -d "$baseline_dir" ]]; then
        log_success "Baseline directory exists: $baseline_dir"
        
        # Count baseline files
        baseline_count=$(find "$baseline_dir" -name "*.json" 2>/dev/null | wc -l)
        log_info "Baseline files found: $baseline_count"
        
        # Check main baseline file
        main_baseline="$baseline_dir/baselines.json"
        if [[ -f "$main_baseline" ]]; then
            log_success "Main baseline file exists"
            
            # Check file size and modification time
            size=$(du -h "$main_baseline" | cut -f1)
            mtime=$(stat -c %y "$main_baseline" 2>/dev/null | cut -d. -f1)
            log_info "Baseline file size: $size, last modified: $mtime"
        else
            log_warning "Main baseline file not found - system may be learning"
        fi
    else
        log_warning "Baseline directory not found: $baseline_dir"
    fi
}

run_full_health_check() {
    log_info "Running full Heimdal health check..."
    echo
    
    local exit_code=0
    
    check_service_status || exit_code=1
    echo
    check_configuration || exit_code=1
    echo
    check_directories || exit_code=1
    echo
    check_user_account || exit_code=1
    echo
    check_network_capabilities || exit_code=1
    echo
    check_disk_space || exit_code=1
    echo
    check_log_files || exit_code=1
    echo
    check_baseline_data || exit_code=1
    
    echo
    if [[ $exit_code -eq 0 ]]; then
        log_success "Health check completed - all systems operational"
    else
        log_warning "Health check completed with warnings/errors"
        log_info "Check the output above for details"
    fi
    
    return $exit_code
}

show_system_info() {
    log_info "System Information:"
    echo
    
    # OS information
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "OS: $PRETTY_NAME"
    fi
    
    # Kernel version
    echo "Kernel: $(uname -r)"
    
    # Architecture
    echo "Architecture: $(uname -m)"
    
    # Python version
    if command -v python3 &> /dev/null; then
        echo "Python: $(python3 --version)"
    fi
    
    # Memory info
    if [[ -f /proc/meminfo ]]; then
        total_mem=$(grep MemTotal /proc/meminfo | awk '{print $2}')
        total_mem_mb=$((total_mem / 1024))
        echo "Total Memory: ${total_mem_mb}MB"
    fi
    
    # Check if Raspberry Pi
    if grep -q "Raspberry Pi" /proc/cpuinfo 2>/dev/null; then
        echo "Hardware: Raspberry Pi"
        
        # Pi model
        model=$(grep "Model" /proc/cpuinfo | cut -d: -f2 | sed 's/^ *//')
        echo "Model: $model"
    fi
}

# Main function
main() {
    case "${1:-full}" in
        "service")
            check_service_status
            ;;
        "config")
            check_configuration
            ;;
        "network")
            check_network_capabilities
            ;;
        "disk")
            check_disk_space
            ;;
        "logs")
            check_log_files
            ;;
        "baseline")
            check_baseline_data
            ;;
        "info")
            show_system_info
            ;;
        "full"|"")
            run_full_health_check
            ;;
        *)
            echo "Usage: $0 [service|config|network|disk|logs|baseline|info|full]"
            echo "  service  - Check service status"
            echo "  config   - Check configuration"
            echo "  network  - Check network capabilities"
            echo "  disk     - Check disk space"
            echo "  logs     - Check log files"
            echo "  baseline - Check baseline data"
            echo "  info     - Show system information"
            echo "  full     - Run all checks (default)"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"