#!/bin/bash

# Heimdal Backup and Restore Script
# Backs up configuration, baselines, and logs

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
HEIMDAL_CONFIG_DIR="/etc/heimdal"
HEIMDAL_LOG_DIR="/var/log/heimdal"
HEIMDAL_DATA_DIR="/var/lib/heimdal"
BACKUP_DIR="/opt/heimdal-backups"
DATE_FORMAT="%Y%m%d_%H%M%S"

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

create_backup_dir() {
    if [[ ! -d "$BACKUP_DIR" ]]; then
        mkdir -p "$BACKUP_DIR"
        chmod 755 "$BACKUP_DIR"
        log_info "Created backup directory: $BACKUP_DIR"
    fi
}

backup_configuration() {
    local backup_path="$1"
    
    log_info "Backing up configuration..."
    
    if [[ -d "$HEIMDAL_CONFIG_DIR" ]]; then
        cp -r "$HEIMDAL_CONFIG_DIR" "$backup_path/config"
        log_success "Configuration backed up"
    else
        log_warning "Configuration directory not found: $HEIMDAL_CONFIG_DIR"
    fi
}

backup_baseline_data() {
    local backup_path="$1"
    
    log_info "Backing up baseline data..."
    
    if [[ -d "$HEIMDAL_DATA_DIR" ]]; then
        cp -r "$HEIMDAL_DATA_DIR" "$backup_path/data"
        log_success "Baseline data backed up"
    else
        log_warning "Data directory not found: $HEIMDAL_DATA_DIR"
    fi
}

backup_logs() {
    local backup_path="$1"
    local include_logs="$2"
    
    if [[ "$include_logs" == "yes" ]]; then
        log_info "Backing up logs..."
        
        if [[ -d "$HEIMDAL_LOG_DIR" ]]; then
            cp -r "$HEIMDAL_LOG_DIR" "$backup_path/logs"
            log_success "Logs backed up"
        else
            log_warning "Log directory not found: $HEIMDAL_LOG_DIR"
        fi
    else
        log_info "Skipping log backup"
    fi
}

create_backup_info() {
    local backup_path="$1"
    
    cat > "$backup_path/backup_info.txt" << EOF
Heimdal Backup Information
=========================

Backup Date: $(date)
Backup Path: $backup_path
Hostname: $(hostname)
OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')
Kernel: $(uname -r)

Backed up directories:
- Configuration: $HEIMDAL_CONFIG_DIR
- Data: $HEIMDAL_DATA_DIR
$(if [[ -d "$backup_path/logs" ]]; then echo "- Logs: $HEIMDAL_LOG_DIR"; fi)

Service Status at backup time:
$(systemctl status heimdal.service --no-pager -l || echo "Service not found")

Disk Usage:
$(df -h "$HEIMDAL_CONFIG_DIR" "$HEIMDAL_DATA_DIR" "$HEIMDAL_LOG_DIR" 2>/dev/null || true)
EOF
    
    log_success "Backup information saved"
}

create_full_backup() {
    local timestamp=$(date +"$DATE_FORMAT")
    local backup_name="heimdal_backup_$timestamp"
    local backup_path="$BACKUP_DIR/$backup_name"
    
    log_info "Creating full backup: $backup_name"
    
    # Ask about including logs
    local include_logs="no"
    if [[ -t 0 ]]; then  # Only ask if running interactively
        read -p "Include log files in backup? (yes/no): " -r
        if [[ $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
            include_logs="yes"
        fi
    fi
    
    # Create backup directory
    mkdir -p "$backup_path"
    
    # Backup components
    backup_configuration "$backup_path"
    backup_baseline_data "$backup_path"
    backup_logs "$backup_path" "$include_logs"
    create_backup_info "$backup_path"
    
    # Create compressed archive
    log_info "Creating compressed archive..."
    cd "$BACKUP_DIR"
    tar -czf "${backup_name}.tar.gz" "$backup_name"
    rm -rf "$backup_name"
    
    local archive_size=$(du -h "${backup_name}.tar.gz" | cut -f1)
    log_success "Backup completed: $BACKUP_DIR/${backup_name}.tar.gz ($archive_size)"
    
    echo "$BACKUP_DIR/${backup_name}.tar.gz"
}

list_backups() {
    log_info "Available backups in $BACKUP_DIR:"
    echo
    
    if [[ -d "$BACKUP_DIR" ]]; then
        local backups=($(find "$BACKUP_DIR" -name "heimdal_backup_*.tar.gz" -type f | sort -r))
        
        if [[ ${#backups[@]} -eq 0 ]]; then
            log_warning "No backups found"
            return 1
        fi
        
        for i in "${!backups[@]}"; do
            local backup="${backups[$i]}"
            local basename=$(basename "$backup")
            local size=$(du -h "$backup" | cut -f1)
            local date=$(echo "$basename" | sed 's/heimdal_backup_\([0-9]\{8\}_[0-9]\{6\}\).tar.gz/\1/' | sed 's/_/ /')
            
            printf "%2d. %s (%s) - %s\n" $((i+1)) "$basename" "$size" "$date"
        done
    else
        log_warning "Backup directory not found: $BACKUP_DIR"
        return 1
    fi
}

restore_from_backup() {
    local backup_file="$1"
    
    if [[ ! -f "$backup_file" ]]; then
        log_error "Backup file not found: $backup_file"
        return 1
    fi
    
    log_info "Restoring from backup: $(basename "$backup_file")"
    
    # Confirm restore
    echo -e "${YELLOW}WARNING: This will overwrite current configuration and data!${NC}"
    read -p "Are you sure you want to continue? (yes/no): " -r
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        log_info "Restore cancelled"
        return 0
    fi
    
    # Stop service if running
    local service_was_running=false
    if systemctl is-active --quiet heimdal.service; then
        log_info "Stopping Heimdal service..."
        systemctl stop heimdal.service
        service_was_running=true
    fi
    
    # Create temporary extraction directory
    local temp_dir=$(mktemp -d)
    
    # Extract backup
    log_info "Extracting backup..."
    tar -xzf "$backup_file" -C "$temp_dir"
    
    # Find extracted directory
    local extracted_dir=$(find "$temp_dir" -name "heimdal_backup_*" -type d | head -n1)
    
    if [[ ! -d "$extracted_dir" ]]; then
        log_error "Could not find extracted backup directory"
        rm -rf "$temp_dir"
        return 1
    fi
    
    # Restore configuration
    if [[ -d "$extracted_dir/config" ]]; then
        log_info "Restoring configuration..."
        rm -rf "$HEIMDAL_CONFIG_DIR"
        cp -r "$extracted_dir/config" "$HEIMDAL_CONFIG_DIR"
        log_success "Configuration restored"
    fi
    
    # Restore data
    if [[ -d "$extracted_dir/data" ]]; then
        log_info "Restoring baseline data..."
        rm -rf "$HEIMDAL_DATA_DIR"
        cp -r "$extracted_dir/data" "$HEIMDAL_DATA_DIR"
        chown -R heimdal:heimdal "$HEIMDAL_DATA_DIR"
        log_success "Baseline data restored"
    fi
    
    # Restore logs (optional)
    if [[ -d "$extracted_dir/logs" ]]; then
        read -p "Restore log files? (yes/no): " -r
        if [[ $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
            log_info "Restoring logs..."
            rm -rf "$HEIMDAL_LOG_DIR"
            cp -r "$extracted_dir/logs" "$HEIMDAL_LOG_DIR"
            chown -R heimdal:heimdal "$HEIMDAL_LOG_DIR"
            log_success "Logs restored"
        fi
    fi
    
    # Clean up
    rm -rf "$temp_dir"
    
    # Restart service if it was running
    if [[ "$service_was_running" == true ]]; then
        log_info "Starting Heimdal service..."
        systemctl start heimdal.service
        
        if systemctl is-active --quiet heimdal.service; then
            log_success "Service started successfully"
        else
            log_error "Service failed to start. Check logs: journalctl -u heimdal -n 20"
        fi
    fi
    
    log_success "Restore completed successfully"
}

interactive_restore() {
    list_backups
    
    local backups=($(find "$BACKUP_DIR" -name "heimdal_backup_*.tar.gz" -type f | sort -r))
    
    if [[ ${#backups[@]} -eq 0 ]]; then
        return 1
    fi
    
    echo
    read -p "Select backup to restore (1-${#backups[@]}): " -r
    
    if [[ "$REPLY" =~ ^[0-9]+$ ]] && [[ "$REPLY" -ge 1 ]] && [[ "$REPLY" -le ${#backups[@]} ]]; then
        local selected_backup="${backups[$((REPLY-1))]}"
        restore_from_backup "$selected_backup"
    else
        log_error "Invalid selection: $REPLY"
        return 1
    fi
}

cleanup_old_backups() {
    local keep_days="${1:-30}"
    
    log_info "Cleaning up backups older than $keep_days days..."
    
    if [[ -d "$BACKUP_DIR" ]]; then
        local deleted_count=0
        while IFS= read -r -d '' backup; do
            rm -f "$backup"
            ((deleted_count++))
            log_info "Deleted: $(basename "$backup")"
        done < <(find "$BACKUP_DIR" -name "heimdal_backup_*.tar.gz" -type f -mtime +$keep_days -print0)
        
        if [[ $deleted_count -eq 0 ]]; then
            log_info "No old backups to clean up"
        else
            log_success "Cleaned up $deleted_count old backup(s)"
        fi
    fi
}

# Main function
main() {
    case "${1:-help}" in
        "create"|"backup")
            check_root
            create_backup_dir
            create_full_backup
            ;;
        "list")
            list_backups
            ;;
        "restore")
            check_root
            if [[ -n "$2" ]]; then
                restore_from_backup "$2"
            else
                interactive_restore
            fi
            ;;
        "cleanup")
            check_root
            cleanup_old_backups "${2:-30}"
            ;;
        "help"|*)
            echo "Heimdal Backup and Restore Tool"
            echo
            echo "Usage: $0 <command> [options]"
            echo
            echo "Commands:"
            echo "  create          Create a new backup"
            echo "  list            List available backups"
            echo "  restore [file]  Restore from backup (interactive if no file specified)"
            echo "  cleanup [days]  Remove backups older than specified days (default: 30)"
            echo "  help            Show this help message"
            echo
            echo "Examples:"
            echo "  $0 create                                    # Create new backup"
            echo "  $0 list                                      # List all backups"
            echo "  $0 restore                                   # Interactive restore"
            echo "  $0 restore /opt/heimdal-backups/backup.tar.gz  # Restore specific backup"
            echo "  $0 cleanup 7                                # Remove backups older than 7 days"
            ;;
    esac
}

# Run main function
main "$@"