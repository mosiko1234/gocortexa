"""
Comprehensive logging and diagnostics manager for Heimdal.

This module provides structured logging with rotation, disk space management,
and different log levels as required by the real-time monitoring specification.
"""

import logging
import logging.handlers
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Any
import json
import threading
import time

from ..interfaces import ILogger


class StructuredFormatter(logging.Formatter):
    """
    Custom formatter that outputs structured JSON logs for better parsing and analysis.
    """
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as structured JSON."""
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        # Add extra fields if present
        if hasattr(record, 'component'):
            log_entry['component'] = record.component
        if hasattr(record, 'device_id'):
            log_entry['device_id'] = record.device_id
        if hasattr(record, 'metric_type'):
            log_entry['metric_type'] = record.metric_type
        if hasattr(record, 'metric_value'):
            log_entry['metric_value'] = record.metric_value
            
        return json.dumps(log_entry)


class LoggingManager(ILogger):
    """
    Centralized logging manager that handles configuration, rotation, and disk space management.
    """
    
    def __init__(self, 
                 log_dir: str = "/var/log/heimdal",
                 log_level: str = "INFO",
                 max_file_size: int = 10 * 1024 * 1024,  # 10MB
                 backup_count: int = 5,
                 max_disk_usage_mb: int = 100):
        """
        Initialize the logging manager.
        
        Args:
            log_dir: Directory to store log files
            log_level: Default log level (DEBUG, INFO, WARN, ERROR)
            max_file_size: Maximum size per log file before rotation
            backup_count: Number of backup files to keep
            max_disk_usage_mb: Maximum disk space for all logs
        """
        self.log_dir = Path(log_dir)
        self.log_level = getattr(logging, log_level.upper())
        self.max_file_size = max_file_size
        self.backup_count = backup_count
        self.max_disk_usage_mb = max_disk_usage_mb
        
        # Create log directory
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Track configured loggers
        self._configured_loggers: Dict[str, logging.Logger] = {}
        self._lock = threading.Lock()
        
        # Start disk space monitoring
        self._monitoring = True
        self._monitor_thread = threading.Thread(target=self._monitor_disk_usage, daemon=True)
        self._monitor_thread.start()
        
        # Configure root logger
        self._configure_root_logger()
    
    def _configure_root_logger(self):
        """Configure the root logger with console and file handlers."""
        root_logger = logging.getLogger()
        root_logger.setLevel(self.log_level)
        
        # Clear existing handlers
        root_logger.handlers.clear()
        
        # Console handler for immediate feedback
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(self.log_level)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)
        
        # File handler for persistent logging
        main_log_file = self.log_dir / "heimdal.log"
        file_handler = logging.handlers.RotatingFileHandler(
            main_log_file,
            maxBytes=self.max_file_size,
            backupCount=self.backup_count
        )
        file_handler.setLevel(self.log_level)
        file_handler.setFormatter(StructuredFormatter())
        root_logger.addHandler(file_handler)
    
    def get_logger(self, name: str, component: Optional[str] = None) -> logging.Logger:
        """
        Get a configured logger for a specific component.
        
        Args:
            name: Logger name (usually __name__)
            component: Component name for structured logging
            
        Returns:
            Configured logger instance
        """
        with self._lock:
            if name not in self._configured_loggers:
                logger = logging.getLogger(name)
                
                # Add component-specific file handler if component specified
                if component:
                    component_log_file = self.log_dir / f"{component}.log"
                    component_handler = logging.handlers.RotatingFileHandler(
                        component_log_file,
                        maxBytes=self.max_file_size,
                        backupCount=self.backup_count
                    )
                    component_handler.setLevel(self.log_level)
                    component_handler.setFormatter(StructuredFormatter())
                    
                    # Add filter to only log messages from this component
                    component_handler.addFilter(lambda record: record.name.startswith(name))
                    logger.addHandler(component_handler)
                
                self._configured_loggers[name] = logger
            
            return self._configured_loggers[name]
    
    def log_metric(self, logger_name: str, metric_type: str, metric_value: Any, 
                   component: Optional[str] = None, device_id: Optional[str] = None):
        """
        Log a metric with structured format for easy parsing.
        
        Args:
            logger_name: Name of the logger
            metric_type: Type of metric (e.g., 'packet_rate', 'cpu_usage')
            metric_value: Value of the metric
            component: Component generating the metric
            device_id: Device ID if metric is device-specific
        """
        logger = self.get_logger(logger_name, component)
        
        # Create log record with extra fields
        extra = {
            'metric_type': metric_type,
            'metric_value': metric_value
        }
        if component:
            extra['component'] = component
        if device_id:
            extra['device_id'] = device_id
        
        logger.info(f"Metric: {metric_type}={metric_value}", extra=extra)
    
    def log_component_activity(self, logger_name: str, component: str, 
                             activity: str, details: Optional[Dict[str, Any]] = None):
        """
        Log component activity with structured format.
        
        Args:
            logger_name: Name of the logger
            component: Component name
            activity: Description of the activity
            details: Additional details as key-value pairs
        """
        logger = self.get_logger(logger_name, component)
        
        extra = {'component': component}
        if details:
            extra.update(details)
        
        logger.info(f"Activity: {activity}", extra=extra)
    
    def _monitor_disk_usage(self):
        """Monitor disk usage and clean up old logs if necessary."""
        while self._monitoring:
            try:
                total_size = self._calculate_log_directory_size()
                if total_size > self.max_disk_usage_mb * 1024 * 1024:
                    self._cleanup_old_logs()
                
                time.sleep(300)  # Check every 5 minutes
            except Exception as e:
                # Use basic logging to avoid recursion
                print(f"Error in disk usage monitoring: {e}")
    
    def _calculate_log_directory_size(self) -> int:
        """Calculate total size of log directory in bytes."""
        total_size = 0
        for file_path in self.log_dir.rglob("*.log*"):
            if file_path.is_file():
                total_size += file_path.stat().st_size
        return total_size
    
    def _cleanup_old_logs(self):
        """Remove oldest log files to free up disk space."""
        log_files = []
        for file_path in self.log_dir.rglob("*.log*"):
            if file_path.is_file():
                log_files.append((file_path.stat().st_mtime, file_path))
        
        # Sort by modification time (oldest first)
        log_files.sort()
        
        # Remove oldest files until under disk limit
        current_size = self._calculate_log_directory_size()
        target_size = self.max_disk_usage_mb * 1024 * 1024 * 0.8  # 80% of limit
        
        for _, file_path in log_files:
            if current_size <= target_size:
                break
            
            try:
                file_size = file_path.stat().st_size
                file_path.unlink()
                current_size -= file_size
                print(f"Removed old log file: {file_path}")
            except Exception as e:
                print(f"Error removing log file {file_path}: {e}")
    
    def set_log_level(self, level: str):
        """
        Change the log level for all configured loggers.
        
        Args:
            level: New log level (DEBUG, INFO, WARN, ERROR)
        """
        new_level = getattr(logging, level.upper())
        self.log_level = new_level
        
        # Update root logger
        logging.getLogger().setLevel(new_level)
        
        # Update all handlers
        for handler in logging.getLogger().handlers:
            handler.setLevel(new_level)
        
        # Update component loggers
        with self._lock:
            for logger in self._configured_loggers.values():
                logger.setLevel(new_level)
                for handler in logger.handlers:
                    handler.setLevel(new_level)
    
    def get_log_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about logging system.
        
        Returns:
            Dictionary with logging statistics
        """
        stats = {
            'log_directory': str(self.log_dir),
            'current_log_level': logging.getLevelName(self.log_level),
            'total_disk_usage_mb': self._calculate_log_directory_size() / (1024 * 1024),
            'max_disk_usage_mb': self.max_disk_usage_mb,
            'configured_loggers': len(self._configured_loggers),
            'log_files': []
        }
        
        # Get info about each log file
        for file_path in self.log_dir.rglob("*.log*"):
            if file_path.is_file():
                file_stat = file_path.stat()
                stats['log_files'].append({
                    'name': file_path.name,
                    'size_mb': file_stat.st_size / (1024 * 1024),
                    'modified': datetime.fromtimestamp(file_stat.st_mtime).isoformat()
                })
        
        return stats
    
    # ILogger interface implementation
    def debug(self, message: str, **kwargs) -> None:
        """Log debug message"""
        logger = logging.getLogger()
        logger.debug(message, extra=kwargs)
    
    def info(self, message: str, **kwargs) -> None:
        """Log info message"""
        logger = logging.getLogger()
        logger.info(message, extra=kwargs)
    
    def warning(self, message: str, **kwargs) -> None:
        """Log warning message"""
        logger = logging.getLogger()
        logger.warning(message, extra=kwargs)
    
    def error(self, message: str, **kwargs) -> None:
        """Log error message"""
        logger = logging.getLogger()
        logger.error(message, extra=kwargs)
    
    def critical(self, message: str, **kwargs) -> None:
        """Log critical message"""
        logger = logging.getLogger()
        logger.critical(message, extra=kwargs)
    
    def shutdown(self):
        """Shutdown the logging manager and cleanup resources."""
        self._monitoring = False
        if self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5)
        
        # Close all handlers
        for logger in self._configured_loggers.values():
            for handler in logger.handlers[:]:
                handler.close()
                logger.removeHandler(handler)


# Global logging manager instance
_logging_manager: Optional[LoggingManager] = None


def initialize_logging(log_dir: str = "/var/log/heimdal",
                      log_level: str = "INFO",
                      max_file_size: int = 10 * 1024 * 1024,
                      backup_count: int = 5,
                      max_disk_usage_mb: int = 100) -> LoggingManager:
    """
    Initialize the global logging manager.
    
    Args:
        log_dir: Directory to store log files
        log_level: Default log level
        max_file_size: Maximum size per log file
        backup_count: Number of backup files to keep
        max_disk_usage_mb: Maximum disk space for all logs
        
    Returns:
        Initialized logging manager
    """
    global _logging_manager
    
    if _logging_manager is not None:
        _logging_manager.shutdown()
    
    _logging_manager = LoggingManager(
        log_dir=log_dir,
        log_level=log_level,
        max_file_size=max_file_size,
        backup_count=backup_count,
        max_disk_usage_mb=max_disk_usage_mb
    )
    
    return _logging_manager


def get_logger(name: str, component: Optional[str] = None) -> logging.Logger:
    """
    Get a logger from the global logging manager.
    
    Args:
        name: Logger name
        component: Component name for structured logging
        
    Returns:
        Configured logger
    """
    if _logging_manager is None:
        # Initialize with defaults if not already initialized
        initialize_logging()
    
    return _logging_manager.get_logger(name, component)


def log_metric(logger_name: str, metric_type: str, metric_value: Any,
               component: Optional[str] = None, device_id: Optional[str] = None):
    """Log a metric using the global logging manager."""
    if _logging_manager is None:
        initialize_logging()
    
    _logging_manager.log_metric(logger_name, metric_type, metric_value, component, device_id)


def log_component_activity(logger_name: str, component: str, activity: str,
                          details: Optional[Dict[str, Any]] = None):
    """Log component activity using the global logging manager."""
    if _logging_manager is None:
        initialize_logging()
    
    _logging_manager.log_component_activity(logger_name, component, activity, details)


def get_logging_statistics() -> Dict[str, Any]:
    """Get logging system statistics."""
    if _logging_manager is None:
        return {'error': 'Logging manager not initialized'}
    
    return _logging_manager.get_log_statistics()


def shutdown_logging():
    """Shutdown the global logging manager."""
    global _logging_manager
    if _logging_manager is not None:
        _logging_manager.shutdown()
        _logging_manager = None