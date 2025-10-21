"""
Configuration management system for Heimdal
"""

import json
import yaml
import os
import threading
import time
from typing import Any, Dict, List, Optional, Callable
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from ..interfaces import IConfigurationManager


class ConfigFileWatcher(FileSystemEventHandler):
    """File system event handler for configuration file changes"""
    
    def __init__(self, config_manager: 'ConfigurationManager'):
        self.config_manager = config_manager
        self.last_modified = 0
        
    def on_modified(self, event):
        if event.is_directory:
            return
            
        # Debounce rapid file changes
        current_time = time.time()
        if current_time - self.last_modified < 1.0:
            return
        self.last_modified = current_time
        
        if event.src_path == self.config_manager._config_path:
            self.config_manager._handle_config_file_change()


class ConfigurationManager(IConfigurationManager):
    """Configuration manager supporting YAML and JSON config files"""
    
    def __init__(self, config_path: Optional[str] = None):
        self._config: Dict[str, Any] = {}
        self._config_path: Optional[str] = config_path
        self._default_config = self._get_default_config()
        self._config_lock = threading.RLock()
        self._reload_callbacks: List[Callable[[Dict[str, Any]], None]] = []
        self._file_observer: Optional[Observer] = None
        self._auto_reload_enabled = False
        
        if config_path:
            self.load_config(config_path)
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration values"""
        return {
            'capture': {
                'interface': 'eth0',
                'filter_expression': None,
                'max_packet_buffer_size': 10000,
                'capture_timeout': 1.0
            },
            'analysis': {
                'processing_batch_size': 100,
                'device_timeout_seconds': 300,
                'feature_extraction_interval': 60
            },
            'anomaly_detection': {
                'thresholds': {
                    'new_destination': 0.7,
                    'unusual_volume': 0.8,
                    'protocol_violation': 0.9,
                    'timing_anomaly': 0.6,
                    'geolocation_violation': 0.85
                },
                'baseline_update_frequency': 60,
                'anomaly_correlation_window': 300
            },
            'baseline': {
                'rolling_window_days': 7,
                'max_baseline_age_days': 30,
                'confidence_threshold': 0.5,
                'auto_save_interval': 300
            },
            'asgard': {
                'api_endpoint': 'https://api.asgard.cortexa.ai',
                'api_key': '',
                'retry_attempts': 3,
                'retry_backoff_seconds': 5,
                'connection_timeout': 30,
                'metadata_queue_size': 1000
            },
            'logging': {
                'level': 'INFO',
                'file_path': '/var/log/heimdal/heimdal.log',
                'max_file_size_mb': 100,
                'backup_count': 5,
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            },
            'system': {
                'sensor_id': '',
                'location': '',
                'capabilities': ['packet_capture', 'anomaly_detection', 'baseline_management'],
                'performance_monitoring': True,
                'health_check_interval': 60
            }
        }
    
    def load_config(self, config_path: str) -> bool:
        """Load configuration from YAML or JSON file"""
        with self._config_lock:
            try:
                config_file = Path(config_path)
                
                if not config_file.exists():
                    # Create default config file if it doesn't exist
                    self._create_default_config_file(config_path)
                    return True
                
                with open(config_path, 'r') as f:
                    if config_path.endswith('.yaml') or config_path.endswith('.yml'):
                        loaded_config = yaml.safe_load(f)
                    elif config_path.endswith('.json'):
                        loaded_config = json.load(f)
                    else:
                        raise ValueError(f"Unsupported config file format: {config_path}")
                
                # Validate loaded config before applying
                validation_errors = self._validate_loaded_config(loaded_config or {})
                if validation_errors:
                    print(f"Configuration validation errors: {validation_errors}")
                    # Continue with warnings but don't fail completely
                
                # Merge with defaults
                old_config = self._config.copy()
                self._config = self._merge_configs(self._default_config, loaded_config or {})
                self._config_path = config_path
                
                # Apply environment variable overrides
                self._apply_environment_overrides()
                
                # Notify callbacks if config changed
                if old_config != self._config:
                    self._notify_reload_callbacks()
                
                return True
                
            except Exception as e:
                print(f"Error loading config from {config_path}: {e}")
                # Fall back to default config
                self._config = self._default_config.copy()
                return False
    
    def _create_default_config_file(self, config_path: str) -> None:
        """Create a default configuration file"""
        config_dir = Path(config_path).parent
        config_dir.mkdir(parents=True, exist_ok=True)
        
        if config_path.endswith('.yaml') or config_path.endswith('.yml'):
            with open(config_path, 'w') as f:
                yaml.dump(self._default_config, f, default_flow_style=False, indent=2)
        else:
            with open(config_path, 'w') as f:
                json.dump(self._default_config, f, indent=2)
    
    def _merge_configs(self, default: Dict[str, Any], loaded: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively merge loaded config with defaults"""
        result = default.copy()
        
        for key, value in loaded.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def get_config(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation (e.g., 'capture.interface')"""
        with self._config_lock:
            keys = key.split('.')
            value = self._config
            
            try:
                for k in keys:
                    value = value[k]
                return value
            except (KeyError, TypeError):
                return default
    
    def set_config(self, key: str, value: Any) -> None:
        """Set configuration value using dot notation"""
        with self._config_lock:
            keys = key.split('.')
            config = self._config
            
            # Navigate to the parent of the target key
            for k in keys[:-1]:
                if k not in config:
                    config[k] = {}
                config = config[k]
            
            # Set the final value
            old_value = config.get(keys[-1])
            config[keys[-1]] = value
            
            # Notify callbacks if value changed
            if old_value != value:
                self._notify_reload_callbacks()
    
    def reload_config(self) -> bool:
        """Reload configuration from file"""
        if self._config_path:
            print(f"Reloading configuration from {self._config_path}")
            return self.load_config(self._config_path)
        return False
    
    def validate_config(self) -> List[str]:
        """Validate configuration and return list of errors"""
        with self._config_lock:
            return self._validate_loaded_config(self._config)
    
    def _validate_loaded_config(self, config: Dict[str, Any]) -> List[str]:
        """Validate a configuration dictionary and return list of errors"""
        errors = []
        
        # Validate capture interface
        interface = self._get_nested_value(config, 'capture.interface')
        if not interface:
            errors.append("Capture interface not specified")
        
        # Validate capture buffer size
        buffer_size = self._get_nested_value(config, 'capture.max_packet_buffer_size')
        if buffer_size is not None and (not isinstance(buffer_size, int) or buffer_size <= 0):
            errors.append("Invalid packet buffer size")
        
        # Validate Asgard API configuration
        api_endpoint = self._get_nested_value(config, 'asgard.api_endpoint')
        if not api_endpoint or not api_endpoint.startswith('http'):
            errors.append("Invalid Asgard API endpoint")
        
        # Validate logging configuration
        log_path = self._get_nested_value(config, 'logging.file_path')
        if log_path:
            log_dir = Path(log_path).parent
            if not log_dir.exists():
                try:
                    log_dir.mkdir(parents=True, exist_ok=True)
                except Exception as e:
                    errors.append(f"Cannot create log directory {log_dir}: {e}")
        
        # Validate log level
        log_level = self._get_nested_value(config, 'logging.level')
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if log_level and log_level not in valid_levels:
            errors.append(f"Invalid log level: {log_level}. Must be one of {valid_levels}")
        
        # Validate anomaly thresholds
        thresholds = self._get_nested_value(config, 'anomaly_detection.thresholds', {})
        for threshold_name, threshold_value in thresholds.items():
            if not isinstance(threshold_value, (int, float)) or not (0 <= threshold_value <= 1):
                errors.append(f"Invalid threshold value for {threshold_name}: {threshold_value}")
        
        # Validate baseline configuration
        rolling_window = self._get_nested_value(config, 'baseline.rolling_window_days')
        if rolling_window is not None and (not isinstance(rolling_window, int) or rolling_window <= 0):
            errors.append("Invalid baseline rolling window days")
        
        max_age = self._get_nested_value(config, 'baseline.max_baseline_age_days')
        if max_age is not None and (not isinstance(max_age, int) or max_age <= 0):
            errors.append("Invalid baseline max age days")
        
        # Validate system configuration
        capabilities = self._get_nested_value(config, 'system.capabilities', [])
        if not isinstance(capabilities, list):
            errors.append("System capabilities must be a list")
        
        health_check_interval = self._get_nested_value(config, 'system.health_check_interval')
        if health_check_interval is not None and (not isinstance(health_check_interval, int) or health_check_interval <= 0):
            errors.append("Invalid health check interval")
        
        return errors
    
    def _get_nested_value(self, config: Dict[str, Any], key: str, default: Any = None) -> Any:
        """Get nested value from config dictionary using dot notation"""
        keys = key.split('.')
        value = config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def save_config(self, config_path: Optional[str] = None) -> bool:
        """Save current configuration to file"""
        path = config_path or self._config_path
        if not path:
            return False
        
        try:
            config_dir = Path(path).parent
            config_dir.mkdir(parents=True, exist_ok=True)
            
            with open(path, 'w') as f:
                if path.endswith('.yaml') or path.endswith('.yml'):
                    yaml.dump(self._config, f, default_flow_style=False, indent=2)
                else:
                    json.dump(self._config, f, indent=2)
            
            return True
            
        except Exception as e:
            print(f"Error saving config to {path}: {e}")
            return False
    
    def get_all_config(self) -> Dict[str, Any]:
        """Get complete configuration dictionary"""
        with self._config_lock:
            return self._config.copy()
    
    def enable_auto_reload(self) -> bool:
        """Enable automatic configuration reload when file changes"""
        if not self._config_path or self._auto_reload_enabled:
            return False
        
        try:
            config_dir = Path(self._config_path).parent
            self._file_observer = Observer()
            self._file_observer.schedule(
                ConfigFileWatcher(self), 
                str(config_dir), 
                recursive=False
            )
            self._file_observer.start()
            self._auto_reload_enabled = True
            print(f"Auto-reload enabled for configuration file: {self._config_path}")
            return True
        except Exception as e:
            print(f"Failed to enable auto-reload: {e}")
            return False
    
    def disable_auto_reload(self) -> None:
        """Disable automatic configuration reload"""
        if self._file_observer:
            self._file_observer.stop()
            self._file_observer.join()
            self._file_observer = None
        self._auto_reload_enabled = False
        print("Auto-reload disabled")
    
    def add_reload_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Add callback to be called when configuration is reloaded"""
        self._reload_callbacks.append(callback)
    
    def remove_reload_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Remove reload callback"""
        if callback in self._reload_callbacks:
            self._reload_callbacks.remove(callback)
    
    def _notify_reload_callbacks(self) -> None:
        """Notify all registered callbacks about configuration changes"""
        config_copy = self._config.copy()
        for callback in self._reload_callbacks:
            try:
                callback(config_copy)
            except Exception as e:
                print(f"Error in configuration reload callback: {e}")
    
    def _handle_config_file_change(self) -> None:
        """Handle configuration file change event"""
        print(f"Configuration file changed: {self._config_path}")
        success = self.reload_config()
        if success:
            print("Configuration reloaded successfully")
        else:
            print("Failed to reload configuration")
    
    def _apply_environment_overrides(self) -> None:
        """Apply environment variable overrides to configuration"""
        # Map of environment variables to config keys
        env_mappings = {
            'HEIMDAL_CAPTURE_INTERFACE': 'capture.interface',
            'HEIMDAL_ASGARD_API_KEY': 'asgard.api_key',
            'HEIMDAL_ASGARD_API_ENDPOINT': 'asgard.api_endpoint',
            'HEIMDAL_LOG_LEVEL': 'logging.level',
            'HEIMDAL_LOG_PATH': 'logging.file_path',
            'HEIMDAL_SENSOR_ID': 'system.sensor_id',
            'HEIMDAL_SENSOR_LOCATION': 'system.location'
        }
        
        for env_var, config_key in env_mappings.items():
            env_value = os.getenv(env_var)
            if env_value:
                self._set_nested_value(self._config, config_key, env_value)
                print(f"Applied environment override: {config_key} = {env_value}")
    
    def _set_nested_value(self, config: Dict[str, Any], key: str, value: Any) -> None:
        """Set nested value in config dictionary using dot notation"""
        keys = key.split('.')
        current = config
        
        # Navigate to the parent of the target key
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        
        # Set the final value
        current[keys[-1]] = value
    
    def export_config_template(self, output_path: str, format: str = 'yaml') -> bool:
        """Export a configuration template with all available options"""
        try:
            template_config = self._get_template_config()
            
            with open(output_path, 'w') as f:
                if format.lower() == 'yaml':
                    yaml.dump(template_config, f, default_flow_style=False, indent=2)
                else:
                    json.dump(template_config, f, indent=2)
            
            print(f"Configuration template exported to: {output_path}")
            return True
        except Exception as e:
            print(f"Failed to export configuration template: {e}")
            return False
    
    def _get_template_config(self) -> Dict[str, Any]:
        """Get configuration template with comments and descriptions"""
        return {
            'capture': {
                'interface': 'eth0',  # Network interface to monitor
                'filter_expression': None,  # Optional BPF filter expression
                'max_packet_buffer_size': 10000,  # Maximum packets to buffer
                'capture_timeout': 1.0  # Capture timeout in seconds
            },
            'analysis': {
                'processing_batch_size': 100,  # Packets to process in each batch
                'device_timeout_seconds': 300,  # Timeout for inactive devices
                'feature_extraction_interval': 60  # Seconds between feature extraction
            },
            'anomaly_detection': {
                'thresholds': {
                    'new_destination': 0.7,  # Threshold for new destination anomalies
                    'unusual_volume': 0.8,  # Threshold for traffic volume anomalies
                    'protocol_violation': 0.9,  # Threshold for protocol violations
                    'timing_anomaly': 0.6,  # Threshold for timing anomalies
                    'geolocation_violation': 0.85  # Threshold for geolocation violations
                },
                'baseline_update_frequency': 60,  # Seconds between baseline updates
                'anomaly_correlation_window': 300  # Seconds to correlate related anomalies
            },
            'baseline': {
                'rolling_window_days': 7,  # Days of behavior to maintain in baseline
                'max_baseline_age_days': 30,  # Maximum age before baseline cleanup
                'confidence_threshold': 0.5,  # Minimum confidence for baseline updates
                'auto_save_interval': 300  # Seconds between automatic baseline saves
            },
            'asgard': {
                'api_endpoint': 'https://api.asgard.cortexa.ai',
                'api_key': '',  # Your Asgard API key (set via environment variable)
                'retry_attempts': 3,  # Number of retry attempts for failed requests
                'retry_backoff_seconds': 5,  # Seconds to wait between retries
                'connection_timeout': 30,  # Connection timeout in seconds
                'metadata_queue_size': 1000  # Maximum queued metadata items
            },
            'logging': {
                'level': 'INFO',  # Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL
                'file_path': '/var/log/heimdal/heimdal.log',  # Log file path
                'max_file_size_mb': 100,  # Maximum log file size in MB
                'backup_count': 5,  # Number of backup log files to keep
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            },
            'system': {
                'sensor_id': '',  # Unique sensor identifier (auto-generated if empty)
                'location': '',  # Sensor location description
                'capabilities': [
                    'packet_capture',
                    'anomaly_detection',
                    'baseline_management'
                ],
                'performance_monitoring': True,  # Enable performance monitoring
                'health_check_interval': 60  # Seconds between health checks
            }
        }
    
    def __del__(self):
        """Cleanup when configuration manager is destroyed"""
        self.disable_auto_reload()