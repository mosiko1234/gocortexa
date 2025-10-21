"""
Configuration management system for Heimdal
"""

import json
import yaml
import os
from typing import Any, Dict, List, Optional
from pathlib import Path

from ..interfaces import IConfigurationManager
from ..models import TrafficPattern


class ConfigurationManager(IConfigurationManager):
    """Configuration manager supporting YAML and JSON config files"""
    
    def __init__(self, config_path: Optional[str] = None):
        self._config: Dict[str, Any] = {}
        self._config_path: Optional[str] = config_path
        self._default_config = self._get_default_config()
        
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
            
            # Merge with defaults
            self._config = self._merge_configs(self._default_config, loaded_config or {})
            self._config_path = config_path
            
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
        keys = key.split('.')
        config = self._config
        
        # Navigate to the parent of the target key
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        # Set the final value
        config[keys[-1]] = value
    
    def reload_config(self) -> bool:
        """Reload configuration from file"""
        if self._config_path:
            return self.load_config(self._config_path)
        return False
    
    def validate_config(self) -> List[str]:
        """Validate configuration and return list of errors"""
        errors = []
        
        # Validate capture interface
        interface = self.get_config('capture.interface')
        if not interface:
            errors.append("Capture interface not specified")
        
        # Validate Asgard API configuration
        api_endpoint = self.get_config('asgard.api_endpoint')
        if not api_endpoint or not api_endpoint.startswith('http'):
            errors.append("Invalid Asgard API endpoint")
        
        api_key = self.get_config('asgard.api_key')
        if not api_key:
            errors.append("Asgard API key not configured")
        
        # Validate logging configuration
        log_path = self.get_config('logging.file_path')
        if log_path:
            log_dir = Path(log_path).parent
            if not log_dir.exists():
                try:
                    log_dir.mkdir(parents=True, exist_ok=True)
                except Exception as e:
                    errors.append(f"Cannot create log directory {log_dir}: {e}")
        
        # Validate anomaly thresholds
        thresholds = self.get_config('anomaly_detection.thresholds', {})
        for threshold_name, threshold_value in thresholds.items():
            if not isinstance(threshold_value, (int, float)) or not (0 <= threshold_value <= 1):
                errors.append(f"Invalid threshold value for {threshold_name}: {threshold_value}")
        
        # Validate system configuration
        sensor_id = self.get_config('system.sensor_id')
        if not sensor_id:
            errors.append("Sensor ID not configured")
        
        return errors
    
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
        return self._config.copy()