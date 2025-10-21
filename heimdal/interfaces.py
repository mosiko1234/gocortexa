"""
Core interfaces for Heimdal real-time monitoring system
"""

from abc import ABC, abstractmethod
from typing import Iterator, List, Optional, Dict, Any
from scapy.packet import Packet

from .models import (
    DeviceBehavior, DeviceBaseline, DeviceFeatures, Anomaly, 
    AnonymizedAnomaly, AnonymizedDevice, GoldenProfile, 
    IntelligenceUpdate, SensorInfo, CaptureStats
)


class IPacketCaptureEngine(ABC):
    """Interface for packet capture engine"""
    
    @abstractmethod
    def start_capture(self, interface: str, filter_expression: Optional[str] = None) -> bool:
        """Start capturing packets from the specified interface"""
        pass
    
    @abstractmethod
    def stop_capture(self) -> bool:
        """Stop packet capture"""
        pass
    
    @abstractmethod
    def get_packet_stream(self) -> Iterator[Packet]:
        """Get iterator for captured packets"""
        pass
    
    @abstractmethod
    def get_capture_statistics(self) -> CaptureStats:
        """Get current capture statistics"""
        pass
    
    @abstractmethod
    def is_capturing(self) -> bool:
        """Check if currently capturing packets"""
        pass


class IRealtimeAnalyzer(ABC):
    """Interface for real-time packet analyzer"""
    
    @abstractmethod
    def process_packet(self, packet: Packet) -> Optional[DeviceBehavior]:
        """Process a single packet and return device behavior if significant"""
        pass
    
    @abstractmethod
    def extract_device_features(self, packet: Packet) -> Optional[DeviceFeatures]:
        """Extract device features from a packet"""
        pass
    
    @abstractmethod
    def update_device_activity(self, device_id: str, features: DeviceFeatures) -> None:
        """Update device activity tracking"""
        pass
    
    @abstractmethod
    def get_device_behavior(self, device_id: str) -> Optional[DeviceBehavior]:
        """Get current behavior for a device"""
        pass


class IBaselineManager(ABC):
    """Interface for baseline management"""
    
    @abstractmethod
    def get_device_baseline(self, device_id: str) -> Optional[DeviceBaseline]:
        """Get baseline for a specific device"""
        pass
    
    @abstractmethod
    def update_baseline(self, device_id: str, new_behavior: DeviceBehavior) -> bool:
        """Update baseline with new behavioral data"""
        pass
    
    @abstractmethod
    def integrate_global_profile(self, device_type: str, golden_profile: GoldenProfile) -> bool:
        """Integrate global profile into local baselines"""
        pass
    
    @abstractmethod
    def save_baselines(self) -> bool:
        """Save baselines to persistent storage"""
        pass
    
    @abstractmethod
    def load_baselines(self) -> bool:
        """Load baselines from persistent storage"""
        pass
    
    @abstractmethod
    def get_all_baselines(self) -> Dict[str, DeviceBaseline]:
        """Get all device baselines"""
        pass


class IAnomalyDetector(ABC):
    """Interface for anomaly detection"""
    
    @abstractmethod
    def detect_anomalies(self, device_id: str, current_behavior: DeviceBehavior) -> List[Anomaly]:
        """Detect anomalies by comparing current behavior to baseline"""
        pass
    
    @abstractmethod
    def calculate_anomaly_score(self, baseline: DeviceBaseline, behavior: DeviceBehavior) -> float:
        """Calculate anomaly score for given behavior"""
        pass
    
    @abstractmethod
    def classify_anomaly_type(self, anomaly: Anomaly) -> Anomaly:
        """Classify and enrich anomaly with additional details"""
        pass
    
    @abstractmethod
    def set_thresholds(self, thresholds: Dict[str, float]) -> None:
        """Set anomaly detection thresholds"""
        pass


class IAsgardCommunicator(ABC):
    """Interface for Asgard cloud communication"""
    
    @abstractmethod
    def send_anomaly_metadata(self, anonymized_anomaly: AnonymizedAnomaly) -> bool:
        """Send anonymized anomaly data to Asgard"""
        pass
    
    @abstractmethod
    def send_device_metadata(self, anonymized_device: AnonymizedDevice) -> bool:
        """Send anonymized device data to Asgard"""
        pass
    
    @abstractmethod
    def receive_intelligence_updates(self) -> List[IntelligenceUpdate]:
        """Receive intelligence updates from Asgard"""
        pass
    
    @abstractmethod
    def register_sensor(self, sensor_info: SensorInfo) -> Optional[str]:
        """Register sensor with Asgard and return sensor ID"""
        pass
    
    @abstractmethod
    def is_connected(self) -> bool:
        """Check if connected to Asgard"""
        pass


class IDataAnonymizer(ABC):
    """Interface for data anonymization"""
    
    @abstractmethod
    def anonymize_anomaly(self, anomaly: Anomaly) -> AnonymizedAnomaly:
        """Anonymize anomaly data for cloud transmission"""
        pass
    
    @abstractmethod
    def anonymize_device(self, device_behavior: DeviceBehavior) -> AnonymizedDevice:
        """Anonymize device data for cloud transmission"""
        pass
    
    @abstractmethod
    def anonymize_ip_address(self, ip_address: str) -> str:
        """Convert IP address to geographic region"""
        pass
    
    @abstractmethod
    def anonymize_mac_address(self, mac_address: str) -> str:
        """Convert MAC address to device type fingerprint"""
        pass


class IConfigurationManager(ABC):
    """Interface for configuration management"""
    
    @abstractmethod
    def load_config(self, config_path: str) -> bool:
        """Load configuration from file"""
        pass
    
    @abstractmethod
    def get_config(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        pass
    
    @abstractmethod
    def set_config(self, key: str, value: Any) -> None:
        """Set configuration value"""
        pass
    
    @abstractmethod
    def reload_config(self) -> bool:
        """Reload configuration without restart"""
        pass
    
    @abstractmethod
    def validate_config(self) -> List[str]:
        """Validate configuration and return list of errors"""
        pass


class ILogger(ABC):
    """Interface for logging system"""
    
    @abstractmethod
    def debug(self, message: str, **kwargs) -> None:
        """Log debug message"""
        pass
    
    @abstractmethod
    def info(self, message: str, **kwargs) -> None:
        """Log info message"""
        pass
    
    @abstractmethod
    def warning(self, message: str, **kwargs) -> None:
        """Log warning message"""
        pass
    
    @abstractmethod
    def error(self, message: str, **kwargs) -> None:
        """Log error message"""
        pass
    
    @abstractmethod
    def critical(self, message: str, **kwargs) -> None:
        """Log critical message"""
        pass


class IMonitoringOrchestrator(ABC):
    """Interface for main monitoring orchestrator"""
    
    @abstractmethod
    def start(self) -> bool:
        """Start the monitoring system"""
        pass
    
    @abstractmethod
    def stop(self) -> bool:
        """Stop the monitoring system"""
        pass
    
    @abstractmethod
    def is_running(self) -> bool:
        """Check if monitoring system is running"""
        pass
    
    @abstractmethod
    def get_status(self) -> Dict[str, Any]:
        """Get system status information"""
        pass
    
    @abstractmethod
    def restart_component(self, component_name: str) -> bool:
        """Restart a specific component"""
        pass