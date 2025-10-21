"""
Core data models for Heimdal real-time monitoring system
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Set, Optional, Any
import json


class AnomalyType(Enum):
    """Types of anomalies that can be detected"""
    NEW_DESTINATION = "new_destination"
    UNUSUAL_VOLUME = "unusual_volume"
    PROTOCOL_VIOLATION = "protocol_violation"
    TIMING_ANOMALY = "timing_anomaly"
    GEOLOCATION_VIOLATION = "geolocation_violation"


class SeverityLevel(Enum):
    """Severity levels for anomalies"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Connection:
    """Represents a network connection"""
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    timestamp: datetime
    bytes_sent: int = 0
    bytes_received: int = 0


@dataclass
class TrafficVolume:
    """Traffic volume metrics"""
    bytes_sent: int
    bytes_received: int
    packets_sent: int
    packets_received: int
    duration_seconds: float


@dataclass
class TrafficPattern:
    """Traffic pattern characteristics"""
    peak_hours: List[int] = field(default_factory=list)
    average_session_duration: float = 0.0
    typical_destinations: Set[str] = field(default_factory=set)
    common_ports: Set[int] = field(default_factory=set)


@dataclass
class DeviceBehavior:
    """Current behavioral data for a device"""
    device_id: str
    timestamp: datetime
    connections: List[Connection] = field(default_factory=list)
    traffic_volume: Optional[TrafficVolume] = None
    protocols_used: Set[str] = field(default_factory=set)
    dns_queries: List[str] = field(default_factory=list)


@dataclass
class DeviceBaseline:
    """Behavioral baseline for a device"""
    device_id: str
    device_type: str
    normal_destinations: Set[str] = field(default_factory=set)
    normal_ports: Set[int] = field(default_factory=set)
    traffic_patterns: Optional[TrafficPattern] = None
    last_updated: Optional[datetime] = None
    confidence_score: float = 0.0
    global_profile_version: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'device_id': self.device_id,
            'device_type': self.device_type,
            'normal_destinations': list(self.normal_destinations),
            'normal_ports': list(self.normal_ports),
            'traffic_patterns': {
                'peak_hours': self.traffic_patterns.peak_hours if self.traffic_patterns else [],
                'average_session_duration': self.traffic_patterns.average_session_duration if self.traffic_patterns else 0.0,
                'typical_destinations': list(self.traffic_patterns.typical_destinations) if self.traffic_patterns else [],
                'common_ports': list(self.traffic_patterns.common_ports) if self.traffic_patterns else []
            } if self.traffic_patterns else None,
            'last_updated': self.last_updated.isoformat() if self.last_updated else None,
            'confidence_score': self.confidence_score,
            'global_profile_version': self.global_profile_version
        }


@dataclass
class Anomaly:
    """Detected anomaly information"""
    device_id: str
    anomaly_type: AnomalyType
    severity: SeverityLevel
    description: str
    timestamp: datetime
    confidence_score: float
    baseline_deviation: float


@dataclass
class AnonymizedAnomaly:
    """Anonymized anomaly data for cloud transmission"""
    device_type: str
    anomaly_type: AnomalyType
    severity: SeverityLevel
    geographic_region: str
    timestamp: datetime
    behavioral_signature: str


@dataclass
class AnonymizedDevice:
    """Anonymized device data for cloud transmission"""
    device_type: str
    geographic_region: str
    behavioral_signature: str
    timestamp: datetime


@dataclass
class GoldenProfile:
    """Global device profile from Asgard"""
    device_type: str
    version: str
    normal_behaviors: Dict[str, Any]
    threat_indicators: List[str]
    last_updated: datetime


@dataclass
class IntelligenceUpdate:
    """Intelligence update from Asgard"""
    update_type: str
    content: Dict[str, Any]
    version: str
    timestamp: datetime


@dataclass
class SensorInfo:
    """Sensor registration information"""
    sensor_id: str
    location: str
    capabilities: List[str]
    version: str


@dataclass
class CaptureStats:
    """Packet capture statistics"""
    packets_captured: int
    packets_dropped: int
    packets_per_second: float
    bytes_captured: int
    capture_duration: float
    errors: int


@dataclass
class DeviceFeatures:
    """Extracted features from device traffic"""
    device_id: str
    mac_address: str
    ip_addresses: Set[str]
    protocols: Set[str]
    ports: Set[int]
    destinations: Set[str]
    traffic_volume: TrafficVolume
    timestamp: datetime