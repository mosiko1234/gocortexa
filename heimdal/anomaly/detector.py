"""
Core Anomaly Detection Engine for Heimdal

This module implements the main anomaly detection algorithms that compare
current device behavior against established baselines to identify potential
security threats and unusual network activity.
"""

import logging
import math
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass

from ..models import (
    DeviceBehavior, DeviceBaseline, Anomaly, AnomalyType, 
    SeverityLevel, Connection, TrafficVolume
)
from ..interfaces import IAnomalyDetector, IBaselineManager


@dataclass
class AnomalyThresholds:
    """Configuration for anomaly detection thresholds"""
    new_destination_threshold: float = 0.7
    volume_deviation_threshold: float = 2.0  # Standard deviations
    timing_anomaly_threshold: float = 0.8
    protocol_violation_threshold: float = 0.9
    geolocation_violation_threshold: float = 0.95
    
    # Severity level thresholds
    low_severity_threshold: float = 0.3
    medium_severity_threshold: float = 0.6
    high_severity_threshold: float = 0.8
    critical_severity_threshold: float = 0.9


class AnomalyDetector(IAnomalyDetector):
    """
    Core anomaly detection engine that compares device behavior against baselines.
    
    Implements multiple detection algorithms:
    - New destination detection
    - Traffic volume anomalies
    - Protocol violations
    - Timing anomalies
    - Geolocation violations
    """
    
    def __init__(self, baseline_manager: IBaselineManager, thresholds: Optional[AnomalyThresholds] = None):
        """
        Initialize the anomaly detector.
        
        Args:
            baseline_manager: Manager for device baselines
            thresholds: Custom threshold configuration
        """
        self.baseline_manager = baseline_manager
        self.thresholds = thresholds or AnomalyThresholds()
        self.logger = logging.getLogger(__name__)
        
        # Cache for recent behavior to detect patterns
        self._recent_behavior_cache: Dict[str, List[DeviceBehavior]] = {}
        self._cache_max_age = timedelta(hours=1)
        self._cache_max_entries = 100
    
    def detect_anomalies(self, device_id: str, current_behavior: DeviceBehavior) -> List[Anomaly]:
        """
        Detect anomalies by comparing current behavior to baseline.
        
        Args:
            device_id: Device identifier
            current_behavior: Current behavioral data
            
        Returns:
            List of detected anomalies
        """
        anomalies = []
        
        try:
            # Get device baseline
            baseline = self.baseline_manager.get_device_baseline(device_id)
            if baseline is None:
                self.logger.debug(f"No baseline found for device {device_id}, skipping anomaly detection")
                return anomalies
            
            # Update behavior cache
            self._update_behavior_cache(device_id, current_behavior)
            
            # Run different anomaly detection algorithms
            anomalies.extend(self._detect_new_destinations(device_id, baseline, current_behavior))
            anomalies.extend(self._detect_volume_anomalies(device_id, baseline, current_behavior))
            anomalies.extend(self._detect_protocol_violations(device_id, baseline, current_behavior))
            anomalies.extend(self._detect_timing_anomalies(device_id, baseline, current_behavior))
            anomalies.extend(self._detect_geolocation_violations(device_id, baseline, current_behavior))
            
            # Classify and enrich anomalies
            for anomaly in anomalies:
                self.classify_anomaly_type(anomaly)
            
            self.logger.debug(f"Detected {len(anomalies)} anomalies for device {device_id}")
            
        except Exception as e:
            self.logger.error(f"Error detecting anomalies for device {device_id}: {e}")
        
        return anomalies
    
    def calculate_anomaly_score(self, baseline: DeviceBaseline, behavior: DeviceBehavior) -> float:
        """
        Calculate overall anomaly score for given behavior.
        
        Args:
            baseline: Device baseline
            behavior: Current behavior
            
        Returns:
            Anomaly score between 0.0 and 1.0
        """
        try:
            scores = []
            
            # Destination anomaly score
            dest_score = self._calculate_destination_anomaly_score(baseline, behavior)
            scores.append(dest_score)
            
            # Volume anomaly score
            volume_score = self._calculate_volume_anomaly_score(baseline, behavior)
            scores.append(volume_score)
            
            # Protocol anomaly score
            protocol_score = self._calculate_protocol_anomaly_score(baseline, behavior)
            scores.append(protocol_score)
            
            # Timing anomaly score
            timing_score = self._calculate_timing_anomaly_score(baseline, behavior)
            scores.append(timing_score)
            
            # Calculate weighted average (can be customized based on threat model)
            weights = [0.3, 0.25, 0.25, 0.2]  # Destinations, Volume, Protocol, Timing
            weighted_score = sum(score * weight for score, weight in zip(scores, weights))
            
            return min(1.0, max(0.0, weighted_score))
            
        except Exception as e:
            self.logger.error(f"Error calculating anomaly score: {e}")
            return 0.0
    
    def classify_anomaly_type(self, anomaly: Anomaly) -> Anomaly:
        """
        Classify and enrich anomaly with additional details.
        
        Args:
            anomaly: Anomaly to classify
            
        Returns:
            Enriched anomaly with updated classification
        """
        try:
            # Determine severity based on confidence score
            if anomaly.confidence_score >= self.thresholds.critical_severity_threshold:
                anomaly.severity = SeverityLevel.CRITICAL
            elif anomaly.confidence_score >= self.thresholds.high_severity_threshold:
                anomaly.severity = SeverityLevel.HIGH
            elif anomaly.confidence_score >= self.thresholds.medium_severity_threshold:
                anomaly.severity = SeverityLevel.MEDIUM
            else:
                anomaly.severity = SeverityLevel.LOW
            
            # Enhance description based on anomaly type
            anomaly.description = self._generate_anomaly_description(anomaly)
            
        except Exception as e:
            self.logger.error(f"Error classifying anomaly: {e}")
        
        return anomaly
    
    def set_thresholds(self, thresholds: Dict[str, float]) -> None:
        """
        Set anomaly detection thresholds.
        
        Args:
            thresholds: Dictionary of threshold values
        """
        try:
            for key, value in thresholds.items():
                if hasattr(self.thresholds, key):
                    setattr(self.thresholds, key, value)
                    self.logger.debug(f"Updated threshold {key} to {value}")
                else:
                    self.logger.warning(f"Unknown threshold key: {key}")
        
        except Exception as e:
            self.logger.error(f"Error setting thresholds: {e}")
    
    def _detect_new_destinations(self, device_id: str, baseline: DeviceBaseline, behavior: DeviceBehavior) -> List[Anomaly]:
        """Detect connections to new/unknown destinations"""
        anomalies = []
        
        try:
            if not baseline.normal_destinations:
                return anomalies
            
            new_destinations = set()
            for connection in behavior.connections:
                if connection.destination_ip not in baseline.normal_destinations:
                    new_destinations.add(connection.destination_ip)
            
            if new_destinations:
                # Calculate anomaly score based on number of new destinations
                total_destinations = len(set(conn.destination_ip for conn in behavior.connections))
                new_ratio = len(new_destinations) / max(1, total_destinations)
                
                if new_ratio >= self.thresholds.new_destination_threshold:
                    anomaly = Anomaly(
                        device_id=device_id,
                        anomaly_type=AnomalyType.NEW_DESTINATION,
                        severity=SeverityLevel.MEDIUM,  # Will be updated in classify_anomaly_type
                        description=f"Device connected to {len(new_destinations)} new destinations",
                        timestamp=behavior.timestamp,
                        confidence_score=min(1.0, new_ratio),
                        baseline_deviation=new_ratio
                    )
                    anomalies.append(anomaly)
        
        except Exception as e:
            self.logger.error(f"Error detecting new destinations: {e}")
        
        return anomalies
    
    def _detect_volume_anomalies(self, device_id: str, baseline: DeviceBaseline, behavior: DeviceBehavior) -> List[Anomaly]:
        """Detect unusual traffic volume patterns"""
        anomalies = []
        
        try:
            if not behavior.traffic_volume or not baseline.traffic_patterns:
                return anomalies
            
            # Get recent behavior for statistical analysis
            recent_behaviors = self._get_recent_behaviors(device_id)
            if len(recent_behaviors) < 3:  # Need minimum data for statistical analysis
                return anomalies
            
            # Calculate volume statistics from recent behavior
            recent_volumes = [b.traffic_volume for b in recent_behaviors if b.traffic_volume]
            if not recent_volumes:
                return anomalies
            
            # Calculate mean and standard deviation
            bytes_sent_values = [v.bytes_sent for v in recent_volumes]
            bytes_received_values = [v.bytes_received for v in recent_volumes]
            
            sent_mean = sum(bytes_sent_values) / len(bytes_sent_values)
            received_mean = sum(bytes_received_values) / len(bytes_received_values)
            
            sent_std = math.sqrt(sum((x - sent_mean) ** 2 for x in bytes_sent_values) / len(bytes_sent_values))
            received_std = math.sqrt(sum((x - received_mean) ** 2 for x in bytes_received_values) / len(bytes_received_values))
            
            # Check for volume anomalies
            current_sent = behavior.traffic_volume.bytes_sent
            current_received = behavior.traffic_volume.bytes_received
            
            sent_deviation = abs(current_sent - sent_mean) / max(1, sent_std)
            received_deviation = abs(current_received - received_mean) / max(1, received_std)
            
            max_deviation = max(sent_deviation, received_deviation)
            
            if max_deviation >= self.thresholds.volume_deviation_threshold:
                anomaly = Anomaly(
                    device_id=device_id,
                    anomaly_type=AnomalyType.UNUSUAL_VOLUME,
                    severity=SeverityLevel.MEDIUM,
                    description=f"Unusual traffic volume detected (deviation: {max_deviation:.2f}σ)",
                    timestamp=behavior.timestamp,
                    confidence_score=min(1.0, max_deviation / 5.0),  # Normalize to 0-1
                    baseline_deviation=max_deviation
                )
                anomalies.append(anomaly)
        
        except Exception as e:
            self.logger.error(f"Error detecting volume anomalies: {e}")
        
        return anomalies
    
    def _detect_protocol_violations(self, device_id: str, baseline: DeviceBaseline, behavior: DeviceBehavior) -> List[Anomaly]:
        """Detect unusual protocol usage"""
        anomalies = []
        
        try:
            if not baseline.traffic_patterns or not baseline.traffic_patterns.common_ports:
                return anomalies
            
            # Check for connections to unusual ports
            unusual_ports = set()
            for connection in behavior.connections:
                if connection.destination_port not in baseline.traffic_patterns.common_ports:
                    unusual_ports.add(connection.destination_port)
            
            # Check for unusual protocols
            baseline_protocols = set()
            recent_behaviors = self._get_recent_behaviors(device_id)
            for recent_behavior in recent_behaviors[-10:]:  # Last 10 behaviors
                baseline_protocols.update(recent_behavior.protocols_used)
            
            unusual_protocols = behavior.protocols_used - baseline_protocols
            
            # Calculate violation score
            total_connections = len(behavior.connections)
            unusual_connections = sum(1 for conn in behavior.connections 
                                    if conn.destination_port in unusual_ports)
            
            if total_connections > 0:
                violation_ratio = unusual_connections / total_connections
                
                if (violation_ratio >= self.thresholds.protocol_violation_threshold or 
                    len(unusual_protocols) > 0):
                    
                    anomaly = Anomaly(
                        device_id=device_id,
                        anomaly_type=AnomalyType.PROTOCOL_VIOLATION,
                        severity=SeverityLevel.MEDIUM,
                        description=f"Unusual protocol usage detected (ports: {unusual_ports}, protocols: {unusual_protocols})",
                        timestamp=behavior.timestamp,
                        confidence_score=min(1.0, violation_ratio + len(unusual_protocols) * 0.2),
                        baseline_deviation=violation_ratio
                    )
                    anomalies.append(anomaly)
        
        except Exception as e:
            self.logger.error(f"Error detecting protocol violations: {e}")
        
        return anomalies
    
    def _detect_timing_anomalies(self, device_id: str, baseline: DeviceBaseline, behavior: DeviceBehavior) -> List[Anomaly]:
        """Detect unusual timing patterns"""
        anomalies = []
        
        try:
            if not baseline.traffic_patterns or not baseline.traffic_patterns.peak_hours:
                return anomalies
            
            current_hour = behavior.timestamp.hour
            
            # Check if current activity is outside normal peak hours
            if current_hour not in baseline.traffic_patterns.peak_hours:
                # Calculate how far from normal hours
                min_distance = min(abs(current_hour - peak_hour) for peak_hour in baseline.traffic_patterns.peak_hours)
                
                # Normalize distance (max distance is 12 hours)
                timing_anomaly_score = min_distance / 12.0
                
                if timing_anomaly_score >= self.thresholds.timing_anomaly_threshold:
                    anomaly = Anomaly(
                        device_id=device_id,
                        anomaly_type=AnomalyType.TIMING_ANOMALY,
                        severity=SeverityLevel.LOW,
                        description=f"Activity detected outside normal hours (current: {current_hour}:00, normal: {baseline.traffic_patterns.peak_hours})",
                        timestamp=behavior.timestamp,
                        confidence_score=timing_anomaly_score,
                        baseline_deviation=timing_anomaly_score
                    )
                    anomalies.append(anomaly)
        
        except Exception as e:
            self.logger.error(f"Error detecting timing anomalies: {e}")
        
        return anomalies
    
    def _detect_geolocation_violations(self, device_id: str, baseline: DeviceBaseline, behavior: DeviceBehavior) -> List[Anomaly]:
        """Detect connections to unusual geographic locations"""
        anomalies = []
        
        try:
            # This is a simplified implementation - in practice, you'd use a GeoIP database
            # For now, we'll detect connections to private vs public IP ranges
            
            suspicious_destinations = []
            for connection in behavior.connections:
                if self._is_suspicious_destination(connection.destination_ip, baseline):
                    suspicious_destinations.append(connection.destination_ip)
            
            if suspicious_destinations:
                violation_ratio = len(suspicious_destinations) / len(behavior.connections)
                
                if violation_ratio >= self.thresholds.geolocation_violation_threshold:
                    anomaly = Anomaly(
                        device_id=device_id,
                        anomaly_type=AnomalyType.GEOLOCATION_VIOLATION,
                        severity=SeverityLevel.HIGH,
                        description=f"Connections to suspicious destinations: {len(suspicious_destinations)} IPs",
                        timestamp=behavior.timestamp,
                        confidence_score=violation_ratio,
                        baseline_deviation=violation_ratio
                    )
                    anomalies.append(anomaly)
        
        except Exception as e:
            self.logger.error(f"Error detecting geolocation violations: {e}")
        
        return anomalies
    
    def _calculate_destination_anomaly_score(self, baseline: DeviceBaseline, behavior: DeviceBehavior) -> float:
        """Calculate anomaly score based on destination analysis"""
        if not baseline.normal_destinations or not behavior.connections:
            return 0.0
        
        current_destinations = set(conn.destination_ip for conn in behavior.connections)
        new_destinations = current_destinations - baseline.normal_destinations
        
        if not current_destinations:
            return 0.0
        
        return len(new_destinations) / len(current_destinations)
    
    def _calculate_volume_anomaly_score(self, baseline: DeviceBaseline, behavior: DeviceBehavior) -> float:
        """Calculate anomaly score based on traffic volume"""
        if not behavior.traffic_volume:
            return 0.0
        
        # Simplified volume scoring - in practice, you'd use historical data
        # For now, we'll use a basic threshold approach
        total_bytes = behavior.traffic_volume.bytes_sent + behavior.traffic_volume.bytes_received
        
        # Define "normal" range (this would come from baseline statistics)
        normal_range = (1024, 10 * 1024 * 1024)  # 1KB to 10MB
        
        if total_bytes < normal_range[0]:
            return 0.1  # Very low traffic
        elif total_bytes > normal_range[1]:
            return min(1.0, total_bytes / (100 * 1024 * 1024))  # Scale up to 100MB
        else:
            return 0.0
    
    def _calculate_protocol_anomaly_score(self, baseline: DeviceBaseline, behavior: DeviceBehavior) -> float:
        """Calculate anomaly score based on protocol usage"""
        if not baseline.traffic_patterns or not baseline.traffic_patterns.common_ports:
            return 0.0
        
        unusual_ports = 0
        total_connections = len(behavior.connections)
        
        for connection in behavior.connections:
            if connection.destination_port not in baseline.traffic_patterns.common_ports:
                unusual_ports += 1
        
        if total_connections == 0:
            return 0.0
        
        return unusual_ports / total_connections
    
    def _calculate_timing_anomaly_score(self, baseline: DeviceBaseline, behavior: DeviceBehavior) -> float:
        """Calculate anomaly score based on timing patterns"""
        if not baseline.traffic_patterns or not baseline.traffic_patterns.peak_hours:
            return 0.0
        
        current_hour = behavior.timestamp.hour
        
        if current_hour in baseline.traffic_patterns.peak_hours:
            return 0.0
        
        # Calculate distance from nearest peak hour
        min_distance = min(abs(current_hour - peak_hour) for peak_hour in baseline.traffic_patterns.peak_hours)
        return min_distance / 12.0  # Normalize to 0-1
    
    def _is_suspicious_destination(self, ip_address: str, baseline: DeviceBaseline) -> bool:
        """Check if destination IP is suspicious"""
        # Simplified implementation - check for known suspicious patterns
        
        # Check if it's a new destination not in baseline
        if ip_address not in baseline.normal_destinations:
            # Additional checks could include:
            # - Known malicious IP lists
            # - Unusual geographic locations
            # - Tor exit nodes
            # - Recently registered domains
            
            # For now, flag IPs that look suspicious based on simple patterns
            if (ip_address.startswith('10.') or 
                ip_address.startswith('192.168.') or 
                ip_address.startswith('172.')):
                return False  # Private IPs are generally safe
            
            # Flag certain suspicious patterns (this is very basic)
            suspicious_patterns = ['0.0.0.0', '127.', '255.255.255.255']
            return any(pattern in ip_address for pattern in suspicious_patterns)
        
        return False
    
    def _update_behavior_cache(self, device_id: str, behavior: DeviceBehavior) -> None:
        """Update the recent behavior cache for a device"""
        if device_id not in self._recent_behavior_cache:
            self._recent_behavior_cache[device_id] = []
        
        # Add new behavior
        self._recent_behavior_cache[device_id].append(behavior)
        
        # Clean up old entries
        cutoff_time = datetime.now() - self._cache_max_age
        self._recent_behavior_cache[device_id] = [
            b for b in self._recent_behavior_cache[device_id] 
            if b.timestamp > cutoff_time
        ]
        
        # Limit cache size
        if len(self._recent_behavior_cache[device_id]) > self._cache_max_entries:
            self._recent_behavior_cache[device_id] = self._recent_behavior_cache[device_id][-self._cache_max_entries:]
    
    def _get_recent_behaviors(self, device_id: str) -> List[DeviceBehavior]:
        """Get recent behaviors for a device"""
        return self._recent_behavior_cache.get(device_id, [])
    
    def _generate_anomaly_description(self, anomaly: Anomaly) -> str:
        """Generate detailed description for an anomaly"""
        base_descriptions = {
            AnomalyType.NEW_DESTINATION: "Device connected to previously unseen destinations",
            AnomalyType.UNUSUAL_VOLUME: "Traffic volume significantly differs from normal patterns",
            AnomalyType.PROTOCOL_VIOLATION: "Unusual protocol or port usage detected",
            AnomalyType.TIMING_ANOMALY: "Network activity outside normal time patterns",
            AnomalyType.GEOLOCATION_VIOLATION: "Connections to suspicious geographic locations"
        }
        
        base_desc = base_descriptions.get(anomaly.anomaly_type, "Unknown anomaly type")
        
        # Add severity and confidence information
        severity_text = anomaly.severity.value.upper()
        confidence_pct = int(anomaly.confidence_score * 100)
        
        return f"{base_desc} (Severity: {severity_text}, Confidence: {confidence_pct}%)"