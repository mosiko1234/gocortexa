"""
Alert Management System for Heimdal Anomaly Detection

This module provides alert generation, correlation, and filtering capabilities
to prevent notification spam while ensuring critical threats are properly escalated.
"""

import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field
from enum import Enum

from ..models import Anomaly, AnomalyType, SeverityLevel


class AlertStatus(Enum):
    """Status of an alert"""
    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"


class CorrelationRule(Enum):
    """Rules for correlating related anomalies"""
    SAME_DEVICE = "same_device"
    SAME_TYPE = "same_type"
    TIME_WINDOW = "time_window"
    ESCALATION_PATTERN = "escalation_pattern"


@dataclass
class Alert:
    """Alert generated from one or more anomalies"""
    alert_id: str
    device_id: str
    alert_type: AnomalyType
    severity: SeverityLevel
    status: AlertStatus
    title: str
    description: str
    first_seen: datetime
    last_seen: datetime
    anomaly_count: int
    correlated_anomalies: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None


@dataclass
class AlertCorrelation:
    """Correlation between related alerts"""
    correlation_id: str
    primary_alert_id: str
    related_alert_ids: List[str]
    correlation_rule: CorrelationRule
    correlation_score: float
    created_at: datetime


@dataclass
class AlertFilterRule:
    """Rule for filtering/suppressing alerts"""
    rule_id: str
    name: str
    device_pattern: Optional[str] = None
    anomaly_types: Optional[Set[AnomalyType]] = None
    severity_threshold: Optional[SeverityLevel] = None
    time_window_minutes: int = 60
    max_alerts_per_window: int = 5
    enabled: bool = True


class AlertManager:
    """
    Manages alert generation, correlation, and filtering for anomaly detection.
    
    Features:
    - Generate alerts from anomalies with severity levels
    - Correlate related anomalies into incidents
    - Filter alerts to prevent notification spam
    - Track alert lifecycle and acknowledgments
    """
    
    def __init__(self, correlation_window_minutes: int = 30, max_alerts_per_device: int = 100):
        """
        Initialize the alert manager.
        
        Args:
            correlation_window_minutes: Time window for correlating related anomalies
            max_alerts_per_device: Maximum alerts to keep per device
        """
        self.correlation_window = timedelta(minutes=correlation_window_minutes)
        self.max_alerts_per_device = max_alerts_per_device
        self.logger = logging.getLogger(__name__)
        
        # Storage for alerts and correlations
        self._alerts: Dict[str, Alert] = {}
        self._device_alerts: Dict[str, List[str]] = {}  # device_id -> alert_ids
        self._correlations: Dict[str, AlertCorrelation] = {}
        self._filter_rules: Dict[str, AlertFilterRule] = {}
        
        # Initialize default filter rules
        self._initialize_default_filters()
    
    def generate_alert(self, anomaly: Anomaly) -> Optional[Alert]:
        """
        Generate an alert from an anomaly, applying correlation and filtering.
        
        Args:
            anomaly: Anomaly to generate alert from
            
        Returns:
            Generated alert or None if filtered/correlated
        """
        try:
            # Check if anomaly should be filtered
            if self._should_filter_anomaly(anomaly):
                self.logger.debug(f"Anomaly filtered for device {anomaly.device_id}")
                return None
            
            # Check for existing alerts to correlate with
            existing_alert = self._find_correlatable_alert(anomaly)
            
            if existing_alert:
                # Update existing alert with new anomaly
                self._update_correlated_alert(existing_alert, anomaly)
                return existing_alert
            else:
                # Create new alert
                alert = self._create_new_alert(anomaly)
                self._store_alert(alert)
                return alert
        
        except Exception as e:
            self.logger.error(f"Error generating alert: {e}")
            return None
    
    def acknowledge_alert(self, alert_id: str, acknowledged_by: str) -> bool:
        """
        Acknowledge an alert.
        
        Args:
            alert_id: Alert identifier
            acknowledged_by: User who acknowledged the alert
            
        Returns:
            True if successful, False otherwise
        """
        try:
            alert = self._alerts.get(alert_id)
            if not alert:
                self.logger.warning(f"Alert {alert_id} not found")
                return False
            
            alert.status = AlertStatus.ACKNOWLEDGED
            alert.acknowledged_by = acknowledged_by
            alert.acknowledged_at = datetime.now()
            
            self.logger.info(f"Alert {alert_id} acknowledged by {acknowledged_by}")
            return True
        
        except Exception as e:
            self.logger.error(f"Error acknowledging alert {alert_id}: {e}")
            return False
    
    def resolve_alert(self, alert_id: str) -> bool:
        """
        Resolve an alert.
        
        Args:
            alert_id: Alert identifier
            
        Returns:
            True if successful, False otherwise
        """
        try:
            alert = self._alerts.get(alert_id)
            if not alert:
                self.logger.warning(f"Alert {alert_id} not found")
                return False
            
            alert.status = AlertStatus.RESOLVED
            alert.resolved_at = datetime.now()
            
            self.logger.info(f"Alert {alert_id} resolved")
            return True
        
        except Exception as e:
            self.logger.error(f"Error resolving alert {alert_id}: {e}")
            return False
    
    def get_active_alerts(self, device_id: Optional[str] = None) -> List[Alert]:
        """
        Get active alerts, optionally filtered by device.
        
        Args:
            device_id: Optional device filter
            
        Returns:
            List of active alerts
        """
        try:
            active_alerts = []
            
            if device_id:
                alert_ids = self._device_alerts.get(device_id, [])
                for alert_id in alert_ids:
                    alert = self._alerts.get(alert_id)
                    if alert and alert.status == AlertStatus.ACTIVE:
                        active_alerts.append(alert)
            else:
                for alert in self._alerts.values():
                    if alert.status == AlertStatus.ACTIVE:
                        active_alerts.append(alert)
            
            # Sort by severity and timestamp
            active_alerts.sort(key=lambda a: (a.severity.value, a.last_seen), reverse=True)
            return active_alerts
        
        except Exception as e:
            self.logger.error(f"Error getting active alerts: {e}")
            return []
    
    def get_alert_statistics(self) -> Dict[str, Any]:
        """
        Get alert statistics and metrics.
        
        Returns:
            Dictionary with alert statistics
        """
        try:
            stats = {
                'total_alerts': len(self._alerts),
                'active_alerts': 0,
                'acknowledged_alerts': 0,
                'resolved_alerts': 0,
                'suppressed_alerts': 0,
                'alerts_by_severity': {level.value: 0 for level in SeverityLevel},
                'alerts_by_type': {atype.value: 0 for atype in AnomalyType},
                'correlations_count': len(self._correlations),
                'devices_with_alerts': len(self._device_alerts)
            }
            
            for alert in self._alerts.values():
                # Count by status
                if alert.status == AlertStatus.ACTIVE:
                    stats['active_alerts'] += 1
                elif alert.status == AlertStatus.ACKNOWLEDGED:
                    stats['acknowledged_alerts'] += 1
                elif alert.status == AlertStatus.RESOLVED:
                    stats['resolved_alerts'] += 1
                elif alert.status == AlertStatus.SUPPRESSED:
                    stats['suppressed_alerts'] += 1
                
                # Count by severity
                stats['alerts_by_severity'][alert.severity.value] += 1
                
                # Count by type
                stats['alerts_by_type'][alert.alert_type.value] += 1
            
            return stats
        
        except Exception as e:
            self.logger.error(f"Error getting alert statistics: {e}")
            return {}
    
    def add_filter_rule(self, rule: AlertFilterRule) -> bool:
        """
        Add a new alert filter rule.
        
        Args:
            rule: Filter rule to add
            
        Returns:
            True if successful, False otherwise
        """
        try:
            self._filter_rules[rule.rule_id] = rule
            self.logger.info(f"Added filter rule: {rule.name}")
            return True
        
        except Exception as e:
            self.logger.error(f"Error adding filter rule: {e}")
            return False
    
    def remove_filter_rule(self, rule_id: str) -> bool:
        """
        Remove an alert filter rule.
        
        Args:
            rule_id: Rule identifier to remove
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if rule_id in self._filter_rules:
                rule_name = self._filter_rules[rule_id].name
                del self._filter_rules[rule_id]
                self.logger.info(f"Removed filter rule: {rule_name}")
                return True
            else:
                self.logger.warning(f"Filter rule {rule_id} not found")
                return False
        
        except Exception as e:
            self.logger.error(f"Error removing filter rule: {e}")
            return False
    
    def cleanup_old_alerts(self, max_age_days: int = 30) -> int:
        """
        Clean up old resolved alerts.
        
        Args:
            max_age_days: Maximum age in days for keeping resolved alerts
            
        Returns:
            Number of alerts cleaned up
        """
        cleanup_count = 0
        cutoff_date = datetime.now() - timedelta(days=max_age_days)
        
        try:
            alerts_to_remove = []
            
            for alert_id, alert in self._alerts.items():
                if (alert.status == AlertStatus.RESOLVED and 
                    alert.resolved_at and 
                    alert.resolved_at < cutoff_date):
                    alerts_to_remove.append(alert_id)
            
            for alert_id in alerts_to_remove:
                alert = self._alerts[alert_id]
                
                # Remove from device alerts list
                if alert.device_id in self._device_alerts:
                    self._device_alerts[alert.device_id] = [
                        aid for aid in self._device_alerts[alert.device_id] if aid != alert_id
                    ]
                
                # Remove alert
                del self._alerts[alert_id]
                cleanup_count += 1
            
            if cleanup_count > 0:
                self.logger.info(f"Cleaned up {cleanup_count} old alerts")
            
            return cleanup_count
        
        except Exception as e:
            self.logger.error(f"Error cleaning up old alerts: {e}")
            return 0
    
    def _should_filter_anomaly(self, anomaly: Anomaly) -> bool:
        """Check if anomaly should be filtered based on rules"""
        try:
            for rule in self._filter_rules.values():
                if not rule.enabled:
                    continue
                
                # Check device pattern
                if rule.device_pattern and rule.device_pattern not in anomaly.device_id:
                    continue
                
                # Check anomaly type
                if rule.anomaly_types and anomaly.anomaly_type not in rule.anomaly_types:
                    continue
                
                # Check severity threshold
                if rule.severity_threshold:
                    severity_levels = [SeverityLevel.LOW, SeverityLevel.MEDIUM, SeverityLevel.HIGH, SeverityLevel.CRITICAL]
                    if severity_levels.index(anomaly.severity) < severity_levels.index(rule.severity_threshold):
                        continue
                
                # Check rate limiting
                if self._is_rate_limited(anomaly, rule):
                    return True
            
            return False
        
        except Exception as e:
            self.logger.error(f"Error checking filter rules: {e}")
            return False
    
    def _is_rate_limited(self, anomaly: Anomaly, rule: AlertFilterRule) -> bool:
        """Check if anomaly is rate limited by the rule"""
        try:
            # Count recent alerts for this device and type
            cutoff_time = datetime.now() - timedelta(minutes=rule.time_window_minutes)
            
            recent_count = 0
            device_alerts = self._device_alerts.get(anomaly.device_id, [])
            
            for alert_id in device_alerts:
                alert = self._alerts.get(alert_id)
                if (alert and 
                    alert.alert_type == anomaly.anomaly_type and
                    alert.last_seen > cutoff_time):
                    recent_count += 1
            
            return recent_count >= rule.max_alerts_per_window
        
        except Exception as e:
            self.logger.error(f"Error checking rate limit: {e}")
            return False
    
    def _find_correlatable_alert(self, anomaly: Anomaly) -> Optional[Alert]:
        """Find existing alert that can be correlated with the anomaly"""
        try:
            device_alerts = self._device_alerts.get(anomaly.device_id, [])
            cutoff_time = datetime.now() - self.correlation_window
            
            for alert_id in device_alerts:
                alert = self._alerts.get(alert_id)
                if not alert or alert.status != AlertStatus.ACTIVE:
                    continue
                
                # Check if within correlation window
                if alert.last_seen < cutoff_time:
                    continue
                
                # Check correlation criteria
                if self._can_correlate(alert, anomaly):
                    return alert
            
            return None
        
        except Exception as e:
            self.logger.error(f"Error finding correlatable alert: {e}")
            return None
    
    def _can_correlate(self, alert: Alert, anomaly: Anomaly) -> bool:
        """Check if alert and anomaly can be correlated"""
        # Same device and same type
        if alert.device_id == anomaly.device_id and alert.alert_type == anomaly.anomaly_type:
            return True
        
        # Same device with escalating severity
        if (alert.device_id == anomaly.device_id and 
            self._is_escalation_pattern(alert.severity, anomaly.severity)):
            return True
        
        return False
    
    def _is_escalation_pattern(self, current_severity: SeverityLevel, new_severity: SeverityLevel) -> bool:
        """Check if new severity represents an escalation"""
        severity_order = [SeverityLevel.LOW, SeverityLevel.MEDIUM, SeverityLevel.HIGH, SeverityLevel.CRITICAL]
        current_index = severity_order.index(current_severity)
        new_index = severity_order.index(new_severity)
        return new_index > current_index
    
    def _update_correlated_alert(self, alert: Alert, anomaly: Anomaly) -> None:
        """Update existing alert with correlated anomaly"""
        try:
            # Update alert metadata
            alert.last_seen = anomaly.timestamp
            alert.anomaly_count += 1
            
            # Escalate severity if needed
            if self._is_escalation_pattern(alert.severity, anomaly.severity):
                alert.severity = anomaly.severity
                alert.description = f"{alert.description} [ESCALATED to {anomaly.severity.value.upper()}]"
            
            # Add anomaly to correlation list
            anomaly_id = f"{anomaly.device_id}_{anomaly.timestamp.isoformat()}"
            alert.correlated_anomalies.append(anomaly_id)
            
            self.logger.debug(f"Updated correlated alert {alert.alert_id} with new anomaly")
        
        except Exception as e:
            self.logger.error(f"Error updating correlated alert: {e}")
    
    def _create_new_alert(self, anomaly: Anomaly) -> Alert:
        """Create a new alert from an anomaly"""
        alert_id = str(uuid.uuid4())
        
        # Generate alert title and description
        title = self._generate_alert_title(anomaly)
        description = self._generate_alert_description(anomaly)
        
        alert = Alert(
            alert_id=alert_id,
            device_id=anomaly.device_id,
            alert_type=anomaly.anomaly_type,
            severity=anomaly.severity,
            status=AlertStatus.ACTIVE,
            title=title,
            description=description,
            first_seen=anomaly.timestamp,
            last_seen=anomaly.timestamp,
            anomaly_count=1,
            correlated_anomalies=[f"{anomaly.device_id}_{anomaly.timestamp.isoformat()}"],
            metadata={
                'confidence_score': anomaly.confidence_score,
                'baseline_deviation': anomaly.baseline_deviation
            }
        )
        
        return alert
    
    def _store_alert(self, alert: Alert) -> None:
        """Store alert in internal data structures"""
        # Store alert
        self._alerts[alert.alert_id] = alert
        
        # Add to device alerts
        if alert.device_id not in self._device_alerts:
            self._device_alerts[alert.device_id] = []
        
        self._device_alerts[alert.device_id].append(alert.alert_id)
        
        # Limit alerts per device
        if len(self._device_alerts[alert.device_id]) > self.max_alerts_per_device:
            # Remove oldest alert
            oldest_alert_id = self._device_alerts[alert.device_id].pop(0)
            if oldest_alert_id in self._alerts:
                del self._alerts[oldest_alert_id]
        
        self.logger.info(f"Created new alert {alert.alert_id} for device {alert.device_id}")
    
    def _generate_alert_title(self, anomaly: Anomaly) -> str:
        """Generate alert title from anomaly"""
        type_titles = {
            AnomalyType.NEW_DESTINATION: "New Destination Connection",
            AnomalyType.UNUSUAL_VOLUME: "Unusual Traffic Volume",
            AnomalyType.PROTOCOL_VIOLATION: "Protocol Violation",
            AnomalyType.TIMING_ANOMALY: "Timing Anomaly",
            AnomalyType.GEOLOCATION_VIOLATION: "Geolocation Violation"
        }
        
        base_title = type_titles.get(anomaly.anomaly_type, "Unknown Anomaly")
        return f"{base_title} - Device {anomaly.device_id}"
    
    def _generate_alert_description(self, anomaly: Anomaly) -> str:
        """Generate detailed alert description from anomaly"""
        severity_text = anomaly.severity.value.upper()
        confidence_pct = int(anomaly.confidence_score * 100)
        
        description = f"{anomaly.description}\n\n"
        description += f"Severity: {severity_text}\n"
        description += f"Confidence: {confidence_pct}%\n"
        description += f"Baseline Deviation: {anomaly.baseline_deviation:.2f}\n"
        description += f"First Detected: {anomaly.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
        
        return description
    
    def _initialize_default_filters(self) -> None:
        """Initialize default filter rules"""
        # Low severity rate limiting
        low_severity_filter = AlertFilterRule(
            rule_id="default_low_severity",
            name="Low Severity Rate Limit",
            severity_threshold=SeverityLevel.LOW,
            time_window_minutes=60,
            max_alerts_per_window=3,
            enabled=True
        )
        self._filter_rules[low_severity_filter.rule_id] = low_severity_filter
        
        # Timing anomaly rate limiting (these tend to be noisy)
        timing_filter = AlertFilterRule(
            rule_id="default_timing_limit",
            name="Timing Anomaly Rate Limit",
            anomaly_types={AnomalyType.TIMING_ANOMALY},
            time_window_minutes=120,
            max_alerts_per_window=2,
            enabled=True
        )
        self._filter_rules[timing_filter.rule_id] = timing_filter