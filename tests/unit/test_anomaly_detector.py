"""
Unit tests for Anomaly Detector
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

from heimdal.anomaly.detector import AnomalyDetector, AnomalyThresholds
from heimdal.models import (
    DeviceBaseline, DeviceBehavior, Anomaly, AnomalyType, 
    SeverityLevel, Connection, TrafficVolume, TrafficPattern
)


class TestAnomalyDetector:
    """Test cases for AnomalyDetector class"""
    
    def test_init(self, mock_baseline_manager):
        """Test AnomalyDetector initialization"""
        detector = AnomalyDetector(mock_baseline_manager)
        
        assert detector.baseline_manager is mock_baseline_manager
        assert isinstance(detector.thresholds, AnomalyThresholds)
        assert isinstance(detector._recent_behavior_cache, dict)
        assert detector._cache_max_age == timedelta(hours=1)
        assert detector._cache_max_entries == 100
    
    def test_init_custom_thresholds(self, mock_baseline_manager):
        """Test initialization with custom thresholds"""
        custom_thresholds = AnomalyThresholds(
            new_destination_threshold=0.5,
            volume_deviation_threshold=1.5
        )
        
        detector = AnomalyDetector(mock_baseline_manager, custom_thresholds)
        
        assert detector.thresholds.new_destination_threshold == 0.5
        assert detector.thresholds.volume_deviation_threshold == 1.5
    
    def test_detect_anomalies_no_baseline(self, mock_baseline_manager, sample_device_behavior):
        """Test anomaly detection when no baseline exists"""
        mock_baseline_manager.get_device_baseline.return_value = None
        
        detector = AnomalyDetector(mock_baseline_manager)
        anomalies = detector.detect_anomalies("test_device", sample_device_behavior)
        
        assert anomalies == []
        mock_baseline_manager.get_device_baseline.assert_called_once_with("test_device")
    
    def test_detect_anomalies_with_baseline(self, mock_baseline_manager, sample_device_baseline, sample_device_behavior):
        """Test anomaly detection with existing baseline"""
        mock_baseline_manager.get_device_baseline.return_value = sample_device_baseline
        
        detector = AnomalyDetector(mock_baseline_manager)
        anomalies = detector.detect_anomalies("test_device", sample_device_behavior)
        
        assert isinstance(anomalies, list)
        # Should not detect anomalies for normal behavior matching baseline
        assert len(anomalies) == 0
    
    def test_detect_new_destinations(self, mock_baseline_manager, sample_device_baseline):
        """Test detection of new destinations"""
        mock_baseline_manager.get_device_baseline.return_value = sample_device_baseline
        
        # Create behavior with new destinations
        new_connections = [
            Connection(
                source_ip="192.168.1.100",
                destination_ip="1.2.3.4",  # New destination not in baseline
                source_port=12345,
                destination_port=80,
                protocol="TCP",
                timestamp=datetime.now(),
                bytes_sent=1024,
                bytes_received=2048
            ),
            Connection(
                source_ip="192.168.1.100",
                destination_ip="5.6.7.8",  # Another new destination
                source_port=12346,
                destination_port=443,
                protocol="TCP",
                timestamp=datetime.now(),
                bytes_sent=512,
                bytes_received=1024
            )
        ]
        
        behavior = DeviceBehavior(
            device_id="test_device",
            timestamp=datetime.now(),
            connections=new_connections,
            traffic_volume=TrafficVolume(1536, 3072, 2, 2, 30.0),
            protocols_used={"TCP"},
            dns_queries=[]
        )
        
        detector = AnomalyDetector(mock_baseline_manager)
        anomalies = detector.detect_anomalies("test_device", behavior)
        
        # Should detect new destination anomaly
        new_dest_anomalies = [a for a in anomalies if a.anomaly_type == AnomalyType.NEW_DESTINATION]
        assert len(new_dest_anomalies) > 0
        
        anomaly = new_dest_anomalies[0]
        assert anomaly.device_id == "test_device"
        assert anomaly.confidence_score > 0.7  # Above threshold
    
    def test_detect_volume_anomalies(self, mock_baseline_manager, sample_device_baseline):
        """Test detection of volume anomalies"""
        mock_baseline_manager.get_device_baseline.return_value = sample_device_baseline
        
        detector = AnomalyDetector(mock_baseline_manager)
        
        # Add some normal behaviors to cache for statistical analysis
        normal_behaviors = []
        for i in range(5):
            behavior = DeviceBehavior(
                device_id="test_device",
                timestamp=datetime.now() - timedelta(minutes=i*10),
                connections=[],
                traffic_volume=TrafficVolume(1000, 2000, 1, 1, 30.0),  # Normal volume
                protocols_used={"TCP"},
                dns_queries=[]
            )
            normal_behaviors.append(behavior)
            detector._update_behavior_cache("test_device", behavior)
        
        # Create behavior with unusual volume
        high_volume_behavior = DeviceBehavior(
            device_id="test_device",
            timestamp=datetime.now(),
            connections=[],
            traffic_volume=TrafficVolume(100000, 200000, 10, 10, 30.0),  # Very high volume
            protocols_used={"TCP"},
            dns_queries=[]
        )
        
        anomalies = detector.detect_anomalies("test_device", high_volume_behavior)
        
        # Should detect volume anomaly
        volume_anomalies = [a for a in anomalies if a.anomaly_type == AnomalyType.UNUSUAL_VOLUME]
        assert len(volume_anomalies) > 0
        
        anomaly = volume_anomalies[0]
        assert anomaly.device_id == "test_device"
        assert anomaly.baseline_deviation > detector.thresholds.volume_deviation_threshold
    
    def test_detect_protocol_violations(self, mock_baseline_manager, sample_device_baseline):
        """Test detection of protocol violations"""
        mock_baseline_manager.get_device_baseline.return_value = sample_device_baseline
        
        # Create behavior with unusual ports
        unusual_connections = [
            Connection(
                source_ip="192.168.1.100",
                destination_ip="8.8.8.8",
                source_port=12345,
                destination_port=8080,  # Unusual port not in baseline
                protocol="TCP",
                timestamp=datetime.now(),
                bytes_sent=1024,
                bytes_received=2048
            ),
            Connection(
                source_ip="192.168.1.100",
                destination_ip="1.1.1.1",
                source_port=12346,
                destination_port=9999,  # Another unusual port
                protocol="TCP",
                timestamp=datetime.now(),
                bytes_sent=512,
                bytes_received=1024
            )
        ]
        
        behavior = DeviceBehavior(
            device_id="test_device",
            timestamp=datetime.now(),
            connections=unusual_connections,
            traffic_volume=TrafficVolume(1536, 3072, 2, 2, 30.0),
            protocols_used={"TCP"},
            dns_queries=[]
        )
        
        detector = AnomalyDetector(mock_baseline_manager)
        anomalies = detector.detect_anomalies("test_device", behavior)
        
        # Should detect protocol violation
        protocol_anomalies = [a for a in anomalies if a.anomaly_type == AnomalyType.PROTOCOL_VIOLATION]
        assert len(protocol_anomalies) > 0
        
        anomaly = protocol_anomalies[0]
        assert anomaly.device_id == "test_device"
        assert "8080" in anomaly.description or "9999" in anomaly.description
    
    def test_detect_timing_anomalies(self, mock_baseline_manager, sample_device_baseline):
        """Test detection of timing anomalies"""
        mock_baseline_manager.get_device_baseline.return_value = sample_device_baseline
        
        # Create behavior at unusual time (3 AM, not in peak hours)
        unusual_time = datetime.now().replace(hour=3, minute=0, second=0, microsecond=0)
        
        behavior = DeviceBehavior(
            device_id="test_device",
            timestamp=unusual_time,
            connections=[],
            traffic_volume=TrafficVolume(1000, 2000, 1, 1, 30.0),
            protocols_used={"TCP"},
            dns_queries=[]
        )
        
        detector = AnomalyDetector(mock_baseline_manager)
        anomalies = detector.detect_anomalies("test_device", behavior)
        
        # Should detect timing anomaly
        timing_anomalies = [a for a in anomalies if a.anomaly_type == AnomalyType.TIMING_ANOMALY]
        assert len(timing_anomalies) > 0
        
        anomaly = timing_anomalies[0]
        assert anomaly.device_id == "test_device"
        assert "3:00" in anomaly.description
    
    def test_calculate_anomaly_score(self, mock_baseline_manager, sample_device_baseline, sample_device_behavior):
        """Test anomaly score calculation"""
        detector = AnomalyDetector(mock_baseline_manager)
        
        score = detector.calculate_anomaly_score(sample_device_baseline, sample_device_behavior)
        
        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0
    
    def test_classify_anomaly_type(self, mock_baseline_manager, sample_anomaly):
        """Test anomaly classification"""
        detector = AnomalyDetector(mock_baseline_manager)
        
        # Test with different confidence scores
        test_cases = [
            (0.95, SeverityLevel.CRITICAL),
            (0.85, SeverityLevel.HIGH),
            (0.65, SeverityLevel.MEDIUM),
            (0.25, SeverityLevel.LOW)
        ]
        
        for confidence, expected_severity in test_cases:
            anomaly = Anomaly(
                device_id="test_device",
                anomaly_type=AnomalyType.NEW_DESTINATION,
                severity=SeverityLevel.LOW,  # Will be updated
                description="Test anomaly",
                timestamp=datetime.now(),
                confidence_score=confidence,
                baseline_deviation=0.5
            )
            
            classified = detector.classify_anomaly_type(anomaly)
            
            assert classified.severity == expected_severity
            assert len(classified.description) > len("Test anomaly")  # Should be enhanced
    
    def test_set_thresholds(self, mock_baseline_manager):
        """Test threshold setting"""
        detector = AnomalyDetector(mock_baseline_manager)
        
        new_thresholds = {
            "new_destination_threshold": 0.5,
            "volume_deviation_threshold": 1.5,
            "invalid_threshold": 0.8  # Should be ignored
        }
        
        detector.set_thresholds(new_thresholds)
        
        assert detector.thresholds.new_destination_threshold == 0.5
        assert detector.thresholds.volume_deviation_threshold == 1.5
        # Invalid threshold should not affect existing values
        assert detector.thresholds.timing_anomaly_threshold == 0.8  # Default value
    
    def test_update_behavior_cache(self, mock_baseline_manager, sample_device_behavior):
        """Test behavior cache update and cleanup"""
        detector = AnomalyDetector(mock_baseline_manager)
        detector._cache_max_age = timedelta(seconds=1)  # Short age for testing
        
        device_id = "test_device"
        
        # Add behavior to cache
        detector._update_behavior_cache(device_id, sample_device_behavior)
        assert len(detector._recent_behavior_cache[device_id]) == 1
        
        # Wait and add another behavior (should trigger cleanup)
        import time
        time.sleep(1.1)
        
        new_behavior = DeviceBehavior(
            device_id=device_id,
            timestamp=datetime.now(),
            connections=[],
            traffic_volume=TrafficVolume(500, 1000, 1, 1, 15.0),
            protocols_used={"UDP"},
            dns_queries=[]
        )
        
        detector._update_behavior_cache(device_id, new_behavior)
        
        # Old behavior should be cleaned up
        assert len(detector._recent_behavior_cache[device_id]) == 1
        assert detector._recent_behavior_cache[device_id][0] is new_behavior
    
    def test_get_recent_behaviors(self, mock_baseline_manager, sample_device_behavior):
        """Test getting recent behaviors"""
        detector = AnomalyDetector(mock_baseline_manager)
        device_id = "test_device"
        
        # Initially empty
        recent = detector._get_recent_behaviors(device_id)
        assert recent == []
        
        # Add behavior
        detector._update_behavior_cache(device_id, sample_device_behavior)
        recent = detector._get_recent_behaviors(device_id)
        assert len(recent) == 1
        assert recent[0] is sample_device_behavior
    
    def test_calculate_destination_anomaly_score(self, mock_baseline_manager, sample_device_baseline):
        """Test destination anomaly score calculation"""
        detector = AnomalyDetector(mock_baseline_manager)
        
        # Behavior with mix of known and unknown destinations
        connections = [
            Connection("192.168.1.100", "8.8.8.8", 12345, 53, "UDP", datetime.now(), 64, 128),  # Known
            Connection("192.168.1.100", "1.2.3.4", 12346, 80, "TCP", datetime.now(), 1024, 2048),  # Unknown
            Connection("192.168.1.100", "5.6.7.8", 12347, 443, "TCP", datetime.now(), 512, 1024)  # Unknown
        ]
        
        behavior = DeviceBehavior(
            device_id="test_device",
            timestamp=datetime.now(),
            connections=connections,
            traffic_volume=TrafficVolume(1600, 3200, 3, 3, 45.0),
            protocols_used={"TCP", "UDP"},
            dns_queries=[]
        )
        
        score = detector._calculate_destination_anomaly_score(sample_device_baseline, behavior)
        
        # Should be 2/3 = 0.67 (2 unknown out of 3 total destinations)
        assert abs(score - 0.67) < 0.01
    
    def test_calculate_volume_anomaly_score(self, mock_baseline_manager):
        """Test volume anomaly score calculation"""
        detector = AnomalyDetector(mock_baseline_manager)
        
        # Test normal volume
        normal_behavior = DeviceBehavior(
            device_id="test_device",
            timestamp=datetime.now(),
            connections=[],
            traffic_volume=TrafficVolume(5000, 10000, 1, 1, 30.0),  # 15KB total
            protocols_used={"TCP"},
            dns_queries=[]
        )
        
        score = detector._calculate_volume_anomaly_score(None, normal_behavior)
        assert score == 0.0  # Within normal range
        
        # Test high volume
        high_volume_behavior = DeviceBehavior(
            device_id="test_device",
            timestamp=datetime.now(),
            connections=[],
            traffic_volume=TrafficVolume(50000000, 50000000, 10, 10, 30.0),  # 100MB total
            protocols_used={"TCP"},
            dns_queries=[]
        )
        
        score = detector._calculate_volume_anomaly_score(None, high_volume_behavior)
        assert score == 1.0  # At maximum scale
    
    def test_calculate_protocol_anomaly_score(self, mock_baseline_manager, sample_device_baseline):
        """Test protocol anomaly score calculation"""
        detector = AnomalyDetector(mock_baseline_manager)
        
        # Behavior with unusual ports
        connections = [
            Connection("192.168.1.100", "8.8.8.8", 12345, 8080, "TCP", datetime.now(), 1024, 2048),  # Unusual
            Connection("192.168.1.100", "1.1.1.1", 12346, 443, "TCP", datetime.now(), 512, 1024)   # Normal
        ]
        
        behavior = DeviceBehavior(
            device_id="test_device",
            timestamp=datetime.now(),
            connections=connections,
            traffic_volume=TrafficVolume(1536, 3072, 2, 2, 30.0),
            protocols_used={"TCP"},
            dns_queries=[]
        )
        
        score = detector._calculate_protocol_anomaly_score(sample_device_baseline, behavior)
        
        # Should be 0.5 (1 unusual out of 2 total connections)
        assert abs(score - 0.5) < 0.01
    
    def test_calculate_timing_anomaly_score(self, mock_baseline_manager, sample_device_baseline):
        """Test timing anomaly score calculation"""
        detector = AnomalyDetector(mock_baseline_manager)
        
        # Behavior during peak hours
        peak_time = datetime.now().replace(hour=10, minute=0, second=0, microsecond=0)
        peak_behavior = DeviceBehavior(
            device_id="test_device",
            timestamp=peak_time,
            connections=[],
            traffic_volume=TrafficVolume(1000, 2000, 1, 1, 30.0),
            protocols_used={"TCP"},
            dns_queries=[]
        )
        
        score = detector._calculate_timing_anomaly_score(sample_device_baseline, peak_behavior)
        assert score == 0.0  # During peak hours
        
        # Behavior during off-peak hours
        off_peak_time = datetime.now().replace(hour=3, minute=0, second=0, microsecond=0)
        off_peak_behavior = DeviceBehavior(
            device_id="test_device",
            timestamp=off_peak_time,
            connections=[],
            traffic_volume=TrafficVolume(1000, 2000, 1, 1, 30.0),
            protocols_used={"TCP"},
            dns_queries=[]
        )
        
        score = detector._calculate_timing_anomaly_score(sample_device_baseline, off_peak_behavior)
        assert score > 0.0  # Should have some anomaly score
    
    def test_is_suspicious_destination(self, mock_baseline_manager, sample_device_baseline):
        """Test suspicious destination detection"""
        detector = AnomalyDetector(mock_baseline_manager)
        
        # Test known destination (should not be suspicious)
        assert detector._is_suspicious_destination("8.8.8.8", sample_device_baseline) is False
        
        # Test private IP (should not be suspicious)
        assert detector._is_suspicious_destination("192.168.1.1", sample_device_baseline) is False
        
        # Test suspicious patterns
        assert detector._is_suspicious_destination("0.0.0.0", sample_device_baseline) is True
        assert detector._is_suspicious_destination("255.255.255.255", sample_device_baseline) is True
    
    def test_generate_anomaly_description(self, mock_baseline_manager):
        """Test anomaly description generation"""
        detector = AnomalyDetector(mock_baseline_manager)
        
        anomaly = Anomaly(
            device_id="test_device",
            anomaly_type=AnomalyType.NEW_DESTINATION,
            severity=SeverityLevel.HIGH,
            description="Original description",
            timestamp=datetime.now(),
            confidence_score=0.85,
            baseline_deviation=0.7
        )
        
        description = detector._generate_anomaly_description(anomaly)
        
        assert "Device connected to previously unseen destinations" in description
        assert "HIGH" in description
        assert "85%" in description
    
    def test_anomaly_thresholds_dataclass(self):
        """Test AnomalyThresholds dataclass"""
        thresholds = AnomalyThresholds()
        
        # Test default values
        assert thresholds.new_destination_threshold == 0.7
        assert thresholds.volume_deviation_threshold == 2.0
        assert thresholds.timing_anomaly_threshold == 0.8
        assert thresholds.protocol_violation_threshold == 0.9
        assert thresholds.geolocation_violation_threshold == 0.95
        
        # Test severity thresholds
        assert thresholds.low_severity_threshold == 0.3
        assert thresholds.medium_severity_threshold == 0.6
        assert thresholds.high_severity_threshold == 0.8
        assert thresholds.critical_severity_threshold == 0.9
        
        # Test custom values
        custom_thresholds = AnomalyThresholds(
            new_destination_threshold=0.5,
            critical_severity_threshold=0.95
        )
        
        assert custom_thresholds.new_destination_threshold == 0.5
        assert custom_thresholds.critical_severity_threshold == 0.95
        # Other values should remain default
        assert custom_thresholds.volume_deviation_threshold == 2.0