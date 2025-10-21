"""
Unit tests for Behavioral Extractor
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
from scapy.packet import Packet
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR

from heimdal.analysis.behavioral_extractor import (
    BehavioralExtractor, BehavioralFeatures, ConnectionPattern, 
    TrafficPattern, DNSPattern
)


class TestBehavioralExtractor:
    """Test cases for BehavioralExtractor class"""
    
    def test_init(self):
        """Test BehavioralExtractor initialization"""
        extractor = BehavioralExtractor()
        
        assert extractor.analysis_window == timedelta(hours=1)
        assert isinstance(extractor.packet_history, dict)
        assert isinstance(extractor.connection_cache, dict)
        assert isinstance(extractor.dns_cache, dict)
        assert isinstance(extractor.geographic_ranges, dict)
        assert isinstance(extractor.domain_categories, dict)
    
    def test_init_custom_window(self):
        """Test initialization with custom analysis window"""
        custom_window = timedelta(minutes=30)
        extractor = BehavioralExtractor(analysis_window=custom_window)
        
        assert extractor.analysis_window == custom_window
    
    def test_extract_behavioral_features_empty_packets(self):
        """Test behavioral feature extraction with empty packet list"""
        extractor = BehavioralExtractor()
        
        features = extractor.extract_behavioral_features("test_device", [])
        
        assert isinstance(features, BehavioralFeatures)
        assert features.device_id == "test_device"
        assert isinstance(features.connection_patterns, ConnectionPattern)
        assert isinstance(features.traffic_patterns, TrafficPattern)
        assert isinstance(features.dns_patterns, DNSPattern)
        assert isinstance(features.anomaly_indicators, dict)
    
    def test_extract_behavioral_features_with_packets(self, synthetic_packet_stream):
        """Test behavioral feature extraction with packet stream"""
        extractor = BehavioralExtractor()
        
        # Use first 10 packets from synthetic stream
        packets = synthetic_packet_stream[:10]
        
        features = extractor.extract_behavioral_features("test_device", packets)
        
        assert isinstance(features, BehavioralFeatures)
        assert features.device_id == "test_device"
        assert len(features.connection_patterns.frequent_destinations) > 0
        assert len(features.connection_patterns.protocol_distribution) > 0
        assert features.traffic_patterns.average_packet_size > 0
    
    def test_update_packet_history(self):
        """Test packet history update and cleanup"""
        extractor = BehavioralExtractor(analysis_window=timedelta(seconds=1))
        device_id = "test_device"
        
        # Create mock packets
        packet1 = Mock(spec=Packet)
        packet2 = Mock(spec=Packet)
        
        # Add packets
        extractor._update_packet_history(device_id, [packet1, packet2])
        
        assert len(extractor.packet_history[device_id]) == 2
        
        # Wait and add more packets (should trigger cleanup)
        import time
        time.sleep(1.1)  # Wait longer than analysis window
        
        packet3 = Mock(spec=Packet)
        extractor._update_packet_history(device_id, [packet3])
        
        # Old packets should be cleaned up
        assert len(extractor.packet_history[device_id]) == 1
    
    def test_extract_connection_patterns_tcp(self):
        """Test connection pattern extraction from TCP packets"""
        extractor = BehavioralExtractor()
        
        # Mock TCP packet
        packet = Mock(spec=Packet)
        
        def haslayer_side_effect(layer):
            return layer in [IP, TCP]
        
        packet.haslayer.side_effect = haslayer_side_effect
        
        ip = Mock()
        ip.src = "192.168.1.100"  # Local IP
        ip.dst = "8.8.8.8"  # External IP
        
        tcp = Mock()
        tcp.dport = 443
        tcp.sport = 12345
        tcp.flags = 0x02  # SYN flag
        
        packet.__getitem__.side_effect = lambda layer: {IP: ip, TCP: tcp}[layer]
        
        pattern = extractor._extract_connection_patterns("test_device", [packet])
        
        assert "8.8.8.8" in pattern.frequent_destinations
        assert pattern.frequent_destinations["8.8.8.8"] == 1
        assert 443 in pattern.port_usage
        assert "TCP" in pattern.protocol_distribution
        assert len(pattern.connection_timing) == 1
    
    def test_extract_connection_patterns_udp(self):
        """Test connection pattern extraction from UDP packets"""
        extractor = BehavioralExtractor()
        
        # Mock UDP packet
        packet = Mock(spec=Packet)
        
        def haslayer_side_effect(layer):
            return layer in [IP, UDP]
        
        packet.haslayer.side_effect = haslayer_side_effect
        
        ip = Mock()
        ip.src = "192.168.1.100"
        ip.dst = "1.1.1.1"
        
        udp = Mock()
        udp.dport = 53
        udp.sport = 12345
        
        packet.__getitem__.side_effect = lambda layer: {IP: ip, UDP: udp}[layer]
        
        pattern = extractor._extract_connection_patterns("test_device", [packet])
        
        assert "1.1.1.1" in pattern.frequent_destinations
        assert 53 in pattern.port_usage
        assert "UDP" in pattern.protocol_distribution
    
    def test_extract_traffic_patterns(self):
        """Test traffic pattern extraction"""
        extractor = BehavioralExtractor()
        
        # Create mock packets with varying sizes
        packets = []
        for i in range(10):
            packet = Mock(spec=Packet)
            packet.__len__.return_value = 100 + i * 50  # Varying sizes
            packets.append(packet)
        
        pattern = extractor._extract_traffic_patterns("test_device", packets)
        
        assert pattern.average_packet_size > 0
        assert pattern.traffic_variance >= 0
        assert len(pattern.hourly_distribution) > 0
        assert len(pattern.inter_packet_intervals) == 9  # n-1 intervals
    
    def test_extract_dns_patterns(self):
        """Test DNS pattern extraction"""
        extractor = BehavioralExtractor()
        
        # Mock DNS packet
        packet = Mock(spec=Packet)
        
        def haslayer_side_effect(layer):
            return layer in [DNS, IP]
        
        packet.haslayer.side_effect = haslayer_side_effect
        
        # Mock DNS query
        dns_query = Mock()
        dns_query.qname = b"apple.com."
        dns_query.qtype = 1  # A record
        
        dns = Mock()
        dns.qd = dns_query
        
        ip = Mock()
        ip.src = "192.168.1.100"
        ip.dst = "8.8.8.8"
        
        packet.__getitem__.side_effect = lambda layer: {DNS: dns, IP: ip}[layer]
        
        pattern = extractor._extract_dns_patterns("test_device", [packet])
        
        assert "apple.com" in pattern.query_domains
        assert pattern.query_domains["apple.com"] == 1
        assert "A" in pattern.query_types
        assert "8.8.8.8" in pattern.dns_servers
        assert "apple.com" in pattern.domain_categories
        assert pattern.domain_categories["apple.com"] == "Cloud Services"
    
    def test_calculate_anomaly_indicators(self):
        """Test anomaly indicator calculation"""
        extractor = BehavioralExtractor()
        
        # Create patterns with known characteristics
        connection_patterns = ConnectionPattern()
        connection_patterns.frequent_destinations = {f"dest{i}": 1 for i in range(50)}
        connection_patterns.port_usage = {i: 1 for i in range(25)}
        connection_patterns.protocol_distribution = {"TCP": 10, "UDP": 5}
        connection_patterns.geographic_regions = {"North America", "Europe"}
        
        traffic_patterns = TrafficPattern()
        traffic_patterns.traffic_variance = 5000.0
        traffic_patterns.peak_traffic_hours = [9, 10, 11, 18, 19, 20]
        
        dns_patterns = DNSPattern()
        dns_patterns.query_domains = {f"domain{i}.com": 1 for i in range(30)}
        dns_patterns.suspicious_domains = ["malware.tk", "phishing.ml"]
        
        indicators = extractor._calculate_anomaly_indicators(
            connection_patterns, traffic_patterns, dns_patterns
        )
        
        assert "destination_diversity" in indicators
        assert "port_diversity" in indicators
        assert "protocol_diversity" in indicators
        assert "traffic_burstiness" in indicators
        assert "dns_diversity" in indicators
        assert "suspicious_dns_ratio" in indicators
        assert "geographic_diversity" in indicators
        assert "peak_hour_activity" in indicators
        
        # Check value ranges
        for key, value in indicators.items():
            assert 0.0 <= value <= 1.0, f"Indicator {key} out of range: {value}"
    
    def test_is_local_ip(self):
        """Test local IP address detection"""
        extractor = BehavioralExtractor()
        
        # Test private IP ranges
        assert extractor._is_local_ip("192.168.1.1") is True
        assert extractor._is_local_ip("10.0.0.1") is True
        assert extractor._is_local_ip("172.16.0.1") is True
        assert extractor._is_local_ip("127.0.0.1") is True
        
        # Test public IPs
        assert extractor._is_local_ip("8.8.8.8") is False
        assert extractor._is_local_ip("1.1.1.1") is False
        assert extractor._is_local_ip("208.67.222.222") is False
        
        # Test invalid IP
        assert extractor._is_local_ip("invalid.ip") is False
    
    def test_get_geographic_region(self):
        """Test geographic region detection"""
        extractor = BehavioralExtractor()
        
        # Test private IP
        region = extractor._get_geographic_region("192.168.1.1")
        assert region == "Local"
        
        # Test public IP (simplified mapping)
        region = extractor._get_geographic_region("8.8.8.8")
        assert region in ["North America", "Europe", "Asia", "Other", "Unknown"]
        
        # Test invalid IP
        region = extractor._get_geographic_region("invalid.ip")
        assert region is None
    
    def test_categorize_domain(self):
        """Test domain categorization"""
        extractor = BehavioralExtractor()
        
        # Test known categories
        assert extractor._categorize_domain("facebook.com") == "Social Media"
        assert extractor._categorize_domain("netflix.com") == "Streaming"
        assert extractor._categorize_domain("amazon.com") in ["Cloud Services", "Shopping"]
        assert extractor._categorize_domain("unknown-domain.com") is None
    
    def test_is_suspicious_domain(self):
        """Test suspicious domain detection"""
        extractor = BehavioralExtractor()
        
        # Test suspicious TLDs
        assert extractor._is_suspicious_domain("malware.tk") is True
        assert extractor._is_suspicious_domain("phishing.ml") is True
        assert extractor._is_suspicious_domain("spam.ga") is True
        
        # Test domains with long numeric sequences
        assert extractor._is_suspicious_domain("domain12345678.com") is True
        
        # Test domains with long random strings
        assert extractor._is_suspicious_domain("test-abcdefghijk.com") is True
        
        # Test legitimate domains
        assert extractor._is_suspicious_domain("google.com") is False
        assert extractor._is_suspicious_domain("apple.com") is False
    
    def test_get_dns_type_name(self):
        """Test DNS type name conversion"""
        extractor = BehavioralExtractor()
        
        assert extractor._get_dns_type_name(1) == "A"
        assert extractor._get_dns_type_name(2) == "NS"
        assert extractor._get_dns_type_name(5) == "CNAME"
        assert extractor._get_dns_type_name(28) == "AAAA"
        assert extractor._get_dns_type_name(999) == "TYPE999"
    
    def test_get_device_behavioral_summary(self):
        """Test device behavioral summary generation"""
        extractor = BehavioralExtractor()
        device_id = "test_device"
        
        # Add some packet history
        packets = [Mock(spec=Packet) for _ in range(5)]
        extractor.packet_history[device_id] = [(datetime.now(), packet) for packet in packets]
        
        with patch.object(extractor, 'extract_behavioral_features') as mock_extract:
            # Mock the behavioral features
            mock_features = Mock()
            mock_features.device_id = device_id
            mock_features.timestamp = datetime.now()
            mock_features.connection_patterns = Mock()
            mock_features.connection_patterns.frequent_destinations = {"dest1": 1, "dest2": 2}
            mock_features.connection_patterns.port_usage = {80: 1, 443: 2}
            mock_features.connection_patterns.protocol_distribution = {"TCP": 3}
            mock_features.connection_patterns.geographic_regions = {"North America"}
            mock_features.dns_patterns = Mock()
            mock_features.dns_patterns.query_domains = {"domain1.com": 1}
            mock_features.dns_patterns.suspicious_domains = []
            mock_features.anomaly_indicators = {"test_indicator": 0.5}
            
            mock_extract.return_value = mock_features
            
            summary = extractor.get_device_behavioral_summary(device_id)
            
            assert summary is not None
            assert summary["device_id"] == device_id
            assert summary["packet_count"] == 5
            assert summary["unique_destinations"] == 2
            assert summary["unique_ports"] == 2
            assert "TCP" in summary["protocols"]
            assert summary["dns_queries"] == 1
            assert summary["suspicious_domains"] == 0
            assert "North America" in summary["geographic_regions"]
            assert 0.0 <= summary["anomaly_score"] <= 1.0
    
    def test_get_device_behavioral_summary_no_history(self):
        """Test behavioral summary for device with no history"""
        extractor = BehavioralExtractor()
        
        summary = extractor.get_device_behavioral_summary("unknown_device")
        assert summary is None
    
    def test_load_geographic_ranges(self):
        """Test geographic ranges loading"""
        extractor = BehavioralExtractor()
        
        ranges = extractor._load_geographic_ranges()
        
        assert isinstance(ranges, dict)
        assert len(ranges) > 0
        
        # Check that ranges have proper structure
        for region, (start, end) in ranges.items():
            assert isinstance(region, str)
            assert isinstance(start, int)
            assert isinstance(end, int)
            assert start <= end
    
    def test_load_domain_categories(self):
        """Test domain categories loading"""
        extractor = BehavioralExtractor()
        
        categories = extractor._load_domain_categories()
        
        assert isinstance(categories, dict)
        assert len(categories) > 0
        
        # Check that categories have proper structure
        for category, patterns in categories.items():
            assert isinstance(category, str)
            assert isinstance(patterns, list)
            assert len(patterns) > 0
            assert all(isinstance(pattern, str) for pattern in patterns)
    
    def test_behavioral_features_dataclass(self):
        """Test BehavioralFeatures dataclass structure"""
        connection_patterns = ConnectionPattern()
        traffic_patterns = TrafficPattern()
        dns_patterns = DNSPattern()
        
        features = BehavioralFeatures(
            device_id="test_device",
            timestamp=datetime.now(),
            connection_patterns=connection_patterns,
            traffic_patterns=traffic_patterns,
            dns_patterns=dns_patterns
        )
        
        assert features.device_id == "test_device"
        assert isinstance(features.timestamp, datetime)
        assert isinstance(features.connection_patterns, ConnectionPattern)
        assert isinstance(features.traffic_patterns, TrafficPattern)
        assert isinstance(features.dns_patterns, DNSPattern)
        assert isinstance(features.anomaly_indicators, dict)
    
    def test_connection_pattern_dataclass(self):
        """Test ConnectionPattern dataclass structure"""
        pattern = ConnectionPattern()
        
        assert isinstance(pattern.frequent_destinations, dict)
        assert isinstance(pattern.port_usage, dict)
        assert isinstance(pattern.protocol_distribution, dict)
        assert isinstance(pattern.connection_timing, list)
        assert isinstance(pattern.session_durations, list)
        assert isinstance(pattern.geographic_regions, set)
    
    def test_traffic_pattern_dataclass(self):
        """Test TrafficPattern dataclass structure"""
        pattern = TrafficPattern()
        
        assert isinstance(pattern.hourly_distribution, dict)
        assert isinstance(pattern.burst_patterns, list)
        assert isinstance(pattern.average_packet_size, float)
        assert isinstance(pattern.peak_traffic_hours, list)
        assert isinstance(pattern.traffic_variance, float)
        assert isinstance(pattern.inter_packet_intervals, list)
    
    def test_dns_pattern_dataclass(self):
        """Test DNSPattern dataclass structure"""
        pattern = DNSPattern()
        
        assert isinstance(pattern.query_domains, dict)
        assert isinstance(pattern.query_types, dict)
        assert isinstance(pattern.dns_servers, set)
        assert isinstance(pattern.suspicious_domains, list)
        assert isinstance(pattern.domain_categories, dict)
        assert isinstance(pattern.query_timing, list)