"""
Integration tests for end-to-end real-time monitoring
"""

import pytest
import asyncio
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock
from typing import List, Dict, Any

from heimdal.analysis.realtime_analyzer import RealtimeAnalyzer
from heimdal.analysis.device_fingerprinter import DeviceFingerprinter
from heimdal.baseline.manager import BaselineManager
from heimdal.anomaly.detector import AnomalyDetector
from heimdal.capture.engine import PacketCaptureEngine
from heimdal.orchestrator import HeimdallOrchestrator
from heimdal.models import DeviceBehavior, Anomaly, AnomalyType, SeverityLevel


class TestEndToEndMonitoring:
    """Integration tests for complete monitoring pipeline"""
    
    @pytest.fixture
    def mock_network_interface(self):
        """Mock network interface for testing"""
        return "eth0"
    
    @pytest.fixture
    def monitoring_components(self, temp_dir):
        """Create integrated monitoring components"""
        baseline_manager = BaselineManager(baseline_dir=temp_dir)
        analyzer = RealtimeAnalyzer()
        detector = AnomalyDetector(baseline_manager)
        
        return {
            'baseline_manager': baseline_manager,
            'analyzer': analyzer,
            'detector': detector
        }
    
    def test_packet_to_behavior_pipeline(self, monitoring_components, synthetic_packet_stream):
        """Test complete pipeline from packets to behavior analysis"""
        analyzer = monitoring_components['analyzer']
        
        # Process packets through analyzer
        behaviors = []
        for packet in synthetic_packet_stream[:20]:  # Process first 20 packets
            behavior = analyzer.process_packet(packet)
            if behavior:
                behaviors.append(behavior)
        
        # Verify behaviors were generated
        assert len(behaviors) > 0
        
        # Verify behavior structure
        for behavior in behaviors:
            assert isinstance(behavior, DeviceBehavior)
            assert behavior.device_id is not None
            assert behavior.timestamp is not None
            assert isinstance(behavior.connections, list)
            assert behavior.traffic_volume is not None
    
    def test_behavior_to_baseline_pipeline(self, monitoring_components, sample_device_behavior):
        """Test pipeline from behavior to baseline updates"""
        baseline_manager = monitoring_components['baseline_manager']
        
        device_id = sample_device_behavior.device_id
        
        # Initially no baseline
        baseline = baseline_manager.get_device_baseline(device_id)
        assert baseline is None
        
        # Update baseline with behavior
        result = baseline_manager.update_baseline(device_id, sample_device_behavior)
        assert result is True
        
        # Verify baseline was created
        baseline = baseline_manager.get_device_baseline(device_id)
        assert baseline is not None
        assert baseline.device_id == device_id
        assert baseline.confidence_score > 0.0
    
    def test_baseline_to_anomaly_pipeline(self, monitoring_components, sample_device_baseline):
        """Test pipeline from baseline to anomaly detection"""
        baseline_manager = monitoring_components['baseline_manager']
        detector = monitoring_components['detector']
        
        # Set up baseline
        baseline_manager.set_device_baseline(sample_device_baseline)
        
        # Create anomalous behavior
        from tests.conftest import generate_anomalous_behavior
        anomalous_behavior = generate_anomalous_behavior(sample_device_baseline.device_id)
        
        # Detect anomalies
        anomalies = detector.detect_anomalies(sample_device_baseline.device_id, anomalous_behavior)
        
        # Verify anomalies were detected
        assert len(anomalies) > 0
        
        # Verify anomaly structure
        for anomaly in anomalies:
            assert isinstance(anomaly, Anomaly)
            assert anomaly.device_id == sample_device_baseline.device_id
            assert anomaly.anomaly_type in AnomalyType
            assert anomaly.severity in SeverityLevel
            assert 0.0 <= anomaly.confidence_score <= 1.0
    
    def test_complete_monitoring_cycle(self, monitoring_components, synthetic_packet_stream):
        """Test complete monitoring cycle: packets -> behavior -> baseline -> anomalies"""
        analyzer = monitoring_components['analyzer']
        baseline_manager = monitoring_components['baseline_manager']
        detector = monitoring_components['detector']
        
        device_behaviors = {}
        all_anomalies = []
        
        # Process packets in batches to simulate real-time monitoring
        batch_size = 10
        for i in range(0, min(50, len(synthetic_packet_stream)), batch_size):
            batch = synthetic_packet_stream[i:i+batch_size]
            
            # Process packets
            for packet in batch:
                behavior = analyzer.process_packet(packet)
                if behavior:
                    device_id = behavior.device_id
                    device_behaviors[device_id] = behavior
                    
                    # Update baseline
                    baseline_manager.update_baseline(device_id, behavior)
                    
                    # Check for anomalies
                    anomalies = detector.detect_anomalies(device_id, behavior)
                    all_anomalies.extend(anomalies)
        
        # Verify the complete cycle worked
        assert len(device_behaviors) > 0
        
        # Verify baselines were created
        for device_id in device_behaviors.keys():
            baseline = baseline_manager.get_device_baseline(device_id)
            assert baseline is not None
            assert baseline.confidence_score > 0.0
        
        # Anomalies may or may not be detected depending on synthetic data
        # but the pipeline should complete without errors
        assert isinstance(all_anomalies, list)
    
    def test_concurrent_device_monitoring(self, monitoring_components):
        """Test monitoring multiple devices concurrently"""
        analyzer = monitoring_components['analyzer']
        baseline_manager = monitoring_components['baseline_manager']
        
        # Create packets for multiple devices
        devices = ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:03"]
        device_packets = {}
        
        for device_mac in devices:
            packets = []
            for i in range(10):
                packet = Mock()
                packet.haslayer.return_value = True
                packet.__len__.return_value = 1024
                
                # Mock Ethernet layer
                ether = Mock()
                ether.src = device_mac
                
                # Mock IP layer
                ip = Mock()
                ip.src = f"192.168.1.{100 + devices.index(device_mac)}"
                ip.dst = "8.8.8.8"
                
                # Mock TCP layer
                tcp = Mock()
                tcp.sport = 12345 + i
                tcp.dport = 443
                tcp.flags = 0x18
                
                packet.__getitem__.side_effect = lambda layer: {
                    'Ether': ether, 'IP': ip, 'TCP': tcp
                }.get(str(layer), Mock())
                
                packets.append(packet)
            
            device_packets[device_mac] = packets
        
        # Process packets for all devices
        device_behaviors = {}
        for device_mac, packets in device_packets.items():
            for packet in packets:
                behavior = analyzer.process_packet(packet)
                if behavior:
                    device_behaviors[device_mac] = behavior
                    baseline_manager.update_baseline(device_mac, behavior)
        
        # Verify all devices were processed
        assert len(device_behaviors) == len(devices)
        
        # Verify baselines were created for all devices
        for device_mac in devices:
            baseline = baseline_manager.get_device_baseline(device_mac)
            assert baseline is not None
    
    def test_performance_under_load(self, monitoring_components):
        """Test system performance under packet load"""
        analyzer = monitoring_components['analyzer']
        baseline_manager = monitoring_components['baseline_manager']
        
        # Generate large number of packets
        packet_count = 1000
        packets = []
        
        for i in range(packet_count):
            packet = Mock()
            packet.haslayer.return_value = True
            packet.__len__.return_value = 64 + (i % 1000)
            
            # Vary source devices
            device_id = f"aa:bb:cc:dd:ee:{(i % 10):02x}"
            
            ether = Mock()
            ether.src = device_id
            
            ip = Mock()
            ip.src = f"192.168.1.{100 + (i % 50)}"
            ip.dst = f"8.8.{(i % 4) + 4}.{(i % 4) + 4}"
            
            tcp = Mock()
            tcp.sport = 12345 + i
            tcp.dport = [80, 443, 993, 5223][i % 4]
            tcp.flags = 0x18
            
            packet.__getitem__.side_effect = lambda layer: {
                'Ether': ether, 'IP': ip, 'TCP': tcp
            }.get(str(layer), Mock())
            
            packets.append(packet)
        
        # Measure processing time
        start_time = time.time()
        
        processed_count = 0
        for packet in packets:
            behavior = analyzer.process_packet(packet)
            if behavior:
                baseline_manager.update_baseline(behavior.device_id, behavior)
                processed_count += 1
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        # Performance assertions
        assert processing_time < 10.0  # Should process 1000 packets in under 10 seconds
        assert processed_count > 0
        
        # Calculate packets per second
        packets_per_second = packet_count / processing_time
        assert packets_per_second > 100  # Should handle at least 100 packets/second
    
    def test_memory_usage_stability(self, monitoring_components):
        """Test memory usage remains stable during extended operation"""
        analyzer = monitoring_components['analyzer']
        baseline_manager = monitoring_components['baseline_manager']
        
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        # Process packets in multiple cycles
        for cycle in range(10):
            for i in range(100):
                packet = Mock()
                packet.haslayer.return_value = True
                packet.__len__.return_value = 1024
                
                device_id = f"aa:bb:cc:dd:ee:{(i % 5):02x}"
                
                ether = Mock()
                ether.src = device_id
                
                ip = Mock()
                ip.src = f"192.168.1.{100 + (i % 10)}"
                ip.dst = "8.8.8.8"
                
                tcp = Mock()
                tcp.sport = 12345 + i
                tcp.dport = 443
                tcp.flags = 0x18
                
                packet.__getitem__.side_effect = lambda layer: {
                    'Ether': ether, 'IP': ip, 'TCP': tcp
                }.get(str(layer), Mock())
                
                behavior = analyzer.process_packet(packet)
                if behavior:
                    baseline_manager.update_baseline(behavior.device_id, behavior)
            
            # Check memory usage periodically
            current_memory = process.memory_info().rss
            memory_growth = (current_memory - initial_memory) / initial_memory
            
            # Memory growth should be reasonable (less than 50% increase)
            assert memory_growth < 0.5, f"Memory growth too high: {memory_growth:.2%}"
    
    def test_error_recovery(self, monitoring_components):
        """Test system recovery from various error conditions"""
        analyzer = monitoring_components['analyzer']
        baseline_manager = monitoring_components['baseline_manager']
        detector = monitoring_components['detector']
        
        # Test with malformed packets
        malformed_packet = Mock()
        malformed_packet.haslayer.return_value = False  # No Ethernet layer
        
        # Should not crash
        behavior = analyzer.process_packet(malformed_packet)
        assert behavior is None
        
        # Test with corrupted baseline data
        corrupted_baseline = Mock()
        corrupted_baseline.device_id = None  # Invalid
        
        result = baseline_manager.set_device_baseline(corrupted_baseline)
        assert result is False
        
        # Test anomaly detection with missing baseline
        test_behavior = DeviceBehavior(
            device_id="nonexistent_device",
            timestamp=datetime.now(),
            connections=[],
            traffic_volume=Mock(),
            protocols_used=set(),
            dns_queries=[]
        )
        
        anomalies = detector.detect_anomalies("nonexistent_device", test_behavior)
        assert anomalies == []  # Should return empty list, not crash
    
    def test_data_consistency(self, monitoring_components, sample_device_behavior):
        """Test data consistency across components"""
        analyzer = monitoring_components['analyzer']
        baseline_manager = monitoring_components['baseline_manager']
        detector = monitoring_components['detector']
        
        device_id = sample_device_behavior.device_id
        
        # Process behavior through pipeline
        baseline_manager.update_baseline(device_id, sample_device_behavior)
        baseline = baseline_manager.get_device_baseline(device_id)
        
        # Verify baseline consistency
        assert baseline.device_id == device_id
        assert len(baseline.normal_destinations) > 0
        
        # Process same behavior again
        baseline_manager.update_baseline(device_id, sample_device_behavior)
        updated_baseline = baseline_manager.get_device_baseline(device_id)
        
        # Baseline should be updated but consistent
        assert updated_baseline.device_id == device_id
        assert updated_baseline.last_updated > baseline.last_updated
        
        # Anomaly detection should be consistent
        anomalies1 = detector.detect_anomalies(device_id, sample_device_behavior)
        anomalies2 = detector.detect_anomalies(device_id, sample_device_behavior)
        
        # Should produce consistent results
        assert len(anomalies1) == len(anomalies2)
    
    def test_real_time_latency_requirements(self, monitoring_components):
        """Test that processing meets real-time latency requirements"""
        analyzer = monitoring_components['analyzer']
        baseline_manager = monitoring_components['baseline_manager']
        detector = monitoring_components['detector']
        
        # Create test packet
        packet = Mock()
        packet.haslayer.return_value = True
        packet.__len__.return_value = 1024
        
        ether = Mock()
        ether.src = "aa:bb:cc:dd:ee:ff"
        
        ip = Mock()
        ip.src = "192.168.1.100"
        ip.dst = "8.8.8.8"
        
        tcp = Mock()
        tcp.sport = 12345
        tcp.dport = 443
        tcp.flags = 0x18
        
        packet.__getitem__.side_effect = lambda layer: {
            'Ether': ether, 'IP': ip, 'TCP': tcp
        }.get(str(layer), Mock())
        
        # Measure processing latency
        latencies = []
        
        for i in range(100):
            start_time = time.time()
            
            # Complete processing pipeline
            behavior = analyzer.process_packet(packet)
            if behavior:
                baseline_manager.update_baseline(behavior.device_id, behavior)
                anomalies = detector.detect_anomalies(behavior.device_id, behavior)
            
            end_time = time.time()
            latency = (end_time - start_time) * 1000  # Convert to milliseconds
            latencies.append(latency)
        
        # Verify latency requirements
        avg_latency = sum(latencies) / len(latencies)
        max_latency = max(latencies)
        
        # Should meet requirement of < 100ms per packet
        assert avg_latency < 100.0, f"Average latency too high: {avg_latency:.2f}ms"
        assert max_latency < 200.0, f"Maximum latency too high: {max_latency:.2f}ms"
        
        # 95th percentile should be reasonable
        sorted_latencies = sorted(latencies)
        p95_latency = sorted_latencies[int(0.95 * len(sorted_latencies))]
        assert p95_latency < 150.0, f"95th percentile latency too high: {p95_latency:.2f}ms"


class TestOrchestrationIntegration:
    """Integration tests for orchestrator component"""
    
    @pytest.fixture
    def mock_orchestrator(self, temp_dir):
        """Create mock orchestrator for testing"""
        with patch('heimdal.capture.engine.PacketCaptureEngine'), \
             patch('heimdal.communication.asgard_communicator.AsgardCommunicator'):
            
            orchestrator = HeimdallOrchestrator()
            return orchestrator
    
    def test_orchestrator_initialization(self, mock_orchestrator):
        """Test orchestrator component initialization"""
        assert mock_orchestrator is not None
        # Additional initialization tests would go here
    
    def test_orchestrator_startup_sequence(self, mock_orchestrator):
        """Test orchestrator startup sequence"""
        # This would test the startup sequence if implemented
        # For now, just verify the orchestrator exists
        assert mock_orchestrator is not None
    
    def test_orchestrator_shutdown_sequence(self, mock_orchestrator):
        """Test orchestrator shutdown sequence"""
        # This would test the shutdown sequence if implemented
        # For now, just verify the orchestrator exists
        assert mock_orchestrator is not None


class TestComponentInteraction:
    """Test interactions between different components"""
    
    def test_analyzer_baseline_interaction(self, temp_dir):
        """Test interaction between analyzer and baseline manager"""
        baseline_manager = BaselineManager(baseline_dir=temp_dir)
        analyzer = RealtimeAnalyzer()
        
        # Create test packet
        packet = Mock()
        packet.haslayer.return_value = True
        packet.__len__.return_value = 1024
        
        ether = Mock()
        ether.src = "aa:bb:cc:dd:ee:ff"
        
        ip = Mock()
        ip.src = "192.168.1.100"
        ip.dst = "8.8.8.8"
        
        tcp = Mock()
        tcp.sport = 12345
        tcp.dport = 443
        tcp.flags = 0x18
        
        packet.__getitem__.side_effect = lambda layer: {
            'Ether': ether, 'IP': ip, 'TCP': tcp
        }.get(str(layer), Mock())
        
        # Process packet through analyzer
        behavior = analyzer.process_packet(packet)
        assert behavior is not None
        
        # Update baseline with behavior
        result = baseline_manager.update_baseline(behavior.device_id, behavior)
        assert result is True
        
        # Verify baseline was created
        baseline = baseline_manager.get_device_baseline(behavior.device_id)
        assert baseline is not None
        assert baseline.device_id == behavior.device_id
    
    def test_baseline_detector_interaction(self, temp_dir, sample_device_baseline):
        """Test interaction between baseline manager and anomaly detector"""
        baseline_manager = BaselineManager(baseline_dir=temp_dir)
        detector = AnomalyDetector(baseline_manager)
        
        # Set up baseline
        baseline_manager.set_device_baseline(sample_device_baseline)
        
        # Create test behavior
        from tests.conftest import generate_anomalous_behavior
        behavior = generate_anomalous_behavior(sample_device_baseline.device_id)
        
        # Detect anomalies
        anomalies = detector.detect_anomalies(sample_device_baseline.device_id, behavior)
        
        # Verify interaction worked
        assert isinstance(anomalies, list)
        # Anomalies should be detected for anomalous behavior
        assert len(anomalies) > 0
    
    def test_fingerprinter_analyzer_interaction(self):
        """Test interaction between device fingerprinter and analyzer"""
        fingerprinter = DeviceFingerprinter()
        analyzer = RealtimeAnalyzer()
        
        # Create test packet with device characteristics
        packet = Mock()
        packet.haslayer.return_value = True
        packet.__len__.return_value = 1024
        
        ether = Mock()
        ether.src = "00:1E:C2:12:34:56"  # Apple MAC
        
        ip = Mock()
        ip.src = "192.168.1.100"
        ip.dst = "17.253.144.10"  # Apple server
        
        tcp = Mock()
        tcp.sport = 12345
        tcp.dport = 5223  # Apple Push Notification service
        tcp.flags = 0x18
        
        packet.__getitem__.side_effect = lambda layer: {
            'Ether': ether, 'IP': ip, 'TCP': tcp
        }.get(str(layer), Mock())
        
        # Identify device
        fingerprint = fingerprinter.identify_device(packet)
        assert fingerprint is not None
        assert fingerprint.vendor == "Apple"
        
        # Process through analyzer
        behavior = analyzer.process_packet(packet)
        assert behavior is not None
        assert behavior.device_id == fingerprint.mac_address