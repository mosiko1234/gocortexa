#!/usr/bin/env python3
"""
Comprehensive system integration test for Heimdal real-time monitoring
This test validates the complete system integration without requiring network privileges
"""

import sys
import time
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
from unittest.mock import Mock, patch, MagicMock

# Add heimdal to path
sys.path.insert(0, str(Path(__file__).parent))

from heimdal.config.manager import ConfigurationManager
from heimdal.orchestrator import MonitoringOrchestrator
from heimdal.analysis.realtime_analyzer import RealtimeAnalyzer
from heimdal.baseline.manager import BaselineManager
from heimdal.anomaly.detector import AnomalyDetector
from heimdal.models import DeviceBehavior, Connection, TrafficVolume


def create_mock_packet():
    """Create a properly mocked packet for testing"""
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP, TCP
    
    packet = Mock()
    
    # Mock haslayer method
    packet.haslayer = Mock(side_effect=lambda layer: layer in [Ether, IP, TCP])
    
    # Mock len
    packet.__len__ = Mock(return_value=1024)
    
    # Create layer mocks
    ether = Mock()
    ether.src = "aa:bb:cc:dd:ee:ff"
    ether.dst = "ff:ff:ff:ff:ff:ff"
    
    ip = Mock()
    ip.src = "192.168.1.100"
    ip.dst = "8.8.8.8"
    ip.version = 4
    
    tcp = Mock()
    tcp.sport = 12345
    tcp.dport = 443
    tcp.flags = 0x18
    
    # Mock getitem
    layer_map = {Ether: ether, IP: ip, TCP: tcp}
    packet.__getitem__ = Mock(side_effect=lambda layer: layer_map.get(layer, Mock()))
    
    return packet


def test_packet_processing_pipeline():
    """Test the complete packet processing pipeline"""
    print("Testing packet processing pipeline...")
    
    # Initialize components
    baseline_manager = BaselineManager("./test_data/baselines")
    analyzer = RealtimeAnalyzer()
    detector = AnomalyDetector(baseline_manager)
    
    # Create test packet
    packet = create_mock_packet()
    
    # Process packet
    behavior = analyzer.process_packet(packet)
    
    if behavior:
        print(f"✓ Packet processed successfully, device: {behavior.device_id}")
        
        # Update baseline
        result = baseline_manager.update_baseline(behavior.device_id, behavior)
        print(f"✓ Baseline updated: {result}")
        
        # Detect anomalies
        anomalies = detector.detect_anomalies(behavior.device_id, behavior)
        print(f"✓ Anomaly detection completed, found {len(anomalies)} anomalies")
        
        return True
    else:
        print("✗ Failed to process packet")
        return False


def test_system_orchestration():
    """Test system orchestration with mocked network interfaces"""
    print("Testing system orchestration...")
    
    # Mock network interfaces and packet capture
    with patch('heimdal.capture.engine.netifaces.interfaces', return_value=['lo']), \
         patch('heimdal.capture.engine.netifaces.ifaddresses') as mock_ifaddresses, \
         patch('heimdal.capture.engine.AsyncSniffer') as mock_sniffer:
        
        # Configure mock network interface
        mock_ifaddresses.return_value = {
            2: [{'addr': '127.0.0.1', 'netmask': '255.0.0.0'}]  # AF_INET
        }
        
        # Configure mock sniffer
        mock_sniffer_instance = Mock()
        mock_sniffer_instance.start = Mock()
        mock_sniffer_instance.stop = Mock()
        mock_sniffer_instance.join = Mock()
        mock_sniffer.return_value = mock_sniffer_instance
        
        # Create configuration
        config_manager = ConfigurationManager("test_config.yaml")
        
        # Initialize orchestrator
        orchestrator = MonitoringOrchestrator(config_manager)
        
        # Test startup
        startup_success = orchestrator.start()
        print(f"✓ Orchestrator startup: {startup_success}")
        
        if startup_success:
            # Test status
            status = orchestrator.get_status()
            print(f"✓ System status - Running: {status['running']}")
            
            # Test component status
            components = status.get('components', {})
            for comp_name, comp_status in components.items():
                print(f"  - {comp_name}: {comp_status['status']}")
            
            # Test shutdown
            shutdown_success = orchestrator.stop()
            print(f"✓ Orchestrator shutdown: {shutdown_success}")
            
            return startup_success and shutdown_success
        
        return False


def test_performance_requirements():
    """Test basic performance requirements"""
    print("Testing performance requirements...")
    
    analyzer = RealtimeAnalyzer()
    packet = create_mock_packet()
    
    # Measure processing latency
    latencies = []
    for i in range(100):
        start_time = time.perf_counter()
        behavior = analyzer.process_packet(packet)
        end_time = time.perf_counter()
        
        latency_ms = (end_time - start_time) * 1000
        latencies.append(latency_ms)
    
    avg_latency = sum(latencies) / len(latencies)
    max_latency = max(latencies)
    
    print(f"✓ Average latency: {avg_latency:.2f}ms")
    print(f"✓ Maximum latency: {max_latency:.2f}ms")
    
    # Check requirements
    latency_ok = avg_latency < 10.0 and max_latency < 100.0
    print(f"✓ Latency requirements met: {latency_ok}")
    
    return latency_ok


def test_data_persistence():
    """Test data persistence and recovery"""
    print("Testing data persistence...")
    
    baseline_manager = BaselineManager("./test_data/baselines")
    
    # Create test behavior
    test_behavior = DeviceBehavior(
        device_id="integration_test_device",
        timestamp=datetime.now(),
        connections=[
            Connection(
                source_ip="192.168.1.100",
                destination_ip="8.8.8.8",
                source_port=12345,
                destination_port=443,
                protocol="TCP",
                timestamp=datetime.now(),
                bytes_sent=1024,
                bytes_received=2048
            )
        ],
        traffic_volume=TrafficVolume(1024, 2048, 1, 1, 30.0),
        protocols_used={"TCP"},
        dns_queries=[]
    )
    
    # Test baseline creation and persistence
    baseline_manager.update_baseline(test_behavior.device_id, test_behavior)
    save_result = baseline_manager.save_baselines()
    print(f"✓ Baseline save: {save_result}")
    
    # Test loading
    load_result = baseline_manager.load_baselines()
    print(f"✓ Baseline load: {load_result}")
    
    # Verify persistence
    loaded_baseline = baseline_manager.get_device_baseline(test_behavior.device_id)
    persistence_ok = loaded_baseline is not None
    print(f"✓ Data persistence: {persistence_ok}")
    
    return save_result and load_result and persistence_ok


def test_error_handling():
    """Test error handling and recovery"""
    print("Testing error handling...")
    
    analyzer = RealtimeAnalyzer()
    baseline_manager = BaselineManager("./test_data/baselines")
    
    # Test malformed packet handling
    malformed_packet = Mock()
    malformed_packet.haslayer = Mock(return_value=False)
    
    behavior = analyzer.process_packet(malformed_packet)
    malformed_ok = behavior is None
    print(f"✓ Malformed packet handling: {malformed_ok}")
    
    # Test invalid data handling
    invalid_result = baseline_manager.update_baseline("", None)
    invalid_ok = not invalid_result
    print(f"✓ Invalid data handling: {invalid_ok}")
    
    return malformed_ok and invalid_ok


def main():
    """Run comprehensive integration tests"""
    print("=" * 60)
    print("HEIMDAL SYSTEM INTEGRATION TEST")
    print("=" * 60)
    
    tests = [
        ("Packet Processing Pipeline", test_packet_processing_pipeline),
        ("Performance Requirements", test_performance_requirements),
        ("Data Persistence", test_data_persistence),
        ("Error Handling", test_error_handling),
        ("System Orchestration", test_system_orchestration),
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        print(f"\n--- {test_name} ---")
        try:
            success = test_func()
            results[test_name] = success
            status = "PASS" if success else "FAIL"
            print(f"Result: {status}")
        except Exception as e:
            print(f"ERROR: {e}")
            results[test_name] = False
    
    # Print summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for result in results.values() if result)
    total = len(results)
    
    for test_name, result in results.items():
        status = "PASS" if result else "FAIL"
        print(f"{test_name}: {status}")
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 ALL INTEGRATION TESTS PASSED!")
        print("System integration is working correctly.")
        return 0
    else:
        print(f"\n❌ {total - passed} tests failed.")
        print("System integration needs attention.")
        return 1


if __name__ == "__main__":
    sys.exit(main())