#!/usr/bin/env python3
"""
Integration validation script for Heimdal real-time monitoring system
This script validates the complete packet capture → analysis → anomaly detection → cloud communication flow
"""

import sys
import time
import threading
import signal
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List
from unittest.mock import Mock, patch

# Add heimdal to path
sys.path.insert(0, str(Path(__file__).parent))

from heimdal.config.manager import ConfigurationManager
from heimdal.orchestrator import MonitoringOrchestrator
from heimdal.main import HeimdallApplication
from heimdal.models import DeviceBehavior, Connection, TrafficVolume


class IntegrationValidator:
    """Validates complete system integration"""
    
    def __init__(self):
        self.results = {}
        self.errors = []
        self.warnings = []
        
    def log_result(self, test_name: str, success: bool, message: str = ""):
        """Log test result"""
        self.results[test_name] = {
            'success': success,
            'message': message,
            'timestamp': datetime.now()
        }
        
        status = "✓" if success else "✗"
        print(f"{status} {test_name}: {message}")
        
        if not success:
            self.errors.append(f"{test_name}: {message}")
    
    def log_warning(self, message: str):
        """Log warning"""
        self.warnings.append(message)
        print(f"⚠ Warning: {message}")
    
    def validate_configuration_system(self) -> bool:
        """Validate configuration management system"""
        print("\n=== Configuration System Validation ===")
        
        try:
            # Test configuration loading
            config_manager = ConfigurationManager("test_config.yaml")
            self.log_result("config_loading", True, "Configuration loaded successfully")
            
            # Test configuration validation
            errors = config_manager.validate_config()
            # Filter out log directory permission errors for testing
            filtered_errors = [e for e in errors if "Cannot create log directory /var/log/heimdal" not in e]
            if filtered_errors:
                self.log_result("config_validation", False, f"Configuration errors: {filtered_errors}")
                return False
            else:
                self.log_result("config_validation", True, "Configuration is valid (ignoring log directory permissions)")
            
            # Test configuration access
            interface = config_manager.get_config("capture.interface", "eth0")
            self.log_result("config_access", True, f"Retrieved interface: {interface}")
            
            return True
            
        except Exception as e:
            self.log_result("config_system", False, f"Configuration system error: {e}")
            return False
    
    def validate_component_initialization(self) -> bool:
        """Validate all components can be initialized"""
        print("\n=== Component Initialization Validation ===")
        
        try:
            config_manager = ConfigurationManager("test_config.yaml")
            
            # Test orchestrator initialization
            orchestrator = MonitoringOrchestrator(config_manager)
            self.log_result("orchestrator_init", True, "Orchestrator initialized")
            
            # Test main application initialization
            app = HeimdallApplication("test_config.yaml")
            self.log_result("application_init", True, "Main application initialized")
            
            return True
            
        except Exception as e:
            self.log_result("component_init", False, f"Component initialization error: {e}")
            return False
    
    def validate_packet_processing_pipeline(self) -> bool:
        """Validate complete packet processing pipeline"""
        print("\n=== Packet Processing Pipeline Validation ===")
        
        try:
            from heimdal.analysis.realtime_analyzer import RealtimeAnalyzer
            from heimdal.baseline.manager import BaselineManager
            from heimdal.anomaly.detector import AnomalyDetector
            
            # Initialize components with correct parameters
            baseline_manager = BaselineManager("./data/baselines")
            analyzer = RealtimeAnalyzer()
            detector = AnomalyDetector(baseline_manager)
            
            # Create test packet
            packet = self._create_test_packet()
            
            # Test packet analysis
            behavior = analyzer.process_packet(packet)
            if behavior:
                self.log_result("packet_analysis", True, f"Packet analyzed, device: {behavior.device_id}")
            else:
                self.log_result("packet_analysis", False, "Failed to analyze packet")
                return False
            
            # Test baseline update
            result = baseline_manager.update_baseline(behavior.device_id, behavior)
            self.log_result("baseline_update", result, "Baseline updated" if result else "Baseline update failed")
            
            # Test anomaly detection
            anomalies = detector.detect_anomalies(behavior.device_id, behavior)
            self.log_result("anomaly_detection", True, f"Anomaly detection completed, found {len(anomalies)} anomalies")
            
            return True
            
        except Exception as e:
            self.log_result("packet_pipeline", False, f"Pipeline error: {e}")
            return False
    
    def validate_data_persistence(self) -> bool:
        """Validate data persistence and loading"""
        print("\n=== Data Persistence Validation ===")
        
        try:
            from heimdal.baseline.manager import BaselineManager
            
            baseline_manager = BaselineManager("./data/baselines")
            
            # Create test behavior
            test_behavior = DeviceBehavior(
                device_id="test_device_123",
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
            
            # Test baseline creation and saving
            baseline_manager.update_baseline(test_behavior.device_id, test_behavior)
            save_result = baseline_manager.save_baselines()
            self.log_result("baseline_save", save_result, "Baselines saved" if save_result else "Save failed")
            
            # Test baseline loading
            load_result = baseline_manager.load_baselines()
            self.log_result("baseline_load", load_result, "Baselines loaded" if load_result else "Load failed")
            
            # Verify data persistence
            loaded_baseline = baseline_manager.get_device_baseline(test_behavior.device_id)
            if loaded_baseline:
                self.log_result("data_persistence", True, f"Baseline persisted for device {loaded_baseline.device_id}")
            else:
                self.log_result("data_persistence", False, "Baseline not found after reload")
            
            return True
            
        except Exception as e:
            self.log_result("data_persistence", False, f"Persistence error: {e}")
            return False
    
    def validate_error_handling(self) -> bool:
        """Validate error handling and recovery"""
        print("\n=== Error Handling Validation ===")
        
        try:
            from heimdal.analysis.realtime_analyzer import RealtimeAnalyzer
            from heimdal.baseline.manager import BaselineManager
            
            baseline_manager = BaselineManager("./data/baselines")
            analyzer = RealtimeAnalyzer()
            
            # Test with malformed packet
            malformed_packet = Mock()
            malformed_packet.haslayer.return_value = False
            
            behavior = analyzer.process_packet(malformed_packet)
            if behavior is None:
                self.log_result("malformed_packet_handling", True, "Malformed packet handled gracefully")
            else:
                self.log_result("malformed_packet_handling", False, "Malformed packet not handled properly")
            
            # Test with invalid baseline data
            invalid_result = baseline_manager.update_baseline("", None)
            if not invalid_result:
                self.log_result("invalid_data_handling", True, "Invalid data rejected properly")
            else:
                self.log_result("invalid_data_handling", False, "Invalid data not handled properly")
            
            return True
            
        except Exception as e:
            self.log_result("error_handling", False, f"Error handling test failed: {e}")
            return False
    
    def validate_performance_requirements(self) -> bool:
        """Validate basic performance requirements"""
        print("\n=== Performance Requirements Validation ===")
        
        try:
            from heimdal.analysis.realtime_analyzer import RealtimeAnalyzer
            from heimdal.baseline.manager import BaselineManager
            
            baseline_manager = BaselineManager("./data/baselines")
            analyzer = RealtimeAnalyzer()
            
            # Test processing latency
            packet = self._create_test_packet()
            
            latencies = []
            for i in range(100):
                start_time = time.perf_counter()
                behavior = analyzer.process_packet(packet)
                end_time = time.perf_counter()
                
                latency_ms = (end_time - start_time) * 1000
                latencies.append(latency_ms)
            
            avg_latency = sum(latencies) / len(latencies)
            max_latency = max(latencies)
            
            # Check latency requirements
            if avg_latency < 10.0:  # 10ms average
                self.log_result("latency_requirement", True, f"Average latency: {avg_latency:.2f}ms")
            else:
                self.log_result("latency_requirement", False, f"Average latency too high: {avg_latency:.2f}ms")
            
            if max_latency < 100.0:  # 100ms max
                self.log_result("max_latency_requirement", True, f"Max latency: {max_latency:.2f}ms")
            else:
                self.log_result("max_latency_requirement", False, f"Max latency too high: {max_latency:.2f}ms")
            
            return True
            
        except Exception as e:
            self.log_result("performance_validation", False, f"Performance validation error: {e}")
            return False
    
    def validate_system_integration(self) -> bool:
        """Validate complete system integration"""
        print("\n=== System Integration Validation ===")
        
        try:
            # Mock network interfaces to avoid requiring root privileges
            with patch('heimdal.capture.engine.netifaces.interfaces', return_value=['eth0', 'lo']), \
                 patch('heimdal.capture.engine.netifaces.ifaddresses', return_value={}), \
                 patch('heimdal.capture.engine.AsyncSniffer') as mock_sniffer:
                
                # Configure mock sniffer
                mock_sniffer_instance = Mock()
                mock_sniffer_instance.start.return_value = None
                mock_sniffer_instance.stop.return_value = None
                mock_sniffer_instance.join.return_value = None
                mock_sniffer.return_value = mock_sniffer_instance
                
                config_manager = ConfigurationManager("test_config.yaml")
                orchestrator = MonitoringOrchestrator(config_manager)
                
                # Test orchestrator startup
                startup_success = orchestrator.start()
                self.log_result("orchestrator_startup", startup_success, "Orchestrator started" if startup_success else "Startup failed")
                
                if startup_success:
                    # Test system status
                    status = orchestrator.get_status()
                    self.log_result("system_status", True, f"System running: {status['running']}")
                    
                    # Test graceful shutdown
                    shutdown_success = orchestrator.stop()
                    self.log_result("orchestrator_shutdown", shutdown_success, "Orchestrator stopped" if shutdown_success else "Shutdown failed")
                
                return startup_success
            
        except Exception as e:
            self.log_result("system_integration", False, f"Integration error: {e}")
            return False
    
    def _create_test_packet(self) -> Mock:
        """Create a mock packet for testing"""
        from scapy.layers.l2 import Ether
        from scapy.layers.inet import IP, TCP
        
        packet = Mock()
        
        # Mock haslayer method to return True for expected layers
        def mock_haslayer(layer_type):
            return layer_type in [Ether, IP, TCP]
        packet.haslayer = mock_haslayer
        
        # Mock the len() function properly
        packet.__len__ = Mock(return_value=1024)
        
        # Mock Ethernet layer
        ether = Mock()
        ether.src = "aa:bb:cc:dd:ee:ff"
        ether.dst = "ff:ff:ff:ff:ff:ff"
        
        # Mock IP layer
        ip = Mock()
        ip.src = "192.168.1.100"
        ip.dst = "8.8.8.8"
        ip.version = 4
        
        # Mock TCP layer
        tcp = Mock()
        tcp.sport = 12345
        tcp.dport = 443
        tcp.flags = 0x18
        
        # Create a simple layer mapping
        layer_map = {
            Ether: ether,
            IP: ip,
            TCP: tcp,
            'Ether': ether,
            'IP': ip,
            'TCP': tcp
        }
        
        # Mock layer access with proper side_effect
        packet.__getitem__ = Mock(side_effect=lambda layer: layer_map.get(layer, Mock()))
        
        return packet
    
    def run_validation(self) -> bool:
        """Run complete validation suite"""
        print("Starting Heimdal Integration Validation")
        print("=" * 50)
        
        validation_steps = [
            ("Configuration System", self.validate_configuration_system),
            ("Component Initialization", self.validate_component_initialization),
            ("Packet Processing Pipeline", self.validate_packet_processing_pipeline),
            ("Data Persistence", self.validate_data_persistence),
            ("Error Handling", self.validate_error_handling),
            ("Performance Requirements", self.validate_performance_requirements),
            ("System Integration", self.validate_system_integration),
        ]
        
        all_passed = True
        
        for step_name, validation_func in validation_steps:
            try:
                success = validation_func()
                if not success:
                    all_passed = False
            except Exception as e:
                self.log_result(step_name, False, f"Validation step failed: {e}")
                all_passed = False
        
        # Print summary
        self.print_summary()
        
        return all_passed
    
    def print_summary(self):
        """Print validation summary"""
        print("\n" + "=" * 50)
        print("VALIDATION SUMMARY")
        print("=" * 50)
        
        passed = sum(1 for r in self.results.values() if r['success'])
        total = len(self.results)
        
        print(f"Tests Passed: {passed}/{total}")
        
        if self.errors:
            print(f"\nErrors ({len(self.errors)}):")
            for error in self.errors:
                print(f"  ✗ {error}")
        
        if self.warnings:
            print(f"\nWarnings ({len(self.warnings)}):")
            for warning in self.warnings:
                print(f"  ⚠ {warning}")
        
        if passed == total:
            print("\n🎉 ALL VALIDATIONS PASSED - System integration is working correctly!")
        else:
            print(f"\n❌ {total - passed} validations failed - System needs attention")


def main():
    """Main entry point"""
    validator = IntegrationValidator()
    
    # Handle Ctrl+C gracefully
    def signal_handler(signum, frame):
        print("\n\nValidation interrupted by user")
        sys.exit(1)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        success = validator.run_validation()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\nFatal error during validation: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()