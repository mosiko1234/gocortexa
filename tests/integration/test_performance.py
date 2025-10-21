"""
Performance tests for real-time monitoring system
"""

import pytest
import time
import asyncio
import threading
import statistics
import concurrent.futures
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
from typing import List, Dict, Any
import psutil
import os

from heimdal.analysis.realtime_analyzer import RealtimeAnalyzer
from heimdal.baseline.manager import BaselineManager
from heimdal.anomaly.detector import AnomalyDetector
from heimdal.capture.engine import PacketCaptureEngine


class TestPerformanceRequirements:
    """Test performance requirements for real-time monitoring"""
    
    @pytest.fixture
    def performance_components(self, temp_dir):
        """Create components for performance testing"""
        baseline_manager = BaselineManager(baseline_dir=temp_dir)
        analyzer = RealtimeAnalyzer()
        detector = AnomalyDetector(baseline_manager)
        
        return {
            'baseline_manager': baseline_manager,
            'analyzer': analyzer,
            'detector': detector
        }
    
    def test_packet_processing_latency(self, performance_components):
        """Test packet processing meets latency requirements (<100ms)"""
        analyzer = performance_components['analyzer']
        
        # Create test packet
        packet = self._create_test_packet("aa:bb:cc:dd:ee:ff", "192.168.1.100", "8.8.8.8")
        
        # Measure processing latency over multiple iterations
        latencies = []
        iterations = 1000
        
        for i in range(iterations):
            start_time = time.perf_counter()
            behavior = analyzer.process_packet(packet)
            end_time = time.perf_counter()
            
            latency_ms = (end_time - start_time) * 1000
            latencies.append(latency_ms)
        
        # Analyze latency statistics
        avg_latency = statistics.mean(latencies)
        max_latency = max(latencies)
        p95_latency = statistics.quantiles(latencies, n=20)[18]  # 95th percentile
        p99_latency = statistics.quantiles(latencies, n=100)[98]  # 99th percentile
        
        # Performance assertions
        assert avg_latency < 5.0, f"Average latency too high: {avg_latency:.2f}ms"
        assert p95_latency < 10.0, f"95th percentile latency too high: {p95_latency:.2f}ms"
        assert p99_latency < 50.0, f"99th percentile latency too high: {p99_latency:.2f}ms"
        assert max_latency < 100.0, f"Maximum latency too high: {max_latency:.2f}ms"
    
    def test_throughput_requirements(self, performance_components):
        """Test system can handle required packet throughput (1000+ pps)"""
        analyzer = performance_components['analyzer']
        baseline_manager = performance_components['baseline_manager']
        
        # Generate packet stream
        packets = []
        for i in range(5000):  # 5000 packets for throughput test
            device_id = f"aa:bb:cc:dd:ee:{(i % 10):02x}"
            src_ip = f"192.168.1.{100 + (i % 50)}"
            dst_ip = f"8.8.{(i % 4) + 4}.{(i % 4) + 4}"
            packet = self._create_test_packet(device_id, src_ip, dst_ip)
            packets.append(packet)
        
        # Measure throughput
        start_time = time.perf_counter()
        processed_count = 0
        
        for packet in packets:
            behavior = analyzer.process_packet(packet)
            if behavior:
                baseline_manager.update_baseline(behavior.device_id, behavior)
                processed_count += 1
        
        end_time = time.perf_counter()
        processing_time = end_time - start_time
        
        # Calculate throughput
        packets_per_second = len(packets) / processing_time
        behaviors_per_second = processed_count / processing_time
        
        # Performance assertions
        assert packets_per_second >= 1000, f"Packet throughput too low: {packets_per_second:.0f} pps"
        assert behaviors_per_second >= 100, f"Behavior processing too low: {behaviors_per_second:.0f} bps"
        
        print(f"Processed {len(packets)} packets in {processing_time:.2f}s")
        print(f"Throughput: {packets_per_second:.0f} packets/second")
        print(f"Behavior generation: {behaviors_per_second:.0f} behaviors/second")
    
    def test_memory_usage_under_load(self, performance_components):
        """Test memory usage remains stable under sustained load"""
        analyzer = performance_components['analyzer']
        baseline_manager = performance_components['baseline_manager']
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        memory_samples = [initial_memory]
        
        # Process packets in batches over time
        for batch in range(20):  # 20 batches
            # Generate batch of packets
            for i in range(500):  # 500 packets per batch
                device_id = f"aa:bb:cc:dd:ee:{(i % 20):02x}"
                packet = self._create_test_packet(device_id, "192.168.1.100", "8.8.8.8")
                
                behavior = analyzer.process_packet(packet)
                if behavior:
                    baseline_manager.update_baseline(behavior.device_id, behavior)
            
            # Sample memory usage
            current_memory = process.memory_info().rss / 1024 / 1024  # MB
            memory_samples.append(current_memory)
            
            # Small delay between batches
            time.sleep(0.1)
        
        # Analyze memory usage
        final_memory = memory_samples[-1]
        max_memory = max(memory_samples)
        memory_growth = (final_memory - initial_memory) / initial_memory
        
        # Memory usage assertions
        assert memory_growth < 0.5, f"Memory growth too high: {memory_growth:.1%}"
        assert max_memory < initial_memory + 100, f"Memory spike too high: {max_memory:.1f}MB"
        
        print(f"Initial memory: {initial_memory:.1f}MB")
        print(f"Final memory: {final_memory:.1f}MB")
        print(f"Memory growth: {memory_growth:.1%}")
    
    def test_concurrent_processing(self, performance_components):
        """Test concurrent packet processing performance"""
        analyzer = performance_components['analyzer']
        
        def process_packet_batch(batch_id: int, packet_count: int) -> Dict[str, Any]:
            """Process a batch of packets in a thread"""
            start_time = time.perf_counter()
            processed = 0
            
            for i in range(packet_count):
                device_id = f"device_{batch_id}_{i:03d}"
                packet = self._create_test_packet(device_id, "192.168.1.100", "8.8.8.8")
                
                behavior = analyzer.process_packet(packet)
                if behavior:
                    processed += 1
            
            end_time = time.perf_counter()
            
            return {
                'batch_id': batch_id,
                'processed': processed,
                'duration': end_time - start_time,
                'pps': packet_count / (end_time - start_time)
            }
        
        # Run concurrent processing
        num_threads = 4
        packets_per_thread = 1000
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = []
            
            start_time = time.perf_counter()
            
            for thread_id in range(num_threads):
                future = executor.submit(process_packet_batch, thread_id, packets_per_thread)
                futures.append(future)
            
            # Collect results
            results = []
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                results.append(result)
            
            end_time = time.perf_counter()
        
        # Analyze concurrent performance
        total_packets = num_threads * packets_per_thread
        total_time = end_time - start_time
        overall_pps = total_packets / total_time
        
        avg_thread_pps = statistics.mean([r['pps'] for r in results])
        
        # Performance assertions
        assert overall_pps >= 2000, f"Concurrent throughput too low: {overall_pps:.0f} pps"
        assert avg_thread_pps >= 500, f"Per-thread throughput too low: {avg_thread_pps:.0f} pps"
        
        print(f"Concurrent processing: {overall_pps:.0f} packets/second overall")
        print(f"Average per thread: {avg_thread_pps:.0f} packets/second")
    
    def test_anomaly_detection_performance(self, performance_components, sample_device_baseline):
        """Test anomaly detection performance under load"""
        detector = performance_components['detector']
        baseline_manager = performance_components['baseline_manager']
        
        # Set up baseline
        baseline_manager.set_device_baseline(sample_device_baseline)
        
        # Generate test behaviors
        behaviors = []
        for i in range(1000):
            behavior = self._create_test_behavior(
                sample_device_baseline.device_id,
                anomalous=(i % 10 == 0)  # 10% anomalous behaviors
            )
            behaviors.append(behavior)
        
        # Measure anomaly detection performance
        start_time = time.perf_counter()
        total_anomalies = 0
        
        for behavior in behaviors:
            anomalies = detector.detect_anomalies(sample_device_baseline.device_id, behavior)
            total_anomalies += len(anomalies)
        
        end_time = time.perf_counter()
        processing_time = end_time - start_time
        
        # Calculate performance metrics
        behaviors_per_second = len(behaviors) / processing_time
        detection_latency = (processing_time / len(behaviors)) * 1000  # ms per behavior
        
        # Performance assertions
        assert behaviors_per_second >= 500, f"Anomaly detection too slow: {behaviors_per_second:.0f} bps"
        assert detection_latency < 10.0, f"Detection latency too high: {detection_latency:.2f}ms"
        assert total_anomalies > 0, "No anomalies detected in test data"
        
        print(f"Anomaly detection: {behaviors_per_second:.0f} behaviors/second")
        print(f"Detection latency: {detection_latency:.2f}ms per behavior")
        print(f"Detected {total_anomalies} anomalies in {len(behaviors)} behaviors")
    
    def _create_test_packet(self, device_mac: str, src_ip: str, dst_ip: str) -> Mock:
        """Create a mock packet for testing"""
        packet = Mock()
        packet.haslayer.return_value = True
        packet.__len__.return_value = 1024
        
        # Mock Ethernet layer
        ether = Mock()
        ether.src = device_mac
        
        # Mock IP layer
        ip = Mock()
        ip.src = src_ip
        ip.dst = dst_ip
        
        # Mock TCP layer
        tcp = Mock()
        tcp.sport = 12345
        tcp.dport = 443
        tcp.flags = 0x18
        tcp.window = 65535
        
        packet.__getitem__.side_effect = lambda layer: {
            'Ether': ether, 'IP': ip, 'TCP': tcp
        }.get(str(layer), Mock())
        
        return packet
    
    def _create_test_behavior(self, device_id: str, anomalous: bool = False) -> 'DeviceBehavior':
        """Create test device behavior"""
        from heimdal.models import DeviceBehavior, Connection, TrafficVolume
        
        if anomalous:
            # Create anomalous behavior
            connections = [
                Connection(
                    source_ip="192.168.1.100",
                    destination_ip="1.2.3.4",  # Unusual destination
                    source_port=12345,
                    destination_port=8080,  # Unusual port
                    protocol="TCP",
                    timestamp=datetime.now(),
                    bytes_sent=10000,
                    bytes_received=50000
                )
            ]
            traffic_volume = TrafficVolume(10000, 50000, 1, 1, 30.0)
        else:
            # Create normal behavior
            connections = [
                Connection(
                    source_ip="192.168.1.100",
                    destination_ip="8.8.8.8",  # Normal destination
                    source_port=12345,
                    destination_port=443,  # Normal port
                    protocol="TCP",
                    timestamp=datetime.now(),
                    bytes_sent=1024,
                    bytes_received=2048
                )
            ]
            traffic_volume = TrafficVolume(1024, 2048, 1, 1, 30.0)
        
        return DeviceBehavior(
            device_id=device_id,
            timestamp=datetime.now(),
            connections=connections,
            traffic_volume=traffic_volume,
            protocols_used={"TCP"},
            dns_queries=[]
        )