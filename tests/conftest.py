"""
Pytest configuration and shared fixtures for Heimdal tests
"""

import pytest
import tempfile
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any
from unittest.mock import Mock, MagicMock

from scapy.packet import Packet
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR

from heimdal.models import (
    DeviceBaseline, DeviceBehavior, DeviceFeatures, Connection, 
    TrafficVolume, TrafficPattern, Anomaly, AnomalyType, SeverityLevel
)
from heimdal.analysis.device_fingerprinter import DeviceFingerprint
from heimdal.baseline.manager import BaselineManager
from heimdal.anomaly.detector import AnomalyDetector


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files"""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)


@pytest.fixture
def baseline_manager(temp_dir):
    """Create a BaselineManager instance with temporary directory"""
    return BaselineManager(baseline_dir=temp_dir)


@pytest.fixture
def mock_baseline_manager():
    """Create a mock BaselineManager for testing"""
    mock = Mock(spec=BaselineManager)
    mock.get_device_baseline.return_value = None
    mock.set_device_baseline.return_value = True
    mock.update_baseline.return_value = True
    return mock


@pytest.fixture
def sample_device_fingerprint():
    """Create a sample device fingerprint for testing"""
    return DeviceFingerprint(
        mac_address="aa:bb:cc:dd:ee:ff",
        vendor="Apple",
        device_type="iPhone",
        confidence_score=0.9,
        characteristics={
            "hostname": "iPhone-Test",
            "vendor_class": "MSFT 5.0",
            "dns_pattern": "apple"
        }
    )


@pytest.fixture
def sample_device_baseline():
    """Create a sample device baseline for testing"""
    traffic_pattern = TrafficPattern(
        peak_hours=[9, 10, 11, 18, 19, 20],
        average_session_duration=300.0,
        typical_destinations={"8.8.8.8", "1.1.1.1", "192.168.1.1"},
        common_ports={80, 443, 53, 993}
    )
    
    return DeviceBaseline(
        device_id="aa:bb:cc:dd:ee:ff",
        device_type="iPhone",
        normal_destinations={"8.8.8.8", "1.1.1.1", "apple.com", "icloud.com"},
        normal_ports={80, 443, 53, 993, 5223},
        traffic_patterns=traffic_pattern,
        last_updated=datetime.now() - timedelta(hours=1),
        confidence_score=0.8,
        global_profile_version="v1.0"
    )


@pytest.fixture
def sample_device_behavior():
    """Create a sample device behavior for testing"""
    connections = [
        Connection(
            source_ip="192.168.1.100",
            destination_ip="8.8.8.8",
            source_port=12345,
            destination_port=53,
            protocol="UDP",
            timestamp=datetime.now(),
            bytes_sent=64,
            bytes_received=128
        ),
        Connection(
            source_ip="192.168.1.100",
            destination_ip="apple.com",
            source_port=12346,
            destination_port=443,
            protocol="TCP",
            timestamp=datetime.now(),
            bytes_sent=1024,
            bytes_received=2048
        )
    ]
    
    traffic_volume = TrafficVolume(
        bytes_sent=1088,
        bytes_received=2176,
        packets_sent=2,
        packets_received=2,
        duration_seconds=30.0
    )
    
    return DeviceBehavior(
        device_id="aa:bb:cc:dd:ee:ff",
        timestamp=datetime.now(),
        connections=connections,
        traffic_volume=traffic_volume,
        protocols_used={"UDP", "TCP"},
        dns_queries=["apple.com", "icloud.com"]
    )


@pytest.fixture
def sample_device_features():
    """Create sample device features for testing"""
    traffic_volume = TrafficVolume(
        bytes_sent=512,
        bytes_received=1024,
        packets_sent=1,
        packets_received=1,
        duration_seconds=0.0
    )
    
    return DeviceFeatures(
        device_id="aa:bb:cc:dd:ee:ff",
        mac_address="aa:bb:cc:dd:ee:ff",
        ip_addresses={"192.168.1.100"},
        protocols={"TCP"},
        ports={443},
        destinations={"apple.com"},
        traffic_volume=traffic_volume,
        timestamp=datetime.now()
    )


@pytest.fixture
def sample_anomaly():
    """Create a sample anomaly for testing"""
    return Anomaly(
        device_id="aa:bb:cc:dd:ee:ff",
        anomaly_type=AnomalyType.NEW_DESTINATION,
        severity=SeverityLevel.MEDIUM,
        description="Device connected to new destination",
        timestamp=datetime.now(),
        confidence_score=0.7,
        baseline_deviation=0.5
    )


@pytest.fixture
def mock_packet_ethernet():
    """Create a mock Ethernet packet"""
    packet = Mock(spec=Packet)
    packet.haslayer.return_value = True
    
    # Mock Ethernet layer
    ether = Mock()
    ether.src = "aa:bb:cc:dd:ee:ff"
    ether.dst = "11:22:33:44:55:66"
    packet.__getitem__.return_value = ether
    
    return packet


@pytest.fixture
def mock_packet_ip():
    """Create a mock IP packet"""
    packet = Mock(spec=Packet)
    
    def haslayer_side_effect(layer):
        return layer in [Ether, IP, TCP]
    
    packet.haslayer.side_effect = haslayer_side_effect
    packet.__len__.return_value = 1024
    
    # Mock layers
    ether = Mock()
    ether.src = "aa:bb:cc:dd:ee:ff"
    packet_layers = {
        Ether: ether,
        IP: Mock(src="192.168.1.100", dst="8.8.8.8"),
        TCP: Mock(sport=12345, dport=443, window=65535, flags=0x18)
    }
    
    packet.__getitem__.side_effect = lambda layer: packet_layers[layer]
    
    return packet


@pytest.fixture
def mock_dns_packet():
    """Create a mock DNS packet"""
    packet = Mock(spec=Packet)
    
    def haslayer_side_effect(layer):
        return layer in [Ether, IP, UDP, DNS, DNSQR]
    
    packet.haslayer.side_effect = haslayer_side_effect
    packet.__len__.return_value = 128
    
    # Mock DNS query
    dns_query = Mock()
    dns_query.qname = b"apple.com."
    dns_query.qtype = 1  # A record
    
    dns = Mock()
    dns.qd = dns_query
    
    packet_layers = {
        Ether: Mock(src="aa:bb:cc:dd:ee:ff"),
        IP: Mock(src="192.168.1.100", dst="8.8.8.8"),
        UDP: Mock(sport=12345, dport=53),
        DNS: dns,
        DNSQR: dns_query
    }
    
    packet.__getitem__.side_effect = lambda layer: packet_layers[layer]
    
    return packet


@pytest.fixture
def synthetic_packet_stream():
    """Generate a stream of synthetic packets for testing"""
    packets = []
    
    # Create various types of packets
    base_time = datetime.now()
    
    for i in range(100):
        packet = Mock(spec=Packet)
        packet.haslayer.return_value = True
        packet.__len__.return_value = 64 + (i % 1000)  # Variable packet sizes
        
        # Ethernet layer
        ether = Mock()
        ether.src = f"aa:bb:cc:dd:ee:{i:02x}"
        ether.dst = "11:22:33:44:55:66"
        
        # IP layer
        ip = Mock()
        ip.src = f"192.168.1.{100 + (i % 50)}"
        ip.dst = f"8.8.{(i % 4) + 4}.{(i % 4) + 4}"
        
        # TCP layer
        tcp = Mock()
        tcp.sport = 12345 + i
        tcp.dport = [80, 443, 993, 5223][i % 4]
        tcp.flags = 0x18  # PSH+ACK
        tcp.window = 65535
        
        packet_layers = {Ether: ether, IP: ip, TCP: tcp}
        packet.__getitem__.side_effect = lambda layer: packet_layers[layer]
        
        packets.append(packet)
    
    return packets


@pytest.fixture
def anomaly_detector(mock_baseline_manager):
    """Create an AnomalyDetector instance with mock baseline manager"""
    return AnomalyDetector(mock_baseline_manager)


# Test data generators
def generate_test_connections(count: int = 5) -> List[Connection]:
    """Generate test connections"""
    connections = []
    base_time = datetime.now()
    
    for i in range(count):
        connection = Connection(
            source_ip=f"192.168.1.{100 + i}",
            destination_ip=f"8.8.{(i % 4) + 4}.{(i % 4) + 4}",
            source_port=12345 + i,
            destination_port=[80, 443, 53, 993][i % 4],
            protocol=["TCP", "UDP"][i % 2],
            timestamp=base_time + timedelta(seconds=i),
            bytes_sent=64 * (i + 1),
            bytes_received=128 * (i + 1)
        )
        connections.append(connection)
    
    return connections


def generate_anomalous_behavior(device_id: str) -> DeviceBehavior:
    """Generate behavior that should trigger anomalies"""
    # Connections to suspicious destinations
    suspicious_connections = [
        Connection(
            source_ip="192.168.1.100",
            destination_ip="1.2.3.4",  # Unknown destination
            source_port=12345,
            destination_port=8080,  # Unusual port
            protocol="TCP",
            timestamp=datetime.now(),
            bytes_sent=10000,  # High volume
            bytes_received=50000
        ),
        Connection(
            source_ip="192.168.1.100",
            destination_ip="5.6.7.8",  # Another unknown destination
            source_port=12346,
            destination_port=9999,  # Very unusual port
            protocol="UDP",
            timestamp=datetime.now(),
            bytes_sent=5000,
            bytes_received=25000
        )
    ]
    
    traffic_volume = TrafficVolume(
        bytes_sent=15000,
        bytes_received=75000,
        packets_sent=2,
        packets_received=2,
        duration_seconds=60.0
    )
    
    return DeviceBehavior(
        device_id=device_id,
        timestamp=datetime.now(),
        connections=suspicious_connections,
        traffic_volume=traffic_volume,
        protocols_used={"TCP", "UDP"},
        dns_queries=["suspicious-domain.tk", "malware-c2.ml"]
    )