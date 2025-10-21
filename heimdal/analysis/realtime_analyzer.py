"""
Real-time packet analyzer for network monitoring
"""

from typing import Dict, Optional, Set, List
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, field
import ipaddress
from scapy.packet import Packet
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.dhcp import DHCP

from ..interfaces import IRealtimeAnalyzer
from ..models import DeviceBehavior, DeviceFeatures, Connection, TrafficVolume
from .device_fingerprinter import DeviceFingerprinter, DeviceFingerprint
from .behavioral_extractor import BehavioralExtractor, BehavioralFeatures


@dataclass
class DeviceActivity:
    """Tracks ongoing activity for a device"""
    device_id: str
    mac_address: str
    ip_addresses: Set[str] = field(default_factory=set)
    connections: List[Connection] = field(default_factory=list)
    protocols: Set[str] = field(default_factory=set)
    ports: Set[int] = field(default_factory=set)
    destinations: Set[str] = field(default_factory=set)
    dns_queries: List[str] = field(default_factory=list)
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    
    def update_traffic(self, packet_size: int, is_outbound: bool):
        """Update traffic statistics"""
        if is_outbound:
            self.bytes_sent += packet_size
            self.packets_sent += 1
        else:
            self.bytes_received += packet_size
            self.packets_received += 1
        self.last_seen = datetime.now()


class RealtimeAnalyzer(IRealtimeAnalyzer):
    """Real-time packet analyzer implementation"""
    
    def __init__(self, local_networks: List[str] = None):
        """
        Initialize the real-time analyzer
        
        Args:
            local_networks: List of local network CIDR blocks (e.g., ['192.168.1.0/24'])
        """
        self.device_fingerprinter = DeviceFingerprinter()
        self.behavioral_extractor = BehavioralExtractor()
        self.device_activities: Dict[str, DeviceActivity] = {}
        self.local_networks = local_networks or ['192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12']
        self.local_network_objects = [ipaddress.ip_network(net) for net in self.local_networks]
        
        # Behavior aggregation settings
        self.behavior_window = timedelta(minutes=5)  # 5-minute behavior windows
        self.max_connections_per_behavior = 100
        self.max_dns_queries_per_behavior = 50
        
        # Activity cleanup settings
        self.activity_timeout = timedelta(hours=1)
        self.last_cleanup = datetime.now()
        self.cleanup_interval = timedelta(minutes=10)
        
        # Packet buffer for behavioral analysis
        self.packet_buffer: Dict[str, List[Packet]] = defaultdict(list)
        self.buffer_max_size = 1000
    
    def process_packet(self, packet: Packet) -> Optional[DeviceBehavior]:
        """
        Process a single packet and return device behavior if significant
        
        Args:
            packet: Network packet to process
            
        Returns:
            DeviceBehavior if behavior should be reported, None otherwise
        """
        if not packet.haslayer(Ether):
            return None
        
        # Identify or register device
        fingerprint = self.device_fingerprinter.identify_device(packet)
        if not fingerprint:
            return None
        
        device_id = fingerprint.mac_address
        
        # Get or create device activity
        if device_id not in self.device_activities:
            self.device_activities[device_id] = DeviceActivity(
                device_id=device_id,
                mac_address=fingerprint.mac_address
            )
        
        activity = self.device_activities[device_id]
        
        # Add packet to buffer for behavioral analysis
        self.packet_buffer[device_id].append(packet)
        if len(self.packet_buffer[device_id]) > self.buffer_max_size:
            self.packet_buffer[device_id] = self.packet_buffer[device_id][-self.buffer_max_size:]
        
        # Extract features from packet
        features = self.extract_device_features(packet)
        if features:
            self.update_device_activity(device_id, features)
        
        # Check if we should generate behavior report
        behavior = self._check_behavior_trigger(activity)
        
        # Periodic cleanup
        self._periodic_cleanup()
        
        return behavior
    
    def extract_device_features(self, packet: Packet) -> Optional[DeviceFeatures]:
        """
        Extract device features from a packet
        
        Args:
            packet: Network packet to analyze
            
        Returns:
            DeviceFeatures if features can be extracted, None otherwise
        """
        if not packet.haslayer(Ether):
            return None
        
        mac_address = packet[Ether].src
        protocols = set()
        ports = set()
        destinations = set()
        ip_addresses = set()
        
        # Extract IP information
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            ip_addresses.add(ip_layer.src)
            
            # Determine if this is outbound traffic
            is_outbound = self._is_local_ip(ip_layer.src)
            if is_outbound:
                destinations.add(ip_layer.dst)
            
            protocols.add('IP')
            
            # Extract transport layer information
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                protocols.add('TCP')
                if is_outbound:
                    ports.add(tcp_layer.dport)
                else:
                    ports.add(tcp_layer.sport)
            
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                protocols.add('UDP')
                if is_outbound:
                    ports.add(udp_layer.dport)
                else:
                    ports.add(udp_layer.sport)
            
            elif packet.haslayer(ICMP):
                protocols.add('ICMP')
        
        # Calculate traffic volume
        packet_size = len(packet)
        is_outbound = packet.haslayer(IP) and self._is_local_ip(packet[IP].src)
        
        traffic_volume = TrafficVolume(
            bytes_sent=packet_size if is_outbound else 0,
            bytes_received=0 if is_outbound else packet_size,
            packets_sent=1 if is_outbound else 0,
            packets_received=0 if is_outbound else 1,
            duration_seconds=0.0  # Single packet, no duration
        )
        
        return DeviceFeatures(
            device_id=mac_address,
            mac_address=mac_address,
            ip_addresses=ip_addresses,
            protocols=protocols,
            ports=ports,
            destinations=destinations,
            traffic_volume=traffic_volume,
            timestamp=datetime.now()
        )
    
    def update_device_activity(self, device_id: str, features: DeviceFeatures) -> None:
        """
        Update device activity tracking
        
        Args:
            device_id: Device identifier
            features: Extracted device features
        """
        if device_id not in self.device_activities:
            return
        
        activity = self.device_activities[device_id]
        
        # Update basic information
        activity.ip_addresses.update(features.ip_addresses)
        activity.protocols.update(features.protocols)
        activity.ports.update(features.ports)
        activity.destinations.update(features.destinations)
        
        # Update traffic statistics
        traffic = features.traffic_volume
        activity.update_traffic(
            traffic.bytes_sent + traffic.bytes_received,
            traffic.bytes_sent > 0
        )
        
        # Create connection records for significant connections
        if features.destinations:
            for dest_ip in features.destinations:
                for port in features.ports:
                    # Find source IP (should be local)
                    src_ip = next((ip for ip in features.ip_addresses if self._is_local_ip(ip)), None)
                    if src_ip:
                        connection = Connection(
                            source_ip=src_ip,
                            destination_ip=dest_ip,
                            source_port=0,  # We don't track source ports in this simplified version
                            destination_port=port,
                            protocol=next(iter(features.protocols)) if features.protocols else 'Unknown',
                            timestamp=features.timestamp,
                            bytes_sent=traffic.bytes_sent,
                            bytes_received=traffic.bytes_received
                        )
                        activity.connections.append(connection)
                        
                        # Limit connection history
                        if len(activity.connections) > self.max_connections_per_behavior:
                            activity.connections = activity.connections[-self.max_connections_per_behavior:]
        
        # Extract DNS queries if present
        self._extract_dns_queries(features, activity)
    
    def get_device_behavior(self, device_id: str) -> Optional[DeviceBehavior]:
        """
        Get current behavior for a device
        
        Args:
            device_id: Device identifier
            
        Returns:
            DeviceBehavior if device exists, None otherwise
        """
        if device_id not in self.device_activities:
            return None
        
        activity = self.device_activities[device_id]
        return self._create_behavior_from_activity(activity)
    
    def _check_behavior_trigger(self, activity: DeviceActivity) -> Optional[DeviceBehavior]:
        """Check if device activity should trigger a behavior report"""
        now = datetime.now()
        
        # Trigger on significant activity changes
        time_since_last = now - activity.last_seen
        
        # Trigger conditions:
        # 1. New connections to external destinations
        # 2. Significant traffic volume changes
        # 3. New protocols or ports
        # 4. Time-based reporting (every behavior_window)
        
        recent_connections = [
            conn for conn in activity.connections 
            if now - conn.timestamp <= self.behavior_window
        ]
        
        if (len(recent_connections) >= 5 or  # Multiple recent connections
            activity.bytes_sent + activity.bytes_received >= 1024 * 1024 or  # 1MB+ traffic
            len(activity.protocols) >= 3 or  # Multiple protocols
            len(activity.destinations) >= 5):  # Multiple destinations
            
            return self._create_behavior_from_activity(activity)
        
        return None
    
    def _create_behavior_from_activity(self, activity: DeviceActivity) -> DeviceBehavior:
        """Create DeviceBehavior from DeviceActivity"""
        now = datetime.now()
        
        # Get recent connections (within behavior window)
        recent_connections = [
            conn for conn in activity.connections 
            if now - conn.timestamp <= self.behavior_window
        ]
        
        # Get recent DNS queries
        recent_dns = activity.dns_queries[-self.max_dns_queries_per_behavior:]
        
        # Calculate traffic volume for the behavior window
        total_bytes_sent = sum(conn.bytes_sent for conn in recent_connections)
        total_bytes_received = sum(conn.bytes_received for conn in recent_connections)
        
        traffic_volume = TrafficVolume(
            bytes_sent=total_bytes_sent,
            bytes_received=total_bytes_received,
            packets_sent=len([c for c in recent_connections if c.bytes_sent > 0]),
            packets_received=len([c for c in recent_connections if c.bytes_received > 0]),
            duration_seconds=self.behavior_window.total_seconds()
        )
        
        return DeviceBehavior(
            device_id=activity.device_id,
            timestamp=now,
            connections=recent_connections,
            traffic_volume=traffic_volume,
            protocols_used=activity.protocols.copy(),
            dns_queries=recent_dns.copy()
        )
    
    def _extract_dns_queries(self, features: DeviceFeatures, activity: DeviceActivity) -> None:
        """Extract DNS queries from packet features"""
        # This is a simplified version - in a real implementation,
        # you would need to parse DNS packets directly
        # For now, we'll infer DNS activity from destinations on port 53
        
        if 53 in features.ports:
            # Assume DNS queries to destinations
            for dest in features.destinations:
                if self._is_likely_dns_server(dest):
                    # In a real implementation, you'd extract the actual query
                    query = f"query_to_{dest}"
                    activity.dns_queries.append(query)
                    
                    # Limit DNS query history
                    if len(activity.dns_queries) > self.max_dns_queries_per_behavior:
                        activity.dns_queries = activity.dns_queries[-self.max_dns_queries_per_behavior:]
    
    def _is_local_ip(self, ip_address: str) -> bool:
        """Check if IP address is in local networks"""
        try:
            ip = ipaddress.ip_address(ip_address)
            return any(ip in network for network in self.local_network_objects)
        except ValueError:
            return False
    
    def _is_likely_dns_server(self, ip_address: str) -> bool:
        """Check if IP address is likely a DNS server"""
        # Common DNS servers
        common_dns = {
            '8.8.8.8', '8.8.4.4',  # Google
            '1.1.1.1', '1.0.0.1',  # Cloudflare
            '208.67.222.222', '208.67.220.220',  # OpenDNS
            '9.9.9.9', '149.112.112.112'  # Quad9
        }
        
        return ip_address in common_dns or not self._is_local_ip(ip_address)
    
    def _periodic_cleanup(self) -> None:
        """Periodically clean up old device activities"""
        now = datetime.now()
        
        if now - self.last_cleanup < self.cleanup_interval:
            return
        
        # Remove inactive devices
        inactive_devices = [
            device_id for device_id, activity in self.device_activities.items()
            if now - activity.last_seen > self.activity_timeout
        ]
        
        for device_id in inactive_devices:
            del self.device_activities[device_id]
        
        self.last_cleanup = now
    
    def get_active_devices(self) -> List[str]:
        """Get list of currently active device IDs"""
        return list(self.device_activities.keys())
    
    def get_device_activity_summary(self, device_id: str) -> Optional[Dict]:
        """Get summary of device activity"""
        if device_id not in self.device_activities:
            return None
        
        activity = self.device_activities[device_id]
        return {
            'device_id': activity.device_id,
            'mac_address': activity.mac_address,
            'ip_addresses': list(activity.ip_addresses),
            'protocols': list(activity.protocols),
            'destinations_count': len(activity.destinations),
            'connections_count': len(activity.connections),
            'bytes_sent': activity.bytes_sent,
            'bytes_received': activity.bytes_received,
            'first_seen': activity.first_seen.isoformat(),
            'last_seen': activity.last_seen.isoformat()
        }
    
    def get_behavioral_features(self, device_id: str) -> Optional[BehavioralFeatures]:
        """
        Get enhanced behavioral features for a device
        
        Args:
            device_id: Device identifier
            
        Returns:
            BehavioralFeatures if device exists and has packet history, None otherwise
        """
        if device_id not in self.packet_buffer or not self.packet_buffer[device_id]:
            return None
        
        packets = self.packet_buffer[device_id]
        return self.behavioral_extractor.extract_behavioral_features(device_id, packets)
    
    def get_behavioral_summary(self, device_id: str) -> Optional[Dict]:
        """Get behavioral analysis summary for a device"""
        return self.behavioral_extractor.get_device_behavioral_summary(device_id)