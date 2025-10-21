"""
Advanced behavioral feature extraction for network monitoring
"""

from typing import Dict, List, Set, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from dataclasses import dataclass, field
import statistics
import ipaddress
from scapy.packet import Packet
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import HTTPRequest, HTTPResponse

from ..models import Connection, TrafficVolume, DeviceBehavior


@dataclass
class ConnectionPattern:
    """Represents connection patterns for a device"""
    frequent_destinations: Dict[str, int] = field(default_factory=dict)
    port_usage: Dict[int, int] = field(default_factory=dict)
    protocol_distribution: Dict[str, int] = field(default_factory=dict)
    connection_timing: List[datetime] = field(default_factory=list)
    session_durations: List[float] = field(default_factory=list)
    geographic_regions: Set[str] = field(default_factory=set)


@dataclass
class TrafficPattern:
    """Represents traffic patterns and timing analysis"""
    hourly_distribution: Dict[int, int] = field(default_factory=dict)
    burst_patterns: List[Tuple[datetime, int]] = field(default_factory=list)  # (time, packet_count)
    average_packet_size: float = 0.0
    peak_traffic_hours: List[int] = field(default_factory=list)
    traffic_variance: float = 0.0
    inter_packet_intervals: List[float] = field(default_factory=list)


@dataclass
class DNSPattern:
    """Represents DNS query patterns"""
    query_domains: Dict[str, int] = field(default_factory=dict)
    query_types: Dict[str, int] = field(default_factory=dict)
    dns_servers: Set[str] = field(default_factory=set)
    suspicious_domains: List[str] = field(default_factory=list)
    domain_categories: Dict[str, str] = field(default_factory=dict)
    query_timing: List[datetime] = field(default_factory=list)


@dataclass
class BehavioralFeatures:
    """Complete behavioral feature set for a device"""
    device_id: str
    timestamp: datetime
    connection_patterns: ConnectionPattern
    traffic_patterns: TrafficPattern
    dns_patterns: DNSPattern
    anomaly_indicators: Dict[str, float] = field(default_factory=dict)


class BehavioralExtractor:
    """Advanced behavioral feature extraction engine"""
    
    def __init__(self, analysis_window: timedelta = timedelta(hours=1)):
        """
        Initialize behavioral extractor
        
        Args:
            analysis_window: Time window for behavioral analysis
        """
        self.analysis_window = analysis_window
        self.packet_history: Dict[str, List[Tuple[datetime, Packet]]] = defaultdict(list)
        self.connection_cache: Dict[str, List[Connection]] = defaultdict(list)
        self.dns_cache: Dict[str, List[Tuple[datetime, str, str]]] = defaultdict(list)  # (time, query, response)
        
        # Geographic IP ranges (simplified)
        self.geographic_ranges = self._load_geographic_ranges()
        
        # Domain categories
        self.domain_categories = self._load_domain_categories()
        
        # Suspicious domain patterns
        self.suspicious_patterns = [
            r'.*\.tk$', r'.*\.ml$', r'.*\.ga$',  # Free TLDs often used maliciously
            r'.*[0-9]{8,}.*',  # Domains with long numeric sequences
            r'.*-[a-z]{10,}\..*',  # Domains with long random strings
        ]
    
    def extract_behavioral_features(self, device_id: str, packets: List[Packet]) -> BehavioralFeatures:
        """
        Extract comprehensive behavioral features from packet list
        
        Args:
            device_id: Device identifier
            packets: List of packets to analyze
            
        Returns:
            BehavioralFeatures object with extracted patterns
        """
        now = datetime.now()
        
        # Update packet history
        self._update_packet_history(device_id, packets)
        
        # Extract connection patterns
        connection_patterns = self._extract_connection_patterns(device_id, packets)
        
        # Extract traffic patterns
        traffic_patterns = self._extract_traffic_patterns(device_id, packets)
        
        # Extract DNS patterns
        dns_patterns = self._extract_dns_patterns(device_id, packets)
        
        # Calculate anomaly indicators
        anomaly_indicators = self._calculate_anomaly_indicators(
            connection_patterns, traffic_patterns, dns_patterns
        )
        
        return BehavioralFeatures(
            device_id=device_id,
            timestamp=now,
            connection_patterns=connection_patterns,
            traffic_patterns=traffic_patterns,
            dns_patterns=dns_patterns,
            anomaly_indicators=anomaly_indicators
        )
    
    def _update_packet_history(self, device_id: str, packets: List[Packet]) -> None:
        """Update packet history for device"""
        now = datetime.now()
        
        # Add new packets
        for packet in packets:
            self.packet_history[device_id].append((now, packet))
        
        # Clean old packets outside analysis window
        cutoff_time = now - self.analysis_window
        self.packet_history[device_id] = [
            (timestamp, packet) for timestamp, packet in self.packet_history[device_id]
            if timestamp > cutoff_time
        ]
    
    def _extract_connection_patterns(self, device_id: str, packets: List[Packet]) -> ConnectionPattern:
        """Extract connection patterns from packets"""
        pattern = ConnectionPattern()
        
        for packet in packets:
            if not packet.haslayer(IP):
                continue
            
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            
            # Determine if outbound (from local device)
            is_outbound = self._is_local_ip(src_ip)
            destination = dst_ip if is_outbound else src_ip
            
            # Count destinations
            if destination not in pattern.frequent_destinations:
                pattern.frequent_destinations[destination] = 0
            pattern.frequent_destinations[destination] += 1
            
            # Extract geographic region
            region = self._get_geographic_region(destination)
            if region:
                pattern.geographic_regions.add(region)
            
            # Protocol analysis
            protocol = 'IP'
            port = None
            
            if packet.haslayer(TCP):
                protocol = 'TCP'
                tcp_layer = packet[TCP]
                port = tcp_layer.dport if is_outbound else tcp_layer.sport
                
                # Session duration tracking (simplified)
                if tcp_layer.flags & 0x02:  # SYN flag
                    pattern.connection_timing.append(datetime.now())
                
            elif packet.haslayer(UDP):
                protocol = 'UDP'
                udp_layer = packet[UDP]
                port = udp_layer.dport if is_outbound else udp_layer.sport
                
            elif packet.haslayer(ICMP):
                protocol = 'ICMP'
            
            # Count protocols
            if protocol not in pattern.protocol_distribution:
                pattern.protocol_distribution[protocol] = 0
            pattern.protocol_distribution[protocol] += 1
            
            # Count ports
            if port:
                if port not in pattern.port_usage:
                    pattern.port_usage[port] = 0
                pattern.port_usage[port] += 1
        
        return pattern
    
    def _extract_traffic_patterns(self, device_id: str, packets: List[Packet]) -> TrafficPattern:
        """Extract traffic timing and volume patterns"""
        pattern = TrafficPattern()
        
        if not packets:
            return pattern
        
        packet_sizes = []
        packet_times = []
        hourly_counts = defaultdict(int)
        
        for i, packet in enumerate(packets):
            packet_size = len(packet)
            packet_sizes.append(packet_size)
            
            # Simulate packet timing (in real implementation, use actual timestamps)
            packet_time = datetime.now() - timedelta(seconds=len(packets) - i)
            packet_times.append(packet_time)
            
            # Hourly distribution
            hour = packet_time.hour
            hourly_counts[hour] += 1
        
        # Calculate statistics
        if packet_sizes:
            pattern.average_packet_size = statistics.mean(packet_sizes)
            if len(packet_sizes) > 1:
                pattern.traffic_variance = statistics.variance(packet_sizes)
        
        # Hourly distribution
        pattern.hourly_distribution = dict(hourly_counts)
        
        # Peak traffic hours (hours with above-average traffic)
        if hourly_counts:
            avg_hourly = statistics.mean(hourly_counts.values())
            pattern.peak_traffic_hours = [
                hour for hour, count in hourly_counts.items()
                if count > avg_hourly
            ]
        
        # Inter-packet intervals
        if len(packet_times) > 1:
            intervals = []
            for i in range(1, len(packet_times)):
                interval = (packet_times[i] - packet_times[i-1]).total_seconds()
                intervals.append(interval)
            pattern.inter_packet_intervals = intervals
        
        # Burst detection (simplified)
        burst_threshold = 10  # packets per second
        current_burst = 0
        burst_start = None
        
        for i, time in enumerate(packet_times):
            if i == 0:
                burst_start = time
                current_burst = 1
                continue
            
            time_diff = (time - packet_times[i-1]).total_seconds()
            if time_diff < 1.0:  # Within 1 second
                current_burst += 1
            else:
                if current_burst >= burst_threshold:
                    pattern.burst_patterns.append((burst_start, current_burst))
                burst_start = time
                current_burst = 1
        
        # Check final burst
        if current_burst >= burst_threshold:
            pattern.burst_patterns.append((burst_start, current_burst))
        
        return pattern
    
    def _extract_dns_patterns(self, device_id: str, packets: List[Packet]) -> DNSPattern:
        """Extract DNS query patterns and analyze domains"""
        pattern = DNSPattern()
        
        for packet in packets:
            if not packet.haslayer(DNS):
                continue
            
            dns_layer = packet[DNS]
            
            # DNS server identification
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                if self._is_local_ip(ip_layer.src):
                    pattern.dns_servers.add(ip_layer.dst)
                else:
                    pattern.dns_servers.add(ip_layer.src)
            
            # Query analysis
            if dns_layer.qd:
                query_name = dns_layer.qd.qname.decode('utf-8').rstrip('.')
                query_type = dns_layer.qd.qtype
                
                # Count queries
                if query_name not in pattern.query_domains:
                    pattern.query_domains[query_name] = 0
                pattern.query_domains[query_name] += 1
                
                # Query type distribution
                qtype_name = self._get_dns_type_name(query_type)
                if qtype_name not in pattern.query_types:
                    pattern.query_types[qtype_name] = 0
                pattern.query_types[qtype_name] += 1
                
                # Domain categorization
                category = self._categorize_domain(query_name)
                if category:
                    pattern.domain_categories[query_name] = category
                
                # Suspicious domain detection
                if self._is_suspicious_domain(query_name):
                    pattern.suspicious_domains.append(query_name)
                
                # Query timing
                pattern.query_timing.append(datetime.now())
        
        return pattern
    
    def _calculate_anomaly_indicators(self, 
                                    connection_patterns: ConnectionPattern,
                                    traffic_patterns: TrafficPattern, 
                                    dns_patterns: DNSPattern) -> Dict[str, float]:
        """Calculate anomaly indicators from behavioral patterns"""
        indicators = {}
        
        # Connection diversity indicator
        unique_destinations = len(connection_patterns.frequent_destinations)
        indicators['destination_diversity'] = min(unique_destinations / 100.0, 1.0)
        
        # Port diversity indicator
        unique_ports = len(connection_patterns.port_usage)
        indicators['port_diversity'] = min(unique_ports / 50.0, 1.0)
        
        # Protocol diversity indicator
        unique_protocols = len(connection_patterns.protocol_distribution)
        indicators['protocol_diversity'] = min(unique_protocols / 5.0, 1.0)
        
        # Traffic variance indicator (high variance = bursty traffic)
        if traffic_patterns.traffic_variance > 0:
            indicators['traffic_burstiness'] = min(traffic_patterns.traffic_variance / 10000.0, 1.0)
        else:
            indicators['traffic_burstiness'] = 0.0
        
        # DNS diversity indicator
        unique_domains = len(dns_patterns.query_domains)
        indicators['dns_diversity'] = min(unique_domains / 100.0, 1.0)
        
        # Suspicious domain indicator
        suspicious_ratio = len(dns_patterns.suspicious_domains) / max(unique_domains, 1)
        indicators['suspicious_dns_ratio'] = suspicious_ratio
        
        # Geographic diversity indicator
        unique_regions = len(connection_patterns.geographic_regions)
        indicators['geographic_diversity'] = min(unique_regions / 10.0, 1.0)
        
        # Peak hour activity indicator
        peak_hours = len(traffic_patterns.peak_traffic_hours)
        indicators['peak_hour_activity'] = min(peak_hours / 24.0, 1.0)
        
        return indicators
    
    def _is_local_ip(self, ip_address: str) -> bool:
        """Check if IP address is local"""
        try:
            ip = ipaddress.ip_address(ip_address)
            return (ip.is_private or 
                   ip.is_loopback or 
                   ip.is_link_local)
        except ValueError:
            return False
    
    def _get_geographic_region(self, ip_address: str) -> Optional[str]:
        """Get geographic region for IP address (simplified)"""
        try:
            ip = ipaddress.ip_address(ip_address)
            if ip.is_private:
                return "Local"
            
            # Simplified geographic mapping
            ip_int = int(ip)
            for region, (start, end) in self.geographic_ranges.items():
                if start <= ip_int <= end:
                    return region
            
            return "Unknown"
        except ValueError:
            return None
    
    def _categorize_domain(self, domain: str) -> Optional[str]:
        """Categorize domain by type"""
        domain_lower = domain.lower()
        
        for category, patterns in self.domain_categories.items():
            for pattern in patterns:
                if pattern in domain_lower:
                    return category
        
        return None
    
    def _is_suspicious_domain(self, domain: str) -> bool:
        """Check if domain matches suspicious patterns"""
        import re
        
        for pattern in self.suspicious_patterns:
            if re.match(pattern, domain, re.IGNORECASE):
                return True
        
        return False
    
    def _get_dns_type_name(self, qtype: int) -> str:
        """Convert DNS query type number to name"""
        dns_types = {
            1: 'A',
            2: 'NS', 
            5: 'CNAME',
            6: 'SOA',
            12: 'PTR',
            15: 'MX',
            16: 'TXT',
            28: 'AAAA'
        }
        return dns_types.get(qtype, f'TYPE{qtype}')
    
    def _load_geographic_ranges(self) -> Dict[str, Tuple[int, int]]:
        """Load geographic IP ranges (simplified)"""
        return {
            'North America': (16777216, 184549375),    # 1.0.0.0 - 10.255.255.255
            'Europe': (184549376, 335544319),          # 11.0.0.0 - 19.255.255.255  
            'Asia': (335544320, 671088639),            # 20.0.0.0 - 39.255.255.255
            'Other': (671088640, 4294967295),          # 40.0.0.0 - 255.255.255.255
        }
    
    def _load_domain_categories(self) -> Dict[str, List[str]]:
        """Load domain category patterns"""
        return {
            'Social Media': ['facebook', 'twitter', 'instagram', 'linkedin', 'tiktok'],
            'Streaming': ['netflix', 'youtube', 'hulu', 'disney', 'spotify'],
            'Cloud Services': ['amazon', 'google', 'microsoft', 'apple', 'dropbox'],
            'CDN': ['cloudflare', 'akamai', 'fastly', 'cloudfront'],
            'Gaming': ['steam', 'xbox', 'playstation', 'nintendo', 'epic'],
            'News': ['cnn', 'bbc', 'reuters', 'ap', 'npr'],
            'Shopping': ['amazon', 'ebay', 'walmart', 'target', 'bestbuy'],
            'Banking': ['bank', 'credit', 'paypal', 'visa', 'mastercard'],
        }
    
    def get_device_behavioral_summary(self, device_id: str) -> Optional[Dict]:
        """Get behavioral summary for a device"""
        if device_id not in self.packet_history:
            return None
        
        packets = [packet for _, packet in self.packet_history[device_id]]
        if not packets:
            return None
        
        features = self.extract_behavioral_features(device_id, packets)
        
        return {
            'device_id': device_id,
            'analysis_window': str(self.analysis_window),
            'packet_count': len(packets),
            'unique_destinations': len(features.connection_patterns.frequent_destinations),
            'unique_ports': len(features.connection_patterns.port_usage),
            'protocols': list(features.connection_patterns.protocol_distribution.keys()),
            'dns_queries': len(features.dns_patterns.query_domains),
            'suspicious_domains': len(features.dns_patterns.suspicious_domains),
            'geographic_regions': list(features.connection_patterns.geographic_regions),
            'anomaly_score': sum(features.anomaly_indicators.values()) / len(features.anomaly_indicators) if features.anomaly_indicators else 0.0,
            'timestamp': features.timestamp.isoformat()
        }