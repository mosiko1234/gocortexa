"""
Data anonymization for cloud transmission to Asgard
Ensures privacy protection while preserving behavioral patterns
"""

import hashlib
import ipaddress
import logging
import re
from datetime import datetime
from typing import Dict, Set, Optional, List
import json

from ..interfaces import IDataAnonymizer
from ..models import (
    Anomaly, AnonymizedAnomaly, DeviceBehavior, AnonymizedDevice,
    AnomalyType, SeverityLevel
)


class DataAnonymizer(IDataAnonymizer):
    """
    Anonymizes sensitive data while preserving behavioral patterns for analysis
    """
    
    def __init__(self, salt: Optional[str] = None):
        """
        Initialize data anonymizer
        
        Args:
            salt: Salt for hashing (generated if None)
        """
        self.salt = salt or self._generate_salt()
        self.logger = logging.getLogger(__name__)
        
        # Geographic region mappings for IP ranges
        self._ip_region_cache = {}
        
        # Device type mappings based on MAC OUI
        self._mac_device_types = {
            # Apple devices
            '00:03:93': 'apple_device',
            '00:05:02': 'apple_device', 
            '00:0a:95': 'apple_device',
            '00:16:cb': 'apple_device',
            '00:17:f2': 'apple_device',
            '00:1b:63': 'apple_device',
            '00:1e:c2': 'apple_device',
            '00:21:e9': 'apple_device',
            '00:23:12': 'apple_device',
            '00:23:df': 'apple_device',
            '00:25:00': 'apple_device',
            '00:25:4b': 'apple_device',
            '00:25:bc': 'apple_device',
            '00:26:08': 'apple_device',
            '00:26:4a': 'apple_device',
            '00:26:b0': 'apple_device',
            '00:26:bb': 'apple_device',
            
            # Samsung devices
            '00:12:fb': 'samsung_device',
            '00:15:99': 'samsung_device',
            '00:16:32': 'samsung_device',
            '00:17:c9': 'samsung_device',
            '00:1a:8a': 'samsung_device',
            '00:1b:98': 'samsung_device',
            '00:1d:25': 'samsung_device',
            '00:1e:7d': 'samsung_device',
            '00:21:19': 'samsung_device',
            '00:23:39': 'samsung_device',
            
            # Generic device types
            '00:50:56': 'virtual_machine',  # VMware
            '08:00:27': 'virtual_machine',  # VirtualBox
            '00:0c:29': 'virtual_machine',  # VMware
        }
    
    def _generate_salt(self) -> str:
        """Generate a random salt for hashing"""
        import secrets
        return secrets.token_hex(32)
    
    def _hash_with_salt(self, data: str) -> str:
        """Hash data with salt for consistent anonymization"""
        combined = f"{data}{self.salt}"
        return hashlib.sha256(combined.encode()).hexdigest()[:16]
    
    def anonymize_ip_address(self, ip_address: str) -> str:
        """
        Convert IP address to geographic region
        
        Args:
            ip_address: IP address to anonymize
            
        Returns:
            Geographic region string
        """
        try:
            ip = ipaddress.ip_address(ip_address)
            
            # Check cache first
            if ip_address in self._ip_region_cache:
                return self._ip_region_cache[ip_address]
            
            # Private/local addresses
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                region = "local_network"
            else:
                # Determine region based on IP ranges (simplified)
                region = self._determine_geographic_region(str(ip))
            
            # Cache result
            self._ip_region_cache[ip_address] = region
            return region
            
        except ValueError:
            # Invalid IP address
            return "unknown_region"
    
    def _determine_geographic_region(self, ip_address: str) -> str:
        """
        Determine geographic region from IP address
        This is a simplified implementation - in production, use a GeoIP database
        """
        ip = ipaddress.ip_address(ip_address)
        
        # Simplified regional mapping based on IP ranges
        # In production, use MaxMind GeoIP2 or similar service
        if ip.version == 4:
            octets = str(ip).split('.')
            first_octet = int(octets[0])
            
            # Very simplified regional mapping
            if 1 <= first_octet <= 126:
                return "north_america"
            elif 128 <= first_octet <= 191:
                return "europe_africa"
            elif 192 <= first_octet <= 223:
                return "asia_pacific"
            else:
                return "other_region"
        else:
            # IPv6 - even more simplified
            return "ipv6_region"
    
    def anonymize_mac_address(self, mac_address: str) -> str:
        """
        Convert MAC address to device type fingerprint
        
        Args:
            mac_address: MAC address to anonymize
            
        Returns:
            Device type fingerprint
        """
        # Normalize MAC address format
        mac_clean = mac_address.replace(':', '').replace('-', '').lower()
        
        if len(mac_clean) >= 6:
            # Extract OUI (first 3 bytes)
            oui = ':'.join([mac_clean[i:i+2] for i in range(0, 6, 2)])
            
            # Look up device type
            device_type = self._mac_device_types.get(oui, 'unknown_device')
            
            # Add a hash suffix for uniqueness while preserving type
            hash_suffix = self._hash_with_salt(mac_address)[:8]
            return f"{device_type}_{hash_suffix}"
        
        return "invalid_mac"
    
    def _extract_behavioral_signature(self, behavior: DeviceBehavior) -> str:
        """
        Extract behavioral signature while preserving privacy
        
        Args:
            behavior: Device behavior data
            
        Returns:
            Anonymized behavioral signature
        """
        signature_components = []
        
        # Protocol usage pattern
        if behavior.protocols_used:
            protocols = sorted(list(behavior.protocols_used))
            signature_components.append(f"protocols:{','.join(protocols)}")
        
        # Connection pattern (anonymized)
        if behavior.connections:
            # Count connections by port ranges
            port_ranges = {
                'web': 0,      # 80, 443
                'mail': 0,     # 25, 110, 143, 993, 995
                'dns': 0,      # 53
                'high': 0,     # 1024+
                'other': 0
            }
            
            for conn in behavior.connections:
                port = conn.destination_port
                if port in [80, 443, 8080, 8443]:
                    port_ranges['web'] += 1
                elif port in [25, 110, 143, 993, 995]:
                    port_ranges['mail'] += 1
                elif port == 53:
                    port_ranges['dns'] += 1
                elif port >= 1024:
                    port_ranges['high'] += 1
                else:
                    port_ranges['other'] += 1
            
            # Add non-zero ranges to signature
            for range_name, count in port_ranges.items():
                if count > 0:
                    signature_components.append(f"{range_name}_ports:{count}")
        
        # Traffic volume pattern
        if behavior.traffic_volume:
            vol = behavior.traffic_volume
            # Categorize volume levels
            total_bytes = vol.bytes_sent + vol.bytes_received
            if total_bytes < 1024:
                volume_category = "low"
            elif total_bytes < 1024 * 1024:
                volume_category = "medium"
            elif total_bytes < 10 * 1024 * 1024:
                volume_category = "high"
            else:
                volume_category = "very_high"
            
            signature_components.append(f"volume:{volume_category}")
        
        # DNS query patterns (anonymized)
        if behavior.dns_queries:
            # Categorize DNS queries by TLD
            tld_counts = {}
            for query in behavior.dns_queries:
                if '.' in query:
                    tld = query.split('.')[-1].lower()
                    tld_counts[tld] = tld_counts.get(tld, 0) + 1
            
            # Add top TLDs to signature
            for tld, count in sorted(tld_counts.items(), key=lambda x: x[1], reverse=True)[:3]:
                signature_components.append(f"dns_{tld}:{count}")
        
        # Combine components
        signature = "|".join(signature_components) if signature_components else "no_activity"
        
        # Add timestamp pattern (hour of day)
        hour = behavior.timestamp.hour
        signature += f"|hour:{hour}"
        
        return signature
    
    def anonymize_anomaly(self, anomaly: Anomaly) -> AnonymizedAnomaly:
        """
        Anonymize anomaly data for cloud transmission
        
        Args:
            anomaly: Original anomaly data
            
        Returns:
            Anonymized anomaly data
        """
        # Extract device type from device ID (assuming format like "mac_address" or similar)
        device_type = self._extract_device_type_from_id(anomaly.device_id)
        
        # Create behavioral signature from anomaly details
        behavioral_signature = self._create_anomaly_signature(anomaly)
        
        return AnonymizedAnomaly(
            device_type=device_type,
            anomaly_type=anomaly.anomaly_type,
            severity=anomaly.severity,
            geographic_region="local_network",  # Sensor location region
            timestamp=anomaly.timestamp,
            behavioral_signature=behavioral_signature
        )
    
    def anonymize_device(self, device_behavior: DeviceBehavior) -> AnonymizedDevice:
        """
        Anonymize device data for cloud transmission
        
        Args:
            device_behavior: Original device behavior data
            
        Returns:
            Anonymized device data
        """
        # Extract device type from device ID
        device_type = self._extract_device_type_from_id(device_behavior.device_id)
        
        # Create behavioral signature
        behavioral_signature = self._extract_behavioral_signature(device_behavior)
        
        return AnonymizedDevice(
            device_type=device_type,
            geographic_region="local_network",  # Sensor location region
            behavioral_signature=behavioral_signature,
            timestamp=device_behavior.timestamp
        )
    
    def _extract_device_type_from_id(self, device_id: str) -> str:
        """
        Extract device type from device ID
        
        Args:
            device_id: Device identifier
            
        Returns:
            Device type string
        """
        # If device_id is a MAC address, use MAC-based detection
        if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', device_id):
            return self.anonymize_mac_address(device_id).split('_')[0]
        
        # If device_id contains MAC address, extract it
        mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', device_id)
        if mac_match:
            return self.anonymize_mac_address(mac_match.group()).split('_')[0]
        
        # Fallback to generic device type
        return "unknown_device"
    
    def _create_anomaly_signature(self, anomaly: Anomaly) -> str:
        """
        Create behavioral signature for anomaly
        
        Args:
            anomaly: Anomaly data
            
        Returns:
            Behavioral signature string
        """
        signature_parts = [
            f"type:{anomaly.anomaly_type.value}",
            f"severity:{anomaly.severity.value}",
            f"confidence:{anomaly.confidence_score:.2f}",
            f"deviation:{anomaly.baseline_deviation:.2f}"
        ]
        
        # Add description hash (to preserve pattern while anonymizing)
        desc_hash = self._hash_with_salt(anomaly.description)[:8]
        signature_parts.append(f"pattern:{desc_hash}")
        
        return "|".join(signature_parts)
    
    def anonymize_destination_list(self, destinations: Set[str]) -> List[str]:
        """
        Anonymize a list of destination addresses
        
        Args:
            destinations: Set of destination addresses (IPs or domains)
            
        Returns:
            List of anonymized destinations
        """
        anonymized = []
        
        for dest in destinations:
            # Check if it's an IP address
            try:
                ipaddress.ip_address(dest)
                # It's an IP - anonymize to region
                anonymized.append(self.anonymize_ip_address(dest))
            except ValueError:
                # It's likely a domain name - anonymize domain
                anonymized.append(self._anonymize_domain(dest))
        
        return list(set(anonymized))  # Remove duplicates
    
    def _anonymize_domain(self, domain: str) -> str:
        """
        Anonymize domain name while preserving useful patterns
        
        Args:
            domain: Domain name to anonymize
            
        Returns:
            Anonymized domain pattern
        """
        if not domain or '.' not in domain:
            return "invalid_domain"
        
        parts = domain.lower().split('.')
        
        # Preserve TLD and domain category
        tld = parts[-1]
        
        # Categorize domain types
        if any(keyword in domain for keyword in ['google', 'youtube', 'gmail']):
            category = "google_services"
        elif any(keyword in domain for keyword in ['facebook', 'instagram', 'whatsapp']):
            category = "meta_services"
        elif any(keyword in domain for keyword in ['amazon', 'aws']):
            category = "amazon_services"
        elif any(keyword in domain for keyword in ['microsoft', 'outlook', 'office']):
            category = "microsoft_services"
        elif any(keyword in domain for keyword in ['apple', 'icloud']):
            category = "apple_services"
        elif tld in ['com', 'org', 'net']:
            category = "commercial"
        elif tld in ['edu', 'gov', 'mil']:
            category = "institutional"
        else:
            category = "other"
        
        return f"{category}.{tld}"
    
    def get_anonymization_stats(self) -> Dict[str, int]:
        """
        Get statistics about anonymization operations
        
        Returns:
            Dictionary with anonymization statistics
        """
        return {
            'ip_cache_size': len(self._ip_region_cache),
            'known_mac_ouis': len(self._mac_device_types)
        }
    
    def clear_cache(self):
        """Clear anonymization caches"""
        self._ip_region_cache.clear()
        self.logger.info("Anonymization caches cleared")