"""
Device identification and fingerprinting for real-time network monitoring
"""

import re
from typing import Dict, Optional, Set, List
from dataclasses import dataclass
from scapy.packet import Packet
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dns import DNS, DNSQR

from ..models import DeviceFeatures


@dataclass
class DeviceFingerprint:
    """Device fingerprint information"""
    mac_address: str
    vendor: str
    device_type: str
    confidence_score: float
    characteristics: Dict[str, str]


class DeviceFingerprinter:
    """Device identification and fingerprinting engine"""
    
    def __init__(self):
        self.known_devices: Dict[str, DeviceFingerprint] = {}
        self.mac_vendor_db = self._load_mac_vendor_database()
        self.device_signatures = self._load_device_signatures()
    
    def identify_device(self, packet: Packet) -> Optional[DeviceFingerprint]:
        """
        Identify device from packet information
        
        Args:
            packet: Network packet to analyze
            
        Returns:
            DeviceFingerprint if device can be identified, None otherwise
        """
        if not packet.haslayer(Ether):
            return None
            
        mac_address = packet[Ether].src
        
        # Check if we already know this device
        if mac_address in self.known_devices:
            return self.known_devices[mac_address]
        
        # Create new fingerprint
        fingerprint = self._create_fingerprint(packet, mac_address)
        
        if fingerprint:
            self.known_devices[mac_address] = fingerprint
            
        return fingerprint
    
    def _create_fingerprint(self, packet: Packet, mac_address: str) -> Optional[DeviceFingerprint]:
        """Create device fingerprint from packet analysis"""
        
        # Get vendor from MAC address
        vendor = self._get_vendor_from_mac(mac_address)
        
        # Extract device characteristics
        characteristics = self._extract_characteristics(packet)
        
        # Determine device type
        device_type, confidence = self._determine_device_type(vendor, characteristics, packet)
        
        return DeviceFingerprint(
            mac_address=mac_address,
            vendor=vendor,
            device_type=device_type,
            confidence_score=confidence,
            characteristics=characteristics
        )
    
    def _get_vendor_from_mac(self, mac_address: str) -> str:
        """Get vendor name from MAC address OUI"""
        # Extract OUI (first 3 octets)
        oui = mac_address.upper().replace(':', '').replace('-', '')[:6]
        
        return self.mac_vendor_db.get(oui, "Unknown")
    
    def _extract_characteristics(self, packet: Packet) -> Dict[str, str]:
        """Extract device characteristics from packet"""
        characteristics = {}
        
        # DHCP fingerprinting
        if packet.haslayer(DHCP):
            dhcp_options = self._extract_dhcp_options(packet)
            characteristics.update(dhcp_options)
        
        # TCP fingerprinting
        if packet.haslayer(TCP):
            tcp_signature = self._extract_tcp_signature(packet)
            characteristics.update(tcp_signature)
        
        # DNS patterns
        if packet.haslayer(DNS):
            dns_patterns = self._extract_dns_patterns(packet)
            characteristics.update(dns_patterns)
        
        return characteristics
    
    def _extract_dhcp_options(self, packet: Packet) -> Dict[str, str]:
        """Extract DHCP options for device fingerprinting"""
        options = {}
        
        if packet.haslayer(BOOTP):
            bootp = packet[BOOTP]
            
            # Extract vendor class identifier
            if hasattr(bootp, 'options'):
                for option in bootp.options:
                    if isinstance(option, tuple) and len(option) == 2:
                        option_code, option_value = option
                        
                        if option_code == 'vendor_class_id':
                            options['vendor_class'] = str(option_value)
                        elif option_code == 'hostname':
                            options['hostname'] = str(option_value)
                        elif option_code == 'param_req_list':
                            options['dhcp_params'] = str(option_value)
        
        return options
    
    def _extract_tcp_signature(self, packet: Packet) -> Dict[str, str]:
        """Extract TCP signature characteristics"""
        signature = {}
        
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            
            # Window size
            signature['tcp_window'] = str(tcp.window)
            
            # TCP options
            if hasattr(tcp, 'options') and tcp.options:
                options_str = ','.join([str(opt[0]) if isinstance(opt, tuple) else str(opt) 
                                     for opt in tcp.options])
                signature['tcp_options'] = options_str
        
        return signature
    
    def _extract_dns_patterns(self, packet: Packet) -> Dict[str, str]:
        """Extract DNS query patterns"""
        patterns = {}
        
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            dns = packet[DNS]
            
            if dns.qd:
                query_name = dns.qd.qname.decode('utf-8').rstrip('.')
                patterns['dns_query'] = query_name
                
                # Check for specific patterns
                if any(pattern in query_name.lower() for pattern in ['apple', 'icloud']):
                    patterns['dns_pattern'] = 'apple'
                elif any(pattern in query_name.lower() for pattern in ['google', 'android']):
                    patterns['dns_pattern'] = 'google'
                elif any(pattern in query_name.lower() for pattern in ['microsoft', 'xbox']):
                    patterns['dns_pattern'] = 'microsoft'
        
        return patterns
    
    def _determine_device_type(self, vendor: str, characteristics: Dict[str, str], packet: Packet) -> tuple[str, float]:
        """Determine device type based on vendor and characteristics"""
        
        # High confidence matches based on vendor
        vendor_lower = vendor.lower()
        
        if 'apple' in vendor_lower:
            if 'iphone' in characteristics.get('hostname', '').lower():
                return 'iPhone', 0.95
            elif 'ipad' in characteristics.get('hostname', '').lower():
                return 'iPad', 0.95
            elif 'apple tv' in characteristics.get('vendor_class', '').lower():
                return 'Apple TV', 0.95
            elif 'macbook' in characteristics.get('hostname', '').lower():
                return 'MacBook', 0.95
            else:
                return 'Apple Device', 0.8
        
        elif 'samsung' in vendor_lower:
            if 'tv' in characteristics.get('hostname', '').lower():
                return 'Samsung TV', 0.9
            elif 'galaxy' in characteristics.get('hostname', '').lower():
                return 'Samsung Galaxy', 0.9
            else:
                return 'Samsung Device', 0.7
        
        elif 'google' in vendor_lower or 'nest' in vendor_lower:
            if 'chromecast' in characteristics.get('hostname', '').lower():
                return 'Chromecast', 0.95
            elif 'nest' in characteristics.get('hostname', '').lower():
                return 'Google Nest', 0.9
            else:
                return 'Google Device', 0.8
        
        elif 'amazon' in vendor_lower:
            if 'echo' in characteristics.get('hostname', '').lower():
                return 'Amazon Echo', 0.9
            elif 'fire' in characteristics.get('hostname', '').lower():
                return 'Amazon Fire', 0.9
            else:
                return 'Amazon Device', 0.8
        
        # Pattern-based detection
        hostname = characteristics.get('hostname', '').lower()
        
        if 'android' in hostname:
            return 'Android Device', 0.8
        elif 'windows' in hostname or 'pc' in hostname:
            return 'Windows PC', 0.8
        elif 'router' in hostname or 'gateway' in hostname:
            return 'Router/Gateway', 0.8
        elif 'printer' in hostname:
            return 'Printer', 0.8
        
        # DNS pattern-based detection
        dns_pattern = characteristics.get('dns_pattern', '')
        if dns_pattern == 'apple':
            return 'Apple Device', 0.7
        elif dns_pattern == 'google':
            return 'Android/Google Device', 0.7
        elif dns_pattern == 'microsoft':
            return 'Microsoft Device', 0.7
        
        # Default classification
        if vendor != "Unknown":
            return f"{vendor} Device", 0.5
        else:
            return "Unknown Device", 0.3
    
    def _load_mac_vendor_database(self) -> Dict[str, str]:
        """Load MAC vendor database (OUI to vendor mapping)"""
        # This is a simplified database - in production, you'd load from a file
        return {
            # Apple
            '001EC2': 'Apple',
            '0050E4': 'Apple',
            '001124': 'Apple',
            '0017F2': 'Apple',
            '001F5B': 'Apple',
            '0025BC': 'Apple',
            '002608': 'Apple',
            '0026BB': 'Apple',
            '002713': 'Apple',
            '0027E2': 'Apple',
            '003065': 'Apple',
            '003EE1': 'Apple',
            '0040D0': 'Apple',
            '004396': 'Apple',
            '0050E4': 'Apple',
            '006171': 'Apple',
            '0078CA': 'Apple',
            '007F28': 'Apple',
            '008865': 'Apple',
            '009027': 'Apple',
            '00A040': 'Apple',
            '00B362': 'Apple',
            '00C610': 'Apple',
            '00D93D': 'Apple',
            '00F4B9': 'Apple',
            '00F76F': 'Apple',
            '10417F': 'Apple',
            '1499E2': 'Apple',
            '18AF61': 'Apple',
            '1C1AC0': 'Apple',
            '1C5CF2': 'Apple',
            '1C9148': 'Apple',
            '1CABA7': 'Apple',
            '20768F': 'Apple',
            '24A074': 'Apple',
            '24AB81': 'Apple',
            '28E02C': 'Apple',
            '28E7CF': 'Apple',
            '2C1F23': 'Apple',
            '2C200B': 'Apple',
            '2C5490': 'Apple',
            '2CAB25': 'Apple',
            '30074D': 'Apple',
            '30636B': 'Apple',
            '30F7C5': 'Apple',
            '34159E': 'Apple',
            '34363B': 'Apple',
            '3451C9': 'Apple',
            '34A395': 'Apple',
            '34C059': 'Apple',
            '38892C': 'Apple',
            '38B54D': 'Apple',
            '3C0754': 'Apple',
            '3C15C2': 'Apple',
            '3CAB8E': 'Apple',
            '40331A': 'Apple',
            '403CFC': 'Apple',
            '404D7F': 'Apple',
            '40A6D9': 'Apple',
            '40B395': 'Apple',
            '40CBC0': 'Apple',
            '44D884': 'Apple',
            '48746E': 'Apple',
            '4C569D': 'Apple',
            '4C7C5F': 'Apple',
            '4C8D79': 'Apple',
            '50EAD6': 'Apple',
            '5433CB': 'Apple',
            '549F13': 'Apple',
            '54AE27': 'Apple',
            '54E43A': 'Apple',
            '58B035': 'Apple',
            '5C1DD9': 'Apple',
            '5C5948': 'Apple',
            '5C8D4E': 'Apple',
            '5C95AE': 'Apple',
            '5CF5DA': 'Apple',
            '5CF7E6': 'Apple',
            '60334B': 'Apple',
            '60C547': 'Apple',
            '60F445': 'Apple',
            '60FB42': 'Apple',
            '64200C': 'Apple',
            '64B9E8': 'Apple',
            '68967A': 'Apple',
            '68AE20': 'Apple',
            '68D93C': 'Apple',
            '6C2483': 'Apple',
            '6C4008': 'Apple',
            '6C4D73': 'Apple',
            '6C709F': 'Apple',
            '6C8DC1': 'Apple',
            '6CAB31': 'Apple',
            '70480F': 'Apple',
            '70DEE2': 'Apple',
            '70ECE4': 'Apple',
            '7014A6': 'Apple',
            '7073CB': 'Apple',
            '70A2B3': 'Apple',
            '74E2F5': 'Apple',
            '78286D': 'Apple',
            '78A3E4': 'Apple',
            '78CA39': 'Apple',
            '78D75F': 'Apple',
            '7C6D62': 'Apple',
            '7CC3A1': 'Apple',
            '7CD1C3': 'Apple',
            '80006E': 'Apple',
            '803F5D': 'Apple',
            '8040F3': 'Apple',
            '80929F': 'Apple',
            '80BE05': 'Apple',
            '80E650': 'Apple',
            '843835': 'Apple',
            '8489AD': 'Apple',
            '84FCAC': 'Apple',
            '84FCFE': 'Apple',
            '88AE07': 'Apple',
            '88E87F': 'Apple',
            '8C006D': 'Apple',
            '8C2937': 'Apple',
            '8C7712': 'Apple',
            '8C8590': 'Apple',
            '8C8EF2': 'Apple',
            '8CFABA': 'Apple',
            '90840D': 'Apple',
            '9027E4': 'Apple',
            '9060F1': 'Apple',
            '907240': 'Apple',
            '90B21F': 'Apple',
            '90FD61': 'Apple',
            '94E96A': 'Apple',
            '98B8E3': 'Apple',
            '98F0AB': 'Apple',
            '9C207B': 'Apple',
            '9C293F': 'Apple',
            '9C35EB': 'Apple',
            '9C84BF': 'Apple',
            '9CF387': 'Apple',
            'A01828': 'Apple',
            'A04EA7': 'Apple',
            'A0999B': 'Apple',
            'A0EDCD': 'Apple',
            'A43135': 'Apple',
            'A45E60': 'Apple',
            'A4B197': 'Apple',
            'A4C361': 'Apple',
            'A4D1D2': 'Apple',
            'A8667F': 'Apple',
            'A8968A': 'Apple',
            'A8FAD8': 'Apple',
            'AC293A': 'Apple',
            'AC3C0B': 'Apple',
            'AC7F3E': 'Apple',
            'AC87A3': 'Apple',
            'ACAFB9': 'Apple',
            'ACCF5C': 'Apple',
            'B019C6': 'Apple',
            'B065BD': 'Apple',
            'B0CA68': 'Apple',
            'B418D1': 'Apple',
            'B48B19': 'Apple',
            'B49CDF': 'Apple',
            'B4F0AB': 'Apple',
            'B4F61A': 'Apple',
            'B853AC': 'Apple',
            'B88D12': 'Apple',
            'BC3BAF': 'Apple',
            'BC52B7': 'Apple',
            'BC6778': 'Apple',
            'BC926B': 'Apple',
            'BCA920': 'Apple',
            'BCEC5D': 'Apple',
            'C01ADA': 'Apple',
            'C06394': 'Apple',
            'C0847A': 'Apple',
            'C0CECD': 'Apple',
            'C0D012': 'Apple',
            'C42C03': 'Apple',
            'C48466': 'Apple',
            'C4B301': 'Apple',
            'C82A14': 'Apple',
            'C8B5B7': 'Apple',
            'C8E0EB': 'Apple',
            'CC08E0': 'Apple',
            'CC25EF': 'Apple',
            'CC29F5': 'Apple',
            'D023DB': 'Apple',
            'D03311': 'Apple',
            'D0817A': 'Apple',
            'D0A637': 'Apple',
            'D4909C': 'Apple',
            'D4F46F': 'Apple',
            'D81D72': 'Apple',
            'D89695': 'Apple',
            'D8A25E': 'Apple',
            'D8BB2C': 'Apple',
            'DC2B2A': 'Apple',
            'DC2B61': 'Apple',
            'DC37C5': 'Apple',
            'DC3714': 'Apple',
            'DC56E7': 'Apple',
            'DC9B9C': 'Apple',
            'DCA904': 'Apple',
            'E0338E': 'Apple',
            'E0B52D': 'Apple',
            'E0F5C6': 'Apple',
            'E0F847': 'Apple',
            'E425E7': 'Apple',
            'E48B7F': 'Apple',
            'E4C63D': 'Apple',
            'E4E4AB': 'Apple',
            'E80688': 'Apple',
            'E88441': 'Apple',
            'E8802E': 'Apple',
            'EC3586': 'Apple',
            'EC8350': 'Apple',
            'ECADB8': 'Apple',
            'F01898': 'Apple',
            'F0189A': 'Apple',
            'F01DBD': 'Apple',
            'F025B7': 'Apple',
            'F0728C': 'Apple',
            'F0B479': 'Apple',
            'F0C1F1': 'Apple',
            'F0D1A9': 'Apple',
            'F0DBE2': 'Apple',
            'F0DCE2': 'Apple',
            'F40F24': 'Apple',
            'F41BA1': 'Apple',
            'F437B7': 'Apple',
            'F45C89': 'Apple',
            'F466F2': 'Apple',
            'F4F15A': 'Apple',
            'F4F951': 'Apple',
            'F82793': 'Apple',
            'F86214': 'Apple',
            'F8042E': 'Apple',
            'F8D0BD': 'Apple',
            'F8E61A': 'Apple',
            'F8F1B6': 'Apple',
            'FC253F': 'Apple',
            'FC2A9C': 'Apple',
            'FCD848': 'Apple',
            'FCFC48': 'Apple',
            
            # Samsung
            '001377': 'Samsung',
            '0015B9': 'Samsung',
            '001632': 'Samsung',
            '0018AF': 'Samsung',
            '001D25': 'Samsung',
            '002454': 'Samsung',
            '0024E9': 'Samsung',
            '002566': 'Samsung',
            '0026CC': 'Samsung',
            '002713': 'Samsung',
            '0050F2': 'Samsung',
            '005A3C': 'Samsung',
            '0060B3': 'Samsung',
            '006295': 'Samsung',
            '0073E0': 'Samsung',
            '007AB4': 'Samsung',
            '008FC7': 'Samsung',
            '00A0C6': 'Samsung',
            '00BB3A': 'Samsung',
            '00E3B2': 'Samsung',
            '00F4B9': 'Samsung',
            '10F96F': 'Samsung',
            '1C5A3E': 'Samsung',
            '1C62B8': 'Samsung',
            '1CBDB9': 'Samsung',
            '20A2E4': 'Samsung',
            '24F677': 'Samsung',
            '28BA7A': 'Samsung',
            '28E14C': 'Samsung',
            '2C44FD': 'Samsung',
            '30074D': 'Samsung',
            '34BE00': 'Samsung',
            '38AA3C': 'Samsung',
            '3C5A37': 'Samsung',
            '40F201': 'Samsung',
            '44D884': 'Samsung',
            '48F8B3': 'Samsung',
            '4C49E3': 'Samsung',
            '4C7C5F': 'Samsung',
            '50CCF8': 'Samsung',
            '544E90': 'Samsung',
            '5C0A5B': 'Samsung',
            '5C57C8': 'Samsung',
            '60A10A': 'Samsung',
            '60D0A9': 'Samsung',
            '64B310': 'Samsung',
            '68A86D': 'Samsung',
            '6C2F2C': 'Samsung',
            '6C4008': 'Samsung',
            '6C8336': 'Samsung',
            '70F927': 'Samsung',
            '78F882': 'Samsung',
            '7C11CB': 'Samsung',
            '7C6193': 'Samsung',
            '7C6456': 'Samsung',
            '7C7A91': 'Samsung',
            '80E650': 'Samsung',
            '84A134': 'Samsung',
            '8843E1': 'Samsung',
            '88C663': 'Samsung',
            '8C77120': 'Samsung',
            '8CB84A': 'Samsung',
            '90187C': 'Samsung',
            '9094E4': 'Samsung',
            '94350A': 'Samsung',
            '9C02A1': 'Samsung',
            '9C3426': 'Samsung',
            '9C65B0': 'Samsung',
            'A0821F': 'Samsung',
            'A0F3C1': 'Samsung',
            'A4EB12': 'Samsung',
            'AC36F4': 'Samsung',
            'AC5A14': 'Samsung',
            'B0EC71': 'Samsung',
            'B4E1C4': 'Samsung',
            'B853AC': 'Samsung',
            'BC20A4': 'Samsung',
            'BC44BD': 'Samsung',
            'BC79AD': 'Samsung',
            'C06599': 'Samsung',
            'C0BD2F': 'Samsung',
            'C4576E': 'Samsung',
            'C8A823': 'Samsung',
            'CC07AB': 'Samsung',
            'D017C2': 'Samsung',
            'D0176A': 'Samsung',
            'D022BE': 'Samsung',
            'D0667B': 'Samsung',
            'D4E8B2': 'Samsung',
            'D85D4C': 'Samsung',
            'DC71F8': 'Samsung',
            'E0DB10': 'Samsung',
            'E4121D': 'Samsung',
            'E81132': 'Samsung',
            'E84E84': 'Samsung',
            'EC1F72': 'Samsung',
            'EC9BF3': 'Samsung',
            'F0E77E': 'Samsung',
            'F4096D': 'Samsung',
            'F4B7E2': 'Samsung',
            'F8A9D0': 'Samsung',
            'FC00B4': 'Samsung',
            'FC1910': 'Samsung',
            'FCAA14': 'Samsung',
            
            # Google/Nest
            '001A11': 'Google',
            '18B905': 'Google',
            '30FD38': 'Google',
            '6476BA': 'Google',
            '64D4DA': 'Google',
            '6C0B84': 'Google',
            '98F4AB': 'Google',
            'A4F1E8': 'Google',
            'B4F7A1': 'Google',
            'CC3ADF': 'Google',
            'DA7C02': 'Google',
            'F4F5D8': 'Google',
            'F8CF7E': 'Google',
            
            # Amazon
            '0C47C9': 'Amazon',
            '44650D': 'Amazon',
            '50F5DA': 'Amazon',
            '68B6B3': 'Amazon',
            '6C5697': 'Amazon',
            '747548': 'Amazon',
            '78E103': 'Amazon',
            '84D6D0': 'Amazon',
            '8C85AC': 'Amazon',
            'AC63BE': 'Amazon',
            'B077AC': 'Amazon',
            'CC9E00': 'Amazon',
            'F0D2F1': 'Amazon',
            'FC65DE': 'Amazon',
            
            # Microsoft
            '000D3A': 'Microsoft',
            '001DD8': 'Microsoft',
            '0050F2': 'Microsoft',
            '00155D': 'Microsoft',
            '001E37': 'Microsoft',
            '0023DF': 'Microsoft',
            '002248': 'Microsoft',
            '0025AE': 'Microsoft',
            '002655': 'Microsoft',
            '0050F2': 'Microsoft',
            '7C1E52': 'Microsoft',
            '98D6BB': 'Microsoft',
            'A0481C': 'Microsoft',
            'B4AE2B': 'Microsoft',
            'E0CB4E': 'Microsoft',
        }
    
    def _load_device_signatures(self) -> Dict[str, Dict[str, str]]:
        """Load device signature patterns"""
        return {
            'apple_devices': {
                'dhcp_vendor_class': ['MSFT 5.0', 'dhcpcd-5.5.6'],
                'user_agents': ['iPhone', 'iPad', 'Macintosh'],
                'dns_patterns': ['apple.com', 'icloud.com', 'mzstatic.com']
            },
            'android_devices': {
                'dhcp_vendor_class': ['android-dhcp'],
                'user_agents': ['Android'],
                'dns_patterns': ['google.com', 'googleapis.com', 'gstatic.com']
            },
            'smart_tv': {
                'dhcp_vendor_class': ['Samsung', 'LG', 'Sony'],
                'dns_patterns': ['netflix.com', 'youtube.com', 'hulu.com']
            }
        }
    
    def get_device_registry(self) -> Dict[str, DeviceFingerprint]:
        """Get all known devices"""
        return self.known_devices.copy()
    
    def register_new_device(self, fingerprint: DeviceFingerprint) -> bool:
        """Register a new device in the system"""
        if fingerprint.mac_address not in self.known_devices:
            self.known_devices[fingerprint.mac_address] = fingerprint
            return True
        return False
    
    def update_device_confidence(self, mac_address: str, new_confidence: float) -> bool:
        """Update device identification confidence"""
        if mac_address in self.known_devices:
            self.known_devices[mac_address].confidence_score = new_confidence
            return True
        return False