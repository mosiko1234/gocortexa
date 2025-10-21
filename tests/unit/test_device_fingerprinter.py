"""
Unit tests for Device Fingerprinter
"""

import pytest
from unittest.mock import Mock, patch
from scapy.packet import Packet
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dns import DNS, DNSQR

from heimdal.analysis.device_fingerprinter import DeviceFingerprinter, DeviceFingerprint


class TestDeviceFingerprinter:
    """Test cases for DeviceFingerprinter class"""
    
    def test_init(self):
        """Test DeviceFingerprinter initialization"""
        fingerprinter = DeviceFingerprinter()
        
        assert fingerprinter.known_devices == {}
        assert isinstance(fingerprinter.mac_vendor_db, dict)
        assert isinstance(fingerprinter.device_signatures, dict)
        assert len(fingerprinter.mac_vendor_db) > 0
    
    def test_identify_device_no_ethernet(self):
        """Test device identification with packet lacking Ethernet layer"""
        fingerprinter = DeviceFingerprinter()
        
        # Mock packet without Ethernet layer
        packet = Mock(spec=Packet)
        packet.haslayer.return_value = False
        
        result = fingerprinter.identify_device(packet)
        assert result is None
    
    def test_identify_device_new_device(self):
        """Test identification of a new device"""
        fingerprinter = DeviceFingerprinter()
        
        # Mock packet with Ethernet layer
        packet = Mock(spec=Packet)
        packet.haslayer.return_value = True
        
        ether = Mock()
        ether.src = "00:1E:C2:12:34:56"  # Apple MAC
        packet.__getitem__.return_value = ether
        
        result = fingerprinter.identify_device(packet)
        
        assert result is not None
        assert isinstance(result, DeviceFingerprint)
        assert result.mac_address == "00:1E:C2:12:34:56"
        assert result.vendor == "Apple"
        assert result.device_type == "Apple Device"
        assert 0.0 <= result.confidence_score <= 1.0
    
    def test_identify_device_known_device(self):
        """Test identification of a previously seen device"""
        fingerprinter = DeviceFingerprinter()
        
        # Create a known device
        known_fingerprint = DeviceFingerprint(
            mac_address="aa:bb:cc:dd:ee:ff",
            vendor="Test Vendor",
            device_type="Test Device",
            confidence_score=0.9,
            characteristics={}
        )
        fingerprinter.known_devices["aa:bb:cc:dd:ee:ff"] = known_fingerprint
        
        # Mock packet
        packet = Mock(spec=Packet)
        packet.haslayer.return_value = True
        
        ether = Mock()
        ether.src = "aa:bb:cc:dd:ee:ff"
        packet.__getitem__.return_value = ether
        
        result = fingerprinter.identify_device(packet)
        
        assert result is known_fingerprint
        assert result.mac_address == "aa:bb:cc:dd:ee:ff"
        assert result.vendor == "Test Vendor"
    
    def test_get_vendor_from_mac_apple(self):
        """Test MAC vendor identification for Apple devices"""
        fingerprinter = DeviceFingerprinter()
        
        # Test various Apple MAC prefixes
        apple_macs = [
            "00:1E:C2:12:34:56",
            "00:50:E4:AB:CD:EF",
            "A4:5E:60:11:22:33"
        ]
        
        for mac in apple_macs:
            vendor = fingerprinter._get_vendor_from_mac(mac)
            assert vendor == "Apple"
    
    def test_get_vendor_from_mac_samsung(self):
        """Test MAC vendor identification for Samsung devices"""
        fingerprinter = DeviceFingerprinter()
        
        # Test Samsung MAC prefix
        vendor = fingerprinter._get_vendor_from_mac("00:13:77:12:34:56")
        assert vendor == "Samsung"
    
    def test_get_vendor_from_mac_unknown(self):
        """Test MAC vendor identification for unknown vendor"""
        fingerprinter = DeviceFingerprinter()
        
        vendor = fingerprinter._get_vendor_from_mac("FF:FF:FF:12:34:56")
        assert vendor == "Unknown"
    
    def test_extract_dhcp_options(self):
        """Test DHCP options extraction"""
        fingerprinter = DeviceFingerprinter()
        
        # Mock packet with DHCP
        packet = Mock(spec=Packet)
        packet.haslayer.return_value = True
        
        bootp = Mock()
        bootp.options = [
            ('vendor_class_id', b'MSFT 5.0'),
            ('hostname', b'iPhone-Test'),
            ('param_req_list', b'\x01\x03\x06\x0f')
        ]
        
        packet.__getitem__.return_value = bootp
        
        options = fingerprinter._extract_dhcp_options(packet)
        
        assert 'vendor_class' in options
        assert 'hostname' in options
        assert 'dhcp_params' in options
        assert 'MSFT 5.0' in options['vendor_class']
        assert 'iPhone-Test' in options['hostname']
    
    def test_extract_tcp_signature(self):
        """Test TCP signature extraction"""
        fingerprinter = DeviceFingerprinter()
        
        # Mock packet with TCP
        packet = Mock(spec=Packet)
        packet.haslayer.return_value = True
        
        tcp = Mock()
        tcp.window = 65535
        tcp.options = [('MSS', 1460), ('NOP', None), ('WScale', 8)]
        
        packet.__getitem__.return_value = tcp
        
        signature = fingerprinter._extract_tcp_signature(packet)
        
        assert 'tcp_window' in signature
        assert signature['tcp_window'] == '65535'
        assert 'tcp_options' in signature
    
    def test_extract_dns_patterns(self):
        """Test DNS pattern extraction"""
        fingerprinter = DeviceFingerprinter()
        
        # Mock packet with DNS
        packet = Mock(spec=Packet)
        
        def haslayer_side_effect(layer):
            return layer in [DNS, DNSQR]
        
        packet.haslayer.side_effect = haslayer_side_effect
        
        # Mock DNS query
        dns_query = Mock()
        dns_query.qname = b"apple.com."
        
        dns = Mock()
        dns.qd = dns_query
        
        packet.__getitem__.return_value = dns
        
        patterns = fingerprinter._extract_dns_patterns(packet)
        
        assert 'dns_query' in patterns
        assert patterns['dns_query'] == 'apple.com'
        assert 'dns_pattern' in patterns
        assert patterns['dns_pattern'] == 'apple'
    
    def test_determine_device_type_apple_iphone(self):
        """Test device type determination for Apple iPhone"""
        fingerprinter = DeviceFingerprinter()
        
        vendor = "Apple"
        characteristics = {
            'hostname': 'iPhone-Test',
            'vendor_class': 'MSFT 5.0'
        }
        packet = Mock()
        
        device_type, confidence = fingerprinter._determine_device_type(vendor, characteristics, packet)
        
        assert device_type == "iPhone"
        assert confidence == 0.95
    
    def test_determine_device_type_samsung_tv(self):
        """Test device type determination for Samsung TV"""
        fingerprinter = DeviceFingerprinter()
        
        vendor = "Samsung"
        characteristics = {
            'hostname': 'Samsung-TV-Living-Room'
        }
        packet = Mock()
        
        device_type, confidence = fingerprinter._determine_device_type(vendor, characteristics, packet)
        
        assert device_type == "Samsung TV"
        assert confidence == 0.9
    
    def test_determine_device_type_unknown_vendor(self):
        """Test device type determination for unknown vendor"""
        fingerprinter = DeviceFingerprinter()
        
        vendor = "Unknown"
        characteristics = {}
        packet = Mock()
        
        device_type, confidence = fingerprinter._determine_device_type(vendor, characteristics, packet)
        
        assert device_type == "Unknown Device"
        assert confidence == 0.3
    
    def test_register_new_device(self):
        """Test registering a new device"""
        fingerprinter = DeviceFingerprinter()
        
        fingerprint = DeviceFingerprint(
            mac_address="aa:bb:cc:dd:ee:ff",
            vendor="Test Vendor",
            device_type="Test Device",
            confidence_score=0.8,
            characteristics={}
        )
        
        result = fingerprinter.register_new_device(fingerprint)
        
        assert result is True
        assert "aa:bb:cc:dd:ee:ff" in fingerprinter.known_devices
        assert fingerprinter.known_devices["aa:bb:cc:dd:ee:ff"] is fingerprint
    
    def test_register_existing_device(self):
        """Test registering an already known device"""
        fingerprinter = DeviceFingerprinter()
        
        # Add existing device
        existing_fingerprint = DeviceFingerprint(
            mac_address="aa:bb:cc:dd:ee:ff",
            vendor="Existing Vendor",
            device_type="Existing Device",
            confidence_score=0.7,
            characteristics={}
        )
        fingerprinter.known_devices["aa:bb:cc:dd:ee:ff"] = existing_fingerprint
        
        # Try to register same device
        new_fingerprint = DeviceFingerprint(
            mac_address="aa:bb:cc:dd:ee:ff",
            vendor="New Vendor",
            device_type="New Device",
            confidence_score=0.9,
            characteristics={}
        )
        
        result = fingerprinter.register_new_device(new_fingerprint)
        
        assert result is False
        # Original device should remain unchanged
        assert fingerprinter.known_devices["aa:bb:cc:dd:ee:ff"] is existing_fingerprint
    
    def test_update_device_confidence(self):
        """Test updating device confidence score"""
        fingerprinter = DeviceFingerprinter()
        
        # Add device
        fingerprint = DeviceFingerprint(
            mac_address="aa:bb:cc:dd:ee:ff",
            vendor="Test Vendor",
            device_type="Test Device",
            confidence_score=0.5,
            characteristics={}
        )
        fingerprinter.known_devices["aa:bb:cc:dd:ee:ff"] = fingerprint
        
        # Update confidence
        result = fingerprinter.update_device_confidence("aa:bb:cc:dd:ee:ff", 0.9)
        
        assert result is True
        assert fingerprinter.known_devices["aa:bb:cc:dd:ee:ff"].confidence_score == 0.9
    
    def test_update_device_confidence_unknown_device(self):
        """Test updating confidence for unknown device"""
        fingerprinter = DeviceFingerprinter()
        
        result = fingerprinter.update_device_confidence("unknown:device", 0.9)
        
        assert result is False
    
    def test_get_device_registry(self):
        """Test getting device registry"""
        fingerprinter = DeviceFingerprinter()
        
        # Add some devices
        fingerprint1 = DeviceFingerprint(
            mac_address="aa:bb:cc:dd:ee:ff",
            vendor="Vendor1",
            device_type="Device1",
            confidence_score=0.8,
            characteristics={}
        )
        fingerprint2 = DeviceFingerprint(
            mac_address="11:22:33:44:55:66",
            vendor="Vendor2",
            device_type="Device2",
            confidence_score=0.9,
            characteristics={}
        )
        
        fingerprinter.known_devices["aa:bb:cc:dd:ee:ff"] = fingerprint1
        fingerprinter.known_devices["11:22:33:44:55:66"] = fingerprint2
        
        registry = fingerprinter.get_device_registry()
        
        assert len(registry) == 2
        assert "aa:bb:cc:dd:ee:ff" in registry
        assert "11:22:33:44:55:66" in registry
        # Should be a copy, not the original
        assert registry is not fingerprinter.known_devices
    
    def test_mac_vendor_database_coverage(self):
        """Test that MAC vendor database has good coverage"""
        fingerprinter = DeviceFingerprinter()
        
        # Test that major vendors are covered
        major_vendors = ['Apple', 'Samsung', 'Google', 'Amazon', 'Microsoft']
        
        vendor_count = {}
        for oui, vendor in fingerprinter.mac_vendor_db.items():
            vendor_count[vendor] = vendor_count.get(vendor, 0) + 1
        
        for vendor in major_vendors:
            assert vendor in vendor_count
            assert vendor_count[vendor] > 0
    
    def test_device_signatures_structure(self):
        """Test device signatures data structure"""
        fingerprinter = DeviceFingerprinter()
        
        signatures = fingerprinter.device_signatures
        
        assert isinstance(signatures, dict)
        assert len(signatures) > 0
        
        # Check that signatures have expected structure
        for device_category, patterns in signatures.items():
            assert isinstance(patterns, dict)
            assert 'dhcp_vendor_class' in patterns or 'user_agents' in patterns or 'dns_patterns' in patterns