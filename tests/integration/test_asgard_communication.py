"""
Integration tests for Asgard API communication
"""

import pytest
import json
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock
from typing import Dict, List, Any

import aiohttp
from aioresponses import aioresponses

from heimdal.communication.asgard_communicator import AsgardCommunicator
from heimdal.communication.data_anonymizer import DataAnonymizer
from heimdal.communication.intelligence_manager import IntelligenceManager
from heimdal.models import (
    AnonymizedAnomaly, AnonymizedDevice, IntelligenceUpdate, 
    GoldenProfile, SensorInfo, DeviceBehavior, Anomaly, AnomalyType, SeverityLevel
)


class TestAsgardCommunication:
    """Integration tests for Asgard API communication"""
    
    @pytest.fixture
    def mock_asgard_config(self):
        """Mock Asgard configuration"""
        return {
            'api_endpoint': 'https://api.asgard.test',
            'api_key': 'test_api_key_12345',
            'sensor_id': 'test_sensor_001',
            'timeout': 30,
            'retry_attempts': 3,
            'retry_delay': 1.0
        }
    
    @pytest.fixture
    def asgard_communicator(self, mock_asgard_config):
        """Create AsgardCommunicator instance"""
        return AsgardCommunicator(
            api_endpoint=mock_asgard_config['api_endpoint'],
            api_key=mock_asgard_config['api_key'],
            sensor_id=mock_asgard_config['sensor_id']
        )
    
    @pytest.fixture
    def data_anonymizer(self):
        """Create DataAnonymizer instance"""
        return DataAnonymizer()
    
    @pytest.fixture
    def intelligence_manager(self, temp_dir):
        """Create IntelligenceManager instance"""
        return IntelligenceManager(cache_dir=temp_dir)
    
    @pytest.fixture
    def sample_anomaly_data(self):
        """Sample anomaly data for testing"""
        return {
            'device_id': 'aa:bb:cc:dd:ee:ff',
            'device_type': 'iPhone',
            'anomaly_type': 'NEW_DESTINATION',
            'severity': 'HIGH',
            'confidence_score': 0.85,
            'timestamp': datetime.now().isoformat(),
            'destinations': ['1.2.3.4', '5.6.7.8'],
            'geographic_region': 'North America',
            'behavioral_signature': 'mobile_device_unusual_connections'
        }
    
    @pytest.fixture
    def sample_device_data(self):
        """Sample device data for testing"""
        return {
            'device_type': 'iPhone',
            'vendor': 'Apple',
            'geographic_region': 'North America',
            'behavioral_patterns': {
                'peak_hours': [9, 10, 11, 18, 19, 20],
                'common_protocols': ['TCP', 'UDP'],
                'typical_ports': [80, 443, 5223, 993]
            },
            'confidence_score': 0.9,
            'timestamp': datetime.now().isoformat()
        }
    
    def test_sensor_registration(self, asgard_communicator, mock_asgard_config):
        """Test sensor registration with Asgard"""
        sensor_info = SensorInfo(
            sensor_id=mock_asgard_config['sensor_id'],
            location='Test Location',
            version='1.0.0',
            capabilities=['real_time_monitoring', 'anomaly_detection'],
            network_info={
                'interfaces': ['eth0'],
                'ip_ranges': ['192.168.1.0/24']
            }
        )
        
        with aioresponses() as mock_responses:
            # Mock successful registration response
            mock_responses.post(
                f"{mock_asgard_config['api_endpoint']}/sensors/register",
                payload={
                    'status': 'success',
                    'sensor_id': mock_asgard_config['sensor_id'],
                    'registration_token': 'test_token_12345',
                    'intelligence_version': 'v1.0'
                },
                status=200
            )
            
            # Test registration
            result = asyncio.run(asgard_communicator.register_sensor(sensor_info))
            
            assert result is not None
            assert result['status'] == 'success'
            assert result['sensor_id'] == mock_asgard_config['sensor_id']
    
    def test_sensor_registration_failure(self, asgard_communicator, mock_asgard_config):
        """Test sensor registration failure handling"""
        sensor_info = SensorInfo(
            sensor_id=mock_asgard_config['sensor_id'],
            location='Test Location',
            version='1.0.0',
            capabilities=[],
            network_info={}
        )
        
        with aioresponses() as mock_responses:
            # Mock registration failure
            mock_responses.post(
                f"{mock_asgard_config['api_endpoint']}/sensors/register",
                status=400,
                payload={'error': 'Invalid sensor configuration'}
            )
            
            # Test registration failure
            result = asyncio.run(asgard_communicator.register_sensor(sensor_info))
            
            assert result is None
    
    def test_send_anomaly_metadata(self, asgard_communicator, data_anonymizer, sample_anomaly_data, mock_asgard_config):
        """Test sending anonymized anomaly metadata"""
        # Create anonymized anomaly
        anonymized_anomaly = AnonymizedAnomaly(
            device_type=sample_anomaly_data['device_type'],
            anomaly_type=AnomalyType.NEW_DESTINATION,
            severity=SeverityLevel.HIGH,
            geographic_region=sample_anomaly_data['geographic_region'],
            timestamp=datetime.fromisoformat(sample_anomaly_data['timestamp']),
            behavioral_signature=sample_anomaly_data['behavioral_signature']
        )
        
        with aioresponses() as mock_responses:
            # Mock successful metadata submission
            mock_responses.post(
                f"{mock_asgard_config['api_endpoint']}/metadata/anomalies",
                payload={
                    'status': 'accepted',
                    'metadata_id': 'anomaly_12345',
                    'processing_status': 'queued'
                },
                status=202
            )
            
            # Test sending anomaly metadata
            result = asyncio.run(asgard_communicator.send_anomaly_metadata(anonymized_anomaly))
            
            assert result is True
    
    def test_send_device_metadata(self, asgard_communicator, sample_device_data, mock_asgard_config):
        """Test sending anonymized device metadata"""
        anonymized_device = AnonymizedDevice(
            device_type=sample_device_data['device_type'],
            vendor=sample_device_data['vendor'],
            geographic_region=sample_device_data['geographic_region'],
            behavioral_patterns=sample_device_data['behavioral_patterns'],
            confidence_score=sample_device_data['confidence_score'],
            timestamp=datetime.fromisoformat(sample_device_data['timestamp'])
        )
        
        with aioresponses() as mock_responses:
            # Mock successful metadata submission
            mock_responses.post(
                f"{mock_asgard_config['api_endpoint']}/metadata/devices",
                payload={
                    'status': 'accepted',
                    'metadata_id': 'device_12345',
                    'processing_status': 'queued'
                },
                status=202
            )
            
            # Test sending device metadata
            result = asyncio.run(asgard_communicator.send_device_metadata(anonymized_device))
            
            assert result is True
    
    def test_receive_intelligence_updates(self, asgard_communicator, mock_asgard_config):
        """Test receiving intelligence updates from Asgard"""
        intelligence_updates = [
            {
                'update_id': 'intel_001',
                'type': 'golden_profile',
                'device_type': 'iPhone',
                'version': 'v1.1',
                'data': {
                    'normal_destinations': ['apple.com', 'icloud.com'],
                    'common_ports': [80, 443, 5223],
                    'behavioral_patterns': {
                        'peak_hours': [9, 18, 19, 20],
                        'session_duration': 300
                    }
                },
                'timestamp': datetime.now().isoformat()
            },
            {
                'update_id': 'intel_002',
                'type': 'threat_signature',
                'signature_id': 'threat_001',
                'version': 'v1.0',
                'data': {
                    'malicious_ips': ['1.2.3.4', '5.6.7.8'],
                    'suspicious_domains': ['malware.tk', 'phishing.ml'],
                    'attack_patterns': ['port_scan', 'dns_tunneling']
                },
                'timestamp': datetime.now().isoformat()
            }
        ]
        
        with aioresponses() as mock_responses:
            # Mock intelligence updates response
            mock_responses.get(
                f"{mock_asgard_config['api_endpoint']}/intelligence/updates",
                payload={
                    'status': 'success',
                    'updates': intelligence_updates,
                    'next_check': (datetime.now() + timedelta(hours=1)).isoformat()
                },
                status=200
            )
            
            # Test receiving intelligence updates
            updates = asyncio.run(asgard_communicator.receive_intelligence_updates())
            
            assert len(updates) == 2
            assert updates[0]['type'] == 'golden_profile'
            assert updates[1]['type'] == 'threat_signature'
    
    def test_api_authentication(self, asgard_communicator, mock_asgard_config):
        """Test API authentication handling"""
        with aioresponses() as mock_responses:
            # Mock authentication failure
            mock_responses.get(
                f"{mock_asgard_config['api_endpoint']}/intelligence/updates",
                status=401,
                payload={'error': 'Invalid API key'}
            )
            
            # Test authentication failure handling
            updates = asyncio.run(asgard_communicator.receive_intelligence_updates())
            
            assert updates == []  # Should return empty list on auth failure
    
    def test_network_timeout_handling(self, asgard_communicator, mock_asgard_config):
        """Test network timeout handling"""
        with aioresponses() as mock_responses:
            # Mock timeout by not adding any response
            pass
        
        # Create a communicator with short timeout
        short_timeout_communicator = AsgardCommunicator(
            api_endpoint=mock_asgard_config['api_endpoint'],
            api_key=mock_asgard_config['api_key'],
            sensor_id=mock_asgard_config['sensor_id'],
            timeout=0.1  # Very short timeout
        )
        
        # Test timeout handling
        updates = asyncio.run(short_timeout_communicator.receive_intelligence_updates())
        
        assert updates == []  # Should return empty list on timeout
    
    def test_retry_mechanism(self, asgard_communicator, mock_asgard_config):
        """Test retry mechanism for failed requests"""
        with aioresponses() as mock_responses:
            # Mock initial failures followed by success
            mock_responses.get(
                f"{mock_asgard_config['api_endpoint']}/intelligence/updates",
                status=500,
                payload={'error': 'Internal server error'}
            )
            mock_responses.get(
                f"{mock_asgard_config['api_endpoint']}/intelligence/updates",
                status=500,
                payload={'error': 'Internal server error'}
            )
            mock_responses.get(
                f"{mock_asgard_config['api_endpoint']}/intelligence/updates",
                status=200,
                payload={
                    'status': 'success',
                    'updates': [],
                    'next_check': datetime.now().isoformat()
                }
            )
            
            # Test retry mechanism
            updates = asyncio.run(asgard_communicator.receive_intelligence_updates())
            
            assert isinstance(updates, list)  # Should eventually succeed
    
    def test_offline_queuing(self, asgard_communicator, sample_anomaly_data):
        """Test offline queuing when Asgard is unavailable"""
        anonymized_anomaly = AnonymizedAnomaly(
            device_type=sample_anomaly_data['device_type'],
            anomaly_type=AnomalyType.NEW_DESTINATION,
            severity=SeverityLevel.HIGH,
            geographic_region=sample_anomaly_data['geographic_region'],
            timestamp=datetime.fromisoformat(sample_anomaly_data['timestamp']),
            behavioral_signature=sample_anomaly_data['behavioral_signature']
        )
        
        with aioresponses() as mock_responses:
            # Mock network unavailable (no responses)
            pass
        
        # Test offline queuing
        result = asyncio.run(asgard_communicator.send_anomaly_metadata(anonymized_anomaly))
        
        # Should queue for later transmission
        assert result is False  # Immediate send failed
        
        # Verify item was queued (would need to check internal queue)
        assert len(asgard_communicator._offline_queue) > 0


class TestDataAnonymization:
    """Integration tests for data anonymization"""
    
    def test_anonymize_device_behavior(self, data_anonymizer, sample_device_behavior):
        """Test anonymizing device behavior data"""
        anonymized = data_anonymizer.anonymize_device_behavior(sample_device_behavior)
        
        assert isinstance(anonymized, AnonymizedDevice)
        assert anonymized.device_type is not None
        assert anonymized.geographic_region is not None
        assert anonymized.behavioral_patterns is not None
        
        # Verify PII is removed
        assert sample_device_behavior.device_id not in str(anonymized.__dict__)
    
    def test_anonymize_anomaly(self, data_anonymizer, sample_anomaly):
        """Test anonymizing anomaly data"""
        anonymized = data_anonymizer.anonymize_anomaly(sample_anomaly)
        
        assert isinstance(anonymized, AnonymizedAnomaly)
        assert anonymized.device_type is not None
        assert anonymized.anomaly_type == sample_anomaly.anomaly_type
        assert anonymized.severity == sample_anomaly.severity
        
        # Verify PII is removed
        assert sample_anomaly.device_id not in str(anonymized.__dict__)
    
    def test_ip_address_anonymization(self, data_anonymizer):
        """Test IP address anonymization"""
        test_ips = [
            '192.168.1.100',  # Private
            '8.8.8.8',        # Public DNS
            '17.253.144.10',  # Apple
            '172.217.164.110' # Google
        ]
        
        for ip in test_ips:
            anonymized = data_anonymizer.anonymize_ip_address(ip)
            
            # Should not contain original IP
            assert ip not in anonymized
            
            # Should contain geographic or category information
            assert len(anonymized) > 0
    
    def test_mac_address_anonymization(self, data_anonymizer):
        """Test MAC address anonymization"""
        test_macs = [
            'aa:bb:cc:dd:ee:ff',
            '00:1E:C2:12:34:56',  # Apple
            '00:13:77:12:34:56'   # Samsung
        ]
        
        for mac in test_macs:
            anonymized = data_anonymizer.anonymize_mac_address(mac)
            
            # Should not contain original MAC
            assert mac not in anonymized
            
            # Should contain device type or vendor information
            assert len(anonymized) > 0
    
    def test_behavioral_signature_generation(self, data_anonymizer, sample_device_behavior):
        """Test behavioral signature generation"""
        signature = data_anonymizer.generate_behavioral_signature(sample_device_behavior)
        
        assert isinstance(signature, str)
        assert len(signature) > 0
        
        # Should be consistent for same behavior
        signature2 = data_anonymizer.generate_behavioral_signature(sample_device_behavior)
        assert signature == signature2
    
    def test_privacy_preservation(self, data_anonymizer, sample_device_behavior, sample_anomaly):
        """Test that anonymization preserves privacy"""
        # Anonymize data
        anonymized_device = data_anonymizer.anonymize_device_behavior(sample_device_behavior)
        anonymized_anomaly = data_anonymizer.anonymize_anomaly(sample_anomaly)
        
        # Convert to JSON to check for PII leakage
        device_json = json.dumps(anonymized_device.__dict__, default=str)
        anomaly_json = json.dumps(anonymized_anomaly.__dict__, default=str)
        
        # Check that no PII is present
        pii_patterns = [
            sample_device_behavior.device_id,
            sample_anomaly.device_id,
            '192.168.',  # Private IP patterns
            '10.',
            '172.'
        ]
        
        for pattern in pii_patterns:
            if pattern:  # Skip None values
                assert pattern not in device_json
                assert pattern not in anomaly_json


class TestIntelligenceManagement:
    """Integration tests for intelligence management"""
    
    def test_golden_profile_integration(self, intelligence_manager, temp_dir):
        """Test golden profile integration"""
        golden_profile = GoldenProfile(
            device_type='iPhone',
            version='v1.1',
            normal_destinations={'apple.com', 'icloud.com', 'mzstatic.com'},
            common_ports={80, 443, 5223, 993},
            behavioral_patterns={
                'peak_hours': [9, 10, 11, 18, 19, 20],
                'session_duration': 300,
                'protocols': ['TCP', 'UDP']
            },
            confidence_score=0.95,
            last_updated=datetime.now()
        )
        
        # Test storing golden profile
        result = intelligence_manager.store_golden_profile(golden_profile)
        assert result is True
        
        # Test retrieving golden profile
        retrieved = intelligence_manager.get_golden_profile('iPhone')
        assert retrieved is not None
        assert retrieved.device_type == 'iPhone'
        assert retrieved.version == 'v1.1'
    
    def test_threat_signature_integration(self, intelligence_manager):
        """Test threat signature integration"""
        threat_signature = {
            'signature_id': 'threat_001',
            'version': 'v1.0',
            'malicious_ips': ['1.2.3.4', '5.6.7.8'],
            'suspicious_domains': ['malware.tk', 'phishing.ml'],
            'attack_patterns': ['port_scan', 'dns_tunneling'],
            'severity': 'HIGH',
            'last_updated': datetime.now().isoformat()
        }
        
        # Test storing threat signature
        result = intelligence_manager.store_threat_signature(threat_signature)
        assert result is True
        
        # Test retrieving threat signature
        retrieved = intelligence_manager.get_threat_signature('threat_001')
        assert retrieved is not None
        assert retrieved['signature_id'] == 'threat_001'
    
    def test_intelligence_update_processing(self, intelligence_manager):
        """Test processing intelligence updates"""
        updates = [
            IntelligenceUpdate(
                update_id='update_001',
                update_type='golden_profile',
                device_type='iPhone',
                version='v1.2',
                data={
                    'normal_destinations': ['apple.com', 'icloud.com'],
                    'common_ports': [80, 443, 5223]
                },
                timestamp=datetime.now()
            ),
            IntelligenceUpdate(
                update_id='update_002',
                update_type='threat_signature',
                signature_id='threat_002',
                version='v1.0',
                data={
                    'malicious_ips': ['9.10.11.12'],
                    'attack_patterns': ['ddos']
                },
                timestamp=datetime.now()
            )
        ]
        
        # Test processing updates
        processed_count = intelligence_manager.process_intelligence_updates(updates)
        assert processed_count == 2
        
        # Verify updates were stored
        golden_profile = intelligence_manager.get_golden_profile('iPhone')
        assert golden_profile is not None
        assert golden_profile.version == 'v1.2'
        
        threat_signature = intelligence_manager.get_threat_signature('threat_002')
        assert threat_signature is not None
    
    def test_intelligence_cache_management(self, intelligence_manager):
        """Test intelligence cache management"""
        # Add multiple profiles
        for i in range(10):
            profile = GoldenProfile(
                device_type=f'Device{i}',
                version='v1.0',
                normal_destinations=set(),
                common_ports=set(),
                behavioral_patterns={},
                confidence_score=0.8,
                last_updated=datetime.now() - timedelta(days=i)
            )
            intelligence_manager.store_golden_profile(profile)
        
        # Test cache cleanup
        cleaned_count = intelligence_manager.cleanup_old_intelligence(max_age_days=5)
        assert cleaned_count > 0
        
        # Verify old profiles were removed
        old_profile = intelligence_manager.get_golden_profile('Device9')
        assert old_profile is None  # Should be cleaned up
        
        recent_profile = intelligence_manager.get_golden_profile('Device0')
        assert recent_profile is not None  # Should remain