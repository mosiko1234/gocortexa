"""
Test suite validation - ensures test infrastructure works correctly
"""

import pytest
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


def test_imports():
    """Test that all required modules can be imported"""
    try:
        from heimdal.models import DeviceBaseline, DeviceBehavior, Anomaly
        from heimdal.analysis.device_fingerprinter import DeviceFingerprinter
        from heimdal.analysis.behavioral_extractor import BehavioralExtractor
        from heimdal.analysis.realtime_analyzer import RealtimeAnalyzer
        from heimdal.baseline.manager import BaselineManager
        from heimdal.anomaly.detector import AnomalyDetector
        assert True
    except ImportError as e:
        pytest.fail(f"Failed to import required modules: {e}")


def test_fixtures_available(sample_device_baseline, sample_device_behavior, sample_anomaly):
    """Test that pytest fixtures are working"""
    assert sample_device_baseline is not None
    assert sample_device_behavior is not None
    assert sample_anomaly is not None
    
    assert sample_device_baseline.device_id is not None
    assert sample_device_behavior.device_id is not None
    assert sample_anomaly.device_id is not None


def test_temp_directory(temp_dir):
    """Test that temporary directory fixture works"""
    temp_path = Path(temp_dir)
    assert temp_path.exists()
    assert temp_path.is_dir()
    
    # Test we can write to it
    test_file = temp_path / "test.txt"
    test_file.write_text("test content")
    assert test_file.exists()
    assert test_file.read_text() == "test content"


def test_mock_packets(mock_packet_ip, mock_dns_packet, synthetic_packet_stream):
    """Test that mock packet fixtures work"""
    assert mock_packet_ip is not None
    assert mock_dns_packet is not None
    assert synthetic_packet_stream is not None
    assert len(synthetic_packet_stream) > 0


def test_baseline_manager_fixture(baseline_manager):
    """Test that baseline manager fixture works"""
    assert baseline_manager is not None
    
    # Test basic functionality
    result = baseline_manager.get_device_baseline("nonexistent")
    assert result is None


def test_anomaly_detector_fixture(anomaly_detector):
    """Test that anomaly detector fixture works"""
    assert anomaly_detector is not None
    assert anomaly_detector.baseline_manager is not None


class TestSuiteStructure:
    """Test the structure of the test suite itself"""
    
    def test_unit_tests_exist(self):
        """Verify unit test files exist"""
        unit_test_dir = Path(__file__).parent / "unit"
        assert unit_test_dir.exists()
        
        expected_files = [
            "test_device_fingerprinter.py",
            "test_behavioral_extractor.py", 
            "test_anomaly_detector.py",
            "test_baseline_manager.py"
        ]
        
        for filename in expected_files:
            test_file = unit_test_dir / filename
            assert test_file.exists(), f"Missing unit test file: {filename}"
    
    def test_integration_tests_exist(self):
        """Verify integration test files exist"""
        integration_test_dir = Path(__file__).parent / "integration"
        assert integration_test_dir.exists()
        
        expected_files = [
            "test_end_to_end_monitoring.py",
            "test_asgard_communication.py",
            "test_performance.py"
        ]
        
        for filename in expected_files:
            test_file = integration_test_dir / filename
            assert test_file.exists(), f"Missing integration test file: {filename}"
    
    def test_conftest_exists(self):
        """Verify conftest.py exists and has required fixtures"""
        conftest_file = Path(__file__).parent / "conftest.py"
        assert conftest_file.exists()
        
        # Read conftest and check for key fixtures
        conftest_content = conftest_file.read_text()
        required_fixtures = [
            "temp_dir",
            "baseline_manager", 
            "sample_device_baseline",
            "sample_device_behavior",
            "sample_anomaly",
            "mock_packet_ip",
            "synthetic_packet_stream"
        ]
        
        for fixture in required_fixtures:
            assert f"def {fixture}(" in conftest_content, f"Missing fixture: {fixture}"


def test_pytest_configuration():
    """Test that pytest is configured correctly"""
    # Check that pytest.ini exists
    pytest_ini = Path(__file__).parent.parent / "pytest.ini"
    assert pytest_ini.exists(), "pytest.ini configuration file missing"
    
    # Check that test runner exists
    test_runner = Path(__file__).parent.parent / "run_tests.py"
    assert test_runner.exists(), "run_tests.py script missing"


def test_requirements_file():
    """Test that test requirements file exists"""
    requirements_file = Path(__file__).parent.parent / "requirements-test.txt"
    assert requirements_file.exists(), "requirements-test.txt missing"
    
    # Check that it contains key dependencies
    content = requirements_file.read_text()
    required_packages = ["pytest", "pytest-cov", "pytest-mock", "aioresponses"]
    
    for package in required_packages:
        assert package in content, f"Missing test dependency: {package}"