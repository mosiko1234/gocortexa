"""
Unit tests for Baseline Manager
"""

import pytest
import json
import tempfile
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch, mock_open

from heimdal.baseline.manager import BaselineManager
from heimdal.models import DeviceBaseline, DeviceBehavior, DeviceFeatures, TrafficPattern, TrafficVolume, Connection


class TestBaselineManager:
    """Test cases for BaselineManager class"""
    
    def test_init(self, temp_dir):
        """Test BaselineManager initialization"""
        manager = BaselineManager(baseline_dir=temp_dir)
        
        assert manager.baseline_dir == Path(temp_dir)
        assert manager.max_versions == 10
        assert isinstance(manager._baselines_cache, dict)
        assert manager._cache_loaded is False
        
        # Check directories are created
        assert manager.baseline_dir.exists()
        assert manager.versions_dir.exists()
    
    def test_init_custom_max_versions(self, temp_dir):
        """Test initialization with custom max versions"""
        manager = BaselineManager(baseline_dir=temp_dir, max_versions=5)
        
        assert manager.max_versions == 5
    
    def test_get_device_baseline_empty_cache(self, temp_dir):
        """Test getting device baseline with empty cache"""
        manager = BaselineManager(baseline_dir=temp_dir)
        
        with patch.object(manager, 'load_baselines', return_value=True) as mock_load:
            result = manager.get_device_baseline("test_device")
            
            assert result is None
            mock_load.assert_called_once()
            assert manager._cache_loaded is True
    
    def test_get_device_baseline_cached(self, temp_dir, sample_device_baseline):
        """Test getting device baseline from cache"""
        manager = BaselineManager(baseline_dir=temp_dir)
        manager._baselines_cache["test_device"] = sample_device_baseline
        manager._cache_loaded = True
        
        result = manager.get_device_baseline("test_device")
        
        assert result is sample_device_baseline
    
    def test_set_device_baseline_valid(self, temp_dir, sample_device_baseline):
        """Test setting valid device baseline"""
        manager = BaselineManager(baseline_dir=temp_dir)
        
        with patch.object(manager, 'save_baselines', return_value=True) as mock_save:
            result = manager.set_device_baseline(sample_device_baseline)
            
            assert result is True
            assert "aa:bb:cc:dd:ee:ff" in manager._baselines_cache
            assert manager._baselines_cache["aa:bb:cc:dd:ee:ff"] is sample_device_baseline
            mock_save.assert_called_once()
    
    def test_set_device_baseline_invalid(self, temp_dir):
        """Test setting invalid device baseline"""
        manager = BaselineManager(baseline_dir=temp_dir)
        
        # Create invalid baseline (missing device_id)
        invalid_baseline = DeviceBaseline(
            device_id="",  # Invalid empty device_id
            device_type="Test Device",
            normal_destinations=set(),
            normal_ports=set(),
            traffic_patterns=None,
            last_updated=datetime.now(),
            confidence_score=0.5,
            global_profile_version=""
        )
        
        result = manager.set_device_baseline(invalid_baseline)
        
        assert result is False
        assert len(manager._baselines_cache) == 0
    
    def test_load_baselines_no_file(self, temp_dir):
        """Test loading baselines when no file exists"""
        manager = BaselineManager(baseline_dir=temp_dir)
        
        result = manager.load_baselines()
        
        assert result is True
        assert manager._baselines_cache == {}
        assert manager._cache_loaded is True
    
    def test_load_baselines_with_file(self, temp_dir, sample_device_baseline):
        """Test loading baselines from existing file"""
        manager = BaselineManager(baseline_dir=temp_dir)
        
        # Create baseline file
        baseline_file = manager.baseline_dir / "baselines.json"
        baseline_data = {
            "version": datetime.now().isoformat(),
            "baselines": {
                "test_device": sample_device_baseline.to_dict()
            }
        }
        
        with open(baseline_file, 'w') as f:
            json.dump(baseline_data, f, default=str)
        
        result = manager.load_baselines()
        
        assert result is True
        assert len(manager._baselines_cache) == 1
        assert "test_device" in manager._baselines_cache
        assert manager._cache_loaded is True
    
    def test_load_baselines_corrupted_file(self, temp_dir):
        """Test loading baselines from corrupted file"""
        manager = BaselineManager(baseline_dir=temp_dir)
        
        # Create corrupted baseline file
        baseline_file = manager.baseline_dir / "baselines.json"
        with open(baseline_file, 'w') as f:
            f.write("invalid json content")
        
        result = manager.load_baselines()
        
        assert result is False
        assert manager._cache_loaded is False
    
    def test_save_baselines_new_file(self, temp_dir, sample_device_baseline):
        """Test saving baselines to new file"""
        manager = BaselineManager(baseline_dir=temp_dir)
        manager._baselines_cache["test_device"] = sample_device_baseline
        
        result = manager.save_baselines()
        
        assert result is True
        
        # Verify file was created
        baseline_file = manager.baseline_dir / "baselines.json"
        assert baseline_file.exists()
        
        # Verify content
        with open(baseline_file, 'r') as f:
            data = json.load(f)
        
        assert "version" in data
        assert "baselines" in data
        assert "test_device" in data["baselines"]
    
    def test_save_baselines_with_backup(self, temp_dir, sample_device_baseline):
        """Test saving baselines with existing file (creates backup)"""
        manager = BaselineManager(baseline_dir=temp_dir)
        
        # Create existing baseline file
        baseline_file = manager.baseline_dir / "baselines.json"
        with open(baseline_file, 'w') as f:
            json.dump({"version": "old", "baselines": {}}, f)
        
        manager._baselines_cache["test_device"] = sample_device_baseline
        
        with patch.object(manager, '_create_version_backup') as mock_backup:
            result = manager.save_baselines()
            
            assert result is True
            mock_backup.assert_called_once()
    
    def test_create_version_snapshot(self, temp_dir):
        """Test creating version snapshot"""
        manager = BaselineManager(baseline_dir=temp_dir)
        
        # Create baseline file
        baseline_file = manager.baseline_dir / "baselines.json"
        with open(baseline_file, 'w') as f:
            json.dump({"version": "test", "baselines": {}}, f)
        
        with patch.object(manager, '_cleanup_old_versions') as mock_cleanup:
            version_name = manager.create_version_snapshot("test_version")
            
            assert version_name == "test_version"
            
            # Verify version file was created
            version_file = manager.versions_dir / "baselines_test_version.json"
            assert version_file.exists()
            
            mock_cleanup.assert_called_once()
    
    def test_create_version_snapshot_no_file(self, temp_dir):
        """Test creating version snapshot when no baseline file exists"""
        manager = BaselineManager(baseline_dir=temp_dir)
        
        version_name = manager.create_version_snapshot("test_version")
        
        assert version_name == ""
    
    def test_rollback_to_version(self, temp_dir):
        """Test rolling back to a specific version"""
        manager = BaselineManager(baseline_dir=temp_dir)
        
        # Create version file
        version_file = manager.versions_dir / "baselines_test_version.json"
        version_data = {"version": "test", "baselines": {"device1": {}}}
        with open(version_file, 'w') as f:
            json.dump(version_data, f)
        
        with patch.object(manager, '_create_version_backup') as mock_backup, \
             patch.object(manager, 'load_baselines', return_value=True) as mock_load:
            
            result = manager.rollback_to_version("test_version")
            
            assert result is True
            mock_backup.assert_called_once_with("pre_rollback")
            mock_load.assert_called_once()
            
            # Verify baseline file was created
            baseline_file = manager.baseline_dir / "baselines.json"
            assert baseline_file.exists()
    
    def test_rollback_to_nonexistent_version(self, temp_dir):
        """Test rolling back to non-existent version"""
        manager = BaselineManager(baseline_dir=temp_dir)
        
        result = manager.rollback_to_version("nonexistent_version")
        
        assert result is False
    
    def test_list_versions(self, temp_dir):
        """Test listing available versions"""
        manager = BaselineManager(baseline_dir=temp_dir)
        
        # Create some version files
        version_files = ["baselines_v1.json", "baselines_v2.json", "baselines_v3.json"]
        for filename in version_files:
            version_file = manager.versions_dir / filename
            with open(version_file, 'w') as f:
                json.dump({}, f)
        
        versions = manager.list_versions()
        
        assert len(versions) == 3
        assert "v3" in versions  # Should be sorted with most recent first
        assert "v2" in versions
        assert "v1" in versions
    
    def test_get_baseline_stats(self, temp_dir):
        """Test getting baseline statistics"""
        manager = BaselineManager(baseline_dir=temp_dir)
        manager._cache_loaded = True
        
        # Add some test baselines
        baseline1 = DeviceBaseline(
            device_id="device1",
            device_type="iPhone",
            normal_destinations={"dest1", "dest2"},
            normal_ports={80, 443},
            traffic_patterns=None,
            last_updated=datetime.now() - timedelta(hours=1),
            confidence_score=0.8,
            global_profile_version=""
        )
        
        baseline2 = DeviceBaseline(
            device_id="device2",
            device_type="Samsung TV",
            normal_destinations={"dest3"},
            normal_ports={80},
            traffic_patterns=None,
            last_updated=datetime.now() - timedelta(hours=2),
            confidence_score=0.6,
            global_profile_version=""
        )
        
        manager._baselines_cache["device1"] = baseline1
        manager._baselines_cache["device2"] = baseline2
        
        stats = manager.get_baseline_stats()
        
        assert stats["total_devices"] == 2
        assert stats["device_types"]["iPhone"] == 1
        assert stats["device_types"]["Samsung TV"] == 1
        assert len(stats["confidence_scores"]) == 2
        assert stats["average_confidence"] == 0.7
        assert stats["last_updated_range"]["oldest"] is not None
        assert stats["last_updated_range"]["newest"] is not None
    
    def test_validate_baseline_valid(self, temp_dir, sample_device_baseline):
        """Test baseline validation with valid baseline"""
        manager = BaselineManager(baseline_dir=temp_dir)
        
        result = manager._validate_baseline(sample_device_baseline)
        
        assert result is True
    
    def test_validate_baseline_invalid(self, temp_dir):
        """Test baseline validation with invalid baseline"""
        manager = BaselineManager(baseline_dir=temp_dir)
        
        # Test missing device_id
        invalid_baseline = DeviceBaseline(
            device_id="",
            device_type="Test Device",
            normal_destinations=set(),
            normal_ports=set(),
            traffic_patterns=None,
            last_updated=datetime.now(),
            confidence_score=0.5,
            global_profile_version=""
        )
        
        result = manager._validate_baseline(invalid_baseline)
        assert result is False
        
        # Test invalid confidence score
        invalid_baseline.device_id = "test_device"
        invalid_baseline.confidence_score = 1.5  # Out of range
        
        result = manager._validate_baseline(invalid_baseline)
        assert result is False
    
    def test_dict_to_baseline(self, temp_dir):
        """Test converting dictionary to baseline object"""
        manager = BaselineManager(baseline_dir=temp_dir)
        
        baseline_dict = {
            "device_id": "test_device",
            "device_type": "Test Device",
            "normal_destinations": ["dest1", "dest2"],
            "normal_ports": [80, 443],
            "traffic_patterns": {
                "peak_hours": [9, 10, 11],
                "average_session_duration": 300.0,
                "typical_destinations": ["dest1"],
                "common_ports": [80, 443]
            },
            "last_updated": datetime.now().isoformat(),
            "confidence_score": 0.8,
            "global_profile_version": "v1.0"
        }
        
        baseline = manager._dict_to_baseline(baseline_dict)
        
        assert baseline is not None
        assert baseline.device_id == "test_device"
        assert baseline.device_type == "Test Device"
        assert "dest1" in baseline.normal_destinations
        assert 80 in baseline.normal_ports
        assert baseline.traffic_patterns is not None
        assert baseline.confidence_score == 0.8
    
    def test_dict_to_baseline_invalid(self, temp_dir):
        """Test converting invalid dictionary to baseline"""
        manager = BaselineManager(baseline_dir=temp_dir)
        
        invalid_dict = {"invalid": "data"}
        
        result = manager._dict_to_baseline(invalid_dict)
        
        assert result is None
    
    def test_cleanup_old_versions(self, temp_dir):
        """Test cleanup of old version files"""
        manager = BaselineManager(baseline_dir=temp_dir, max_versions=2)
        
        # Create more version files than max_versions
        version_files = []
        for i in range(5):
            version_file = manager.versions_dir / f"baselines_v{i}.json"
            with open(version_file, 'w') as f:
                json.dump({}, f)
            version_files.append(version_file)
            
            # Add small delay to ensure different modification times
            import time
            time.sleep(0.01)
        
        manager._cleanup_old_versions()
        
        # Should only keep max_versions files
        remaining_files = list(manager.versions_dir.glob("baselines_*.json"))
        assert len(remaining_files) == 2
        
        # Should keep the newest files
        assert version_files[-1].exists()  # Most recent
        assert version_files[-2].exists()  # Second most recent
        assert not version_files[0].exists()  # Oldest should be removed
    
    def test_update_baseline_new_device(self, temp_dir, sample_device_behavior):
        """Test updating baseline for new device"""
        manager = BaselineManager(baseline_dir=temp_dir)
        
        with patch.object(manager, 'set_device_baseline', return_value=True) as mock_set:
            result = manager.update_baseline("new_device", sample_device_behavior)
            
            assert result is True
            mock_set.assert_called_once()
            
            # Verify baseline was created
            call_args = mock_set.call_args[0][0]
            assert call_args.device_id == "new_device"
            assert call_args.confidence_score == 0.1  # Low confidence for new baseline
    
    def test_update_baseline_existing_device(self, temp_dir, sample_device_baseline, sample_device_behavior):
        """Test updating baseline for existing device"""
        manager = BaselineManager(baseline_dir=temp_dir)
        manager._baselines_cache["test_device"] = sample_device_baseline
        manager._cache_loaded = True
        
        with patch.object(manager, 'set_device_baseline', return_value=True) as mock_set:
            result = manager.update_baseline("test_device", sample_device_behavior)
            
            assert result is True
            mock_set.assert_called_once()
            
            # Verify baseline was updated
            call_args = mock_set.call_args[0][0]
            assert call_args.device_id == "test_device"
            assert call_args.last_updated is not None
    
    def test_update_baseline_from_features(self, temp_dir, sample_device_features):
        """Test updating baseline from device features"""
        manager = BaselineManager(baseline_dir=temp_dir)
        
        with patch.object(manager, 'update_baseline', return_value=True) as mock_update:
            result = manager.update_baseline_from_features(sample_device_features)
            
            assert result is True
            mock_update.assert_called_once()
            
            # Verify correct device_id was used
            call_args = mock_update.call_args
            assert call_args[0][0] == sample_device_features.device_id
    
    def test_apply_rolling_window_cleanup(self, temp_dir):
        """Test rolling window cleanup"""
        manager = BaselineManager(baseline_dir=temp_dir)
        manager._cache_loaded = True
        
        # Add baselines with different ages and confidence scores
        old_low_confidence = DeviceBaseline(
            device_id="old_low",
            device_type="Test",
            normal_destinations=set(),
            normal_ports=set(),
            traffic_patterns=None,
            last_updated=datetime.now() - timedelta(days=10),
            confidence_score=0.2,  # Low confidence
            global_profile_version=""
        )
        
        old_high_confidence = DeviceBaseline(
            device_id="old_high",
            device_type="Test",
            normal_destinations=set(),
            normal_ports=set(),
            traffic_patterns=None,
            last_updated=datetime.now() - timedelta(days=10),
            confidence_score=0.8,  # High confidence
            global_profile_version=""
        )
        
        recent_baseline = DeviceBaseline(
            device_id="recent",
            device_type="Test",
            normal_destinations=set(),
            normal_ports=set(),
            traffic_patterns=None,
            last_updated=datetime.now() - timedelta(hours=1),
            confidence_score=0.5,
            global_profile_version=""
        )
        
        manager._baselines_cache["old_low"] = old_low_confidence
        manager._baselines_cache["old_high"] = old_high_confidence
        manager._baselines_cache["recent"] = recent_baseline
        
        with patch.object(manager, 'save_baselines', return_value=True) as mock_save:
            cleanup_count = manager.apply_rolling_window_cleanup(window_days=7)
            
            assert cleanup_count == 1  # Only old_low should be removed
            assert "old_low" not in manager._baselines_cache
            assert "old_high" in manager._baselines_cache
            assert "recent" in manager._baselines_cache
            
            # High confidence baseline should have reduced confidence
            assert manager._baselines_cache["old_high"].confidence_score < 0.8
            
            mock_save.assert_called_once()
    
    def test_calculate_confidence_score(self, temp_dir, sample_device_baseline, sample_device_behavior):
        """Test confidence score calculation"""
        manager = BaselineManager(baseline_dir=temp_dir)
        
        score = manager._calculate_confidence_score(sample_device_baseline, sample_device_behavior)
        
        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0
    
    def test_calculate_learning_rate(self, temp_dir, sample_device_baseline):
        """Test learning rate calculation"""
        manager = BaselineManager(baseline_dir=temp_dir)
        
        # Test with different confidence scores
        sample_device_baseline.confidence_score = 0.1  # Low confidence
        rate_low = manager._calculate_learning_rate(sample_device_baseline)
        
        sample_device_baseline.confidence_score = 0.9  # High confidence
        rate_high = manager._calculate_learning_rate(sample_device_baseline)
        
        # Low confidence should have higher learning rate
        assert rate_low > rate_high
        assert 0.01 <= rate_low <= 0.5
        assert 0.01 <= rate_high <= 0.5
    
    def test_adaptive_set_merge(self, temp_dir):
        """Test adaptive set merging"""
        manager = BaselineManager(baseline_dir=temp_dir)
        
        existing_set = {"item1", "item2", "item3"}
        new_set = {"item3", "item4", "item5"}
        
        # High learning rate - should add new items
        merged_high = manager._adaptive_set_merge(existing_set, new_set, 0.5)
        assert "item4" in merged_high
        assert "item5" in merged_high
        assert len(merged_high) >= len(existing_set)
        
        # Low learning rate - should be more conservative
        merged_low = manager._adaptive_set_merge(existing_set, new_set, 0.05)
        assert len(merged_low) >= len(existing_set)  # Should at least keep existing items