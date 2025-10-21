"""
Baseline Management System for Heimdal Real-time Monitoring

This module provides the BaselineManager class that handles:
- Loading and saving device baselines to JSON files
- Baseline versioning and rollback capabilities
- Device baseline data validation
"""

import json
import os
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, List, Any
import logging

from ..models import DeviceBaseline, TrafficPattern, GoldenProfile, DeviceBehavior, DeviceFeatures


class BaselineManager:
    """
    Manages device behavioral baselines with local JSON storage.
    
    Provides functionality for:
    - Loading and saving baselines to JSON files
    - Baseline versioning and rollback
    - Data validation and error handling
    """
    
    def __init__(self, baseline_dir: str = "data/baselines", max_versions: int = 10):
        """
        Initialize the BaselineManager.
        
        Args:
            baseline_dir: Directory to store baseline files
            max_versions: Maximum number of baseline versions to keep
        """
        self.baseline_dir = Path(baseline_dir)
        self.max_versions = max_versions
        self.logger = logging.getLogger(__name__)
        
        # Create baseline directory if it doesn't exist
        self.baseline_dir.mkdir(parents=True, exist_ok=True)
        self.versions_dir = self.baseline_dir / "versions"
        self.versions_dir.mkdir(exist_ok=True)
        
        # In-memory cache of loaded baselines
        self._baselines_cache: Dict[str, DeviceBaseline] = {}
        self._cache_loaded = False
    
    def get_device_baseline(self, device_id: str) -> Optional[DeviceBaseline]:
        """
        Get the baseline for a specific device.
        
        Args:
            device_id: Unique identifier for the device
            
        Returns:
            DeviceBaseline object if found, None otherwise
        """
        if not self._cache_loaded:
            self.load_baselines()
        
        return self._baselines_cache.get(device_id)
    
    def set_device_baseline(self, baseline: DeviceBaseline) -> bool:
        """
        Set/update the baseline for a device.
        
        Args:
            baseline: DeviceBaseline object to store
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Validate baseline data
            if not self._validate_baseline(baseline):
                self.logger.error(f"Invalid baseline data for device {baseline.device_id}")
                return False
            
            # Update cache
            self._baselines_cache[baseline.device_id] = baseline
            
            # Save to disk
            return self.save_baselines()
            
        except Exception as e:
            self.logger.error(f"Error setting baseline for device {baseline.device_id}: {e}")
            return False
    
    def load_baselines(self) -> bool:
        """
        Load all baselines from the JSON file.
        
        Returns:
            True if successful, False otherwise
        """
        baseline_file = self.baseline_dir / "baselines.json"
        
        try:
            if not baseline_file.exists():
                self.logger.info("No existing baseline file found, starting with empty baselines")
                self._baselines_cache = {}
                self._cache_loaded = True
                return True
            
            with open(baseline_file, 'r') as f:
                data = json.load(f)
            
            # Convert JSON data back to DeviceBaseline objects
            self._baselines_cache = {}
            for device_id, baseline_data in data.get('baselines', {}).items():
                baseline = self._dict_to_baseline(baseline_data)
                if baseline:
                    self._baselines_cache[device_id] = baseline
            
            self._cache_loaded = True
            self.logger.info(f"Loaded {len(self._baselines_cache)} device baselines")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading baselines: {e}")
            return False
    
    def save_baselines(self) -> bool:
        """
        Save all baselines to the JSON file with versioning.
        
        Returns:
            True if successful, False otherwise
        """
        baseline_file = self.baseline_dir / "baselines.json"
        
        try:
            # Create backup version before saving
            if baseline_file.exists():
                self._create_version_backup()
            
            # Prepare data for JSON serialization
            data = {
                'version': datetime.now().isoformat(),
                'baselines': {}
            }
            
            for device_id, baseline in self._baselines_cache.items():
                data['baselines'][device_id] = baseline.to_dict()
            
            # Write to temporary file first, then rename (atomic operation)
            temp_file = baseline_file.with_suffix('.tmp')
            with open(temp_file, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            
            # Atomic rename
            temp_file.rename(baseline_file)
            
            self.logger.info(f"Saved {len(self._baselines_cache)} device baselines")
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving baselines: {e}")
            return False
    
    def create_version_snapshot(self, version_name: Optional[str] = None) -> str:
        """
        Create a named version snapshot of current baselines.
        
        Args:
            version_name: Optional name for the version, defaults to timestamp
            
        Returns:
            Version identifier string
        """
        if version_name is None:
            version_name = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        baseline_file = self.baseline_dir / "baselines.json"
        version_file = self.versions_dir / f"baselines_{version_name}.json"
        
        try:
            if baseline_file.exists():
                shutil.copy2(baseline_file, version_file)
                self.logger.info(f"Created baseline version snapshot: {version_name}")
                
                # Clean up old versions
                self._cleanup_old_versions()
                
                return version_name
            else:
                self.logger.warning("No baseline file exists to create version from")
                return ""
                
        except Exception as e:
            self.logger.error(f"Error creating version snapshot: {e}")
            return ""
    
    def rollback_to_version(self, version_name: str) -> bool:
        """
        Rollback baselines to a specific version.
        
        Args:
            version_name: Version identifier to rollback to
            
        Returns:
            True if successful, False otherwise
        """
        version_file = self.versions_dir / f"baselines_{version_name}.json"
        baseline_file = self.baseline_dir / "baselines.json"
        
        try:
            if not version_file.exists():
                self.logger.error(f"Version {version_name} not found")
                return False
            
            # Create backup of current state before rollback
            self._create_version_backup("pre_rollback")
            
            # Copy version file to current baseline
            shutil.copy2(version_file, baseline_file)
            
            # Reload baselines from file
            self._cache_loaded = False
            success = self.load_baselines()
            
            if success:
                self.logger.info(f"Successfully rolled back to version {version_name}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error rolling back to version {version_name}: {e}")
            return False
    
    def list_versions(self) -> List[str]:
        """
        List all available baseline versions.
        
        Returns:
            List of version identifiers
        """
        try:
            versions = []
            for version_file in self.versions_dir.glob("baselines_*.json"):
                # Extract version name from filename
                version_name = version_file.stem.replace("baselines_", "")
                versions.append(version_name)
            
            return sorted(versions, reverse=True)  # Most recent first
            
        except Exception as e:
            self.logger.error(f"Error listing versions: {e}")
            return []
    
    def get_baseline_stats(self) -> Dict[str, Any]:
        """
        Get statistics about current baselines.
        
        Returns:
            Dictionary with baseline statistics
        """
        if not self._cache_loaded:
            self.load_baselines()
        
        stats = {
            'total_devices': len(self._baselines_cache),
            'device_types': {},
            'confidence_scores': [],
            'last_updated_range': {'oldest': None, 'newest': None}
        }
        
        for baseline in self._baselines_cache.values():
            # Count device types
            device_type = baseline.device_type
            stats['device_types'][device_type] = stats['device_types'].get(device_type, 0) + 1
            
            # Collect confidence scores
            stats['confidence_scores'].append(baseline.confidence_score)
            
            # Track update timestamps
            if baseline.last_updated:
                if stats['last_updated_range']['oldest'] is None or baseline.last_updated < stats['last_updated_range']['oldest']:
                    stats['last_updated_range']['oldest'] = baseline.last_updated
                if stats['last_updated_range']['newest'] is None or baseline.last_updated > stats['last_updated_range']['newest']:
                    stats['last_updated_range']['newest'] = baseline.last_updated
        
        # Calculate average confidence score
        if stats['confidence_scores']:
            stats['average_confidence'] = sum(stats['confidence_scores']) / len(stats['confidence_scores'])
        else:
            stats['average_confidence'] = 0.0
        
        return stats
    
    def _validate_baseline(self, baseline: DeviceBaseline) -> bool:
        """
        Validate baseline data structure and content.
        
        Args:
            baseline: DeviceBaseline object to validate
            
        Returns:
            True if valid, False otherwise
        """
        try:
            # Check required fields
            if not baseline.device_id or not baseline.device_type:
                return False
            
            # Validate confidence score range
            if not (0.0 <= baseline.confidence_score <= 1.0):
                return False
            
            # Validate sets are not None
            if baseline.normal_destinations is None:
                baseline.normal_destinations = set()
            if baseline.normal_ports is None:
                baseline.normal_ports = set()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Baseline validation error: {e}")
            return False
    
    def _dict_to_baseline(self, data: Dict[str, Any]) -> Optional[DeviceBaseline]:
        """
        Convert dictionary data to DeviceBaseline object.
        
        Args:
            data: Dictionary containing baseline data
            
        Returns:
            DeviceBaseline object or None if conversion fails
        """
        try:
            # Parse traffic patterns if present
            traffic_patterns = None
            if data.get('traffic_patterns'):
                tp_data = data['traffic_patterns']
                traffic_patterns = TrafficPattern(
                    peak_hours=tp_data.get('peak_hours', []),
                    average_session_duration=tp_data.get('average_session_duration', 0.0),
                    typical_destinations=set(tp_data.get('typical_destinations', [])),
                    common_ports=set(tp_data.get('common_ports', []))
                )
            
            # Parse last_updated timestamp
            last_updated = None
            if data.get('last_updated'):
                last_updated = datetime.fromisoformat(data['last_updated'])
            
            baseline = DeviceBaseline(
                device_id=data['device_id'],
                device_type=data['device_type'],
                normal_destinations=set(data.get('normal_destinations', [])),
                normal_ports=set(data.get('normal_ports', [])),
                traffic_patterns=traffic_patterns,
                last_updated=last_updated,
                confidence_score=data.get('confidence_score', 0.0),
                global_profile_version=data.get('global_profile_version', '')
            )
            
            return baseline
            
        except Exception as e:
            self.logger.error(f"Error converting dict to baseline: {e}")
            return None
    
    def _create_version_backup(self, suffix: str = None) -> None:
        """
        Create a timestamped backup version of current baselines.
        
        Args:
            suffix: Optional suffix for the backup filename
        """
        baseline_file = self.baseline_dir / "baselines.json"
        
        if not baseline_file.exists():
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if suffix:
            version_name = f"{timestamp}_{suffix}"
        else:
            version_name = timestamp
        
        version_file = self.versions_dir / f"baselines_{version_name}.json"
        
        try:
            shutil.copy2(baseline_file, version_file)
            self.logger.debug(f"Created backup version: {version_name}")
        except Exception as e:
            self.logger.error(f"Error creating backup version: {e}")
    
    def _cleanup_old_versions(self) -> None:
        """
        Remove old version files beyond the maximum limit.
        """
        try:
            version_files = list(self.versions_dir.glob("baselines_*.json"))
            
            if len(version_files) <= self.max_versions:
                return
            
            # Sort by modification time (oldest first)
            version_files.sort(key=lambda f: f.stat().st_mtime)
            
            # Remove oldest files
            files_to_remove = version_files[:-self.max_versions]
            for file_path in files_to_remove:
                file_path.unlink()
                self.logger.debug(f"Removed old version file: {file_path.name}")
                
        except Exception as e:
            self.logger.error(f"Error cleaning up old versions: {e}")
    
    def update_baseline(self, device_id: str, new_behavior: DeviceBehavior) -> bool:
        """
        Update device baseline with new behavioral data using adaptive algorithms.
        
        Args:
            device_id: Device identifier
            new_behavior: New behavioral data to incorporate
            
        Returns:
            True if successful, False otherwise
        """
        try:
            current_baseline = self.get_device_baseline(device_id)
            
            if current_baseline is None:
                # Create new baseline from behavior
                current_baseline = self._create_baseline_from_behavior(device_id, new_behavior)
            else:
                # Update existing baseline
                current_baseline = self._update_existing_baseline(current_baseline, new_behavior)
            
            # Update confidence score based on data quality and age
            current_baseline.confidence_score = self._calculate_confidence_score(current_baseline, new_behavior)
            
            # Update timestamp
            current_baseline.last_updated = datetime.now()
            
            # Store updated baseline
            return self.set_device_baseline(current_baseline)
            
        except Exception as e:
            self.logger.error(f"Error updating baseline for device {device_id}: {e}")
            return False
    
    def update_baseline_from_features(self, device_features: DeviceFeatures) -> bool:
        """
        Update baseline from extracted device features.
        
        Args:
            device_features: Extracted features from device traffic
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Convert features to behavior format
            behavior = DeviceBehavior(
                device_id=device_features.device_id,
                timestamp=device_features.timestamp,
                protocols_used=device_features.protocols,
                traffic_volume=device_features.traffic_volume
            )
            
            return self.update_baseline(device_features.device_id, behavior)
            
        except Exception as e:
            self.logger.error(f"Error updating baseline from features: {e}")
            return False
    
    def apply_rolling_window_cleanup(self, window_days: int = 7) -> int:
        """
        Apply rolling window cleanup to remove stale baseline data.
        
        Args:
            window_days: Number of days to keep in rolling window
            
        Returns:
            Number of baselines cleaned up
        """
        cleanup_count = 0
        cutoff_date = datetime.now() - timedelta(days=window_days)
        
        try:
            if not self._cache_loaded:
                self.load_baselines()
            
            devices_to_remove = []
            
            for device_id, baseline in self._baselines_cache.items():
                if baseline.last_updated and baseline.last_updated < cutoff_date:
                    # Check if baseline is stale and has low confidence
                    if baseline.confidence_score < 0.3:
                        devices_to_remove.append(device_id)
                        cleanup_count += 1
                    else:
                        # Reduce confidence for old but still valid baselines
                        baseline.confidence_score *= 0.9
                        self.logger.debug(f"Reduced confidence for stale baseline {device_id}")
            
            # Remove stale baselines
            for device_id in devices_to_remove:
                del self._baselines_cache[device_id]
                self.logger.info(f"Removed stale baseline for device {device_id}")
            
            if cleanup_count > 0:
                self.save_baselines()
            
            return cleanup_count
            
        except Exception as e:
            self.logger.error(f"Error during rolling window cleanup: {e}")
            return 0
    
    def integrate_global_profile(self, device_type: str, golden_profile: GoldenProfile) -> int:
        """
        Integrate global device profile into local baselines.
        
        Args:
            device_type: Type of device to update
            golden_profile: Global profile from Asgard
            
        Returns:
            Number of baselines updated
        """
        updated_count = 0
        
        try:
            if not self._cache_loaded:
                self.load_baselines()
            
            for device_id, baseline in self._baselines_cache.items():
                if baseline.device_type == device_type:
                    # Update baseline with global profile data
                    if self._merge_global_profile(baseline, golden_profile):
                        baseline.global_profile_version = golden_profile.version
                        updated_count += 1
            
            if updated_count > 0:
                self.save_baselines()
                self.logger.info(f"Updated {updated_count} baselines with global profile {golden_profile.version}")
            
            return updated_count
            
        except Exception as e:
            self.logger.error(f"Error integrating global profile: {e}")
            return 0
    
    def _create_baseline_from_behavior(self, device_id: str, behavior: DeviceBehavior) -> DeviceBaseline:
        """
        Create a new baseline from behavioral data.
        
        Args:
            device_id: Device identifier
            behavior: Behavioral data
            
        Returns:
            New DeviceBaseline object
        """
        # Extract destinations from connections
        destinations = set()
        ports = set()
        
        for connection in behavior.connections:
            destinations.add(connection.destination_ip)
            ports.add(connection.destination_port)
        
        # Create traffic pattern from behavior
        traffic_pattern = None
        if behavior.traffic_volume:
            traffic_pattern = TrafficPattern(
                peak_hours=[behavior.timestamp.hour],
                average_session_duration=behavior.traffic_volume.duration_seconds,
                typical_destinations=destinations,
                common_ports=ports
            )
        
        # Infer device type from behavior patterns (simplified)
        device_type = self._infer_device_type(behavior)
        
        return DeviceBaseline(
            device_id=device_id,
            device_type=device_type,
            normal_destinations=destinations,
            normal_ports=ports,
            traffic_patterns=traffic_pattern,
            last_updated=datetime.now(),
            confidence_score=0.1,  # Start with low confidence for new baselines
            global_profile_version=""
        )
    
    def _update_existing_baseline(self, baseline: DeviceBaseline, new_behavior: DeviceBehavior) -> DeviceBaseline:
        """
        Update existing baseline with new behavioral data using adaptive algorithms.
        
        Args:
            baseline: Existing baseline
            new_behavior: New behavioral data
            
        Returns:
            Updated baseline
        """
        # Adaptive learning rate based on confidence and data age
        learning_rate = self._calculate_learning_rate(baseline)
        
        # Update destinations with adaptive merging
        new_destinations = set()
        new_ports = set()
        
        for connection in new_behavior.connections:
            new_destinations.add(connection.destination_ip)
            new_ports.add(connection.destination_port)
        
        # Merge destinations with adaptive approach
        baseline.normal_destinations = self._adaptive_set_merge(
            baseline.normal_destinations, new_destinations, learning_rate
        )
        
        # Merge ports with adaptive approach
        baseline.normal_ports = self._adaptive_set_merge(
            baseline.normal_ports, new_ports, learning_rate
        )
        
        # Update traffic patterns
        if baseline.traffic_patterns and new_behavior.traffic_volume:
            baseline.traffic_patterns = self._update_traffic_patterns(
                baseline.traffic_patterns, new_behavior, learning_rate
            )
        
        return baseline
    
    def _calculate_confidence_score(self, baseline: DeviceBaseline, new_behavior: DeviceBehavior) -> float:
        """
        Calculate confidence score based on data quality, consistency, and age.
        
        Args:
            baseline: Current baseline
            new_behavior: New behavioral data
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        # Start with current confidence
        confidence = baseline.confidence_score
        
        # Factor 1: Data age (newer data increases confidence)
        if baseline.last_updated:
            age_hours = (datetime.now() - baseline.last_updated).total_seconds() / 3600
            age_factor = max(0.1, 1.0 - (age_hours / (24 * 7)))  # Decay over a week
        else:
            age_factor = 0.1
        
        # Factor 2: Data consistency (consistent behavior increases confidence)
        consistency_factor = self._calculate_behavior_consistency(baseline, new_behavior)
        
        # Factor 3: Data volume (more data points increase confidence)
        volume_factor = min(1.0, len(baseline.normal_destinations) / 10.0)
        
        # Combine factors with weights
        new_confidence = (
            0.4 * age_factor +
            0.4 * consistency_factor +
            0.2 * volume_factor
        )
        
        # Smooth transition (don't change confidence too rapidly)
        smoothing_factor = 0.1
        final_confidence = (1 - smoothing_factor) * confidence + smoothing_factor * new_confidence
        
        return max(0.0, min(1.0, final_confidence))
    
    def _calculate_learning_rate(self, baseline: DeviceBaseline) -> float:
        """
        Calculate adaptive learning rate based on baseline confidence and age.
        
        Args:
            baseline: Current baseline
            
        Returns:
            Learning rate between 0.01 and 0.5
        """
        # Higher learning rate for low confidence baselines
        confidence_factor = 1.0 - baseline.confidence_score
        
        # Higher learning rate for newer baselines
        if baseline.last_updated:
            age_hours = (datetime.now() - baseline.last_updated).total_seconds() / 3600
            age_factor = min(1.0, age_hours / 24.0)  # Normalize to days
        else:
            age_factor = 1.0
        
        # Combine factors
        learning_rate = 0.01 + 0.49 * (0.7 * confidence_factor + 0.3 * age_factor)
        
        return max(0.01, min(0.5, learning_rate))
    
    def _adaptive_set_merge(self, existing_set: set, new_set: set, learning_rate: float) -> set:
        """
        Merge sets using adaptive learning rate.
        
        Args:
            existing_set: Current set of values
            new_set: New set of values to merge
            learning_rate: Learning rate for adaptation
            
        Returns:
            Merged set
        """
        # Always keep existing values
        merged = existing_set.copy()
        
        # Add new values based on learning rate
        for item in new_set:
            if item not in existing_set:
                # Add new item with probability based on learning rate
                if learning_rate > 0.1:  # Only add if learning rate is significant
                    merged.add(item)
        
        # Remove old values that haven't been seen recently (with low probability)
        if learning_rate < 0.2:  # Only remove if we're confident in the baseline
            items_to_remove = []
            for item in existing_set:
                if item not in new_set and len(existing_set) > 3:  # Keep minimum set size
                    # Small chance to remove unseen items
                    if learning_rate < 0.05:
                        items_to_remove.append(item)
            
            for item in items_to_remove:
                merged.discard(item)
        
        return merged
    
    def _update_traffic_patterns(self, patterns: TrafficPattern, new_behavior: DeviceBehavior, learning_rate: float) -> TrafficPattern:
        """
        Update traffic patterns with new behavioral data.
        
        Args:
            patterns: Current traffic patterns
            new_behavior: New behavioral data
            learning_rate: Learning rate for updates
            
        Returns:
            Updated traffic patterns
        """
        # Update peak hours
        current_hour = new_behavior.timestamp.hour
        if current_hour not in patterns.peak_hours:
            if learning_rate > 0.1:
                patterns.peak_hours.append(current_hour)
        
        # Update average session duration
        if new_behavior.traffic_volume and new_behavior.traffic_volume.duration_seconds > 0:
            new_duration = new_behavior.traffic_volume.duration_seconds
            patterns.average_session_duration = (
                (1 - learning_rate) * patterns.average_session_duration +
                learning_rate * new_duration
            )
        
        # Update typical destinations and common ports
        new_destinations = set()
        new_ports = set()
        
        for connection in new_behavior.connections:
            new_destinations.add(connection.destination_ip)
            new_ports.add(connection.destination_port)
        
        patterns.typical_destinations = self._adaptive_set_merge(
            patterns.typical_destinations, new_destinations, learning_rate
        )
        patterns.common_ports = self._adaptive_set_merge(
            patterns.common_ports, new_ports, learning_rate
        )
        
        return patterns
    
    def _calculate_behavior_consistency(self, baseline: DeviceBaseline, new_behavior: DeviceBehavior) -> float:
        """
        Calculate how consistent new behavior is with existing baseline.
        
        Args:
            baseline: Current baseline
            new_behavior: New behavioral data
            
        Returns:
            Consistency score between 0.0 and 1.0
        """
        consistency_scores = []
        
        # Check destination consistency
        new_destinations = set()
        for connection in new_behavior.connections:
            new_destinations.add(connection.destination_ip)
        
        if baseline.normal_destinations and new_destinations:
            overlap = len(baseline.normal_destinations.intersection(new_destinations))
            total = len(baseline.normal_destinations.union(new_destinations))
            dest_consistency = overlap / total if total > 0 else 0.0
            consistency_scores.append(dest_consistency)
        
        # Check protocol consistency
        if baseline.traffic_patterns and new_behavior.protocols_used:
            # Simplified protocol consistency check
            protocol_consistency = 0.8 if new_behavior.protocols_used else 0.5
            consistency_scores.append(protocol_consistency)
        
        # Return average consistency
        return sum(consistency_scores) / len(consistency_scores) if consistency_scores else 0.5
    
    def _infer_device_type(self, behavior: DeviceBehavior) -> str:
        """
        Infer device type from behavioral patterns (simplified heuristics).
        
        Args:
            behavior: Behavioral data
            
        Returns:
            Inferred device type string
        """
        # Simple heuristics based on protocols and destinations
        protocols = behavior.protocols_used
        destinations = set()
        
        for connection in behavior.connections:
            destinations.add(connection.destination_ip)
        
        # Check for common patterns
        if 'HTTPS' in protocols or 'UDP' in protocols:
            # Check for common mobile/web destinations
            web_destinations = {'google.com', 'facebook.com', 'apple.com', 'microsoft.com'}
            if any(dest in str(destinations) for dest in web_destinations):
                if len(behavior.connections) > 5:
                    return 'laptop'
                else:
                    return 'smartphone'
            elif '8.8.8.8' in destinations or '1.1.1.1' in destinations:
                # DNS queries suggest active device
                return 'smartphone'
        
        if 'HTTP' in protocols and 'HTTPS' not in protocols:
            return 'iot_device'
        
        return 'unknown'
    
    def _merge_global_profile(self, baseline: DeviceBaseline, golden_profile: GoldenProfile) -> bool:
        """
        Merge global profile data into local baseline.
        
        Args:
            baseline: Local baseline to update
            golden_profile: Global profile data
            
        Returns:
            True if merge was successful
        """
        try:
            # Extract normal behaviors from golden profile
            normal_behaviors = golden_profile.normal_behaviors
            
            if 'destinations' in normal_behaviors:
                global_destinations = set(normal_behaviors['destinations'])
                baseline.normal_destinations = baseline.normal_destinations.union(global_destinations)
            
            if 'ports' in normal_behaviors:
                global_ports = set(normal_behaviors['ports'])
                baseline.normal_ports = baseline.normal_ports.union(global_ports)
            
            # Boost confidence score when integrating global profile
            baseline.confidence_score = min(1.0, baseline.confidence_score + 0.1)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error merging global profile: {e}")
            return False