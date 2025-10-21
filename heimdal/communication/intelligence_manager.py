"""
Intelligence reception and management from Asgard cloud platform
Handles threat intelligence updates and Golden Profile integration
"""

import json
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Callable, Any

from ..interfaces import IBaselineManager
from ..models import (
    IntelligenceUpdate, GoldenProfile, DeviceBaseline, TrafficPattern
)
from .asgard_communicator import AsgardCommunicator


class IntelligenceManager:
    """
    Manages intelligence reception from Asgard and integration into local systems
    """
    
    def __init__(self, 
                 asgard_communicator: AsgardCommunicator,
                 baseline_manager: IBaselineManager,
                 update_interval: int = 300,  # 5 minutes
                 auto_start: bool = True):
        """
        Initialize intelligence manager
        
        Args:
            asgard_communicator: Asgard communication client
            baseline_manager: Local baseline manager for integration
            update_interval: Interval between intelligence checks (seconds)
            auto_start: Whether to automatically start intelligence polling
        """
        self.asgard_communicator = asgard_communicator
        self.baseline_manager = baseline_manager
        self.update_interval = update_interval
        
        # Intelligence state
        self._running = False
        self._update_thread = None
        self._last_update_check = None
        self._intelligence_version = {}  # Track versions by update type
        
        # Threat intelligence data
        self._threat_signatures = {}
        self._enforcement_rules = []
        self._golden_profiles = {}  # device_type -> GoldenProfile
        
        # Callbacks for intelligence updates
        self._update_callbacks = {
            'threat_signatures': [],
            'enforcement_rules': [],
            'golden_profiles': [],
            'general': []
        }
        
        # Logger
        self.logger = logging.getLogger(__name__)
        
        # Statistics
        self._stats = {
            'updates_received': 0,
            'profiles_integrated': 0,
            'signatures_updated': 0,
            'rules_updated': 0,
            'last_successful_update': None,
            'update_errors': 0
        }
        
        if auto_start:
            self.start()
    
    def start(self):
        """Start intelligence polling"""
        if not self._running:
            self._running = True
            self._update_thread = threading.Thread(
                target=self._intelligence_update_loop,
                daemon=True
            )
            self._update_thread.start()
            self.logger.info("Started intelligence manager")
    
    def stop(self):
        """Stop intelligence polling"""
        if self._running:
            self._running = False
            if self._update_thread and self._update_thread.is_alive():
                self._update_thread.join(timeout=10)
            self.logger.info("Stopped intelligence manager")
    
    def _intelligence_update_loop(self):
        """Main loop for receiving intelligence updates"""
        while self._running:
            try:
                # Check for intelligence updates
                self._check_for_updates()
                
                # Sleep until next check
                time.sleep(self.update_interval)
                
            except Exception as e:
                self.logger.error(f"Error in intelligence update loop: {e}")
                self._stats['update_errors'] += 1
                time.sleep(60)  # Wait longer on error
    
    def _check_for_updates(self):
        """Check for and process intelligence updates from Asgard"""
        try:
            # Get intelligence updates
            updates = self.asgard_communicator.receive_intelligence_updates()
            
            if updates:
                self.logger.info(f"Received {len(updates)} intelligence updates")
                self._stats['updates_received'] += len(updates)
                
                for update in updates:
                    self._process_intelligence_update(update)
                
                self._stats['last_successful_update'] = datetime.now()
            
            self._last_update_check = datetime.now()
            
        except Exception as e:
            self.logger.error(f"Failed to check for intelligence updates: {e}")
            self._stats['update_errors'] += 1
    
    def _process_intelligence_update(self, update: IntelligenceUpdate):
        """
        Process a single intelligence update
        
        Args:
            update: Intelligence update to process
        """
        try:
            update_type = update.update_type
            content = update.content
            version = update.version
            
            self.logger.debug(f"Processing intelligence update: {update_type} v{version}")
            
            # Check if this is a newer version
            current_version = self._intelligence_version.get(update_type, "0.0.0")
            if self._is_newer_version(version, current_version):
                
                if update_type == "threat_signatures":
                    self._update_threat_signatures(content, version)
                elif update_type == "enforcement_rules":
                    self._update_enforcement_rules(content, version)
                elif update_type == "golden_profiles":
                    self._update_golden_profiles(content, version)
                else:
                    self.logger.warning(f"Unknown intelligence update type: {update_type}")
                
                # Update version tracking
                self._intelligence_version[update_type] = version
                
                # Notify callbacks
                self._notify_callbacks(update_type, content, version)
                
            else:
                self.logger.debug(f"Skipping older/same version update: {update_type} v{version}")
                
        except Exception as e:
            self.logger.error(f"Error processing intelligence update: {e}")
    
    def _is_newer_version(self, new_version: str, current_version: str) -> bool:
        """
        Compare version strings to determine if new version is newer
        
        Args:
            new_version: New version string
            current_version: Current version string
            
        Returns:
            True if new version is newer
        """
        try:
            new_parts = [int(x) for x in new_version.split('.')]
            current_parts = [int(x) for x in current_version.split('.')]
            
            # Pad shorter version with zeros
            max_len = max(len(new_parts), len(current_parts))
            new_parts.extend([0] * (max_len - len(new_parts)))
            current_parts.extend([0] * (max_len - len(current_parts)))
            
            return new_parts > current_parts
            
        except ValueError:
            # If version parsing fails, assume new version is newer
            return True
    
    def _update_threat_signatures(self, content: Dict[str, Any], version: str):
        """
        Update threat signatures
        
        Args:
            content: Threat signature content
            version: Version string
        """
        try:
            signatures = content.get('signatures', {})
            self._threat_signatures.update(signatures)
            
            self.logger.info(f"Updated {len(signatures)} threat signatures to version {version}")
            self._stats['signatures_updated'] += len(signatures)
            
        except Exception as e:
            self.logger.error(f"Error updating threat signatures: {e}")
    
    def _update_enforcement_rules(self, content: Dict[str, Any], version: str):
        """
        Update enforcement rules
        
        Args:
            content: Enforcement rules content
            version: Version string
        """
        try:
            rules = content.get('rules', [])
            self._enforcement_rules = rules  # Replace all rules
            
            self.logger.info(f"Updated {len(rules)} enforcement rules to version {version}")
            self._stats['rules_updated'] += len(rules)
            
        except Exception as e:
            self.logger.error(f"Error updating enforcement rules: {e}")
    
    def _update_golden_profiles(self, content: Dict[str, Any], version: str):
        """
        Update Golden Profiles and integrate into local baselines
        
        Args:
            content: Golden Profiles content
            version: Version string
        """
        try:
            profiles_data = content.get('profiles', [])
            
            for profile_data in profiles_data:
                # Create GoldenProfile object
                golden_profile = GoldenProfile(
                    device_type=profile_data['device_type'],
                    version=profile_data['version'],
                    normal_behaviors=profile_data['normal_behaviors'],
                    threat_indicators=profile_data['threat_indicators'],
                    last_updated=datetime.fromisoformat(profile_data['last_updated'])
                )
                
                # Store profile
                self._golden_profiles[golden_profile.device_type] = golden_profile
                
                # Integrate into local baselines
                self._integrate_golden_profile(golden_profile)
            
            self.logger.info(f"Updated {len(profiles_data)} Golden Profiles to version {version}")
            self._stats['profiles_integrated'] += len(profiles_data)
            
        except Exception as e:
            self.logger.error(f"Error updating Golden Profiles: {e}")
    
    def _integrate_golden_profile(self, golden_profile: GoldenProfile):
        """
        Integrate Golden Profile into local baselines
        
        Args:
            golden_profile: Golden Profile to integrate
        """
        try:
            # Get all local baselines for this device type
            all_baselines = self.baseline_manager.get_all_baselines()
            
            for device_id, baseline in all_baselines.items():
                if baseline.device_type == golden_profile.device_type:
                    # Update baseline with global profile data
                    updated = self._merge_profile_into_baseline(baseline, golden_profile)
                    if updated:
                        # Save updated baseline
                        self.baseline_manager.update_baseline(device_id, None)  # Trigger save
                        self.logger.debug(f"Integrated Golden Profile into baseline for {device_id}")
            
            # Also use the baseline manager's integration method if available
            success = self.baseline_manager.integrate_global_profile(
                golden_profile.device_type, 
                golden_profile
            )
            
            if success:
                self.logger.debug(f"Successfully integrated Golden Profile for {golden_profile.device_type}")
            
        except Exception as e:
            self.logger.error(f"Error integrating Golden Profile: {e}")
    
    def _merge_profile_into_baseline(self, baseline: DeviceBaseline, profile: GoldenProfile) -> bool:
        """
        Merge Golden Profile data into local baseline
        
        Args:
            baseline: Local baseline to update
            profile: Golden Profile to merge
            
        Returns:
            True if baseline was modified
        """
        modified = False
        
        try:
            # Update normal behaviors
            normal_behaviors = profile.normal_behaviors
            
            # Merge normal destinations
            if 'normal_destinations' in normal_behaviors:
                new_destinations = set(normal_behaviors['normal_destinations'])
                if not new_destinations.issubset(baseline.normal_destinations):
                    baseline.normal_destinations.update(new_destinations)
                    modified = True
            
            # Merge normal ports
            if 'normal_ports' in normal_behaviors:
                new_ports = set(normal_behaviors['normal_ports'])
                if not new_ports.issubset(baseline.normal_ports):
                    baseline.normal_ports.update(new_ports)
                    modified = True
            
            # Update traffic patterns
            if 'traffic_patterns' in normal_behaviors:
                pattern_data = normal_behaviors['traffic_patterns']
                if baseline.traffic_patterns is None:
                    baseline.traffic_patterns = TrafficPattern()
                
                # Merge traffic pattern data
                if 'peak_hours' in pattern_data:
                    new_hours = set(pattern_data['peak_hours'])
                    current_hours = set(baseline.traffic_patterns.peak_hours)
                    if new_hours != current_hours:
                        baseline.traffic_patterns.peak_hours = list(new_hours.union(current_hours))
                        modified = True
                
                if 'typical_destinations' in pattern_data:
                    new_destinations = set(pattern_data['typical_destinations'])
                    if not new_destinations.issubset(baseline.traffic_patterns.typical_destinations):
                        baseline.traffic_patterns.typical_destinations.update(new_destinations)
                        modified = True
                
                if 'common_ports' in pattern_data:
                    new_ports = set(pattern_data['common_ports'])
                    if not new_ports.issubset(baseline.traffic_patterns.common_ports):
                        baseline.traffic_patterns.common_ports.update(new_ports)
                        modified = True
            
            # Update global profile version
            if baseline.global_profile_version != profile.version:
                baseline.global_profile_version = profile.version
                modified = True
            
            return modified
            
        except Exception as e:
            self.logger.error(f"Error merging profile into baseline: {e}")
            return False
    
    def register_update_callback(self, update_type: str, callback: Callable):
        """
        Register callback for intelligence updates
        
        Args:
            update_type: Type of update ('threat_signatures', 'enforcement_rules', 'golden_profiles', 'general')
            callback: Callback function to call on updates
        """
        if update_type in self._update_callbacks:
            self._update_callbacks[update_type].append(callback)
            self.logger.debug(f"Registered callback for {update_type} updates")
        else:
            self.logger.warning(f"Unknown update type for callback: {update_type}")
    
    def _notify_callbacks(self, update_type: str, content: Dict[str, Any], version: str):
        """
        Notify registered callbacks of intelligence updates
        
        Args:
            update_type: Type of update
            content: Update content
            version: Update version
        """
        # Notify specific callbacks
        callbacks = self._update_callbacks.get(update_type, [])
        for callback in callbacks:
            try:
                callback(update_type, content, version)
            except Exception as e:
                self.logger.error(f"Error in update callback: {e}")
        
        # Notify general callbacks
        for callback in self._update_callbacks.get('general', []):
            try:
                callback(update_type, content, version)
            except Exception as e:
                self.logger.error(f"Error in general update callback: {e}")
    
    def get_threat_signatures(self) -> Dict[str, Any]:
        """Get current threat signatures"""
        return self._threat_signatures.copy()
    
    def get_enforcement_rules(self) -> List[Dict[str, Any]]:
        """Get current enforcement rules"""
        return self._enforcement_rules.copy()
    
    def get_golden_profiles(self) -> Dict[str, GoldenProfile]:
        """Get current Golden Profiles"""
        return self._golden_profiles.copy()
    
    def get_golden_profile(self, device_type: str) -> Optional[GoldenProfile]:
        """
        Get Golden Profile for specific device type
        
        Args:
            device_type: Device type to get profile for
            
        Returns:
            Golden Profile if available, None otherwise
        """
        return self._golden_profiles.get(device_type)
    
    def force_update_check(self):
        """Force an immediate intelligence update check"""
        self.logger.info("Forcing intelligence update check")
        self._check_for_updates()
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get intelligence manager statistics
        
        Returns:
            Dictionary with statistics
        """
        stats = self._stats.copy()
        stats.update({
            'running': self._running,
            'last_update_check': self._last_update_check.isoformat() if self._last_update_check else None,
            'intelligence_versions': self._intelligence_version.copy(),
            'threat_signatures_count': len(self._threat_signatures),
            'enforcement_rules_count': len(self._enforcement_rules),
            'golden_profiles_count': len(self._golden_profiles)
        })
        return stats
    
    def is_running(self) -> bool:
        """Check if intelligence manager is running"""
        return self._running