"""
Main monitoring orchestrator for Heimdal real-time monitoring system
"""

import threading
import time
import uuid
from typing import Dict, Any, Optional, List
from datetime import datetime

from .interfaces import (
    IMonitoringOrchestrator, IPacketCaptureEngine, IRealtimeAnalyzer,
    IBaselineManager, IAnomalyDetector, IAsgardCommunicator, ILogger,
    IConfigurationManager
)
from .capture.engine import PacketCaptureEngine
from .analysis.realtime_analyzer import RealtimeAnalyzer
from .baseline.manager import BaselineManager
from .anomaly.detector import AnomalyDetector
from .communication.asgard_communicator import AsgardCommunicator
from .logging.manager import LoggingManager
from .models import SensorInfo


class ComponentStatus:
    """Status tracking for system components"""
    
    def __init__(self, name: str):
        self.name = name
        self.status = "stopped"  # stopped, starting, running, error
        self.last_heartbeat = None
        self.error_message = None
        self.restart_count = 0
        self.last_restart = None


class MonitoringOrchestrator(IMonitoringOrchestrator):
    """Main orchestrator that coordinates all monitoring components"""
    
    def __init__(self, config_manager: IConfigurationManager):
        self.config_manager = config_manager
        self.logger: Optional[ILogger] = None
        
        # Component instances
        self.capture_engine: Optional[IPacketCaptureEngine] = None
        self.analyzer: Optional[IRealtimeAnalyzer] = None
        self.baseline_manager: Optional[IBaselineManager] = None
        self.anomaly_detector: Optional[IAnomalyDetector] = None
        self.asgard_communicator: Optional[IAsgardCommunicator] = None
        
        # System state
        self._running = False
        self._startup_complete = False
        self._shutdown_requested = False
        self._main_thread: Optional[threading.Thread] = None
        self._health_check_thread: Optional[threading.Thread] = None
        
        # Component status tracking
        self._component_status: Dict[str, ComponentStatus] = {}
        self._status_lock = threading.RLock()
        
        # Performance metrics
        self._start_time: Optional[datetime] = None
        self._packets_processed = 0
        self._anomalies_detected = 0
        self._last_activity = None
        
        # Initialize component status tracking
        self._init_component_status()
        
        # Register for configuration changes
        self.config_manager.add_reload_callback(self._handle_config_reload)
    
    def _init_component_status(self) -> None:
        """Initialize component status tracking"""
        components = [
            "capture_engine", "analyzer", "baseline_manager", 
            "anomaly_detector", "asgard_communicator", "logger"
        ]
        
        for component in components:
            self._component_status[component] = ComponentStatus(component)
    
    def start(self) -> bool:
        """Start the monitoring system"""
        if self._running:
            return True
        
        try:
            print("Starting Heimdal monitoring orchestrator...")
            self._start_time = datetime.now()
            self._running = True
            self._shutdown_requested = False
            
            # Initialize logging first
            if not self._initialize_logging():
                return False
            
            self.logger.info("Heimdal monitoring system starting up")
            
            # Initialize all components
            if not self._initialize_components():
                self.stop()
                return False
            
            # Start main monitoring loop
            self._main_thread = threading.Thread(target=self._main_loop, daemon=True)
            self._main_thread.start()
            
            # Start health check monitoring
            self._health_check_thread = threading.Thread(target=self._health_check_loop, daemon=True)
            self._health_check_thread.start()
            
            # Register sensor with Asgard
            self._register_with_asgard()
            
            self._startup_complete = True
            self.logger.info("Heimdal monitoring system started successfully")
            print("Heimdal monitoring system started successfully")
            
            return True
            
        except Exception as e:
            error_msg = f"Failed to start monitoring system: {e}"
            if self.logger:
                self.logger.error(error_msg)
            else:
                print(error_msg)
            self.stop()
            return False
    
    def stop(self) -> bool:
        """Stop the monitoring system"""
        if not self._running:
            return True
        
        try:
            if self.logger:
                self.logger.info("Shutting down Heimdal monitoring system")
            print("Shutting down Heimdal monitoring system...")
            
            self._shutdown_requested = True
            self._running = False
            
            # Stop packet capture first to prevent new data
            if self.capture_engine:
                self._update_component_status("capture_engine", "stopping")
                self.capture_engine.stop_capture()
                self._update_component_status("capture_engine", "stopped")
            
            # Stop other components
            self._shutdown_components()
            
            # Wait for threads to finish
            if self._main_thread and self._main_thread.is_alive():
                self._main_thread.join(timeout=5.0)
            
            if self._health_check_thread and self._health_check_thread.is_alive():
                self._health_check_thread.join(timeout=2.0)
            
            if self.logger:
                self.logger.info("Heimdal monitoring system stopped")
            print("Heimdal monitoring system stopped")
            
            return True
            
        except Exception as e:
            error_msg = f"Error during shutdown: {e}"
            if self.logger:
                self.logger.error(error_msg)
            else:
                print(error_msg)
            return False
    
    def is_running(self) -> bool:
        """Check if monitoring system is running"""
        return self._running and self._startup_complete
    
    def get_status(self) -> Dict[str, Any]:
        """Get system status information"""
        with self._status_lock:
            uptime = None
            if self._start_time:
                uptime = (datetime.now() - self._start_time).total_seconds()
            
            return {
                "running": self._running,
                "startup_complete": self._startup_complete,
                "uptime_seconds": uptime,
                "packets_processed": self._packets_processed,
                "anomalies_detected": self._anomalies_detected,
                "last_activity": self._last_activity.isoformat() if self._last_activity else None,
                "components": {
                    name: {
                        "status": status.status,
                        "last_heartbeat": status.last_heartbeat.isoformat() if status.last_heartbeat else None,
                        "error_message": status.error_message,
                        "restart_count": status.restart_count
                    }
                    for name, status in self._component_status.items()
                }
            }
    
    def restart_component(self, component_name: str) -> bool:
        """Restart a specific component"""
        if not self._running:
            return False
        
        try:
            if self.logger:
                self.logger.info(f"Restarting component: {component_name}")
            
            with self._status_lock:
                if component_name not in self._component_status:
                    return False
                
                status = self._component_status[component_name]
                status.restart_count += 1
                status.last_restart = datetime.now()
            
            # Restart specific component
            if component_name == "capture_engine":
                return self._restart_capture_engine()
            elif component_name == "analyzer":
                return self._restart_analyzer()
            elif component_name == "baseline_manager":
                return self._restart_baseline_manager()
            elif component_name == "anomaly_detector":
                return self._restart_anomaly_detector()
            elif component_name == "asgard_communicator":
                return self._restart_asgard_communicator()
            else:
                return False
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to restart component {component_name}: {e}")
            return False
    
    def _initialize_logging(self) -> bool:
        """Initialize logging system"""
        try:
            self._update_component_status("logger", "starting")
            self.logger = LoggingManager(self.config_manager)
            self._update_component_status("logger", "running")
            return True
        except Exception as e:
            print(f"Failed to initialize logging: {e}")
            self._update_component_status("logger", "error", str(e))
            return False
    
    def _initialize_components(self) -> bool:
        """Initialize all monitoring components"""
        try:
            # Initialize baseline manager first (needed by other components)
            self._update_component_status("baseline_manager", "starting")
            self.baseline_manager = BaselineManager(self.config_manager, self.logger)
            if not self.baseline_manager.load_baselines():
                self.logger.warning("Failed to load existing baselines, starting fresh")
            self._update_component_status("baseline_manager", "running")
            
            # Initialize anomaly detector
            self._update_component_status("anomaly_detector", "starting")
            self.anomaly_detector = AnomalyDetector(self.config_manager, self.logger)
            self._update_component_status("anomaly_detector", "running")
            
            # Initialize Asgard communicator
            self._update_component_status("asgard_communicator", "starting")
            self.asgard_communicator = AsgardCommunicator(self.config_manager, self.logger)
            self._update_component_status("asgard_communicator", "running")
            
            # Initialize real-time analyzer
            self._update_component_status("analyzer", "starting")
            self.analyzer = RealtimeAnalyzer(
                self.config_manager, 
                self.baseline_manager,
                self.anomaly_detector,
                self.asgard_communicator,
                self.logger
            )
            self._update_component_status("analyzer", "running")
            
            # Initialize packet capture engine last
            self._update_component_status("capture_engine", "starting")
            self.capture_engine = PacketCaptureEngine(self.config_manager, self.logger)
            
            # Start packet capture
            interface = self.config_manager.get_config("capture.interface")
            filter_expr = self.config_manager.get_config("capture.filter_expression")
            
            if not self.capture_engine.start_capture(interface, filter_expr):
                raise Exception("Failed to start packet capture")
            
            self._update_component_status("capture_engine", "running")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize components: {e}")
            return False
    
    def _shutdown_components(self) -> None:
        """Shutdown all components gracefully"""
        components = [
            ("analyzer", self.analyzer),
            ("anomaly_detector", self.anomaly_detector),
            ("asgard_communicator", self.asgard_communicator),
            ("baseline_manager", self.baseline_manager)
        ]
        
        for name, component in components:
            if component:
                try:
                    self._update_component_status(name, "stopping")
                    # Components should implement their own cleanup if needed
                    self._update_component_status(name, "stopped")
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"Error stopping {name}: {e}")
    
    def _main_loop(self) -> None:
        """Main monitoring loop"""
        self.logger.info("Starting main monitoring loop")
        
        try:
            while self._running and not self._shutdown_requested:
                # Process packets from capture engine
                if self.capture_engine and self.analyzer:
                    try:
                        # Get packet stream and process
                        for packet in self.capture_engine.get_packet_stream():
                            if self._shutdown_requested:
                                break
                            
                            # Process packet through analyzer
                            device_behavior = self.analyzer.process_packet(packet)
                            if device_behavior:
                                self._packets_processed += 1
                                self._last_activity = datetime.now()
                                
                                # Check for anomalies
                                if self.anomaly_detector:
                                    anomalies = self.anomaly_detector.detect_anomalies(
                                        device_behavior.device_id, device_behavior
                                    )
                                    
                                    if anomalies:
                                        self._anomalies_detected += len(anomalies)
                                        self.logger.info(f"Detected {len(anomalies)} anomalies for device {device_behavior.device_id}")
                            
                            # Brief pause to prevent CPU overload
                            time.sleep(0.001)
                    
                    except Exception as e:
                        self.logger.error(f"Error in main processing loop: {e}")
                        time.sleep(1.0)  # Pause before retrying
                
                else:
                    time.sleep(0.1)  # Wait for components to be ready
                    
        except Exception as e:
            self.logger.error(f"Fatal error in main loop: {e}")
        
        self.logger.info("Main monitoring loop stopped")
    
    def _health_check_loop(self) -> None:
        """Health check monitoring loop"""
        check_interval = self.config_manager.get_config("system.health_check_interval", 60)
        
        while self._running and not self._shutdown_requested:
            try:
                self._perform_health_checks()
                time.sleep(check_interval)
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error in health check loop: {e}")
                time.sleep(check_interval)
    
    def _perform_health_checks(self) -> None:
        """Perform health checks on all components"""
        current_time = datetime.now()
        
        # Update heartbeats for running components
        for name, status in self._component_status.items():
            if status.status == "running":
                status.last_heartbeat = current_time
        
        # Check capture engine statistics
        if self.capture_engine and self.capture_engine.is_capturing():
            stats = self.capture_engine.get_capture_statistics()
            if stats.dropped_packets > 0:
                self.logger.warning(f"Packet capture dropping packets: {stats.dropped_packets}")
        
        # Check Asgard connectivity
        if self.asgard_communicator and not self.asgard_communicator.is_connected():
            self.logger.warning("Lost connection to Asgard cloud platform")
        
        # Save baselines periodically
        if self.baseline_manager:
            save_interval = self.config_manager.get_config("baseline.auto_save_interval", 300)
            if hasattr(self, '_last_baseline_save'):
                if (current_time - self._last_baseline_save).total_seconds() > save_interval:
                    self.baseline_manager.save_baselines()
                    self._last_baseline_save = current_time
            else:
                self._last_baseline_save = current_time
    
    def _update_component_status(self, component_name: str, status: str, error_message: Optional[str] = None) -> None:
        """Update component status"""
        with self._status_lock:
            if component_name in self._component_status:
                comp_status = self._component_status[component_name]
                comp_status.status = status
                comp_status.error_message = error_message
                if status == "running":
                    comp_status.last_heartbeat = datetime.now()
    
    def _register_with_asgard(self) -> None:
        """Register sensor with Asgard cloud platform"""
        if not self.asgard_communicator:
            return
        
        try:
            sensor_id = self.config_manager.get_config("system.sensor_id")
            if not sensor_id:
                sensor_id = str(uuid.uuid4())
                self.config_manager.set_config("system.sensor_id", sensor_id)
                self.config_manager.save_config()
            
            sensor_info = SensorInfo(
                sensor_id=sensor_id,
                location=self.config_manager.get_config("system.location", ""),
                capabilities=self.config_manager.get_config("system.capabilities", []),
                version="1.0.0"
            )
            
            registered_id = self.asgard_communicator.register_sensor(sensor_info)
            if registered_id:
                self.logger.info(f"Successfully registered with Asgard: {registered_id}")
            else:
                self.logger.warning("Failed to register with Asgard")
                
        except Exception as e:
            self.logger.error(f"Error registering with Asgard: {e}")
    
    def _handle_config_reload(self, new_config: Dict[str, Any]) -> None:
        """Handle configuration reload"""
        self.logger.info("Configuration reloaded, updating components")
        
        # Update anomaly detector thresholds
        if self.anomaly_detector:
            thresholds = new_config.get("anomaly_detection", {}).get("thresholds", {})
            self.anomaly_detector.set_thresholds(thresholds)
    
    # Component restart methods
    def _restart_capture_engine(self) -> bool:
        """Restart packet capture engine"""
        try:
            if self.capture_engine:
                self.capture_engine.stop_capture()
            
            interface = self.config_manager.get_config("capture.interface")
            filter_expr = self.config_manager.get_config("capture.filter_expression")
            
            success = self.capture_engine.start_capture(interface, filter_expr)
            if success:
                self._update_component_status("capture_engine", "running")
            else:
                self._update_component_status("capture_engine", "error", "Failed to restart capture")
            
            return success
        except Exception as e:
            self._update_component_status("capture_engine", "error", str(e))
            return False
    
    def _restart_analyzer(self) -> bool:
        """Restart real-time analyzer"""
        # Analyzer doesn't need explicit restart, just update status
        self._update_component_status("analyzer", "running")
        return True
    
    def _restart_baseline_manager(self) -> bool:
        """Restart baseline manager"""
        try:
            if self.baseline_manager:
                self.baseline_manager.save_baselines()
                self.baseline_manager.load_baselines()
            
            self._update_component_status("baseline_manager", "running")
            return True
        except Exception as e:
            self._update_component_status("baseline_manager", "error", str(e))
            return False
    
    def _restart_anomaly_detector(self) -> bool:
        """Restart anomaly detector"""
        try:
            if self.anomaly_detector:
                thresholds = self.config_manager.get_config("anomaly_detection.thresholds", {})
                self.anomaly_detector.set_thresholds(thresholds)
            
            self._update_component_status("anomaly_detector", "running")
            return True
        except Exception as e:
            self._update_component_status("anomaly_detector", "error", str(e))
            return False
    
    def _restart_asgard_communicator(self) -> bool:
        """Restart Asgard communicator"""
        try:
            # Re-register with Asgard
            self._register_with_asgard()
            self._update_component_status("asgard_communicator", "running")
            return True
        except Exception as e:
            self._update_component_status("asgard_communicator", "error", str(e))
            return False