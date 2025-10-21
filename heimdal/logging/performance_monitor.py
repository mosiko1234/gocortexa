"""
Performance monitoring and metrics collection for Heimdal.

This module tracks system performance (CPU, memory, packet rates) and provides
diagnostic endpoints for system health checking as required by the real-time
monitoring specification.
"""

import psutil
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, asdict
from collections import deque
import json

from .manager import get_logger, log_metric


@dataclass
class SystemMetrics:
    """System performance metrics snapshot."""
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    memory_used_mb: float
    memory_available_mb: float
    disk_usage_percent: float
    disk_free_gb: float
    network_bytes_sent: int
    network_bytes_recv: int
    process_count: int


@dataclass
class PacketMetrics:
    """Packet processing metrics."""
    timestamp: datetime
    packets_captured: int
    packets_processed: int
    packets_dropped: int
    processing_rate_pps: float  # packets per second
    average_processing_time_ms: float
    buffer_utilization_percent: float


@dataclass
class AsgardMetrics:
    """Asgard communication metrics."""
    timestamp: datetime
    api_calls_total: int
    api_calls_successful: int
    api_calls_failed: int
    average_response_time_ms: float
    last_successful_call: Optional[datetime]
    queue_size: int
    connection_status: str  # 'connected', 'disconnected', 'error'


@dataclass
class ComponentHealth:
    """Health status of a system component."""
    component_name: str
    status: str  # 'healthy', 'warning', 'error', 'stopped'
    last_activity: datetime
    error_count: int
    warning_count: int
    uptime_seconds: float
    details: Dict[str, Any]


class PerformanceMonitor:
    """
    Comprehensive performance monitoring and metrics collection system.
    """
    
    def __init__(self, 
                 collection_interval: int = 30,
                 history_retention_hours: int = 24,
                 alert_thresholds: Optional[Dict[str, float]] = None):
        """
        Initialize the performance monitor.
        
        Args:
            collection_interval: Seconds between metric collections
            history_retention_hours: Hours to retain metric history
            alert_thresholds: Thresholds for performance alerts
        """
        self.collection_interval = collection_interval
        self.history_retention = timedelta(hours=history_retention_hours)
        self.alert_thresholds = alert_thresholds or {
            'cpu_percent': 80.0,
            'memory_percent': 85.0,
            'disk_usage_percent': 90.0,
            'packet_drop_rate': 5.0,
            'api_failure_rate': 10.0
        }
        
        self.logger = get_logger(__name__, 'performance_monitor')
        
        # Metric storage
        self._system_metrics: deque = deque()
        self._packet_metrics: deque = deque()
        self._asgard_metrics: deque = deque()
        self._component_health: Dict[str, ComponentHealth] = {}
        
        # Monitoring state
        self._monitoring = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        
        # Performance counters
        self._start_time = datetime.now()
        self._last_network_stats = psutil.net_io_counters()
        
        # Health check callbacks
        self._health_check_callbacks: Dict[str, Callable[[], Dict[str, Any]]] = {}
    
    def start_monitoring(self):
        """Start the performance monitoring thread."""
        if self._monitoring:
            return
        
        self._monitoring = True
        self._monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self._monitor_thread.start()
        
        self.logger.info("Performance monitoring started", 
                        extra={'component': 'performance_monitor'})
    
    def stop_monitoring(self):
        """Stop the performance monitoring thread."""
        self._monitoring = False
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5)
        
        self.logger.info("Performance monitoring stopped",
                        extra={'component': 'performance_monitor'})
    
    def _monitoring_loop(self):
        """Main monitoring loop that collects metrics periodically."""
        while self._monitoring:
            try:
                # Collect system metrics
                system_metrics = self._collect_system_metrics()
                with self._lock:
                    self._system_metrics.append(system_metrics)
                    self._cleanup_old_metrics(self._system_metrics)
                
                # Log key metrics
                log_metric(__name__, 'cpu_percent', system_metrics.cpu_percent, 
                          'performance_monitor')
                log_metric(__name__, 'memory_percent', system_metrics.memory_percent,
                          'performance_monitor')
                log_metric(__name__, 'disk_usage_percent', system_metrics.disk_usage_percent,
                          'performance_monitor')
                
                # Check for alerts
                self._check_performance_alerts(system_metrics)
                
                # Update component health
                self._update_component_health()
                
                time.sleep(self.collection_interval)
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}",
                                extra={'component': 'performance_monitor'})
                time.sleep(self.collection_interval)
    
    def _collect_system_metrics(self) -> SystemMetrics:
        """Collect current system performance metrics."""
        # CPU and memory
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        
        # Disk usage for root partition
        disk = psutil.disk_usage('/')
        
        # Network I/O
        network_stats = psutil.net_io_counters()
        
        return SystemMetrics(
            timestamp=datetime.now(),
            cpu_percent=cpu_percent,
            memory_percent=memory.percent,
            memory_used_mb=memory.used / (1024 * 1024),
            memory_available_mb=memory.available / (1024 * 1024),
            disk_usage_percent=(disk.used / disk.total) * 100,
            disk_free_gb=disk.free / (1024 * 1024 * 1024),
            network_bytes_sent=network_stats.bytes_sent,
            network_bytes_recv=network_stats.bytes_recv,
            process_count=len(psutil.pids())
        )
    
    def record_packet_metrics(self, 
                            packets_captured: int,
                            packets_processed: int, 
                            packets_dropped: int,
                            processing_rate_pps: float,
                            average_processing_time_ms: float,
                            buffer_utilization_percent: float):
        """
        Record packet processing metrics.
        
        Args:
            packets_captured: Total packets captured
            packets_processed: Total packets processed
            packets_dropped: Total packets dropped
            processing_rate_pps: Current processing rate
            average_processing_time_ms: Average processing time
            buffer_utilization_percent: Buffer utilization percentage
        """
        metrics = PacketMetrics(
            timestamp=datetime.now(),
            packets_captured=packets_captured,
            packets_processed=packets_processed,
            packets_dropped=packets_dropped,
            processing_rate_pps=processing_rate_pps,
            average_processing_time_ms=average_processing_time_ms,
            buffer_utilization_percent=buffer_utilization_percent
        )
        
        with self._lock:
            self._packet_metrics.append(metrics)
            self._cleanup_old_metrics(self._packet_metrics)
        
        # Log key packet metrics
        log_metric(__name__, 'packet_processing_rate', processing_rate_pps,
                  'packet_capture')
        log_metric(__name__, 'packet_drop_rate', 
                  (packets_dropped / max(packets_captured, 1)) * 100,
                  'packet_capture')
        log_metric(__name__, 'buffer_utilization', buffer_utilization_percent,
                  'packet_capture')
        
        # Check for packet processing alerts
        drop_rate = (packets_dropped / max(packets_captured, 1)) * 100
        if drop_rate > self.alert_thresholds.get('packet_drop_rate', 5.0):
            self.logger.warning(f"High packet drop rate: {drop_rate:.2f}%",
                              extra={'component': 'packet_capture'})
    
    def record_asgard_metrics(self,
                            api_calls_total: int,
                            api_calls_successful: int,
                            api_calls_failed: int,
                            average_response_time_ms: float,
                            last_successful_call: Optional[datetime],
                            queue_size: int,
                            connection_status: str):
        """
        Record Asgard communication metrics.
        
        Args:
            api_calls_total: Total API calls made
            api_calls_successful: Successful API calls
            api_calls_failed: Failed API calls
            average_response_time_ms: Average response time
            last_successful_call: Timestamp of last successful call
            queue_size: Current queue size
            connection_status: Connection status
        """
        metrics = AsgardMetrics(
            timestamp=datetime.now(),
            api_calls_total=api_calls_total,
            api_calls_successful=api_calls_successful,
            api_calls_failed=api_calls_failed,
            average_response_time_ms=average_response_time_ms,
            last_successful_call=last_successful_call,
            queue_size=queue_size,
            connection_status=connection_status
        )
        
        with self._lock:
            self._asgard_metrics.append(metrics)
            self._cleanup_old_metrics(self._asgard_metrics)
        
        # Log Asgard metrics
        log_metric(__name__, 'asgard_response_time', average_response_time_ms,
                  'asgard_communicator')
        log_metric(__name__, 'asgard_queue_size', queue_size,
                  'asgard_communicator')
        log_metric(__name__, 'asgard_connection_status', connection_status,
                  'asgard_communicator')
        
        # Check for Asgard communication alerts
        failure_rate = (api_calls_failed / max(api_calls_total, 1)) * 100
        if failure_rate > self.alert_thresholds.get('api_failure_rate', 10.0):
            self.logger.warning(f"High Asgard API failure rate: {failure_rate:.2f}%",
                              extra={'component': 'asgard_communicator'})
    
    def register_health_check(self, component_name: str, 
                            health_check_callback: Callable[[], Dict[str, Any]]):
        """
        Register a health check callback for a component.
        
        Args:
            component_name: Name of the component
            health_check_callback: Function that returns health status dict
        """
        self._health_check_callbacks[component_name] = health_check_callback
        self.logger.info(f"Registered health check for component: {component_name}",
                        extra={'component': 'performance_monitor'})
    
    def _update_component_health(self):
        """Update health status for all registered components."""
        for component_name, callback in self._health_check_callbacks.items():
            try:
                health_data = callback()
                
                health = ComponentHealth(
                    component_name=component_name,
                    status=health_data.get('status', 'unknown'),
                    last_activity=health_data.get('last_activity', datetime.now()),
                    error_count=health_data.get('error_count', 0),
                    warning_count=health_data.get('warning_count', 0),
                    uptime_seconds=(datetime.now() - self._start_time).total_seconds(),
                    details=health_data.get('details', {})
                )
                
                with self._lock:
                    self._component_health[component_name] = health
                
            except Exception as e:
                self.logger.error(f"Error updating health for {component_name}: {e}",
                                extra={'component': 'performance_monitor'})
    
    def _check_performance_alerts(self, metrics: SystemMetrics):
        """Check system metrics against alert thresholds."""
        if metrics.cpu_percent > self.alert_thresholds.get('cpu_percent', 80.0):
            self.logger.warning(f"High CPU usage: {metrics.cpu_percent:.1f}%",
                              extra={'component': 'performance_monitor'})
        
        if metrics.memory_percent > self.alert_thresholds.get('memory_percent', 85.0):
            self.logger.warning(f"High memory usage: {metrics.memory_percent:.1f}%",
                              extra={'component': 'performance_monitor'})
        
        if metrics.disk_usage_percent > self.alert_thresholds.get('disk_usage_percent', 90.0):
            self.logger.warning(f"High disk usage: {metrics.disk_usage_percent:.1f}%",
                              extra={'component': 'performance_monitor'})
    
    def _cleanup_old_metrics(self, metrics_deque: deque):
        """Remove metrics older than retention period."""
        cutoff_time = datetime.now() - self.history_retention
        while metrics_deque and metrics_deque[0].timestamp < cutoff_time:
            metrics_deque.popleft()
    
    def get_system_health_summary(self) -> Dict[str, Any]:
        """
        Get comprehensive system health summary.
        
        Returns:
            Dictionary with system health information
        """
        with self._lock:
            # Get latest metrics
            latest_system = self._system_metrics[-1] if self._system_metrics else None
            latest_packet = self._packet_metrics[-1] if self._packet_metrics else None
            latest_asgard = self._asgard_metrics[-1] if self._asgard_metrics else None
            
            summary = {
                'timestamp': datetime.now().isoformat(),
                'uptime_seconds': (datetime.now() - self._start_time).total_seconds(),
                'overall_status': self._calculate_overall_status(),
                'system_metrics': asdict(latest_system) if latest_system else None,
                'packet_metrics': asdict(latest_packet) if latest_packet else None,
                'asgard_metrics': asdict(latest_asgard) if latest_asgard else None,
                'component_health': {
                    name: asdict(health) for name, health in self._component_health.items()
                },
                'alert_thresholds': self.alert_thresholds,
                'metrics_history_count': {
                    'system': len(self._system_metrics),
                    'packet': len(self._packet_metrics),
                    'asgard': len(self._asgard_metrics)
                }
            }
        
        return summary
    
    def _calculate_overall_status(self) -> str:
        """Calculate overall system status based on all metrics."""
        # Check system metrics
        if self._system_metrics:
            latest = self._system_metrics[-1]
            if (latest.cpu_percent > self.alert_thresholds.get('cpu_percent', 80.0) or
                latest.memory_percent > self.alert_thresholds.get('memory_percent', 85.0) or
                latest.disk_usage_percent > self.alert_thresholds.get('disk_usage_percent', 90.0)):
                return 'warning'
        
        # Check component health
        for health in self._component_health.values():
            if health.status == 'error':
                return 'error'
            elif health.status == 'warning':
                return 'warning'
        
        # Check packet metrics
        if self._packet_metrics:
            latest = self._packet_metrics[-1]
            drop_rate = (latest.packets_dropped / max(latest.packets_captured, 1)) * 100
            if drop_rate > self.alert_thresholds.get('packet_drop_rate', 5.0):
                return 'warning'
        
        # Check Asgard metrics
        if self._asgard_metrics:
            latest = self._asgard_metrics[-1]
            if latest.connection_status == 'error':
                return 'warning'
            failure_rate = (latest.api_calls_failed / max(latest.api_calls_total, 1)) * 100
            if failure_rate > self.alert_thresholds.get('api_failure_rate', 10.0):
                return 'warning'
        
        return 'healthy'
    
    def get_metrics_history(self, 
                          metric_type: str = 'system',
                          hours: int = 1) -> List[Dict[str, Any]]:
        """
        Get historical metrics for analysis.
        
        Args:
            metric_type: Type of metrics ('system', 'packet', 'asgard')
            hours: Number of hours of history to return
            
        Returns:
            List of metric dictionaries
        """
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        with self._lock:
            if metric_type == 'system':
                metrics = [asdict(m) for m in self._system_metrics 
                          if m.timestamp >= cutoff_time]
            elif metric_type == 'packet':
                metrics = [asdict(m) for m in self._packet_metrics 
                          if m.timestamp >= cutoff_time]
            elif metric_type == 'asgard':
                metrics = [asdict(m) for m in self._asgard_metrics 
                          if m.timestamp >= cutoff_time]
            else:
                return []
        
        return metrics


# Global performance monitor instance
_performance_monitor: Optional[PerformanceMonitor] = None


def initialize_performance_monitoring(collection_interval: int = 30,
                                    history_retention_hours: int = 24,
                                    alert_thresholds: Optional[Dict[str, float]] = None) -> PerformanceMonitor:
    """
    Initialize the global performance monitor.
    
    Args:
        collection_interval: Seconds between metric collections
        history_retention_hours: Hours to retain metric history
        alert_thresholds: Performance alert thresholds
        
    Returns:
        Initialized performance monitor
    """
    global _performance_monitor
    
    if _performance_monitor is not None:
        _performance_monitor.stop_monitoring()
    
    _performance_monitor = PerformanceMonitor(
        collection_interval=collection_interval,
        history_retention_hours=history_retention_hours,
        alert_thresholds=alert_thresholds
    )
    
    _performance_monitor.start_monitoring()
    return _performance_monitor


def get_performance_monitor() -> Optional[PerformanceMonitor]:
    """Get the global performance monitor instance."""
    return _performance_monitor


def get_system_health() -> Dict[str, Any]:
    """Get system health summary from global monitor."""
    if _performance_monitor is None:
        return {'error': 'Performance monitor not initialized'}
    
    return _performance_monitor.get_system_health_summary()


def shutdown_performance_monitoring():
    """Shutdown the global performance monitor."""
    global _performance_monitor
    if _performance_monitor is not None:
        _performance_monitor.stop_monitoring()
        _performance_monitor = None