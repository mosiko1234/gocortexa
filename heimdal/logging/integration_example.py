"""
Integration example showing how to use the comprehensive logging and diagnostics system.

This example demonstrates how components should integrate with the logging system
and how to set up performance monitoring and diagnostics.
"""

import time
from datetime import datetime
from typing import Dict, Any

from . import (
    initialize_logging,
    initialize_performance_monitoring,
    initialize_diagnostics_server,
    get_logger,
    log_metric,
    log_component_activity,
    get_performance_monitor,
    get_system_health,
    shutdown_logging,
    shutdown_performance_monitoring,
    shutdown_diagnostics_server
)


class ExampleComponent:
    """Example component showing proper logging integration."""
    
    def __init__(self, component_name: str):
        self.component_name = component_name
        self.logger = get_logger(__name__, component_name)
        self.start_time = datetime.now()
        self.error_count = 0
        self.warning_count = 0
        
        # Register health check with performance monitor
        monitor = get_performance_monitor()
        if monitor:
            monitor.register_health_check(component_name, self._health_check)
        
        self.logger.info(f"Component {component_name} initialized",
                        extra={'component': component_name})
    
    def do_work(self):
        """Simulate component work with logging."""
        log_component_activity(__name__, self.component_name, 
                             "Starting work cycle")
        
        try:
            # Simulate some work
            time.sleep(0.1)
            
            # Log some metrics
            log_metric(__name__, 'work_cycles_completed', 1, 
                      self.component_name)
            log_metric(__name__, 'processing_time_ms', 100,
                      self.component_name)
            
            self.logger.info("Work cycle completed successfully",
                           extra={'component': self.component_name})
            
        except Exception as e:
            self.error_count += 1
            self.logger.error(f"Error during work cycle: {e}",
                            extra={'component': self.component_name})
    
    def _health_check(self) -> Dict[str, Any]:
        """Health check callback for performance monitor."""
        uptime = (datetime.now() - self.start_time).total_seconds()
        
        # Determine status based on error rate
        if self.error_count == 0:
            status = 'healthy'
        elif self.error_count < 5:
            status = 'warning'
        else:
            status = 'error'
        
        return {
            'status': status,
            'last_activity': datetime.now(),
            'error_count': self.error_count,
            'warning_count': self.warning_count,
            'details': {
                'uptime_seconds': uptime,
                'component_name': self.component_name
            }
        }


def run_integration_example():
    """Run the integration example."""
    print("Starting Heimdal logging and diagnostics integration example...")
    
    # Initialize logging system
    logging_manager = initialize_logging(
        log_dir="./example_logs",
        log_level="INFO",
        max_file_size=1024*1024,  # 1MB
        backup_count=3,
        max_disk_usage_mb=10
    )
    
    # Initialize performance monitoring
    performance_monitor = initialize_performance_monitoring(
        collection_interval=10,  # 10 seconds for demo
        history_retention_hours=1,
        alert_thresholds={
            'cpu_percent': 70.0,
            'memory_percent': 80.0,
            'disk_usage_percent': 85.0
        }
    )
    
    # Initialize diagnostics server
    diagnostics_server = initialize_diagnostics_server(
        port=8080,
        bind_address='127.0.0.1'
    )
    
    # Create example components
    components = [
        ExampleComponent("packet_capture"),
        ExampleComponent("anomaly_detector"),
        ExampleComponent("asgard_communicator")
    ]
    
    print("System initialized. Components running...")
    print("Diagnostics available at: http://127.0.0.1:8080/health")
    print("Available endpoints:")
    print("  - /health - Basic health check")
    print("  - /status - Detailed status")
    print("  - /metrics - Performance metrics")
    print("  - /diagnostics - Run diagnostic tests")
    
    try:
        # Run components for a while
        for i in range(30):  # Run for 30 iterations
            for component in components:
                component.do_work()
            
            # Record some packet metrics
            performance_monitor.record_packet_metrics(
                packets_captured=1000 + i * 10,
                packets_processed=990 + i * 10,
                packets_dropped=i,
                processing_rate_pps=100.0,
                average_processing_time_ms=5.0,
                buffer_utilization_percent=25.0
            )
            
            # Record Asgard metrics
            performance_monitor.record_asgard_metrics(
                api_calls_total=50 + i,
                api_calls_successful=48 + i,
                api_calls_failed=2,
                average_response_time_ms=150.0,
                last_successful_call=datetime.now(),
                queue_size=5,
                connection_status='connected'
            )
            
            time.sleep(2)  # Wait 2 seconds between cycles
            
            if i % 10 == 0:
                # Print health summary every 10 cycles
                health = get_system_health()
                print(f"\nCycle {i}: Overall status = {health.get('overall_status', 'unknown')}")
                print(f"  CPU: {health.get('system_metrics', {}).get('cpu_percent', 0):.1f}%")
                print(f"  Memory: {health.get('system_metrics', {}).get('memory_percent', 0):.1f}%")
                print(f"  Components: {len(health.get('component_health', {}))}")
    
    except KeyboardInterrupt:
        print("\nShutting down...")
    
    finally:
        # Cleanup
        shutdown_diagnostics_server()
        shutdown_performance_monitoring()
        shutdown_logging()
        print("Example completed.")


if __name__ == "__main__":
    run_integration_example()