"""
Logging and diagnostics components for Heimdal.

This module provides comprehensive logging with structured output, log rotation,
disk space management, and different log levels as required by the real-time
monitoring specification.
"""

from .manager import (
    LoggingManager,
    StructuredFormatter,
    initialize_logging,
    get_logger,
    log_metric,
    log_component_activity,
    get_logging_statistics,
    shutdown_logging
)

from .performance_monitor import (
    PerformanceMonitor,
    SystemMetrics,
    PacketMetrics,
    AsgardMetrics,
    ComponentHealth,
    initialize_performance_monitoring,
    get_performance_monitor,
    get_system_health,
    shutdown_performance_monitoring
)

from .diagnostics import (
    DiagnosticsServer,
    DiagnosticTest,
    initialize_diagnostics_server,
    get_diagnostics_server,
    shutdown_diagnostics_server
)

__all__ = [
    # Logging manager
    'LoggingManager',
    'StructuredFormatter', 
    'initialize_logging',
    'get_logger',
    'log_metric',
    'log_component_activity',
    'get_logging_statistics',
    'shutdown_logging',
    
    # Performance monitoring
    'PerformanceMonitor',
    'SystemMetrics',
    'PacketMetrics', 
    'AsgardMetrics',
    'ComponentHealth',
    'initialize_performance_monitoring',
    'get_performance_monitor',
    'get_system_health',
    'shutdown_performance_monitoring',
    
    # Diagnostics
    'DiagnosticsServer',
    'DiagnosticTest',
    'initialize_diagnostics_server',
    'get_diagnostics_server',
    'shutdown_diagnostics_server'
]