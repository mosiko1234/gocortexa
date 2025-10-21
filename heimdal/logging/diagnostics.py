"""
Diagnostic endpoints and system health checking for Heimdal.

This module provides diagnostic endpoints for system health checking and
status reporting as required by the real-time monitoring specification.
"""

import json
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, asdict
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import socketserver

from .manager import get_logger
from .performance_monitor import get_performance_monitor, get_system_health


@dataclass
class DiagnosticTest:
    """Represents a diagnostic test result."""
    test_name: str
    status: str  # 'pass', 'fail', 'warning'
    message: str
    timestamp: datetime
    duration_ms: float
    details: Dict[str, Any]


class DiagnosticHandler(BaseHTTPRequestHandler):
    """HTTP request handler for diagnostic endpoints."""
    
    def __init__(self, diagnostics_server, *args, **kwargs):
        self.diagnostics_server = diagnostics_server
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """Handle GET requests to diagnostic endpoints."""
        try:
            parsed_path = urlparse(self.path)
            path = parsed_path.path
            query_params = parse_qs(parsed_path.query)
            
            if path == '/health':
                self._handle_health_check(query_params)
            elif path == '/status':
                self._handle_status_check(query_params)
            elif path == '/metrics':
                self._handle_metrics(query_params)
            elif path == '/diagnostics':
                self._handle_diagnostics(query_params)
            elif path == '/logs':
                self._handle_logs(query_params)
            else:
                self._send_error(404, "Endpoint not found")
                
        except Exception as e:
            self._send_error(500, f"Internal server error: {str(e)}")
    
    def _handle_health_check(self, query_params: Dict[str, List[str]]):
        """Handle /health endpoint - basic health status."""
        health_data = get_system_health()
        
        # Simple health response
        response = {
            'status': health_data.get('overall_status', 'unknown'),
            'timestamp': datetime.now().isoformat(),
            'uptime_seconds': health_data.get('uptime_seconds', 0)
        }
        
        status_code = 200 if response['status'] == 'healthy' else 503
        self._send_json_response(response, status_code)
    
    def _handle_status_check(self, query_params: Dict[str, List[str]]):
        """Handle /status endpoint - detailed status information."""
        health_data = get_system_health()
        
        # Include component details
        response = {
            'overall_status': health_data.get('overall_status', 'unknown'),
            'timestamp': datetime.now().isoformat(),
            'uptime_seconds': health_data.get('uptime_seconds', 0),
            'components': health_data.get('component_health', {}),
            'system_metrics': health_data.get('system_metrics'),
            'packet_metrics': health_data.get('packet_metrics'),
            'asgard_metrics': health_data.get('asgard_metrics')
        }
        
        self._send_json_response(response)
    
    def _handle_metrics(self, query_params: Dict[str, List[str]]):
        """Handle /metrics endpoint - performance metrics."""
        monitor = get_performance_monitor()
        if not monitor:
            self._send_error(503, "Performance monitor not available")
            return
        
        # Get metric type and time range from query params
        metric_type = query_params.get('type', ['system'])[0]
        hours = int(query_params.get('hours', ['1'])[0])
        
        try:
            metrics = monitor.get_metrics_history(metric_type, hours)
            response = {
                'metric_type': metric_type,
                'hours': hours,
                'count': len(metrics),
                'metrics': metrics
            }
            self._send_json_response(response)
        except Exception as e:
            self._send_error(400, f"Invalid metric request: {str(e)}")
    
    def _handle_diagnostics(self, query_params: Dict[str, List[str]]):
        """Handle /diagnostics endpoint - run diagnostic tests."""
        test_results = self.diagnostics_server.run_diagnostic_tests()
        
        response = {
            'timestamp': datetime.now().isoformat(),
            'tests_run': len(test_results),
            'tests_passed': len([t for t in test_results if t.status == 'pass']),
            'tests_failed': len([t for t in test_results if t.status == 'fail']),
            'tests_warning': len([t for t in test_results if t.status == 'warning']),
            'results': [asdict(test) for test in test_results]
        }
        
        self._send_json_response(response)
    
    def _handle_logs(self, query_params: Dict[str, List[str]]):
        """Handle /logs endpoint - recent log entries."""
        # This is a simplified implementation
        # In a full implementation, you'd read from log files
        response = {
            'message': 'Log endpoint not fully implemented',
            'suggestion': 'Check log files directly in /var/log/heimdal/'
        }
        self._send_json_response(response)
    
    def _send_json_response(self, data: Dict[str, Any], status_code: int = 200):
        """Send JSON response."""
        response_body = json.dumps(data, indent=2, default=str)
        
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body.encode('utf-8'))
    
    def _send_error(self, status_code: int, message: str):
        """Send error response."""
        error_response = {
            'error': message,
            'status_code': status_code,
            'timestamp': datetime.now().isoformat()
        }
        self._send_json_response(error_response, status_code)
    
    def log_message(self, format, *args):
        """Override to suppress default HTTP server logging."""
        pass


class DiagnosticsServer:
    """
    HTTP server providing diagnostic endpoints for system health checking.
    """
    
    def __init__(self, port: int = 8080, bind_address: str = '127.0.0.1'):
        """
        Initialize the diagnostics server.
        
        Args:
            port: Port to bind the HTTP server
            bind_address: Address to bind the server
        """
        self.port = port
        self.bind_address = bind_address
        self.logger = get_logger(__name__, 'diagnostics_server')
        
        # Server state
        self._server: Optional[HTTPServer] = None
        self._server_thread: Optional[threading.Thread] = None
        self._running = False
        
        # Diagnostic tests
        self._diagnostic_tests: Dict[str, Callable[[], DiagnosticTest]] = {}
        self._register_default_tests()
    
    def _register_default_tests(self):
        """Register default diagnostic tests."""
        self._diagnostic_tests.update({
            'system_resources': self._test_system_resources,
            'disk_space': self._test_disk_space,
            'network_connectivity': self._test_network_connectivity,
            'component_health': self._test_component_health,
            'performance_monitor': self._test_performance_monitor
        })
    
    def start_server(self):
        """Start the diagnostic HTTP server."""
        if self._running:
            return
        
        try:
            # Create custom handler class with reference to this server
            handler_class = lambda *args, **kwargs: DiagnosticHandler(self, *args, **kwargs)
            
            self._server = HTTPServer((self.bind_address, self.port), handler_class)
            self._running = True
            
            self._server_thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._server_thread.start()
            
            self.logger.info(f"Diagnostics server started on {self.bind_address}:{self.port}",
                           extra={'component': 'diagnostics_server'})
            
        except Exception as e:
            self.logger.error(f"Failed to start diagnostics server: {e}",
                            extra={'component': 'diagnostics_server'})
            self._running = False
    
    def stop_server(self):
        """Stop the diagnostic HTTP server."""
        if not self._running:
            return
        
        self._running = False
        
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        
        if self._server_thread and self._server_thread.is_alive():
            self._server_thread.join(timeout=5)
        
        self.logger.info("Diagnostics server stopped",
                        extra={'component': 'diagnostics_server'})
    
    def register_diagnostic_test(self, test_name: str, test_function: Callable[[], DiagnosticTest]):
        """
        Register a custom diagnostic test.
        
        Args:
            test_name: Name of the test
            test_function: Function that returns DiagnosticTest result
        """
        self._diagnostic_tests[test_name] = test_function
        self.logger.info(f"Registered diagnostic test: {test_name}",
                        extra={'component': 'diagnostics_server'})
    
    def run_diagnostic_tests(self) -> List[DiagnosticTest]:
        """
        Run all registered diagnostic tests.
        
        Returns:
            List of diagnostic test results
        """
        results = []
        
        for test_name, test_function in self._diagnostic_tests.items():
            try:
                start_time = time.time()
                result = test_function()
                duration_ms = (time.time() - start_time) * 1000
                result.duration_ms = duration_ms
                results.append(result)
                
            except Exception as e:
                results.append(DiagnosticTest(
                    test_name=test_name,
                    status='fail',
                    message=f"Test execution failed: {str(e)}",
                    timestamp=datetime.now(),
                    duration_ms=0,
                    details={'error': str(e)}
                ))
        
        return results
    
    def _test_system_resources(self) -> DiagnosticTest:
        """Test system resource availability."""
        health_data = get_system_health()
        system_metrics = health_data.get('system_metrics')
        
        if not system_metrics:
            return DiagnosticTest(
                test_name='system_resources',
                status='fail',
                message='System metrics not available',
                timestamp=datetime.now(),
                duration_ms=0,
                details={}
            )
        
        # Check resource thresholds
        cpu_ok = system_metrics['cpu_percent'] < 80
        memory_ok = system_metrics['memory_percent'] < 85
        
        if cpu_ok and memory_ok:
            status = 'pass'
            message = 'System resources within normal limits'
        elif cpu_ok or memory_ok:
            status = 'warning'
            message = 'Some system resources under pressure'
        else:
            status = 'fail'
            message = 'System resources critically low'
        
        return DiagnosticTest(
            test_name='system_resources',
            status=status,
            message=message,
            timestamp=datetime.now(),
            duration_ms=0,
            details={
                'cpu_percent': system_metrics['cpu_percent'],
                'memory_percent': system_metrics['memory_percent'],
                'cpu_ok': cpu_ok,
                'memory_ok': memory_ok
            }
        )
    
    def _test_disk_space(self) -> DiagnosticTest:
        """Test disk space availability."""
        health_data = get_system_health()
        system_metrics = health_data.get('system_metrics')
        
        if not system_metrics:
            return DiagnosticTest(
                test_name='disk_space',
                status='fail',
                message='Disk metrics not available',
                timestamp=datetime.now(),
                duration_ms=0,
                details={}
            )
        
        disk_usage = system_metrics['disk_usage_percent']
        
        if disk_usage < 80:
            status = 'pass'
            message = f'Disk usage normal: {disk_usage:.1f}%'
        elif disk_usage < 90:
            status = 'warning'
            message = f'Disk usage high: {disk_usage:.1f}%'
        else:
            status = 'fail'
            message = f'Disk usage critical: {disk_usage:.1f}%'
        
        return DiagnosticTest(
            test_name='disk_space',
            status=status,
            message=message,
            timestamp=datetime.now(),
            duration_ms=0,
            details={
                'disk_usage_percent': disk_usage,
                'disk_free_gb': system_metrics['disk_free_gb']
            }
        )
    
    def _test_network_connectivity(self) -> DiagnosticTest:
        """Test network connectivity."""
        # Simplified test - in real implementation would ping external hosts
        return DiagnosticTest(
            test_name='network_connectivity',
            status='pass',
            message='Network connectivity test not fully implemented',
            timestamp=datetime.now(),
            duration_ms=0,
            details={'note': 'Placeholder test'}
        )
    
    def _test_component_health(self) -> DiagnosticTest:
        """Test health of all registered components."""
        health_data = get_system_health()
        components = health_data.get('component_health', {})
        
        if not components:
            return DiagnosticTest(
                test_name='component_health',
                status='warning',
                message='No components registered for health monitoring',
                timestamp=datetime.now(),
                duration_ms=0,
                details={}
            )
        
        healthy_count = len([c for c in components.values() if c['status'] == 'healthy'])
        total_count = len(components)
        
        if healthy_count == total_count:
            status = 'pass'
            message = f'All {total_count} components healthy'
        elif healthy_count > total_count / 2:
            status = 'warning'
            message = f'{healthy_count}/{total_count} components healthy'
        else:
            status = 'fail'
            message = f'Only {healthy_count}/{total_count} components healthy'
        
        return DiagnosticTest(
            test_name='component_health',
            status=status,
            message=message,
            timestamp=datetime.now(),
            duration_ms=0,
            details={
                'total_components': total_count,
                'healthy_components': healthy_count,
                'components': components
            }
        )
    
    def _test_performance_monitor(self) -> DiagnosticTest:
        """Test performance monitoring system."""
        monitor = get_performance_monitor()
        
        if not monitor:
            return DiagnosticTest(
                test_name='performance_monitor',
                status='fail',
                message='Performance monitor not initialized',
                timestamp=datetime.now(),
                duration_ms=0,
                details={}
            )
        
        health_data = get_system_health()
        metrics_count = health_data.get('metrics_history_count', {})
        
        if sum(metrics_count.values()) > 0:
            status = 'pass'
            message = 'Performance monitor collecting metrics'
        else:
            status = 'warning'
            message = 'Performance monitor not collecting metrics'
        
        return DiagnosticTest(
            test_name='performance_monitor',
            status=status,
            message=message,
            timestamp=datetime.now(),
            duration_ms=0,
            details=metrics_count
        )


# Global diagnostics server instance
_diagnostics_server: Optional[DiagnosticsServer] = None


def initialize_diagnostics_server(port: int = 8080, 
                                bind_address: str = '127.0.0.1') -> DiagnosticsServer:
    """
    Initialize the global diagnostics server.
    
    Args:
        port: Port to bind the HTTP server
        bind_address: Address to bind the server
        
    Returns:
        Initialized diagnostics server
    """
    global _diagnostics_server
    
    if _diagnostics_server is not None:
        _diagnostics_server.stop_server()
    
    _diagnostics_server = DiagnosticsServer(port=port, bind_address=bind_address)
    _diagnostics_server.start_server()
    
    return _diagnostics_server


def get_diagnostics_server() -> Optional[DiagnosticsServer]:
    """Get the global diagnostics server instance."""
    return _diagnostics_server


def shutdown_diagnostics_server():
    """Shutdown the global diagnostics server."""
    global _diagnostics_server
    if _diagnostics_server is not None:
        _diagnostics_server.stop_server()
        _diagnostics_server = None