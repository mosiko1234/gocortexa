"""
Packet capture engine implementation using scapy AsyncSniffer
"""

import threading
import time
import psutil
import netifaces
from collections import deque
from datetime import datetime
from typing import Iterator, Optional, Deque, List
import logging

from scapy.all import AsyncSniffer, Packet, get_if_list
from scapy.error import Scapy_Exception

from ..interfaces import IPacketCaptureEngine
from ..models import CaptureStats


class PacketCaptureEngine(IPacketCaptureEngine):
    """
    Real-time packet capture engine using scapy AsyncSniffer.
    
    Provides non-blocking packet capture with buffering to handle burst traffic
    and a streaming interface for real-time packet processing.
    """
    
    def __init__(self, max_buffer_size: int = 10000, logger: Optional[logging.Logger] = None):
        """
        Initialize the packet capture engine.
        
        Args:
            max_buffer_size: Maximum number of packets to buffer
            logger: Logger instance for capture events
        """
        self.max_buffer_size = max_buffer_size
        self.logger = logger or logging.getLogger(__name__)
        
        # Capture state
        self._sniffer: Optional[AsyncSniffer] = None
        self._is_capturing = False
        self._capture_thread: Optional[threading.Thread] = None
        self._current_interface: Optional[str] = None
        self._current_filter: Optional[str] = None
        
        # Packet buffer - thread-safe deque for packet storage
        self._packet_buffer: Deque[Packet] = deque(maxlen=max_buffer_size)
        self._buffer_lock = threading.Lock()
        
        # Statistics tracking
        self._stats_lock = threading.Lock()
        self._packets_captured = 0
        self._packets_dropped = 0
        self._bytes_captured = 0
        self._capture_start_time: Optional[datetime] = None
        self._errors = 0
        
        # Performance tracking
        self._last_stats_time = time.time()
        self._last_packet_count = 0
        self._performance_log_interval = 30.0  # Log performance every 30 seconds
        self._last_performance_log = time.time()
        
        # Error handling and recovery
        self._recovery_enabled = True
        self._max_consecutive_errors = 5
        self._consecutive_errors = 0
        self._last_error_time: Optional[datetime] = None
        self._recovery_delay = 5.0  # seconds
        self._interface_fallback_list: List[str] = []
        self._fallback_index = 0
        self._network_check_interval = 30.0  # seconds
        self._last_network_check = 0.0
    
    def _discover_available_interfaces(self) -> List[str]:
        """
        Discover available network interfaces for packet capture.
        
        Returns:
            List of available interface names
        """
        available_interfaces = []
        
        try:
            # Get interfaces from scapy
            scapy_interfaces = get_if_list()
            
            # Get interfaces from netifaces for additional validation
            netifaces_interfaces = netifaces.interfaces()
            
            # Combine and validate interfaces
            all_interfaces = set(scapy_interfaces + netifaces_interfaces)
            
            for iface in all_interfaces:
                try:
                    # Check if interface is up and has an IP address
                    if iface in netifaces_interfaces:
                        addrs = netifaces.ifaddresses(iface)
                        # Check for IPv4 or IPv6 addresses
                        if netifaces.AF_INET in addrs or netifaces.AF_INET6 in addrs:
                            # Additional check using psutil if available
                            try:
                                stats = psutil.net_if_stats()
                                if iface in stats and stats[iface].isup:
                                    available_interfaces.append(iface)
                            except (AttributeError, KeyError):
                                # Fallback if psutil doesn't have interface info
                                available_interfaces.append(iface)
                except Exception as e:
                    self.logger.debug(f"Error checking interface {iface}: {e}")
                    continue
            
            # Filter out loopback and other non-useful interfaces
            filtered_interfaces = []
            for iface in available_interfaces:
                if not iface.startswith(('lo', 'dummy', 'virbr')):
                    filtered_interfaces.append(iface)
            
            self.logger.debug(f"Discovered {len(filtered_interfaces)} available interfaces: {filtered_interfaces}")
            return filtered_interfaces
            
        except Exception as e:
            self.logger.error(f"Error discovering network interfaces: {e}")
            return []
    
    def _validate_interface(self, interface: str) -> bool:
        """
        Validate that an interface exists and is suitable for packet capture.
        
        Args:
            interface: Interface name to validate
            
        Returns:
            True if interface is valid, False otherwise
        """
        try:
            # Check if interface exists in system
            if interface not in netifaces.interfaces():
                self.logger.warning(f"Interface {interface} not found in system")
                return False
            
            # Check if interface is up
            try:
                stats = psutil.net_if_stats()
                if interface in stats and not stats[interface].isup:
                    self.logger.warning(f"Interface {interface} is down")
                    return False
            except (AttributeError, KeyError):
                self.logger.debug(f"Could not check interface status for {interface}")
            
            # Check if interface has addresses
            addrs = netifaces.ifaddresses(interface)
            if not (netifaces.AF_INET in addrs or netifaces.AF_INET6 in addrs):
                self.logger.warning(f"Interface {interface} has no IP addresses")
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error validating interface {interface}: {e}")
            return False
    
    def _setup_interface_fallbacks(self, primary_interface: str) -> None:
        """
        Set up fallback interfaces in case primary interface fails.
        
        Args:
            primary_interface: Primary interface to use
        """
        available_interfaces = self._discover_available_interfaces()
        
        # Create fallback list with primary interface first
        self._interface_fallback_list = [primary_interface]
        
        # Add other interfaces as fallbacks
        for iface in available_interfaces:
            if iface != primary_interface and self._validate_interface(iface):
                self._interface_fallback_list.append(iface)
        
        self._fallback_index = 0
        self.logger.info(f"Interface fallback list: {self._interface_fallback_list}")
    
    def _get_next_fallback_interface(self) -> Optional[str]:
        """
        Get the next fallback interface to try.
        
        Returns:
            Next interface name or None if no more fallbacks
        """
        if not self._interface_fallback_list:
            return None
        
        self._fallback_index = (self._fallback_index + 1) % len(self._interface_fallback_list)
        
        # If we've cycled through all interfaces, return None
        if self._fallback_index == 0:
            return None
        
        return self._interface_fallback_list[self._fallback_index]
    
    def _check_network_connectivity(self) -> bool:
        """
        Check if network connectivity is available.
        
        Returns:
            True if network appears to be working, False otherwise
        """
        try:
            current_time = time.time()
            
            # Only check periodically to avoid overhead
            if current_time - self._last_network_check < self._network_check_interval:
                return True  # Assume OK if we checked recently
            
            self._last_network_check = current_time
            
            # Check if any interface has network activity
            try:
                stats_before = psutil.net_io_counters(pernic=True)
                time.sleep(0.1)  # Brief pause
                stats_after = psutil.net_io_counters(pernic=True)
                
                # Look for any network activity
                for iface in stats_before:
                    if iface in stats_after:
                        before = stats_before[iface]
                        after = stats_after[iface]
                        if (after.bytes_sent > before.bytes_sent or 
                            after.bytes_recv > before.bytes_recv):
                            return True
                            
            except Exception as e:
                self.logger.debug(f"Error checking network activity: {e}")
            
            # Fallback: check if any interface is up
            try:
                stats = psutil.net_if_stats()
                for iface, stat in stats.items():
                    if stat.isup and not iface.startswith(('lo', 'dummy')):
                        return True
            except Exception as e:
                self.logger.debug(f"Error checking interface status: {e}")
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error in network connectivity check: {e}")
            return False
    
    def start_capture(self, interface: str, filter_expression: Optional[str] = None) -> bool:
        """
        Start capturing packets from the specified network interface with error handling and fallbacks.
        
        Args:
            interface: Network interface name (e.g., 'eth0', 'wlan0')
            filter_expression: Optional BPF filter expression
            
        Returns:
            True if capture started successfully, False otherwise
        """
        if self._is_capturing:
            self.logger.warning("Packet capture is already running")
            return False
        
        # Store current configuration for recovery
        self._current_interface = interface
        self._current_filter = filter_expression
        
        # Set up interface fallbacks
        self._setup_interface_fallbacks(interface)
        
        # Reset error counters
        self._consecutive_errors = 0
        
        return self._attempt_capture_start(interface, filter_expression)
    
    def _attempt_capture_start(self, interface: str, filter_expression: Optional[str] = None) -> bool:
        """
        Attempt to start packet capture with comprehensive error handling.
        
        Args:
            interface: Network interface name
            filter_expression: Optional BPF filter expression
            
        Returns:
            True if capture started successfully, False otherwise
        """
        try:
            # Validate interface before attempting capture
            if not self._validate_interface(interface):
                self.logger.error(f"Interface {interface} is not valid for packet capture")
                return self._try_fallback_interface(filter_expression)
            
            # Check network connectivity
            if not self._check_network_connectivity():
                self.logger.warning("Network connectivity issues detected")
            
            # Create AsyncSniffer instance
            self._sniffer = AsyncSniffer(
                iface=interface,
                filter=filter_expression,
                prn=self._packet_handler,
                store=False,  # Don't store packets in sniffer
                stop_filter=lambda x: not self._is_capturing
            )
            
            # Start capture
            self._is_capturing = True
            self._capture_start_time = datetime.now()
            self._reset_statistics()
            
            # Start the sniffer in a separate thread
            self._capture_thread = threading.Thread(
                target=self._run_capture_with_recovery,
                name="PacketCapture",
                daemon=True
            )
            self._capture_thread.start()
            
            self.logger.info(
                f"Started packet capture on interface {interface}"
                f"{f' with filter: {filter_expression}' if filter_expression else ''}"
            )
            
            # Reset error counters on successful start
            self._consecutive_errors = 0
            return True
            
        except PermissionError as e:
            self.logger.error(f"Permission denied for packet capture on {interface}. "
                            f"Please run with appropriate privileges (sudo): {e}")
            return False
            
        except Scapy_Exception as e:
            self.logger.error(f"Scapy error starting capture on {interface}: {e}")
            return self._try_fallback_interface(filter_expression)
            
        except OSError as e:
            if "No such device" in str(e) or "Device not found" in str(e):
                self.logger.error(f"Network interface {interface} not found: {e}")
                return self._try_fallback_interface(filter_expression)
            else:
                self.logger.error(f"OS error starting capture on {interface}: {e}")
                return self._try_fallback_interface(filter_expression)
                
        except Exception as e:
            self.logger.error(f"Unexpected error starting capture on {interface}: {e}")
            self._consecutive_errors += 1
            
            if self._consecutive_errors < self._max_consecutive_errors:
                return self._try_fallback_interface(filter_expression)
            else:
                self.logger.error(f"Too many consecutive errors ({self._consecutive_errors}), giving up")
                self._is_capturing = False
                return False
    
    def _try_fallback_interface(self, filter_expression: Optional[str] = None) -> bool:
        """
        Try to start capture on a fallback interface.
        
        Args:
            filter_expression: Optional BPF filter expression
            
        Returns:
            True if fallback succeeded, False otherwise
        """
        fallback_interface = self._get_next_fallback_interface()
        
        if fallback_interface is None:
            self.logger.error("No more fallback interfaces available")
            return False
        
        self.logger.info(f"Trying fallback interface: {fallback_interface}")
        return self._attempt_capture_start(fallback_interface, filter_expression)
    
    def stop_capture(self) -> bool:
        """
        Stop packet capture gracefully.
        
        Returns:
            True if capture stopped successfully, False otherwise
        """
        if not self._is_capturing:
            self.logger.warning("Packet capture is not running")
            return False
        
        try:
            self.logger.info("Initiating graceful shutdown of packet capture...")
            
            # Set flag to stop capture
            self._is_capturing = False
            
            # Stop the sniffer
            if self._sniffer:
                try:
                    self._sniffer.stop()
                    self.logger.debug("AsyncSniffer stopped successfully")
                except Exception as e:
                    self.logger.warning(f"Error stopping AsyncSniffer: {e}")
            
            # Wait for capture thread to finish gracefully
            if self._capture_thread and self._capture_thread.is_alive():
                self.logger.debug("Waiting for capture thread to finish...")
                self._capture_thread.join(timeout=5.0)
                
                if self._capture_thread.is_alive():
                    self.logger.warning("Capture thread did not stop within timeout")
                else:
                    self.logger.debug("Capture thread stopped successfully")
            
            # Log final performance metrics
            self.force_performance_log()
            
            # Log final statistics
            stats = self.get_capture_statistics()
            buffer_status = self.get_buffer_status()
            
            self.logger.info(
                f"Packet capture stopped gracefully. Final statistics: "
                f"Captured: {stats.packets_captured} packets, "
                f"Dropped: {stats.packets_dropped}, "
                f"Errors: {stats.errors}, "
                f"Duration: {stats.capture_duration:.2f}s, "
                f"Avg rate: {stats.packets_per_second:.2f} pps, "
                f"Buffer remaining: {buffer_status['buffer_size']} packets"
            )
            
            # Clean up resources
            self._sniffer = None
            self._capture_thread = None
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error during graceful shutdown: {e}")
            # Force cleanup even if there were errors
            self._is_capturing = False
            self._sniffer = None
            self._capture_thread = None
            return False
    
    def get_packet_stream(self) -> Iterator[Packet]:
        """
        Get iterator for captured packets.
        
        Yields packets from the buffer as they become available.
        This is a blocking iterator that will wait for new packets.
        
        Yields:
            Packet: Next available packet from the buffer
        """
        while self._is_capturing or len(self._packet_buffer) > 0:
            try:
                with self._buffer_lock:
                    if self._packet_buffer:
                        packet = self._packet_buffer.popleft()
                        yield packet
                    else:
                        # No packets available, sleep briefly to avoid busy waiting
                        time.sleep(0.001)  # 1ms sleep
            except IndexError:
                # Buffer was empty, continue waiting
                time.sleep(0.001)
            except Exception as e:
                self.logger.error(f"Error in packet stream: {e}")
                break
    
    def get_capture_statistics(self) -> CaptureStats:
        """
        Get current capture statistics.
        
        Returns:
            CaptureStats: Current capture statistics
        """
        with self._stats_lock:
            current_time = time.time()
            duration = (
                current_time - self._capture_start_time.timestamp()
                if self._capture_start_time else 0.0
            )
            
            # Calculate packets per second
            time_diff = current_time - self._last_stats_time
            packet_diff = self._packets_captured - self._last_packet_count
            
            if time_diff > 0:
                packets_per_second = packet_diff / time_diff
            else:
                packets_per_second = 0.0
            
            # Update tracking variables
            self._last_stats_time = current_time
            self._last_packet_count = self._packets_captured
            
            return CaptureStats(
                packets_captured=self._packets_captured,
                packets_dropped=self._packets_dropped,
                packets_per_second=packets_per_second,
                bytes_captured=self._bytes_captured,
                capture_duration=duration,
                errors=self._errors
            )
    
    def is_capturing(self) -> bool:
        """
        Check if currently capturing packets.
        
        Returns:
            True if capturing, False otherwise
        """
        return self._is_capturing
    
    def get_buffer_status(self) -> dict:
        """
        Get current buffer status information.
        
        Returns:
            Dictionary with buffer status details
        """
        with self._buffer_lock:
            buffer_size = len(self._packet_buffer)
            buffer_utilization = (buffer_size / self.max_buffer_size) * 100
            
        return {
            'buffer_size': buffer_size,
            'max_buffer_size': self.max_buffer_size,
            'buffer_utilization_percent': buffer_utilization,
            'is_full': buffer_size >= self.max_buffer_size
        }
    
    def force_performance_log(self) -> None:
        """Force immediate logging of performance metrics."""
        self._log_performance_metrics()
    
    def _run_capture_with_recovery(self) -> None:
        """
        Run the packet capture in a separate thread with automatic recovery.
        """
        while self._is_capturing and self._recovery_enabled:
            try:
                if self._sniffer:
                    self.logger.debug("Starting packet capture sniffer")
                    self._sniffer.start()
                    
                    # If we get here, capture ended normally
                    if self._is_capturing:
                        self.logger.warning("Packet capture ended unexpectedly, attempting recovery")
                        self._handle_capture_failure()
                    
            except Scapy_Exception as e:
                self.logger.error(f"Scapy error in capture thread: {e}")
                self._handle_capture_failure()
                
            except OSError as e:
                self.logger.error(f"OS error in capture thread: {e}")
                self._handle_capture_failure()
                
            except Exception as e:
                self.logger.error(f"Unexpected error in capture thread: {e}")
                self._handle_capture_failure()
            
            # Brief pause before potential retry
            if self._is_capturing and self._recovery_enabled:
                time.sleep(1.0)
    
    def _run_capture(self) -> None:
        """
        Legacy run capture method for backward compatibility.
        """
        self._run_capture_with_recovery()
    
    def _handle_capture_failure(self) -> None:
        """
        Handle capture failure and attempt recovery.
        """
        with self._stats_lock:
            self._errors += 1
            self._consecutive_errors += 1
            self._last_error_time = datetime.now()
        
        if not self._recovery_enabled:
            self.logger.info("Recovery disabled, stopping capture")
            self._is_capturing = False
            return
        
        if self._consecutive_errors >= self._max_consecutive_errors:
            self.logger.error(f"Too many consecutive capture failures ({self._consecutive_errors}), stopping")
            self._is_capturing = False
            return
        
        self.logger.info(f"Attempting automatic recovery (attempt {self._consecutive_errors}/{self._max_consecutive_errors})")
        
        # Wait before retry
        time.sleep(self._recovery_delay)
        
        # Check network connectivity
        if not self._check_network_connectivity():
            self.logger.warning("Network connectivity issues detected during recovery")
            time.sleep(self._recovery_delay * 2)  # Wait longer for network issues
        
        # Try to recover with current interface first
        if self._current_interface and self._validate_interface(self._current_interface):
            self.logger.info(f"Attempting recovery with original interface: {self._current_interface}")
            if self._recreate_sniffer(self._current_interface, self._current_filter):
                self._consecutive_errors = 0  # Reset on successful recovery
                return
        
        # Try fallback interfaces
        fallback_interface = self._get_next_fallback_interface()
        if fallback_interface:
            self.logger.info(f"Attempting recovery with fallback interface: {fallback_interface}")
            if self._recreate_sniffer(fallback_interface, self._current_filter):
                self._current_interface = fallback_interface
                self._consecutive_errors = 0  # Reset on successful recovery
                return
        
        # If all recovery attempts fail, increase delay for next attempt
        self._recovery_delay = min(self._recovery_delay * 1.5, 60.0)  # Cap at 60 seconds
    
    def _recreate_sniffer(self, interface: str, filter_expression: Optional[str] = None) -> bool:
        """
        Recreate the packet sniffer with a new interface.
        
        Args:
            interface: Network interface to use
            filter_expression: Optional BPF filter expression
            
        Returns:
            True if sniffer created successfully, False otherwise
        """
        try:
            # Clean up old sniffer
            if self._sniffer:
                try:
                    self._sniffer.stop()
                except:
                    pass  # Ignore errors during cleanup
                self._sniffer = None
            
            # Validate interface
            if not self._validate_interface(interface):
                return False
            
            # Create new sniffer
            self._sniffer = AsyncSniffer(
                iface=interface,
                filter=filter_expression,
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda x: not self._is_capturing
            )
            
            self.logger.info(f"Successfully recreated sniffer for interface {interface}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to recreate sniffer for interface {interface}: {e}")
            return False
    
    def enable_recovery(self, enabled: bool = True) -> None:
        """
        Enable or disable automatic recovery.
        
        Args:
            enabled: Whether to enable automatic recovery
        """
        self._recovery_enabled = enabled
        self.logger.info(f"Automatic recovery {'enabled' if enabled else 'disabled'}")
    
    def get_recovery_status(self) -> dict:
        """
        Get current recovery status information.
        
        Returns:
            Dictionary with recovery status details
        """
        return {
            'recovery_enabled': self._recovery_enabled,
            'consecutive_errors': self._consecutive_errors,
            'max_consecutive_errors': self._max_consecutive_errors,
            'last_error_time': self._last_error_time.isoformat() if self._last_error_time else None,
            'current_interface': self._current_interface,
            'fallback_interfaces': self._interface_fallback_list,
            'fallback_index': self._fallback_index,
            'recovery_delay': self._recovery_delay
        }
    
    def _packet_handler(self, packet: Packet) -> None:
        """
        Handle captured packets by adding them to the buffer with comprehensive error handling.
        
        Args:
            packet: Captured packet from scapy
        """
        try:
            # Validate packet
            if packet is None:
                self.logger.debug("Received null packet, skipping")
                return
            
            with self._buffer_lock:
                # Check if buffer is full
                if len(self._packet_buffer) >= self.max_buffer_size:
                    # Buffer is full, drop the oldest packet
                    dropped_packet = self._packet_buffer.popleft()
                    with self._stats_lock:
                        self._packets_dropped += 1
                    
                    # Log warning if drop rate is high
                    if self._packets_dropped % 100 == 0:  # Log every 100 drops
                        drop_rate = (self._packets_dropped / max(self._packets_captured, 1)) * 100
                        self.logger.warning(f"High packet drop rate: {drop_rate:.2f}% ({self._packets_dropped} dropped)")
                
                # Add new packet to buffer
                self._packet_buffer.append(packet)
            
            # Update statistics
            with self._stats_lock:
                self._packets_captured += 1
                
                # Calculate packet size safely
                try:
                    packet_size = len(packet) if hasattr(packet, '__len__') else 0
                    self._bytes_captured += packet_size
                except (TypeError, AttributeError):
                    # Some packet types might not support len()
                    pass
            
            # Log performance metrics periodically
            self._log_performance_metrics()
            
            # Reset consecutive errors on successful packet processing
            if self._consecutive_errors > 0:
                self._consecutive_errors = 0
                self._recovery_delay = 5.0  # Reset recovery delay
                
        except MemoryError as e:
            self.logger.error(f"Memory error handling packet - system may be low on memory: {e}")
            with self._stats_lock:
                self._errors += 1
            # Try to free some buffer space
            try:
                with self._buffer_lock:
                    # Drop half the buffer to free memory
                    drop_count = len(self._packet_buffer) // 2
                    for _ in range(drop_count):
                        if self._packet_buffer:
                            self._packet_buffer.popleft()
                    with self._stats_lock:
                        self._packets_dropped += drop_count
                    self.logger.warning(f"Dropped {drop_count} packets due to memory pressure")
            except Exception as cleanup_error:
                self.logger.error(f"Error during memory cleanup: {cleanup_error}")
                
        except Exception as e:
            self.logger.error(f"Unexpected error handling packet: {e}")
            with self._stats_lock:
                self._errors += 1
                
            # If we're getting too many packet handling errors, it might indicate
            # a deeper problem with the capture
            if self._errors % 50 == 0:  # Log every 50 errors
                self.logger.warning(f"High error rate in packet handling: {self._errors} total errors")
    
    def _reset_statistics(self) -> None:
        """Reset capture statistics."""
        with self._stats_lock:
            self._packets_captured = 0
            self._packets_dropped = 0
            self._bytes_captured = 0
            self._errors = 0
            self._last_packet_count = 0
            self._last_stats_time = time.time()
            self._last_performance_log = time.time()
    
    def _log_performance_metrics(self) -> None:
        """Log performance metrics periodically."""
        current_time = time.time()
        
        # Check if it's time to log performance metrics
        if current_time - self._last_performance_log >= self._performance_log_interval:
            stats = self.get_capture_statistics()
            
            # Calculate buffer utilization
            buffer_utilization = (len(self._packet_buffer) / self.max_buffer_size) * 100
            
            # Log comprehensive performance metrics
            self.logger.info(
                f"Capture Performance Metrics: "
                f"Packets/sec: {stats.packets_per_second:.2f}, "
                f"Total captured: {stats.packets_captured}, "
                f"Dropped: {stats.packets_dropped}, "
                f"Buffer utilization: {buffer_utilization:.1f}%, "
                f"Errors: {stats.errors}, "
                f"Bytes captured: {stats.bytes_captured}"
            )
            
            # Log warnings for performance issues
            if stats.packets_dropped > 0:
                drop_rate = (stats.packets_dropped / max(stats.packets_captured, 1)) * 100
                if drop_rate > 1.0:  # More than 1% drop rate
                    self.logger.warning(
                        f"High packet drop rate detected: {drop_rate:.2f}% "
                        f"({stats.packets_dropped}/{stats.packets_captured})"
                    )
            
            if buffer_utilization > 80.0:
                self.logger.warning(
                    f"High buffer utilization: {buffer_utilization:.1f}% "
                    f"({len(self._packet_buffer)}/{self.max_buffer_size})"
                )
            
            if stats.errors > 0:
                self.logger.warning(f"Capture errors detected: {stats.errors}")
            
            self._last_performance_log = current_time