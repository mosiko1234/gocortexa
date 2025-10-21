"""
Packet capture engine implementation using scapy AsyncSniffer
"""

import threading
import time
from collections import deque
from datetime import datetime
from typing import Iterator, Optional, Deque
import logging

from scapy.all import AsyncSniffer, Packet
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
    
    def start_capture(self, interface: str, filter_expression: Optional[str] = None) -> bool:
        """
        Start capturing packets from the specified network interface.
        
        Args:
            interface: Network interface name (e.g., 'eth0', 'wlan0')
            filter_expression: Optional BPF filter expression
            
        Returns:
            True if capture started successfully, False otherwise
        """
        if self._is_capturing:
            self.logger.warning("Packet capture is already running")
            return False
        
        try:
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
                target=self._run_capture,
                name="PacketCapture",
                daemon=True
            )
            self._capture_thread.start()
            
            self.logger.info(
                f"Started packet capture on interface {interface}"
                f"{f' with filter: {filter_expression}' if filter_expression else ''}"
            )
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start packet capture: {e}")
            self._is_capturing = False
            return False
    
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
    
    def _run_capture(self) -> None:
        """
        Run the packet capture in a separate thread.
        """
        try:
            if self._sniffer:
                self._sniffer.start()
        except Exception as e:
            self.logger.error(f"Error in capture thread: {e}")
            with self._stats_lock:
                self._errors += 1
            self._is_capturing = False
    
    def _packet_handler(self, packet: Packet) -> None:
        """
        Handle captured packets by adding them to the buffer.
        
        Args:
            packet: Captured packet from scapy
        """
        try:
            with self._buffer_lock:
                # Check if buffer is full
                if len(self._packet_buffer) >= self.max_buffer_size:
                    # Buffer is full, drop the oldest packet
                    self._packet_buffer.popleft()
                    with self._stats_lock:
                        self._packets_dropped += 1
                
                # Add new packet to buffer
                self._packet_buffer.append(packet)
            
            # Update statistics
            with self._stats_lock:
                self._packets_captured += 1
                self._bytes_captured += len(packet) if hasattr(packet, '__len__') else 0
            
            # Log performance metrics periodically
            self._log_performance_metrics()
                
        except Exception as e:
            self.logger.error(f"Error handling packet: {e}")
            with self._stats_lock:
                self._errors += 1
    
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