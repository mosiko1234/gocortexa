"""
Asgard cloud communication client with HTTP API, authentication, and retry logic
"""

import json
import logging
import time
import random
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin
import uuid
import queue
import threading
from enum import Enum

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ..interfaces import IAsgardCommunicator
from ..models import (
    AnonymizedAnomaly, AnonymizedDevice, GoldenProfile, 
    IntelligenceUpdate, SensorInfo, Anomaly, DeviceBehavior
)
from .data_anonymizer import DataAnonymizer


class ConnectionState(Enum):
    """Connection state enumeration"""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    AUTHENTICATION_FAILED = "auth_failed"
    RATE_LIMITED = "rate_limited"
    ERROR = "error"


class QueuedRequest:
    """Represents a queued request for retry"""
    
    def __init__(self, method: str, endpoint: str, data: Dict, priority: int = 0):
        self.method = method
        self.endpoint = endpoint
        self.data = data
        self.priority = priority
        self.timestamp = datetime.now()
        self.retry_count = 0
        self.last_retry = None
        self.max_retries = 5


class AsgardCommunicator(IAsgardCommunicator):
    """
    HTTP client for communicating with Asgard cloud platform
    Handles sensor registration, authentication, and data transmission with retry logic
    """
    
    def __init__(self, 
                 api_endpoint: str,
                 api_key: str,
                 sensor_id: Optional[str] = None,
                 max_retries: int = 3,
                 backoff_factor: float = 1.0,
                 timeout: int = 30,
                 max_queue_size: int = 1000,
                 anonymizer: Optional[DataAnonymizer] = None):
        """
        Initialize Asgard communicator with comprehensive error handling
        
        Args:
            api_endpoint: Base URL for Asgard API
            api_key: API key for authentication
            sensor_id: Unique sensor identifier (generated if None)
            max_retries: Maximum number of retry attempts
            backoff_factor: Exponential backoff factor for retries
            timeout: Request timeout in seconds
            max_queue_size: Maximum size of offline queue
        """
        self.api_endpoint = api_endpoint.rstrip('/')
        self.api_key = api_key
        self.sensor_id = sensor_id or str(uuid.uuid4())
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.timeout = timeout
        self.max_queue_size = max_queue_size
        
        # Enhanced connection state management
        self._connection_state = ConnectionState.DISCONNECTED
        self._last_connection_attempt = None
        self._connection_retry_delay = 60  # seconds
        self._consecutive_failures = 0
        self._max_consecutive_failures = 10
        
        # Exponential backoff configuration
        self._base_retry_delay = 1.0  # seconds
        self._max_retry_delay = 300.0  # 5 minutes max
        self._jitter_factor = 0.1  # Add randomness to prevent thundering herd
        
        # Authentication state
        self._auth_token = None
        self._auth_expires = None
        self._auth_retry_count = 0
        self._max_auth_retries = 3
        
        # Rate limiting
        self._rate_limit_reset = None
        self._rate_limit_remaining = None
        self._rate_limit_window = 60  # seconds
        
        # Enhanced offline queue with priority
        self._offline_queue = queue.PriorityQueue(maxsize=max_queue_size)
        self._queue_worker_running = False
        self._queue_worker_thread = None
        self._queue_stats = {
            'total_queued': 0,
            'total_processed': 0,
            'total_failed': 0,
            'queue_full_drops': 0
        }
        
        # HTTP session with enhanced retry strategy
        self._session = self._create_enhanced_session()
        
        # Data anonymizer
        self.anonymizer = anonymizer or DataAnonymizer()
        
        # Logger
        self.logger = logging.getLogger(__name__)
        
        # Metrics tracking
        self._metrics = {
            'requests_sent': 0,
            'requests_successful': 0,
            'requests_failed': 0,
            'auth_failures': 0,
            'rate_limit_hits': 0,
            'connection_errors': 0,
            'timeout_errors': 0
        }
        
        # Start enhanced queue worker
        self._start_enhanced_queue_worker()
    
    def _create_enhanced_session(self) -> requests.Session:
        """Create HTTP session with enhanced retry strategy and error handling"""
        session = requests.Session()
        
        # Configure enhanced retry strategy
        retry_strategy = Retry(
            total=0,  # We'll handle retries manually for better control
            backoff_factor=self.backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE", "POST"],
            raise_on_status=False  # We'll handle status codes manually
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set default headers
        session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': f'Heimdal-Sensor/{self.sensor_id}',
            'Accept': 'application/json'
        })
        
        return session
    
    def _calculate_backoff_delay(self, attempt: int, base_delay: Optional[float] = None) -> float:
        """
        Calculate exponential backoff delay with jitter.
        
        Args:
            attempt: Current attempt number (0-based)
            base_delay: Base delay in seconds (uses instance default if None)
            
        Returns:
            Delay in seconds
        """
        if base_delay is None:
            base_delay = self._base_retry_delay
        
        # Exponential backoff: base_delay * (2 ^ attempt)
        delay = base_delay * (2 ** attempt)
        
        # Cap at maximum delay
        delay = min(delay, self._max_retry_delay)
        
        # Add jitter to prevent thundering herd
        jitter = delay * self._jitter_factor * random.random()
        delay += jitter
        
        return delay
    
    def _update_auth_headers(self) -> None:
        """Update session headers with current authentication"""
        if self._auth_token:
            self._session.headers['Authorization'] = f'Bearer {self._auth_token}'
        else:
            self._session.headers['Authorization'] = f'Bearer {self.api_key}'
    
    def _handle_rate_limiting(self, response: requests.Response) -> bool:
        """
        Handle rate limiting response.
        
        Args:
            response: HTTP response object
            
        Returns:
            True if rate limiting was handled, False otherwise
        """
        if response.status_code == 429:
            self._metrics['rate_limit_hits'] += 1
            self._connection_state = ConnectionState.RATE_LIMITED
            
            # Extract rate limit headers
            retry_after = response.headers.get('Retry-After')
            if retry_after:
                try:
                    self._rate_limit_reset = datetime.now() + timedelta(seconds=int(retry_after))
                    self.logger.warning(f"Rate limited, retry after {retry_after} seconds")
                    return True
                except ValueError:
                    pass
            
            # Fallback rate limit handling
            self._rate_limit_reset = datetime.now() + timedelta(seconds=self._rate_limit_window)
            self.logger.warning(f"Rate limited, using default {self._rate_limit_window}s window")
            return True
        
        return False
    
    def _is_rate_limited(self) -> bool:
        """Check if currently rate limited"""
        if self._rate_limit_reset and datetime.now() < self._rate_limit_reset:
            return True
        
        # Reset rate limit state if window has passed
        if self._rate_limit_reset and datetime.now() >= self._rate_limit_reset:
            self._rate_limit_reset = None
            if self._connection_state == ConnectionState.RATE_LIMITED:
                self._connection_state = ConnectionState.DISCONNECTED
        
        return False
    
    def _start_enhanced_queue_worker(self):
        """Start enhanced background thread to process offline queue"""
        if not self._queue_worker_running:
            self._queue_worker_running = True
            self._queue_worker_thread = threading.Thread(
                target=self._process_enhanced_offline_queue,
                daemon=True,
                name="AsgardQueueWorker"
            )
            self._queue_worker_thread.start()
            self.logger.info("Started enhanced offline queue worker thread")
    
    def _process_enhanced_offline_queue(self):
        """Enhanced processing of queued requests with better error handling"""
        while self._queue_worker_running:
            try:
                # Check if we can process requests
                if (self._connection_state in [ConnectionState.CONNECTED, ConnectionState.DISCONNECTED] and 
                    not self._is_rate_limited() and 
                    not self._offline_queue.empty()):
                    
                    # Process queued items in batches
                    processed = 0
                    failed_requests = []
                    batch_size = 10
                    
                    while not self._offline_queue.empty() and processed < batch_size:
                        try:
                            # Get next request (priority queue returns (priority, request))
                            priority, queued_request = self._offline_queue.get_nowait()
                            
                            # Check if request has exceeded max retries
                            if queued_request.retry_count >= queued_request.max_retries:
                                self.logger.warning(f"Dropping request after {queued_request.retry_count} retries: "
                                                  f"{queued_request.method} {queued_request.endpoint}")
                                self._queue_stats['total_failed'] += 1
                                continue
                            
                            # Check if request is too old (older than 1 hour)
                            if (datetime.now() - queued_request.timestamp).total_seconds() > 3600:
                                self.logger.warning(f"Dropping expired request: {queued_request.method} {queued_request.endpoint}")
                                self._queue_stats['total_failed'] += 1
                                continue
                            
                            # Attempt to process request
                            queued_request.retry_count += 1
                            queued_request.last_retry = datetime.now()
                            
                            success = self._make_enhanced_request(
                                queued_request.method, 
                                queued_request.endpoint, 
                                queued_request.data, 
                                queue_on_failure=False
                            )
                            
                            if success:
                                processed += 1
                                self._queue_stats['total_processed'] += 1
                                self.logger.debug(f"Successfully processed queued {queued_request.method} request to {queued_request.endpoint}")
                            else:
                                # Re-queue if not at max retries
                                if queued_request.retry_count < queued_request.max_retries:
                                    failed_requests.append((priority, queued_request))
                                else:
                                    self._queue_stats['total_failed'] += 1
                                
                                # Stop processing if we're having connection issues
                                if self._connection_state == ConnectionState.ERROR:
                                    break
                                
                        except queue.Empty:
                            break
                        except Exception as e:
                            self.logger.error(f"Error processing queued request: {e}")
                    
                    # Re-queue failed requests
                    for priority, failed_request in failed_requests:
                        try:
                            self._offline_queue.put_nowait((priority, failed_request))
                        except queue.Full:
                            self.logger.warning("Queue full, dropping failed request")
                            self._queue_stats['queue_full_drops'] += 1
                    
                    if processed > 0:
                        self.logger.info(f"Processed {processed} queued requests, {len(failed_requests)} re-queued")
                
                # Adaptive sleep based on queue size and connection state
                if self._offline_queue.empty():
                    sleep_time = 60  # Longer sleep when queue is empty
                elif self._connection_state == ConnectionState.ERROR:
                    sleep_time = 120  # Even longer sleep when in error state
                elif self._is_rate_limited():
                    sleep_time = 30  # Moderate sleep when rate limited
                else:
                    sleep_time = 10  # Short sleep when actively processing
                
                time.sleep(sleep_time)
                
            except Exception as e:
                self.logger.error(f"Error in enhanced offline queue worker: {e}")
                time.sleep(60)
    
    def _make_enhanced_request(self, 
                              method: str, 
                              endpoint: str, 
                              data: Optional[Dict] = None,
                              queue_on_failure: bool = True,
                              max_retries: Optional[int] = None) -> bool:
        """
        Make HTTP request with comprehensive error handling, exponential backoff, and queuing
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path
            data: Request data
            queue_on_failure: Whether to queue request on failure
            max_retries: Maximum retry attempts (uses instance default if None)
            
        Returns:
            True if request succeeded, False otherwise
        """
        if max_retries is None:
            max_retries = self.max_retries
        
        url = urljoin(self.api_endpoint, endpoint)
        self._metrics['requests_sent'] += 1
        
        # Check if rate limited
        if self._is_rate_limited():
            self.logger.debug(f"Skipping request due to rate limiting: {method} {endpoint}")
            if queue_on_failure and data is not None:
                self._queue_request(method, endpoint, data, priority=1)  # Lower priority for rate limited
            return False
        
        # Update authentication headers
        self._update_auth_headers()
        
        for attempt in range(max_retries + 1):
            try:
                # Make the HTTP request
                if method.upper() == 'GET':
                    response = self._session.get(url, timeout=self.timeout)
                elif method.upper() == 'POST':
                    response = self._session.post(url, json=data, timeout=self.timeout)
                elif method.upper() == 'PUT':
                    response = self._session.put(url, json=data, timeout=self.timeout)
                elif method.upper() == 'DELETE':
                    response = self._session.delete(url, timeout=self.timeout)
                else:
                    raise ValueError(f"Unsupported HTTP method: {method}")
                
                # Handle different response status codes
                if response.status_code == 200 or response.status_code == 201:
                    # Success
                    self._metrics['requests_successful'] += 1
                    self._connection_state = ConnectionState.CONNECTED
                    self._consecutive_failures = 0
                    return True
                
                elif response.status_code == 401:
                    # Authentication failed
                    self._metrics['auth_failures'] += 1
                    self._connection_state = ConnectionState.AUTHENTICATION_FAILED
                    self.logger.error(f"Authentication failed for {method} {endpoint}")
                    
                    # Try to re-authenticate
                    if self._attempt_reauthentication():
                        continue  # Retry with new auth
                    else:
                        return False  # Don't queue auth failures
                
                elif response.status_code == 403:
                    # Forbidden - don't retry
                    self.logger.error(f"Forbidden access to {method} {endpoint}")
                    self._metrics['requests_failed'] += 1
                    return False
                
                elif response.status_code == 429:
                    # Rate limited
                    if self._handle_rate_limiting(response):
                        if queue_on_failure and data is not None:
                            self._queue_request(method, endpoint, data, priority=1)
                        return False
                
                elif response.status_code >= 500:
                    # Server error - retry with backoff
                    if attempt < max_retries:
                        delay = self._calculate_backoff_delay(attempt)
                        self.logger.warning(f"Server error {response.status_code} for {method} {endpoint}, "
                                          f"retrying in {delay:.2f}s (attempt {attempt + 1}/{max_retries + 1})")
                        time.sleep(delay)
                        continue
                    else:
                        self.logger.error(f"Server error {response.status_code} for {method} {endpoint} after {max_retries} retries")
                
                elif response.status_code >= 400:
                    # Client error - don't retry
                    self.logger.error(f"Client error {response.status_code} for {method} {endpoint}: {response.text}")
                    self._metrics['requests_failed'] += 1
                    return False
                
                else:
                    # Unexpected status code
                    self.logger.warning(f"Unexpected status code {response.status_code} for {method} {endpoint}")
                    if attempt < max_retries:
                        delay = self._calculate_backoff_delay(attempt)
                        time.sleep(delay)
                        continue
                
            except requests.exceptions.Timeout as e:
                self._metrics['timeout_errors'] += 1
                self.logger.warning(f"Timeout for {method} {endpoint}: {e}")
                if attempt < max_retries:
                    delay = self._calculate_backoff_delay(attempt)
                    time.sleep(delay)
                    continue
                
            except requests.exceptions.ConnectionError as e:
                self._metrics['connection_errors'] += 1
                self._connection_state = ConnectionState.ERROR
                self.logger.warning(f"Connection error for {method} {endpoint}: {e}")
                if attempt < max_retries:
                    delay = self._calculate_backoff_delay(attempt)
                    time.sleep(delay)
                    continue
                
            except requests.exceptions.RequestException as e:
                self.logger.error(f"Request exception for {method} {endpoint}: {e}")
                if attempt < max_retries:
                    delay = self._calculate_backoff_delay(attempt)
                    time.sleep(delay)
                    continue
                
            except Exception as e:
                self.logger.error(f"Unexpected error for {method} {endpoint}: {e}")
                break
        
        # All retries failed
        self._metrics['requests_failed'] += 1
        self._consecutive_failures += 1
        self._connection_state = ConnectionState.ERROR
        
        # Queue request for later retry if enabled
        if queue_on_failure and data is not None:
            self._queue_request(method, endpoint, data, priority=0)  # High priority for failed requests
        
        return False
    
    def _make_request(self, method: str, endpoint: str, data: Optional[Dict] = None, queue_on_failure: bool = True) -> bool:
        """Legacy method for backward compatibility"""
        return self._make_enhanced_request(method, endpoint, data, queue_on_failure)
    
    def _queue_request(self, method: str, endpoint: str, data: Dict, priority: int = 0) -> bool:
        """
        Queue a request for later retry.
        
        Args:
            method: HTTP method
            endpoint: API endpoint
            data: Request data
            priority: Request priority (0 = high, 1 = normal, 2 = low)
            
        Returns:
            True if queued successfully, False otherwise
        """
        try:
            queued_request = QueuedRequest(method, endpoint, data, priority)
            self._offline_queue.put_nowait((priority, queued_request))
            self._queue_stats['total_queued'] += 1
            self.logger.debug(f"Queued failed request for retry: {method} {endpoint}")
            return True
        except queue.Full:
            self.logger.warning("Offline queue is full, dropping request")
            self._queue_stats['queue_full_drops'] += 1
            return False
    
    def _attempt_reauthentication(self) -> bool:
        """
        Attempt to re-authenticate with Asgard.
        
        Returns:
            True if re-authentication succeeded, False otherwise
        """
        if self._auth_retry_count >= self._max_auth_retries:
            self.logger.error("Maximum authentication retry attempts exceeded")
            return False
        
        self._auth_retry_count += 1
        self.logger.info(f"Attempting re-authentication (attempt {self._auth_retry_count}/{self._max_auth_retries})")
        
        try:
            # Try to get a new auth token or refresh existing one
            # For now, we'll just reset to use the original API key
            self._auth_token = None
            self._auth_expires = None
            self._update_auth_headers()
            
            # Test authentication with a simple health check
            test_url = urljoin(self.api_endpoint, '/api/v1/health')
            response = self._session.get(test_url, timeout=10)
            
            if response.status_code == 200:
                self.logger.info("Re-authentication successful")
                self._auth_retry_count = 0
                self._connection_state = ConnectionState.CONNECTED
                return True
            else:
                self.logger.warning(f"Re-authentication failed with status {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error during re-authentication: {e}")
            return False
    
    def register_sensor(self, sensor_info: SensorInfo) -> Optional[str]:
        """
        Register sensor with Asgard platform with enhanced error handling
        
        Args:
            sensor_info: Sensor information for registration
            
        Returns:
            Sensor ID if registration successful, None otherwise
        """
        self.logger.info(f"Registering sensor {self.sensor_id} with Asgard")
        
        registration_data = {
            'sensor_id': self.sensor_id,
            'location': sensor_info.location,
            'capabilities': sensor_info.capabilities,
            'version': sensor_info.version,
            'timestamp': datetime.now().isoformat()
        }
        
        # Registration is critical, so try multiple times with longer delays
        max_registration_retries = 5
        for attempt in range(max_registration_retries):
            success = self._make_enhanced_request('POST', '/api/v1/sensors/register', registration_data, queue_on_failure=False)
            
            if success:
                self.logger.info(f"Successfully registered sensor {self.sensor_id}")
                self._connection_state = ConnectionState.CONNECTED
                return self.sensor_id
            
            if attempt < max_registration_retries - 1:
                delay = self._calculate_backoff_delay(attempt, base_delay=5.0)  # Longer base delay for registration
                self.logger.warning(f"Registration attempt {attempt + 1} failed, retrying in {delay:.2f}s")
                time.sleep(delay)
        
        self.logger.error(f"Failed to register sensor {self.sensor_id} after {max_registration_retries} attempts")
        return None
    
    def send_anomaly_metadata(self, anonymized_anomaly: AnonymizedAnomaly) -> bool:
        """
        Send anonymized anomaly data to Asgard with enhanced error handling
        
        Args:
            anonymized_anomaly: Anonymized anomaly data
            
        Returns:
            True if sent successfully, False otherwise
        """
        anomaly_data = {
            'sensor_id': self.sensor_id,
            'device_type': anonymized_anomaly.device_type,
            'anomaly_type': anonymized_anomaly.anomaly_type.value,
            'severity': anonymized_anomaly.severity.value,
            'geographic_region': anonymized_anomaly.geographic_region,
            'timestamp': anonymized_anomaly.timestamp.isoformat(),
            'behavioral_signature': anonymized_anomaly.behavioral_signature
        }
        
        # Anomaly data is high priority, so use priority 0 for queuing
        success = self._make_enhanced_request('POST', '/api/v1/anomalies', anomaly_data, queue_on_failure=True)
        
        if success:
            self.logger.debug(f"Sent anomaly metadata for {anonymized_anomaly.device_type}")
        else:
            self.logger.debug(f"Anomaly metadata for {anonymized_anomaly.device_type} queued for retry")
        
        return success
    
    def send_device_metadata(self, anonymized_device: AnonymizedDevice) -> bool:
        """
        Send anonymized device data to Asgard with enhanced error handling
        
        Args:
            anonymized_device: Anonymized device data
            
        Returns:
            True if sent successfully, False otherwise
        """
        device_data = {
            'sensor_id': self.sensor_id,
            'device_type': anonymized_device.device_type,
            'geographic_region': anonymized_device.geographic_region,
            'behavioral_signature': anonymized_device.behavioral_signature,
            'timestamp': anonymized_device.timestamp.isoformat()
        }
        
        # Device metadata is normal priority, so use priority 1 for queuing
        success = self._make_enhanced_request('POST', '/api/v1/devices', device_data, queue_on_failure=True)
        
        if success:
            self.logger.debug(f"Sent device metadata for {anonymized_device.device_type}")
        else:
            self.logger.debug(f"Device metadata for {anonymized_device.device_type} queued for retry")
        
        return success
    
    def send_raw_anomaly(self, anomaly: Anomaly) -> bool:
        """
        Send raw anomaly data (will be automatically anonymized)
        
        Args:
            anomaly: Raw anomaly data
            
        Returns:
            True if sent successfully, False otherwise
        """
        anonymized_anomaly = self.anonymizer.anonymize_anomaly(anomaly)
        return self.send_anomaly_metadata(anonymized_anomaly)
    
    def send_raw_device_behavior(self, device_behavior: DeviceBehavior) -> bool:
        """
        Send raw device behavior data (will be automatically anonymized)
        
        Args:
            device_behavior: Raw device behavior data
            
        Returns:
            True if sent successfully, False otherwise
        """
        anonymized_device = self.anonymizer.anonymize_device(device_behavior)
        return self.send_device_metadata(anonymized_device)
    
    def receive_intelligence_updates(self) -> List[IntelligenceUpdate]:
        """
        Receive intelligence updates from Asgard
        
        Returns:
            List of intelligence updates
        """
        try:
            url = urljoin(self.api_endpoint, f'/api/v1/intelligence/updates/{self.sensor_id}')
            response = self._session.get(url, timeout=self.timeout)
            response.raise_for_status()
            
            updates_data = response.json()
            updates = []
            
            for update_data in updates_data.get('updates', []):
                update = IntelligenceUpdate(
                    update_type=update_data['update_type'],
                    content=update_data['content'],
                    version=update_data['version'],
                    timestamp=datetime.fromisoformat(update_data['timestamp'])
                )
                updates.append(update)
            
            self._connected = True
            self.logger.debug(f"Received {len(updates)} intelligence updates")
            return updates
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to receive intelligence updates: {e}")
            self._connected = False
            return []
    
    def get_golden_profiles(self, device_types: List[str]) -> List[GoldenProfile]:
        """
        Get Golden Profiles for specified device types
        
        Args:
            device_types: List of device types to get profiles for
            
        Returns:
            List of Golden Profiles
        """
        try:
            url = urljoin(self.api_endpoint, '/api/v1/profiles/golden')
            params = {'device_types': ','.join(device_types)}
            
            response = self._session.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            
            profiles_data = response.json()
            profiles = []
            
            for profile_data in profiles_data.get('profiles', []):
                profile = GoldenProfile(
                    device_type=profile_data['device_type'],
                    version=profile_data['version'],
                    normal_behaviors=profile_data['normal_behaviors'],
                    threat_indicators=profile_data['threat_indicators'],
                    last_updated=datetime.fromisoformat(profile_data['last_updated'])
                )
                profiles.append(profile)
            
            self._connected = True
            self.logger.debug(f"Retrieved {len(profiles)} Golden Profiles")
            return profiles
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get Golden Profiles: {e}")
            self._connected = False
            return []
    
    def is_connected(self) -> bool:
        """
        Check if connected to Asgard with enhanced state management
        
        Returns:
            True if connected, False otherwise
        """
        # Perform connectivity check if we haven't checked recently
        now = datetime.now()
        if (self._last_connection_attempt is None or 
            now - self._last_connection_attempt > timedelta(seconds=self._connection_retry_delay)):
            
            self._last_connection_attempt = now
            self._check_connectivity()
        
        return self._connection_state == ConnectionState.CONNECTED
    
    def _check_connectivity(self) -> bool:
        """
        Check connectivity to Asgard API with enhanced error handling
        
        Returns:
            True if connected, False otherwise
        """
        try:
            self._connection_state = ConnectionState.CONNECTING
            url = urljoin(self.api_endpoint, '/api/v1/health')
            response = self._session.get(url, timeout=10)
            
            if response.status_code == 200:
                self._connection_state = ConnectionState.CONNECTED
                self._consecutive_failures = 0
                self.logger.debug("Asgard connectivity check successful")
                return True
            elif response.status_code == 401:
                self._connection_state = ConnectionState.AUTHENTICATION_FAILED
                self.logger.warning("Asgard connectivity check failed: authentication error")
                return False
            else:
                self._connection_state = ConnectionState.ERROR
                self.logger.warning(f"Asgard connectivity check failed: HTTP {response.status_code}")
                return False
                
        except requests.exceptions.Timeout as e:
            self._connection_state = ConnectionState.ERROR
            self._consecutive_failures += 1
            self.logger.debug(f"Asgard connectivity check timed out: {e}")
            return False
            
        except requests.exceptions.ConnectionError as e:
            self._connection_state = ConnectionState.ERROR
            self._consecutive_failures += 1
            self.logger.debug(f"Asgard connectivity check failed: connection error: {e}")
            return False
            
        except requests.exceptions.RequestException as e:
            self._connection_state = ConnectionState.ERROR
            self._consecutive_failures += 1
            self.logger.debug(f"Asgard connectivity check failed: {e}")
            return False
            
        except Exception as e:
            self._connection_state = ConnectionState.ERROR
            self._consecutive_failures += 1
            self.logger.error(f"Unexpected error in connectivity check: {e}")
            return False
    
    def get_enhanced_status(self) -> Dict[str, Any]:
        """
        Get comprehensive status of Asgard communicator
        
        Returns:
            Dictionary with detailed status information
        """
        return {
            'connection_state': self._connection_state.value,
            'consecutive_failures': self._consecutive_failures,
            'queue_size': self._offline_queue.qsize(),
            'max_queue_size': self.max_queue_size,
            'worker_running': self._queue_worker_running,
            'last_connection_attempt': self._last_connection_attempt.isoformat() if self._last_connection_attempt else None,
            'rate_limited': self._is_rate_limited(),
            'rate_limit_reset': self._rate_limit_reset.isoformat() if self._rate_limit_reset else None,
            'auth_retry_count': self._auth_retry_count,
            'queue_stats': self._queue_stats.copy(),
            'metrics': self._metrics.copy()
        }
    
    def get_queue_status(self) -> Dict[str, Any]:
        """
        Get status of offline queue (legacy method for backward compatibility)
        
        Returns:
            Dictionary with queue status information
        """
        return {
            'queue_size': self._offline_queue.qsize(),
            'max_queue_size': self.max_queue_size,
            'worker_running': self._queue_worker_running,
            'connected': self._connection_state == ConnectionState.CONNECTED,
            'last_connection_attempt': self._last_connection_attempt.isoformat() if self._last_connection_attempt else None
        }
    
    def get_metrics(self) -> Dict[str, Any]:
        """
        Get communication metrics
        
        Returns:
            Dictionary with metrics information
        """
        total_requests = self._metrics['requests_sent']
        success_rate = (self._metrics['requests_successful'] / total_requests * 100) if total_requests > 0 else 0
        
        return {
            **self._metrics,
            'success_rate_percent': round(success_rate, 2),
            'queue_stats': self._queue_stats.copy()
        }
    
    def reset_metrics(self) -> None:
        """Reset all metrics counters"""
        self._metrics = {
            'requests_sent': 0,
            'requests_successful': 0,
            'requests_failed': 0,
            'auth_failures': 0,
            'rate_limit_hits': 0,
            'connection_errors': 0,
            'timeout_errors': 0
        }
        self._queue_stats = {
            'total_queued': 0,
            'total_processed': 0,
            'total_failed': 0,
            'queue_full_drops': 0
        }
        self.logger.info("Metrics reset")
    
    def force_reconnect(self) -> bool:
        """
        Force a reconnection attempt to Asgard
        
        Returns:
            True if reconnection succeeded, False otherwise
        """
        self.logger.info("Forcing reconnection to Asgard")
        self._connection_state = ConnectionState.CONNECTING
        self._consecutive_failures = 0
        self._auth_retry_count = 0
        
        # Test connection with health check
        return self._check_connectivity()
    
    def shutdown(self):
        """Shutdown the communicator and cleanup resources"""
        self.logger.info("Shutting down Asgard communicator")
        
        # Stop queue worker
        self._queue_worker_running = False
        if self._queue_worker_thread and self._queue_worker_thread.is_alive():
            self.logger.debug("Waiting for queue worker thread to stop...")
            self._queue_worker_thread.join(timeout=10)
            
            if self._queue_worker_thread.is_alive():
                self.logger.warning("Queue worker thread did not stop within timeout")
        
        # Log final queue statistics
        if not self._offline_queue.empty():
            self.logger.info(f"Shutting down with {self._offline_queue.qsize()} requests still queued")
        
        final_stats = self.get_metrics()
        self.logger.info(f"Final communication statistics: {final_stats}")
        
        # Close HTTP session
        if self._session:
            self._session.close()
        
        self._connection_state = ConnectionState.DISCONNECTED
        self.logger.info("Asgard communicator shutdown complete")