"""
Asgard cloud communication client with HTTP API, authentication, and retry logic
"""

import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin
import uuid
import queue
import threading

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ..interfaces import IAsgardCommunicator
from ..models import (
    AnonymizedAnomaly, AnonymizedDevice, GoldenProfile, 
    IntelligenceUpdate, SensorInfo, Anomaly, DeviceBehavior
)
from .data_anonymizer import DataAnonymizer


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
        Initialize Asgard communicator
        
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
        
        # Connection state
        self._connected = False
        self._last_connection_attempt = None
        self._connection_retry_delay = 60  # seconds
        
        # Offline queue for failed requests
        self._offline_queue = queue.Queue(maxsize=max_queue_size)
        self._queue_worker_running = False
        self._queue_worker_thread = None
        
        # HTTP session with retry strategy
        self._session = self._create_session()
        
        # Data anonymizer
        self.anonymizer = anonymizer or DataAnonymizer()
        
        # Logger
        self.logger = logging.getLogger(__name__)
        
        # Start queue worker
        self._start_queue_worker()
    
    def _create_session(self) -> requests.Session:
        """Create HTTP session with retry strategy"""
        session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=self.backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE", "POST"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set default headers
        session.headers.update({
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.api_key}',
            'User-Agent': f'Heimdal-Sensor/{self.sensor_id}'
        })
        
        return session
    
    def _start_queue_worker(self):
        """Start background thread to process offline queue"""
        if not self._queue_worker_running:
            self._queue_worker_running = True
            self._queue_worker_thread = threading.Thread(
                target=self._process_offline_queue,
                daemon=True
            )
            self._queue_worker_thread.start()
            self.logger.info("Started offline queue worker thread")
    
    def _process_offline_queue(self):
        """Process queued requests when connection is restored"""
        while self._queue_worker_running:
            try:
                if self._connected and not self._offline_queue.empty():
                    # Process queued items
                    processed = 0
                    while not self._offline_queue.empty() and processed < 10:  # Process in batches
                        try:
                            queued_item = self._offline_queue.get_nowait()
                            method = queued_item['method']
                            url = queued_item['url']
                            data = queued_item['data']
                            
                            success = self._make_request(method, url, data, queue_on_failure=False)
                            if success:
                                processed += 1
                                self.logger.debug(f"Successfully processed queued {method} request to {url}")
                            else:
                                # Put back in queue if still failing
                                if self._offline_queue.qsize() < self.max_queue_size:
                                    self._offline_queue.put(queued_item)
                                break  # Stop processing if requests are still failing
                                
                        except queue.Empty:
                            break
                    
                    if processed > 0:
                        self.logger.info(f"Processed {processed} queued requests")
                
                # Sleep before next check
                time.sleep(30)
                
            except Exception as e:
                self.logger.error(f"Error in offline queue worker: {e}")
                time.sleep(60)
    
    def _make_request(self, 
                     method: str, 
                     endpoint: str, 
                     data: Optional[Dict] = None,
                     queue_on_failure: bool = True) -> bool:
        """
        Make HTTP request with error handling and queuing
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path
            data: Request data
            queue_on_failure: Whether to queue request on failure
            
        Returns:
            True if request succeeded, False otherwise
        """
        url = urljoin(self.api_endpoint, endpoint)
        
        try:
            if method.upper() == 'GET':
                response = self._session.get(url, timeout=self.timeout)
            elif method.upper() == 'POST':
                response = self._session.post(url, json=data, timeout=self.timeout)
            elif method.upper() == 'PUT':
                response = self._session.put(url, json=data, timeout=self.timeout)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            response.raise_for_status()
            self._connected = True
            return True
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request failed: {method} {url} - {e}")
            self._connected = False
            
            # Queue request for retry if enabled
            if queue_on_failure and data is not None:
                try:
                    queued_item = {
                        'method': method,
                        'url': endpoint,
                        'data': data,
                        'timestamp': datetime.now()
                    }
                    self._offline_queue.put_nowait(queued_item)
                    self.logger.info(f"Queued failed request for retry: {method} {endpoint}")
                except queue.Full:
                    self.logger.warning("Offline queue is full, dropping request")
            
            return False
    
    def register_sensor(self, sensor_info: SensorInfo) -> Optional[str]:
        """
        Register sensor with Asgard platform
        
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
        
        success = self._make_request('POST', '/api/v1/sensors/register', registration_data)
        
        if success:
            self.logger.info(f"Successfully registered sensor {self.sensor_id}")
            return self.sensor_id
        else:
            self.logger.error(f"Failed to register sensor {self.sensor_id}")
            return None
    
    def send_anomaly_metadata(self, anonymized_anomaly: AnonymizedAnomaly) -> bool:
        """
        Send anonymized anomaly data to Asgard
        
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
        
        success = self._make_request('POST', '/api/v1/anomalies', anomaly_data)
        
        if success:
            self.logger.debug(f"Sent anomaly metadata for {anonymized_anomaly.device_type}")
        else:
            self.logger.warning(f"Failed to send anomaly metadata for {anonymized_anomaly.device_type}")
        
        return success
    
    def send_device_metadata(self, anonymized_device: AnonymizedDevice) -> bool:
        """
        Send anonymized device data to Asgard
        
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
        
        success = self._make_request('POST', '/api/v1/devices', device_data)
        
        if success:
            self.logger.debug(f"Sent device metadata for {anonymized_device.device_type}")
        else:
            self.logger.warning(f"Failed to send device metadata for {anonymized_device.device_type}")
        
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
        Check if connected to Asgard
        
        Returns:
            True if connected, False otherwise
        """
        # Perform connectivity check if we haven't checked recently
        now = datetime.now()
        if (self._last_connection_attempt is None or 
            now - self._last_connection_attempt > timedelta(seconds=self._connection_retry_delay)):
            
            self._last_connection_attempt = now
            self._check_connectivity()
        
        return self._connected
    
    def _check_connectivity(self):
        """Check connectivity to Asgard API"""
        try:
            url = urljoin(self.api_endpoint, '/api/v1/health')
            response = self._session.get(url, timeout=10)
            response.raise_for_status()
            self._connected = True
            self.logger.debug("Asgard connectivity check successful")
        except requests.exceptions.RequestException as e:
            self._connected = False
            self.logger.debug(f"Asgard connectivity check failed: {e}")
    
    def get_queue_status(self) -> Dict[str, Any]:
        """
        Get status of offline queue
        
        Returns:
            Dictionary with queue status information
        """
        return {
            'queue_size': self._offline_queue.qsize(),
            'max_queue_size': self.max_queue_size,
            'worker_running': self._queue_worker_running,
            'connected': self._connected,
            'last_connection_attempt': self._last_connection_attempt.isoformat() if self._last_connection_attempt else None
        }
    
    def shutdown(self):
        """Shutdown the communicator and cleanup resources"""
        self.logger.info("Shutting down Asgard communicator")
        
        # Stop queue worker
        self._queue_worker_running = False
        if self._queue_worker_thread and self._queue_worker_thread.is_alive():
            self._queue_worker_thread.join(timeout=5)
        
        # Close HTTP session
        if self._session:
            self._session.close()
        
        self.logger.info("Asgard communicator shutdown complete")