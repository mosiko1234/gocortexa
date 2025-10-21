"""
Main entry point for Heimdal real-time monitoring system
"""

import sys
import signal
import argparse
from pathlib import Path
from typing import Optional

from .config.manager import ConfigurationManager
from .interfaces import IMonitoringOrchestrator


class HeimdallApplication:
    """Main application class for Heimdal monitoring system"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_manager = ConfigurationManager(config_path)
        self.orchestrator: Optional[IMonitoringOrchestrator] = None
        self._running = False
        
        # Set up signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print(f"\nReceived signal {signum}, shutting down gracefully...")
        self.stop()
    
    def start(self) -> bool:
        """Start the Heimdal monitoring system"""
        try:
            # Validate configuration
            config_errors = self.config_manager.validate_config()
            if config_errors:
                print("Configuration errors found:")
                for error in config_errors:
                    print(f"  - {error}")
                return False
            
            print("Starting Heimdal real-time monitoring system...")
            
            # TODO: Initialize orchestrator when implemented
            # self.orchestrator = MonitoringOrchestrator(self.config_manager)
            # return self.orchestrator.start()
            
            self._running = True
            print("Heimdal system started successfully")
            return True
            
        except Exception as e:
            print(f"Failed to start Heimdal system: {e}")
            return False
    
    def stop(self) -> bool:
        """Stop the Heimdal monitoring system"""
        try:
            if self.orchestrator:
                self.orchestrator.stop()
            
            self._running = False
            print("Heimdal system stopped")
            return True
            
        except Exception as e:
            print(f"Error stopping Heimdal system: {e}")
            return False
    
    def is_running(self) -> bool:
        """Check if the system is running"""
        return self._running
    
    def run(self) -> None:
        """Run the application until stopped"""
        if not self.start():
            sys.exit(1)
        
        try:
            # Keep the application running
            while self._running:
                import time
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Heimdal Real-time Network Monitoring")
    parser.add_argument(
        "--config", "-c",
        type=str,
        default="config/heimdal.yaml",
        help="Path to configuration file (default: config/heimdal.yaml)"
    )
    parser.add_argument(
        "--validate-config",
        action="store_true",
        help="Validate configuration and exit"
    )
    
    args = parser.parse_args()
    
    # Validate configuration if requested
    if args.validate_config:
        config_manager = ConfigurationManager(args.config)
        errors = config_manager.validate_config()
        
        if errors:
            print("Configuration validation failed:")
            for error in errors:
                print(f"  - {error}")
            sys.exit(1)
        else:
            print("Configuration is valid")
            sys.exit(0)
    
    # Run the application
    app = HeimdallApplication(args.config)
    app.run()


if __name__ == "__main__":
    main()