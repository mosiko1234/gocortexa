"""
Main entry point for Heimdal real-time monitoring system
"""

import sys
import signal
import argparse
from pathlib import Path
from typing import Optional

from .config.manager import ConfigurationManager
from .orchestrator import MonitoringOrchestrator
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
            
            # Initialize and start orchestrator
            self.orchestrator = MonitoringOrchestrator(self.config_manager)
            success = self.orchestrator.start()
            
            if success:
                self._running = True
                print("Heimdal system started successfully")
            
            return success
            
        except Exception as e:
            print(f"Failed to start Heimdal system: {e}")
            return False
    
    def stop(self) -> bool:
        """Stop the Heimdal monitoring system"""
        try:
            if self.orchestrator:
                success = self.orchestrator.stop()
            else:
                success = True
            
            self._running = False
            print("Heimdal system stopped")
            return success
            
        except Exception as e:
            print(f"Error stopping Heimdal system: {e}")
            return False
    
    def is_running(self) -> bool:
        """Check if the system is running"""
        if self.orchestrator:
            return self.orchestrator.is_running()
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
    parser.add_argument(
        "--create-config",
        type=str,
        metavar="PATH",
        help="Create a default configuration file at the specified path"
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show system status (requires running instance)"
    )
    parser.add_argument(
        "--enable-auto-reload",
        action="store_true",
        help="Enable automatic configuration reload on file changes"
    )
    
    args = parser.parse_args()
    
    # Create default configuration if requested
    if args.create_config:
        config_manager = ConfigurationManager()
        if config_manager.export_config_template(args.create_config):
            print(f"Default configuration created at: {args.create_config}")
            sys.exit(0)
        else:
            print("Failed to create configuration file")
            sys.exit(1)
    
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
    
    # Show status if requested (this would need IPC in a real implementation)
    if args.status:
        print("Status checking not implemented in this version")
        print("This would require inter-process communication with a running instance")
        sys.exit(0)
    
    # Run the application
    app = HeimdallApplication(args.config)
    
    # Enable auto-reload if requested
    if args.enable_auto_reload:
        app.config_manager.enable_auto_reload()
    
    app.run()


if __name__ == "__main__":
    main()