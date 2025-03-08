#!/usr/bin/env python3
"""
Network Intrusion Detection System (NIDS) - Main Application

This module serves as the entry point for the NIDS application.
It initializes components, handles configuration, and coordinates
the packet capture and analysis pipeline.
"""

import argparse
import json
import logging
import os
import signal
import sys
from typing import Dict, Any, Optional

# Import NIDS components
from feature_extractor.capture.packet_capturer import PacketCapturer
from feature_extractor.features.basic_features import BasicFeatureExtractor


class NIDSController:
    """
    Controller class that coordinates the NIDS components.
    
    This class acts as the central orchestrator for the NIDS application,
    initializing components, handling events, and managing the flow of data
    from packet capture through feature extraction.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the NIDS controller with configuration.
        
        Args:
            config: A dictionary containing the NIDS configuration
        """
        self.config = config
        self.logger = self._setup_logger()
        self.logger.info("Initializing NIDS Controller")
        
        # Initialize components
        self.feature_extractor = BasicFeatureExtractor()
        self.packet_capturer = PacketCapturer(
            config=self.config.get("capture", {}),
            callback=self.packet_handler
        )
        
        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        self.is_running = False
        self.packet_count = 0
        
        self.logger.info("NIDS Controller initialized successfully")
    
    def _setup_logger(self) -> logging.Logger:
        """
        Configure and return a logger based on configuration.
        
        Returns:
            A configured logger instance
        """
        log_config = self.config.get("logging", {})
        log_level = getattr(logging, log_config.get("level", "INFO"))
        log_format = log_config.get("format", 
                                    "%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        log_file = log_config.get("file")
        
        # Create logger
        logger = logging.getLogger("nids")
        logger.setLevel(log_level)
        
        # Create console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_handler.setFormatter(logging.Formatter(log_format))
        logger.addHandler(console_handler)
        
        # Create file handler if log file is specified
        if log_file:
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(log_level)
            file_handler.setFormatter(logging.Formatter(log_format))
            logger.addHandler(file_handler)
        
        return logger
    
    def packet_handler(self, packet) -> None:
        """
        Process a captured packet.
        
        This callback function is called by the PacketCapturer for each
        captured packet. It extracts features and performs analysis.
        
        Args:
            packet: A Scapy packet object
        """
        self.packet_count += 1
        
        try:
            # Extract basic features
            features = self.feature_extractor.extract_from_packet(packet)
            
            # Log packet information at debug level
            self.logger.debug(f"Packet {self.packet_count}: {features}")
            
            # Print features if verbose mode is enabled
            if self.config.get("general", {}).get("verbose", False):
                print(f"\nPacket {self.packet_count}:")
                for key, value in features.items():
                    print(f"  {key}: {value}")
        
        except Exception as e:
            self.logger.error(f"Error processing packet: {str(e)}")
    
    def start(self) -> None:
        """
        Start the NIDS application.
        
        This method initializes components and begins packet capture.
        """
        if self.is_running:
            self.logger.warning("NIDS is already running")
            return
        
        self.is_running = True
        self.logger.info("Starting NIDS")
        
        # Display startup information
        self._display_startup_info()
        
        try:
            # Start packet capture
            self.packet_capturer.start_capture()
            
        except Exception as e:
            self.logger.error(f"Error starting NIDS: {str(e)}")
            self.is_running = False
            raise
    
    def stop(self) -> None:
        """
        Stop the NIDS application.
        
        This method terminates packet capture and performs cleanup.
        """
        if not self.is_running:
            self.logger.warning("NIDS is not running")
            return
        
        self.logger.info("Stopping NIDS")
        
        try:
            # Stop packet capture
            self.packet_capturer.stop_capture()
            
            # Display summary
            self.logger.info(f"Processed {self.packet_count} packets")
            
        except Exception as e:
            self.logger.error(f"Error stopping NIDS: {str(e)}")
        
        self.is_running = False
    
    def _signal_handler(self, sig, frame) -> None:
        """
        Handle signals (SIGINT, SIGTERM) for graceful shutdown.
        
        Args:
            sig: Signal number
            frame: Current stack frame
        """
        signal_name = signal.Signals(sig).name
        self.logger.info(f"Received {signal_name} signal")
        self.stop()
        sys.exit(0)
    
    def _display_startup_info(self) -> None:
        """
        Display information about the NIDS configuration on startup.
        """
        capture_config = self.config.get("capture", {})
        interface = capture_config.get("interface", "unknown")
        mode = "Live capture" if not capture_config.get("pcap_file") else "PCAP analysis"
        
        self.logger.info(f"NIDS Startup Information:")
        self.logger.info(f"  Mode: {mode}")
        self.logger.info(f"  Interface: {interface}")
        self.logger.info(f"  Capture Filter: {capture_config.get('filter', 'none')}")
        
        # Additional configuration details can be added here


def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load and validate the configuration from a JSON file.
    
    Args:
        config_path: Path to the configuration file
        
    Returns:
        A dictionary containing the configuration
        
    Raises:
        FileNotFoundError: If the configuration file doesn't exist
        json.JSONDecodeError: If the configuration file is not valid JSON
    """
    try:
        with open(config_path, 'r') as config_file:
            config = json.load(config_file)
        
        # Validate required configuration sections
        required_sections = ["capture", "logging", "general"]
        for section in required_sections:
            if section not in config:
                config[section] = {}
        
        return config
    
    except FileNotFoundError:
        print(f"Error: Configuration file not found: {config_path}")
        sys.exit(1)
    
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in configuration file: {config_path}")
        sys.exit(1)


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.
    
    Returns:
        An object containing the parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="Network Intrusion Detection System (NIDS)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        "-c", "--config",
        default="config/settings.json",
        help="Path to the configuration file"
    )
    
    parser.add_argument(
        "-i", "--interface",
        help="Network interface to capture packets from (overrides config)"
    )
    
    parser.add_argument(
        "-f", "--file",
        help="PCAP file to read packets from (overrides config)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--filter",
        help="BPF filter for packet capture (overrides config)"
    )
    
    return parser.parse_args()


def main() -> None:
    """
    Main function that initializes and runs the NIDS application.
    """
    # Parse command-line arguments
    args = parse_arguments()
    
    # Load configuration
    config = load_config(args.config)
    
    # Override configuration with command-line arguments
    if args.interface:
        config["capture"]["interface"] = args.interface
    
    if args.file:
        config["capture"]["pcap_file"] = args.file
    
    if args.verbose:
        config["general"]["verbose"] = True
    
    if args.filter:
        config["capture"]["filter"] = args.filter
    
    # Initialize and start the NIDS controller
    controller = NIDSController(config)
    
    try:
        controller.start()
        
        # Keep the main thread alive
        while controller.is_running:
            signal.pause()
    
    except KeyboardInterrupt:
        # This will be caught by the signal handler
        pass
    
    except Exception as e:
        logging.error(f"Unhandled exception: {str(e)}")
        controller.stop()
        sys.exit(1)


if __name__ == "__main__":
    main()