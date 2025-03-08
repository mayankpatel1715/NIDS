#!/usr/bin/env python3
"""
Network Intrusion Detection System (NIDS)

Main entry point for the NIDS application that connects packet capture
and feature extraction modules.

Usage:
    python main.py -i eth0 -c config.json -m live
    python main.py -f capture.pcap -c config.json -m offline
"""

import os
import sys
import json
import time
import signal
import logging
import argparse
from datetime import datetime
from typing import Dict, Any, List, Optional
import threading

# Import from our package
from src.feature_extractor.capture import PacketCapturer, CaptureStatistics
try:
    from src.feature_extractor.features.basic_features import extract_basic_features
except ImportError:
    # Create a placeholder if the module doesn't exist yet
    def extract_basic_features(packet):
        return {"packet_size": len(packet)}

# Global variables for signal handling
running = True
capturer = None
stats_thread = None

# Default configuration
DEFAULT_CONFIG = {
    "logging": {
        "level": "INFO",
        "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        "file": "nids.log",
        "console": True
    },
    "capture": {
        "interface": None,
        "filter": "",
        "timeout": 0,
        "count": 0
    },
    "features": {
        "enabled": ["basic"],
        "save_path": "features.csv"
    },
    "system": {
        "stats_interval": 5
    }
}

def setup_logging(config: Dict[str, Any]) -> None:
    """
    Set up logging based on configuration.
    
    Args:
        config: Configuration dictionary containing logging settings
    """
    log_config = config.get("logging", {})
    log_level = getattr(logging, log_config.get("level", "INFO"))
    log_format = log_config.get("format", "%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    log_file = log_config.get("file")
    console_output = log_config.get("console", True)
    
    # Create logger
    logger = logging.getLogger()
    logger.setLevel(log_level)
    
    # Remove existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Create formatter
    formatter = logging.Formatter(log_format)
    
    # Add file handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    # Add console handler if enabled
    if console_output:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    logging.info("Logging initialized")

def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load configuration from a JSON file.
    
    Args:
        config_path: Path to the configuration file
        
    Returns:
        Configuration dictionary
    """
    try:
        if not os.path.exists(config_path):
            logging.warning(f"Configuration file {config_path} not found. Using default configuration.")
            return DEFAULT_CONFIG
            
        with open(config_path, 'r') as f:
            config = json.load(f)
            
        # Merge with default config to ensure all required fields exist
        merged_config = DEFAULT_CONFIG.copy()
        for section, values in config.items():
            if section in merged_config and isinstance(merged_config[section], dict):
                merged_config[section].update(values)
            else:
                merged_config[section] = values
                
        return merged_config
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON in configuration file: {config_path}")
        return DEFAULT_CONFIG
    except Exception as e:
        logging.error(f"Error loading configuration: {str(e)}")
        return DEFAULT_CONFIG

def validate_config(config: Dict[str, Any]) -> bool:
    """
    Validate the configuration.
    
    Args:
        config: Configuration dictionary
        
    Returns:
        True if configuration is valid, False otherwise
    """
    # Check required sections
    required_sections = ["logging", "capture", "features", "system"]
    for section in required_sections:
        if section not in config:
            logging.error(f"Missing required configuration section: {section}")
            return False
    
    # Validate capture configuration
    capture_config = config.get("capture", {})
    if not capture_config.get("interface") and not capture_config.get("input_file"):
        logging.warning("No capture interface or input file specified in config")
        # This is not a fatal error as it can be specified via command line
    
    return True

def parse_arguments() -> argparse.Namespace:
    """
    Parse command line arguments.
    
    Returns:
        Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description='Network Intrusion Detection System',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Capture options
    capture_group = parser.add_argument_group('Capture Options')
    capture_group.add_argument('-i', '--interface', type=str, help='Network interface to capture from')
    capture_group.add_argument('-f', '--file', type=str, help='PCAP file to read packets from')
    capture_group.add_argument('-b', '--bpf-filter', type=str, help='BPF filter string')
    
    # General options
    parser.add_argument('-c', '--config', type=str, default='settings.json', help='Path to configuration file')
    parser.add_argument('-m', '--mode', type=str, choices=['live', 'offline'], default='live', 
                        help='Operation mode: live (capture) or offline (read from file)')
    parser.add_argument('-o', '--output', type=str, help='Output file for extracted features')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-l', '--list-interfaces', action='store_true', help='List available network interfaces and exit')
    
    return parser.parse_args()

def signal_handler(sig, frame) -> None:
    """
    Handle signals for graceful shutdown.
    
    Args:
        sig: Signal number
        frame: Current stack frame
    """
    global running
    signal_name = signal.Signals(sig).name
    logging.info(f"Received {signal_name} signal. Shutting down...")
    running = False
    
    if capturer:
        logging.info("Stopping packet capture...")
        capturer.stop_capture()

def display_statistics(stats_interval: int) -> None:
    """
    Periodically display capture statistics.
    
    Args:
        stats_interval: Interval in seconds between statistics updates
    """
    global running, capturer
    
    while running and capturer:
        try:
            stats = capturer.get_stats()
            
            # Clear line and display statistics
            sys.stdout.write("\r\033[K")  # Clear line
            sys.stdout.write(
                f"Packets: {stats.total_packets} | "
                f"Bytes: {stats.total_bytes} | "
                f"Rate: {stats.packets_per_second:.2f} pkt/s, {stats.bytes_per_second/1024:.2f} KB/s"
            )
            sys.stdout.flush()
            
            time.sleep(stats_interval)
        except Exception as e:
            logging.error(f"Error displaying statistics: {str(e)}")
            break
    
    # Clear line on exit
    sys.stdout.write("\r\033[K")
    sys.stdout.flush()

def packet_callback(packet) -> None:
    """
    Process captured packets.
    
    Args:
        packet: Captured network packet
    """
    try:
        # Extract features from the packet
        features = extract_basic_features(packet)
        
        # Here you would typically:
        # 1. Store features for later analysis
        # 2. Perform real-time analysis
        # 3. Trigger alerts if suspicious activity is detected
        
        # For debugging in verbose mode
        logging.debug(f"Packet: {packet.summary()} | Features: {features}")
    except Exception as e:
        logging.error(f"Error processing packet: {str(e)}")

def main() -> int:
    """
    Main function.
    
    Returns:
        Exit code (0 for success, non-zero for error)
    """
    global running, capturer, stats_thread
    
    # Parse command line arguments
    args = parse_arguments()
    
    # List interfaces if requested
    if args.list_interfaces:
        try:
            interfaces = PacketCapturer.list_interfaces()
            print("Available network interfaces:")
            for interface in interfaces:
                print(f"  - {interface}")
            return 0
        except Exception as e:
            print(f"Error listing interfaces: {str(e)}")
            return 1
    
    # Load configuration
    config = load_config(args.config)
    
    # Set up logging
    setup_logging(config)
    
    # Set log level based on verbosity
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validate configuration
    if not validate_config(config):
        logging.error("Invalid configuration. Exiting.")
        return 1
    
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Configure packet capture
    capture_config = config["capture"].copy()
    
    # Command line arguments override configuration file
    if args.interface:
        capture_config["interface"] = args.interface
    if args.file:
        capture_config["input_file"] = args.file
    if args.bpf_filter:
        capture_config["filter"] = args.bpf_filter
    if args.output:
        config["features"]["save_path"] = args.output
    
    # Validate capture configuration
    if args.mode == "live" and "interface" not in capture_config:
        # List available interfaces
        interfaces = PacketCapturer.list_interfaces()
        logging.error(
            f"No interface specified for live capture. Use -i option.\n"
            f"Available interfaces: {', '.join(interfaces)}"
        )
        return 1
    elif args.mode == "offline" and "input_file" not in capture_config:
        logging.error("No input file specified for offline mode. Use -f option.")
        return 1
    
    try:
        # Create packet capturer
        logging.info("Initializing packet capturer...")
        capturer = PacketCapturer(capture_config, packet_callback)
        
        # Start statistics display thread
        stats_interval = config["system"]["stats_interval"]
        stats_thread = threading.Thread(target=display_statistics, args=(stats_interval,))
        stats_thread.daemon = True
        stats_thread.start()
        
        # Start capture
        logging.info(f"Starting packet capture in {args.mode} mode...")
        start_time = datetime.now()
        
        capturer.start_capture()
        
        # Main loop - in practice, the capture runs in its own thread
        # so this loop just keeps the main thread alive until signaled to stop
        while running:
            time.sleep(0.1)
        
    except KeyboardInterrupt:
        logging.info("Capture interrupted by user.")
    except Exception as e:
        logging.error(f"Error during capture: {str(e)}")
        return 1
    finally:
        # Clean up resources
        running = False
        
        if capturer:
            try:
                # Get final statistics
                stats = capturer.get_stats()
                logging.info(f"Capture completed. Final statistics:\n{stats}")
            except Exception as e:
                logging.error(f"Error getting final statistics: {str(e)}")
        
        # Wait for threads to finish
        if stats_thread and stats_thread.is_alive():
            try:
                stats_thread.join(timeout=1.0)
            except Exception:
                pass
        
        logging.info("NIDS shutdown complete.")
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 