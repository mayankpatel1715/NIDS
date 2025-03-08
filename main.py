#!/usr/bin/env python3
"""
NIDS - Network Intrusion Detection System

Main entry point for the NIDS application.
"""

import sys
import logging
import argparse
from datetime import datetime

# Import from our package
from src.feature_extractor.capture import PacketCapturer, CaptureStatistics

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('nids')

def packet_callback(packet):
    """Callback function for processing captured packets."""
    logger.debug(f"Packet received: {packet.summary()}")
    # Here you would typically extract features and analyze the packet

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Network Intrusion Detection System')
    
    parser.add_argument('-i', '--interface', type=str, help='Network interface to capture from')
    parser.add_argument('-f', '--file', type=str, help='PCAP file to read packets from')
    parser.add_argument('-c', '--count', type=int, default=0, help='Number of packets to capture (0 for unlimited)')
    parser.add_argument('-t', '--timeout', type=int, default=0, help='Capture timeout in seconds (0 for no timeout)')
    parser.add_argument('-b', '--bpf-filter', type=str, default='', help='BPF filter string')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    return parser.parse_args()

def main():
    """Main function."""
    args = parse_arguments()
    
    # Set log level based on verbosity
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Configure packet capture
    config = {}
    
    if args.file:
        config['input_file'] = args.file
        logger.info(f"Reading packets from file: {args.file}")
    elif args.interface:
        config['interface'] = args.interface
        logger.info(f"Capturing from interface: {args.interface}")
    else:
        # List available interfaces
        interfaces = PacketCapturer.list_interfaces()
        logger.info(f"Available interfaces: {', '.join(interfaces)}")
        logger.error("No interface or file specified. Use -i or -f option.")
        return 1
    
    # Add other configuration options
    if args.count > 0:
        config['count'] = args.count
    if args.timeout > 0:
        config['timeout'] = args.timeout
    if args.bpf_filter:
        config['filter'] = args.bpf_filter
    
    try:
        # Create packet capturer
        capturer = PacketCapturer(config, packet_callback)
        
        # Start capture
        logger.info("Starting packet capture...")
        start_time = datetime.now()
        capturer.start_capture()
        
        # Get and display statistics
        stats = capturer.get_stats()
        logger.info(f"Capture completed. Statistics:\n{stats}")
        
    except KeyboardInterrupt:
        logger.info("Capture interrupted by user.")
    except Exception as e:
        logger.error(f"Error during capture: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 