#!/usr/bin/env python3
"""
Network Packet Capture Module

This module provides functionality to capture network packets using Scapy.
It supports both live capture from network interfaces and reading from PCAP files.
"""

import time
import os
from typing import Callable, Dict, Any, Optional, Union, List
from datetime import datetime
import logging
from pathlib import Path

try:
    from scapy.all import sniff, conf, PcapReader
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import Ether
    from scapy.packet import Packet
except ImportError:
    raise ImportError("Scapy is required for packet capture. Install it using: pip install scapy")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("PacketCapturer")

class PacketCapturer:
    """
    A class for capturing network packets using Scapy.
    
    This class provides methods to start and stop packet capture from a network
    interface or PCAP file, and processes each packet through a callback function.
    """
    
    def __init__(self, config: Dict[str, Any], packet_callback: Callable[[Packet], None]):
        """
        Initialize the PacketCapturer with configuration and callback function.
        
        Args:
            config: Dictionary containing configuration parameters:
                - interface: Network interface to capture from (e.g., 'eth0')
                - bpf_filter: Berkeley Packet Filter string (e.g., 'tcp port 80')
                - timeout: Capture timeout in seconds (0 for no timeout)
                - pcap_file: Path to PCAP file (if reading from file)
                - packet_count: Maximum number of packets to capture (0 for unlimited)
            packet_callback: Function to call for each captured packet
        """
        self.config = config
        self.packet_callback = packet_callback
        self.running = False
        self.stats = {
            "start_time": None,
            "end_time": None,
            "packet_count": 0,
            "bytes_captured": 0,
            "packets_per_second": 0,
            "bytes_per_second": 0,
            "protocol_counts": {
                "TCP": 0,
                "UDP": 0,
                "ICMP": 0,
                "Other": 0
            }
        }
        
        # Set default values if not in config
        self._set_default_config()
        
        logger.info(f"PacketCapturer initialized with interface: {self.config.get('interface', 'None')}")
        if self.config.get('pcap_file'):
            logger.info(f"Reading from PCAP file: {self.config['pcap_file']}")
    
    def _set_default_config(self) -> None:
        """Set default configuration values if not provided."""
        if 'interface' not in self.config and 'pcap_file' not in self.config:
            self.config['interface'] = conf.iface
            
        if 'bpf_filter' not in self.config:
            self.config['bpf_filter'] = ""
            
        if 'timeout' not in self.config:
            self.config['timeout'] = 0
            
        if 'packet_count' not in self.config:
            self.config['packet_count'] = 0
    
    def _process_packet(self, packet: Packet) -> None:
        """
        Process a captured packet: update statistics and call the callback.
        
        Args:
            packet: The captured Scapy packet
        """
        # Update packet statistics
        self.stats["packet_count"] += 1
        
        # Calculate packet size (in bytes)
        try:
            packet_size = len(packet)
            self.stats["bytes_captured"] += packet_size
        except Exception:
            pass
        
        # Update protocol statistics
        if packet.haslayer(TCP):
            self.stats["protocol_counts"]["TCP"] += 1
        elif packet.haslayer(UDP):
            self.stats["protocol_counts"]["UDP"] += 1
        elif packet.haslayer(IP) and packet[IP].proto == 1:  # ICMP
            self.stats["protocol_counts"]["ICMP"] += 1
        else:
            self.stats["protocol_counts"]["Other"] += 1
        
        # Call the provided callback function with the packet
        try:
            self.packet_callback(packet)
        except Exception as e:
            logger.error(f"Error in packet callback: {str(e)}")
    
    def start_capture(self) -> None:
        """
        Start capturing packets according to the configuration.
        If a PCAP file is specified, read from the file.
        Otherwise, capture live traffic from the specified interface.
        """
        if self.running:
            logger.warning("Packet capture is already running")
            return
        
        self.running = True
        self.stats["start_time"] = datetime.now()
        
        try:
            if self.config.get('pcap_file'):
                self._read_from_pcap()
            else:
                self._capture_live()
                
        except KeyboardInterrupt:
            logger.info("Packet capture stopped by user")
        except Exception as e:
            logger.error(f"Error during packet capture: {str(e)}")
        finally:
            self.stop_capture()
    
    def _capture_live(self) -> None:
        """Capture packets live from the network interface."""
        interface = self.config.get('interface')
        bpf_filter = self.config.get('bpf_filter', "")
        timeout = self.config.get('timeout', 0)
        packet_count = self.config.get('packet_count', 0)
        
        logger.info(f"Starting live capture on interface {interface}")
        if bpf_filter:
            logger.info(f"Using BPF filter: {bpf_filter}")
        
        # Start packet sniffing
        sniff(
            iface=interface,
            filter=bpf_filter,
            prn=self._process_packet,
            store=False,
            timeout=timeout if timeout > 0 else None,
            count=packet_count if packet_count > 0 else None,
            stop_filter=lambda p: not self.running
        )
    
    def _read_from_pcap(self) -> None:
        """Read packets from a PCAP file."""
        pcap_file = self.config.get('pcap_file')
        packet_count = self.config.get('packet_count', 0)
        
        if not os.path.exists(pcap_file):
            raise FileNotFoundError(f"PCAP file not found: {pcap_file}")
        
        logger.info(f"Reading packets from PCAP file: {pcap_file}")
        
        count = 0
        with PcapReader(pcap_file) as pcap_reader:
            for packet in pcap_reader:
                if not self.running:
                    break
                    
                self._process_packet(packet)
                count += 1
                
                if packet_count > 0 and count >= packet_count:
                    break
    
    def stop_capture(self) -> Dict[str, Any]:
        """
        Stop the packet capture and calculate final statistics.
        
        Returns:
            Dictionary containing capture statistics
        """
        if not self.running:
            return self.stats
        
        self.running = False
        self.stats["end_time"] = datetime.now()
        
        # Calculate overall statistics
        if self.stats["start_time"]:
            duration = (self.stats["end_time"] - self.stats["start_time"]).total_seconds()
            if duration > 0:
                self.stats["packets_per_second"] = self.stats["packet_count"] / duration
                self.stats["bytes_per_second"] = self.stats["bytes_captured"] / duration
        
        logger.info(f"Capture stopped. Captured {self.stats['packet_count']} packets "
                   f"({self.stats['bytes_captured']} bytes).")
        
        return self.stats
    
    def get_available_interfaces(self) -> List[str]:
        """
        Get a list of available network interfaces.
        
        Returns:
            List of interface names
        """
        return list(conf.ifaces.keys())
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get current capture statistics.
        
        Returns:
            Dictionary containing capture statistics
        """
        # Recalculate stats if capture is still running
        if self.running and self.stats["start_time"]:
            current_time = datetime.now()
            duration = (current_time - self.stats["start_time"]).total_seconds()
            if duration > 0:
                self.stats["packets_per_second"] = self.stats["packet_count"] / duration
                self.stats["bytes_per_second"] = self.stats["bytes_captured"] / duration
        
        return self.stats
    
    def save_to_pcap(self, output_file: Union[str, Path]) -> bool:
        """
        Save captured packets to a PCAP file.
        Note: This would require storing packets in memory, which is not
        implemented here to avoid memory issues with large captures.
        
        Args:
            output_file: Path to save the PCAP file
            
        Returns:
            Boolean indicating success or failure
        """
        logger.warning("Saving to PCAP is not implemented in this version "
                     "to avoid memory issues with large captures.")
        return False


# Usage example (only executed when run directly)
if __name__ == "__main__":
    def packet_handler(packet: Packet) -> None:
        """Example packet handler function."""
        summary = packet.summary()
        print(f"Captured: {summary}")
    
    # Example configuration
    example_config = {
        "interface": conf.iface,  # Default interface
        "bpf_filter": "tcp",      # Capture only TCP packets
        "timeout": 10,            # Capture for 10 seconds
        "packet_count": 0         # No packet limit
    }
    
    capturer = PacketCapturer(example_config, packet_handler)
    
    print(f"Available interfaces: {capturer.get_available_interfaces()}")
    print(f"Starting capture on interface: {example_config['interface']}")
    print("Press Ctrl+C to stop capture")
    
    capturer.start_capture()
    
    # Display final statistics
    stats = capturer.get_stats()
    print("\nCapture Statistics:")
    for key, value in stats.items():
        if key in ["start_time", "end_time"]:
            if value:
                print(f"{key}: {value.strftime('%Y-%m-%d %H:%M:%S')}")
        elif key == "protocol_counts":
            print(f"{key}:")
            for proto, count in value.items():
                print(f"  {proto}: {count}")
        else:
            print(f"{key}: {value}")