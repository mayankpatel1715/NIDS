"""
Packet Capture Module

This module provides functionality for capturing network packets using Scapy.
It supports both live capture from network interfaces and reading from PCAP files.

Dependencies:
    - scapy: For packet capture and manipulation
    - typing: For type hints
"""

from typing import Callable, Dict, Any, Union, List
from pathlib import Path
import time
import logging
import threading
from dataclasses import dataclass

try:
    from scapy.all import sniff, PcapReader, conf, get_if_list, rdpcap, PacketList
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.packet import Packet
except ImportError:
    raise ImportError("Scapy is required for this module. Install it using 'pip install scapy'.")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('packet_capturer')


@dataclass
class CaptureStatistics:
    """Statistics collected during packet capture."""
    total_packets: int = 0
    total_bytes: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    protocols: Dict[str, int] = None
    
    def __post_init__(self):
        """Initialize mutable default values."""
        if self.protocols is None:
            self.protocols = {}
    
    @property
    def duration(self) -> float:
        """Return the duration of the capture in seconds."""
        if self.end_time == 0.0:
            return time.time() - self.start_time
        return self.end_time - self.start_time
    
    @property
    def packets_per_second(self) -> float:
        """Return the average number of packets captured per second."""
        if self.duration == 0:
            return 0
        return self.total_packets / self.duration
    
    @property
    def bytes_per_second(self) -> float:
        """Return the average number of bytes captured per second."""
        if self.duration == 0:
            return 0
        return self.total_bytes / self.duration
    
    def update_from_packet(self, packet: Packet) -> None:
        """Update statistics based on a captured packet."""
        self.total_packets += 1
        self.total_bytes += len(packet)
        
        # Update protocol statistics
        if IP in packet:
            ip_layer = "IPv4"
            if packet[IP].proto == 6:  # TCP
                proto = "TCP"
            elif packet[IP].proto == 17:  # UDP
                proto = "UDP"
            else:
                proto = f"IP Protocol {packet[IP].proto}"
        else:
            # Non-IP packet (e.g., ARP, Ethernet)
            ip_layer = "Non-IP"
            proto = packet.name if hasattr(packet, 'name') else "Unknown"
        
        # Update protocol counts
        key = f"{ip_layer}/{proto}"
        self.protocols[key] = self.protocols.get(key, 0) + 1
    
    def __str__(self) -> str:
        """Return a human-readable string representation of the statistics."""
        if self.end_time == 0.0:
            self.end_time = time.time()
            
        result = [
            f"Capture Statistics:",
            f"  Duration: {self.duration:.2f} seconds",
            f"  Total Packets: {self.total_packets}",
            f"  Total Bytes: {self.total_bytes}",
            f"  Avg Packets/sec: {self.packets_per_second:.2f}",
            f"  Avg Bytes/sec: {self.bytes_per_second:.2f}",
            f"  Protocol Distribution:"
        ]
        
        for proto, count in sorted(self.protocols.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / self.total_packets) * 100 if self.total_packets > 0 else 0
            result.append(f"    {proto}: {count} ({percentage:.1f}%)")
            
        return "\n".join(result)


class PacketCapturer:
    """
    A class for capturing network packets using Scapy.
    
    This class provides methods to start and stop packet capture from a network
    interface or a PCAP file. It processes packets through a callback function
    and collects statistics about the captured packets.
    """
    
    def __init__(self, config: Dict[str, Any], callback: Callable[[Packet], None]):
        """
        Initialize the PacketCapturer with configuration and callback function.
        
        Args:
            config: A dictionary containing configuration for the packet capturer.
                Required keys depend on the capture mode:
                - For live capture:
                    - interface: Network interface to capture from (str)
                    - filter: BPF filter string (str, optional)
                    - count: Maximum number of packets to capture (int, optional)
                    - timeout: Timeout for capture in seconds (int, optional)
                - For file capture:
                    - input_file: Path to PCAP file (str)
            callback: A function that will be called for each captured packet.
                The function should accept a Scapy packet object as its argument.
        
        Raises:
            ValueError: If the configuration is invalid or missing required keys.
        """
        self.config = config
        self.callback = callback
        self.stats = CaptureStatistics()
        self.running = False
        self._capture_thread = None
        self._stop_event = threading.Event()
        
        # Validate configuration
        self._validate_config()
        
        # Set up logger
        self.logger = logger
    
    def _validate_config(self) -> None:
        """
        Validate the configuration dictionary.
        
        Raises:
            ValueError: If the configuration is invalid or missing required keys.
        """
        if 'input_file' in self.config:
            # File capture mode
            input_file = Path(self.config['input_file'])
            if not input_file.exists():
                raise ValueError(f"Input file does not exist: {input_file}")
        else:
            # Live capture mode
            if 'interface' not in self.config:
                raise ValueError("Interface must be specified for live capture")
            
            interface = self.config['interface']
            available_interfaces = get_if_list()
            
            if interface not in available_interfaces:
                raise ValueError(
                    f"Interface '{interface}' not found. Available interfaces: {', '.join(available_interfaces)}"
                )
    
    def start_capture(self) -> None:
        """
        Start capturing packets based on the configuration.
        
        For live capture, this starts a background thread for packet sniffing.
        For file capture, this processes the PCAP file synchronously.
        
        Raises:
            RuntimeError: If capture is already running.
        """
        if self.running:
            raise RuntimeError("Capture is already running")
        
        self.running = True
        self.stats = CaptureStatistics()
        self.stats.start_time = time.time()
        self._stop_event.clear()
        
        if 'input_file' in self.config:
            # File capture mode (synchronous)
            self._capture_from_file()
        else:
            # Live capture mode (asynchronous)
            self._capture_thread = threading.Thread(target=self._capture_from_interface)
            self._capture_thread.daemon = True
            self._capture_thread.start()
            self.logger.info(f"Started packet capture on interface {self.config['interface']}")
    
    def stop_capture(self) -> CaptureStatistics:
        """
        Stop the packet capture if it's running.
        
        Returns:
            CaptureStatistics: Statistics about the captured packets.
        
        Raises:
            RuntimeError: If capture is not running.
        """
        if not self.running:
            raise RuntimeError("Capture is not running")
        
        self._stop_event.set()
        
        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=3.0)
            if self._capture_thread.is_alive():
                self.logger.warning("Capture thread did not terminate gracefully")
        
        self.running = False
        self.stats.end_time = time.time()
        self.logger.info("Stopped packet capture")
        self.logger.info(str(self.stats))
        
        return self.stats
    
    def is_running(self) -> bool:
        """
        Check if packet capture is currently running.
        
        Returns:
            bool: True if capture is running, False otherwise.
        """
        return self.running
    
    def get_stats(self) -> CaptureStatistics:
        """
        Get current statistics about the packet capture.
        
        Returns:
            CaptureStatistics: Statistics about the captured packets.
        """
        return self.stats
    
    def _packet_handler(self, packet: Packet) -> None:
        """
        Process a captured packet: update statistics and call the user callback.
        
        Args:
            packet: The captured Scapy packet.
        """
        try:
            # Update statistics
            self.stats.update_from_packet(packet)
            
            # Call user-provided callback
            self.callback(packet)
                
        except Exception as e:
            self.logger.error(f"Error processing packet: {str(e)}")
    
    def _capture_from_interface(self) -> None:
        """
        Capture packets from a network interface using Scapy's sniff function.
        
        This method runs in a separate thread and can be stopped by setting
        the stop_event.
        """
        try:
            # Extract configuration
            interface = self.config['interface']
            bpf_filter = self.config.get('filter', '')
            count = self.config.get('count', 0)  # 0 means infinite
            timeout = self.config.get('timeout', None)
            
            # Set up parameters for sniff
            kwargs = {
                'iface': interface,
                'prn': self._packet_handler,
                'store': False,  # Don't store packets in memory
                'filter': bpf_filter if bpf_filter else None,
                'count': count if count > 0 else None,
                'timeout': timeout,
                'stop_filter': lambda _: self._stop_event.is_set()
            }
            
            # Remove None values
            kwargs = {k: v for k, v in kwargs.items() if v is not None}
            
            self.logger.info(f"Starting capture on {interface}" + 
                           (f" with filter: {bpf_filter}" if bpf_filter else ""))
            
            # Start sniffing
            sniff(**kwargs)
            
        except KeyboardInterrupt:
            self.logger.info("Capture stopped by keyboard interrupt")
        except Exception as e:
            self.logger.error(f"Error during packet capture: {str(e)}")
        finally:
            self.running = False
            self.stats.end_time = time.time()
    
    def _capture_from_file(self) -> None:
        """
        Read and process packets from a PCAP file.
        
        This method processes the file synchronously.
        """
        try:
            input_file = self.config['input_file']
            count = self.config.get('count', 0)  # 0 means all packets
            bpf_filter = self.config.get('filter', '')
            
            self.logger.info(f"Reading packets from file: {input_file}" +
                           (f" with filter: {bpf_filter}" if bpf_filter else ""))
            
            # Read the PCAP file
            packets = rdpcap(input_file)
            
            total = len(packets)
            processed = 0
            
            self.logger.info(f"Found {total} packets in file")
            
            # Process packets
            for packet in packets:
                if self._stop_event.is_set():
                    self.logger.info("Processing stopped by user")
                    break
                    
                # Apply BPF filter if provided
                if bpf_filter:
                    # Scapy doesn't provide a direct way to apply BPF to loaded packets
                    # This is a simplification - full BPF implementation would be complex
                    if not self._simple_filter_match(packet, bpf_filter):
                        continue
                
                self._packet_handler(packet)
                processed += 1
                
                if count > 0 and processed >= count:
                    break
            
            self.logger.info(f"Processed {processed} packets from file")
            
        except Exception as e:
            self.logger.error(f"Error processing PCAP file: {str(e)}")
        finally:
            self.running = False
            self.stats.end_time = time.time()
    
    def _simple_filter_match(self, packet: Packet, filter_str: str) -> bool:
        """
        A simple implementation to match packets against common filter patterns.
        
        This is NOT a full BPF implementation and only supports basic filters.
        
        Args:
            packet: The packet to check
            filter_str: A simplified filter string
            
        Returns:
            bool: True if the packet matches the filter, False otherwise
        """
        # This is a very simplified implementation that only handles a few common cases
        # A real implementation would parse and evaluate the BPF filter expression
        
        filter_str = filter_str.lower()
        
        # Check for TCP
        if "tcp" in filter_str and TCP in packet:
            return True
            
        # Check for UDP
        if "udp" in filter_str and UDP in packet:
            return True
            
        # Check for IP
        if "ip" in filter_str and IP in packet:
            # Check for specific IP addresses
            if "host" in filter_str:
                for host in filter_str.split("host")[1:]:
                    ip_addr = host.strip().split()[0]
                    if packet[IP].src == ip_addr or packet[IP].dst == ip_addr:
                        return True
                return False
            return True
            
        # Check for ports (very simplified)
        if "port" in filter_str and (TCP in packet or UDP in packet):
            for port_part in filter_str.split("port")[1:]:
                port_str = port_part.strip().split()[0]
                try:
                    port = int(port_str)
                    if TCP in packet:
                        if packet[TCP].sport == port or packet[TCP].dport == port:
                            return True
                    if UDP in packet:
                        if packet[UDP].sport == port or packet[UDP].dport == port:
                            return True
                except ValueError:
                    pass
            return False
            
        # If no specific filter or not recognized, consider it a match
        if not filter_str:
            return True
            
        # Default case - if we don't recognize the filter, let it through
        # This is a simplification; a real implementation would properly parse BPF
        return True

    @staticmethod
    def list_interfaces() -> List[str]:
        """
        Get a list of available network interfaces.
        
        Returns:
            List[str]: A list of interface names.
        """
        return get_if_list()
    
    @staticmethod
    def get_interface_info() -> Dict[str, Dict[str, Any]]:
        """
        Get detailed information about available interfaces.
        
        Returns:
            Dict[str, Dict[str, Any]]: A dictionary of interface information.
        """
        interfaces = {}
        for iface in get_if_list():
            # Get basic info from Scapy
            iface_obj = conf.ifaces.get(iface, None)
            if iface_obj:
                interfaces[iface] = {
                    'name': iface,
                    'mac': getattr(iface_obj, 'mac', 'Unknown'),
                    'ip': getattr(iface_obj, 'ip', 'Unknown'),
                    'description': str(iface_obj)
                }
            else:
                interfaces[iface] = {
                    'name': iface,
                    'description': 'Unknown'
                }
        return interfaces


# Example usage
if __name__ == "__main__":
    def example_callback(packet):
        """Example callback function that prints basic packet info."""
        print(f"Packet: {packet.summary()}")
    
    # Example configuration for live capture
    live_config = {
        'interface': get_if_list()[0],  # Use first available interface
        'filter': 'tcp port 80',  # Capture HTTP traffic
        'count': 10,  # Capture 10 packets
        'timeout': 30  # Stop after 30 seconds
    }
    
    # Example configuration for file capture
    file_config = {
        'input_file': 'example.pcap',
        'filter': 'tcp',
        'count': 100
    }
    
    try:
        # Create and start live capture
        print(f"Available interfaces: {', '.join(PacketCapturer.list_interfaces())}")
        capturer = PacketCapturer(live_config, example_callback)
        print("Starting packet capture...")
        capturer.start_capture()
        
        # Wait for capture to complete or be stopped
        try:
            while capturer.is_running():
                time.sleep(1)
                # Print live statistics every second
                stats = capturer.get_stats()
                print(f"Captured {stats.total_packets} packets ({stats.total_bytes} bytes)")
        except KeyboardInterrupt:
            print("Stopping capture...")
            capturer.stop_capture()
        
        # Print final statistics
        final_stats = capturer.get_stats()
        print(str(final_stats))
        
    except Exception as e:
        print(f"Error: {str(e)}")