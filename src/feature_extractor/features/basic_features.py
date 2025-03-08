"""
Basic Feature Extraction Module

This module provides functionality for extracting fundamental features from network packets 
using Scapy. It handles various packet types including TCP, UDP, ICMP, and supports both
IPv4 and IPv6 packets.

Dependencies:
    - scapy: For packet parsing and manipulation
    - typing: For type hints
    - datetime: For timestamp handling
"""

from typing import Dict, Any, Optional, List, Tuple, Union
import logging
import datetime
from ipaddress import IPv4Address, IPv6Address, ip_address

try:
    from scapy.all import IP, IPv6, TCP, UDP, ICMP, ICMPv6, ARP, Ether, Packet, Raw
    from scapy.layers.inet import IPOptions
    from scapy.layers.inet6 import IPv6ExtHdrRouting, IPv6ExtHdrFragment, IPv6ExtHdrHopByHop
except ImportError:
    raise ImportError("Scapy is required for this module. Install it using 'pip install scapy'.")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('basic_features')


class BasicFeatureExtractor:
    """
    A class for extracting basic features from network packets.
    
    This class processes individual packets and extracts fundamental network features
    such as IP addresses, ports, protocol information, packet lengths, flags, etc.
    """
    
    # Protocol mapping for common IP protocols
    PROTOCOL_MAP = {
        0: "HOPOPT",
        1: "ICMP",
        2: "IGMP",
        6: "TCP",
        17: "UDP",
        41: "IPv6",
        43: "IPv6-Route",
        44: "IPv6-Frag",
        47: "GRE",
        50: "ESP",
        51: "AH",
        58: "IPv6-ICMP",
        59: "IPv6-NoNxt",
        60: "IPv6-Opts",
        89: "OSPF",
        132: "SCTP"
    }
    
    # TCP flags mapping
    TCP_FLAGS = {
        'F': 'FIN',
        'S': 'SYN',
        'R': 'RST',
        'P': 'PSH',
        'A': 'ACK',
        'U': 'URG',
        'E': 'ECE',
        'C': 'CWR'
    }
    
    def __init__(self, include_raw_payload: bool = False, include_hex_payload: bool = False):
        """
        Initialize the BasicFeatureExtractor with configuration options.
        
        Args:
            include_raw_payload: Whether to include the raw payload in the extracted features
            include_hex_payload: Whether to include the hex-encoded payload in the extracted features
        """
        self.include_raw_payload = include_raw_payload
        self.include_hex_payload = include_hex_payload
        self.logger = logger
    
    def extract_features(self, packet: Packet) -> Dict[str, Any]:
        """
        Extract basic features from a network packet.
        
        Args:
            packet: A Scapy packet object
            
        Returns:
            Dict[str, Any]: A dictionary containing extracted features
        """
        try:
            # Initialize features dictionary with timestamp
            features = self._extract_timestamp(packet)
            
            # Extract basic Ethernet features if available
            if Ether in packet:
                features.update(self._extract_ethernet_features(packet))
            
            # Extract IP features (IPv4 or IPv6)
            if IP in packet:
                features.update(self._extract_ipv4_features(packet))
            elif IPv6 in packet:
                features.update(self._extract_ipv6_features(packet))
            else:
                features['ip_version'] = None
            
            # Extract transport layer features
            if TCP in packet:
                features.update(self._extract_tcp_features(packet))
            elif UDP in packet:
                features.update(self._extract_udp_features(packet))
            elif ICMP in packet:
                features.update(self._extract_icmp_features(packet))
            elif ICMPv6 in packet:
                features.update(self._extract_icmpv6_features(packet))
            elif ARP in packet:
                features.update(self._extract_arp_features(packet))
            
            # Extract payload features
            features.update(self._extract_payload_features(packet))
            
            # Calculate packet lengths
            features.update(self._calculate_packet_lengths(packet))
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting features: {str(e)}")
            # Return basic information even if extraction fails
            return {
                'timestamp': datetime.datetime.now().isoformat(),
                'error': str(e),
                'packet_summary': packet.summary() if hasattr(packet, 'summary') else 'Unknown packet'
            }
    
    def _extract_timestamp(self, packet: Packet) -> Dict[str, Any]:
        """
        Extract timestamp information from the packet.
        
        Args:
            packet: A Scapy packet object
            
        Returns:
            Dict[str, Any]: Dictionary with timestamp features
        """
        features = {}
        
        # Get packet timestamp if available
        if hasattr(packet, 'time'):
            packet_time = packet.time
            features['timestamp'] = packet_time
            features['timestamp_iso'] = datetime.datetime.fromtimestamp(packet_time).isoformat()
        else:
            # Use current time if packet doesn't have a timestamp
            current_time = datetime.datetime.now()
            features['timestamp'] = current_time.timestamp()
            features['timestamp_iso'] = current_time.isoformat()
        
        return features
    
    def _extract_ethernet_features(self, packet: Packet) -> Dict[str, Any]:
        """
        Extract Ethernet layer features.
        
        Args:
            packet: A Scapy packet object with Ethernet layer
            
        Returns:
            Dict[str, Any]: Dictionary with Ethernet features
        """
        features = {}
        
        eth = packet[Ether]
        features['eth_src'] = eth.src
        features['eth_dst'] = eth.dst
        features['eth_type'] = eth.type
        
        return features
    
    def _extract_ipv4_features(self, packet: Packet) -> Dict[str, Any]:
        """
        Extract IPv4 features from the packet.
        
        Args:
            packet: A Scapy packet object with IPv4 layer
            
        Returns:
            Dict[str, Any]: Dictionary with IPv4 features
        """
        features = {}
        ip = packet[IP]
        
        # Basic IP information
        features['ip_version'] = 4
        features['src_ip'] = ip.src
        features['dst_ip'] = ip.dst
        features['protocol'] = ip.proto
        features['protocol_name'] = self.PROTOCOL_MAP.get(ip.proto, f"Unknown ({ip.proto})")
        
        # TTL and other IP header fields
        features['ttl'] = ip.ttl
        features['ip_id'] = ip.id
        features['ip_ihl'] = ip.ihl
        features['ip_tos'] = ip.tos
        features['ip_len'] = ip.len
        
        # IP Flags
        ip_flags = []
        if ip.flags:
            flag_value = int(ip.flags)
            if flag_value & 0x1:  # Reserved bit
                ip_flags.append('RB')
            if flag_value & 0x2:  # Don't Fragment
                ip_flags.append('DF')
            if flag_value & 0x4:  # More Fragments
                ip_flags.append('MF')
        
        features['ip_flags'] = ip_flags
        features['ip_frag'] = ip.frag
        
        # IP Options
        ip_options = []
        if ip.options:
            for option in ip.options:
                if isinstance(option, tuple) and len(option) >= 2:
                    opt_name, opt_value = option[0], option[1]
                    ip_options.append(f"{opt_name}:{opt_value}")
                else:
                    ip_options.append(str(option))
        
        features['ip_options'] = ip_options
        
        # Try to get geographical information from IP (placeholder)
        features['src_country'] = None  # Would require external geolocation database
        features['dst_country'] = None  # Would require external geolocation database
        
        return features
    
    def _extract_ipv6_features(self, packet: Packet) -> Dict[str, Any]:
        """
        Extract IPv6 features from the packet.
        
        Args:
            packet: A Scapy packet object with IPv6 layer
            
        Returns:
            Dict[str, Any]: Dictionary with IPv6 features
        """
        features = {}
        ipv6 = packet[IPv6]
        
        # Basic IPv6 information
        features['ip_version'] = 6
        features['src_ip'] = ipv6.src
        features['dst_ip'] = ipv6.dst
        features['next_header'] = ipv6.nh
        features['protocol_name'] = self.PROTOCOL_MAP.get(ipv6.nh, f"Unknown ({ipv6.nh})")
        
        # IPv6 specific fields
        features['hop_limit'] = ipv6.hlim  # IPv6 equivalent of TTL
        features['traffic_class'] = ipv6.tc
        features['flow_label'] = ipv6.fl
        
        # Check for IPv6 extension headers
        features['has_routing_header'] = 1 if IPv6ExtHdrRouting in packet else 0
        features['has_fragment_header'] = 1 if IPv6ExtHdrFragment in packet else 0
        features['has_hopbyhop_header'] = 1 if IPv6ExtHdrHopByHop in packet else 0
        
        # Try to get geographical information from IP (placeholder)
        features['src_country'] = None  # Would require external geolocation database
        features['dst_country'] = None  # Would require external geolocation database
        
        return features
    
    def _extract_tcp_features(self, packet: Packet) -> Dict[str, Any]:
        """
        Extract TCP features from the packet.
        
        Args:
            packet: A Scapy packet object with TCP layer
            
        Returns:
            Dict[str, Any]: Dictionary with TCP features
        """
        features = {}
        tcp = packet[TCP]
        
        # Basic TCP information
        features['transport_protocol'] = 'TCP'
        features['src_port'] = tcp.sport
        features['dst_port'] = tcp.dport
        features['tcp_seq'] = tcp.seq
        features['tcp_ack'] = tcp.ack
        features['tcp_dataofs'] = tcp.dataofs
        features['tcp_window'] = tcp.window
        features['tcp_urgptr'] = tcp.urgptr
        
        # TCP Flags
        flag_str = tcp.flags.value if hasattr(tcp.flags, 'value') else str(tcp.flags)
        tcp_flags_list = []
        
        for flag_char, flag_name in self.TCP_FLAGS.items():
            if flag_char in flag_str:
                tcp_flags_list.append(flag_name)
        
        features['tcp_flags'] = tcp_flags_list
        
        # TCP Options
        tcp_options = []
        if tcp.options:
            for option in tcp.options:
                if isinstance(option, tuple) and len(option) >= 2:
                    opt_name, opt_value = option[0], option[1]
                    tcp_options.append(f"{opt_name}:{opt_value}")
                else:
                    tcp_options.append(str(option))
        
        features['tcp_options'] = tcp_options
        
        # Service identification based on port (placeholder)
        features['service'] = self._identify_service(tcp.sport, tcp.dport, 'TCP')
        
        return features
    
    def _extract_udp_features(self, packet: Packet) -> Dict[str, Any]:
        """
        Extract UDP features from the packet.
        
        Args:
            packet: A Scapy packet object with UDP layer
            
        Returns:
            Dict[str, Any]: Dictionary with UDP features
        """
        features = {}
        udp = packet[UDP]
        
        # Basic UDP information
        features['transport_protocol'] = 'UDP'
        features['src_port'] = udp.sport
        features['dst_port'] = udp.dport
        features['udp_len'] = udp.len
        features['udp_chksum'] = udp.chksum
        
        # Service identification based on port (placeholder)
        features['service'] = self._identify_service(udp.sport, udp.dport, 'UDP')
        
        return features
    
    def _extract_icmp_features(self, packet: Packet) -> Dict[str, Any]:
        """
        Extract ICMP features from the packet.
        
        Args:
            packet: A Scapy packet object with ICMP layer
            
        Returns:
            Dict[str, Any]: Dictionary with ICMP features
        """
        features = {}
        icmp = packet[ICMP]
        
        # Basic ICMP information
        features['transport_protocol'] = 'ICMP'
        features['icmp_type'] = icmp.type
        features['icmp_code'] = icmp.code
        features['icmp_chksum'] = icmp.chksum
        
        # Interpret ICMP type and code
        icmp_type_str = "Unknown"
        
        # Common ICMP types
        icmp_types = {
            0: "Echo Reply",
            3: "Destination Unreachable",
            4: "Source Quench",
            5: "Redirect",
            8: "Echo Request",
            11: "Time Exceeded",
            12: "Parameter Problem",
            13: "Timestamp",
            14: "Timestamp Reply",
            15: "Information Request",
            16: "Information Reply"
        }
        
        features['icmp_type_str'] = icmp_types.get(icmp.type, f"Unknown ({icmp.type})")
        
        # Special handling for Echo Request/Reply
        if icmp.type in [0, 8]:
            if hasattr(icmp, 'id'):
                features['icmp_id'] = icmp.id
            if hasattr(icmp, 'seq'):
                features['icmp_seq'] = icmp.seq
        
        return features
    
    def _extract_icmpv6_features(self, packet: Packet) -> Dict[str, Any]:
        """
        Extract ICMPv6 features from the packet.
        
        Args:
            packet: A Scapy packet object with ICMPv6 layer
            
        Returns:
            Dict[str, Any]: Dictionary with ICMPv6 features
        """
        features = {}
        icmpv6 = packet[ICMPv6]
        
        # Basic ICMPv6 information
        features['transport_protocol'] = 'ICMPv6'
        features['icmpv6_type'] = icmpv6.type
        features['icmpv6_code'] = icmpv6.code
        features['icmpv6_cksum'] = icmpv6.cksum
        
        # Interpret ICMPv6 type
        icmpv6_types = {
            1: "Destination Unreachable",
            2: "Packet Too Big",
            3: "Time Exceeded",
            4: "Parameter Problem",
            128: "Echo Request",
            129: "Echo Reply",
            130: "Multicast Listener Query",
            131: "Multicast Listener Report",
            132: "Multicast Listener Done",
            133: "Router Solicitation",
            134: "Router Advertisement",
            135: "Neighbor Solicitation",
            136: "Neighbor Advertisement",
            137: "Redirect Message"
        }
        
        features['icmpv6_type_str'] = icmpv6_types.get(icmpv6.type, f"Unknown ({icmpv6.type})")
        
        return features
    
    def _extract_arp_features(self, packet: Packet) -> Dict[str, Any]:
        """
        Extract ARP features from the packet.
        
        Args:
            packet: A Scapy packet object with ARP layer
            
        Returns:
            Dict[str, Any]: Dictionary with ARP features
        """
        features = {}
        arp = packet[ARP]
        
        # Basic ARP information
        features['transport_protocol'] = 'ARP'
        features['arp_hwtype'] = arp.hwtype
        features['arp_ptype'] = arp.ptype
        features['arp_hwlen'] = arp.hwlen
        features['arp_plen'] = arp.plen
        features['arp_op'] = arp.op
        
        # ARP operation type
        arp_op_types = {
            1: "who-has",
            2: "is-at",
            3: "RARP-req",
            4: "RARP-rep",
            5: "Dyn-RARP-req",
            6: "Dyn-RARP-rep",
            7: "Dyn-RARP-err",
            8: "InARP-req",
            9: "InARP-rep"
        }
        features['arp_op_str'] = arp_op_types.get(arp.op, f"Unknown ({arp.op})")
        
        # ARP addresses
        features['arp_hwsrc'] = arp.hwsrc
        features['arp_hwdst'] = arp.hwdst
        features['arp_psrc'] = arp.psrc
        features['arp_pdst'] = arp.pdst
        
        return features
    
    def _extract_payload_features(self, packet: Packet) -> Dict[str, Any]:
        """
        Extract features from the packet payload.
        
        Args:
            packet: A Scapy packet object
            
        Returns:
            Dict[str, Any]: Dictionary with payload features
        """
        features = {}
        
        # Try to extract payload
        payload = None
        payload_layer = None
        
        # Check for Raw layer
        if Raw in packet:
            payload = packet[Raw].load
            payload_layer = 'Raw'
        
        # Check other common payload situations
        elif TCP in packet and hasattr(packet[TCP], 'payload'):
            payload = bytes(packet[TCP].payload)
            payload_layer = 'TCP'
        elif UDP in packet and hasattr(packet[UDP], 'payload'):
            payload = bytes(packet[UDP].payload)
            payload_layer = 'UDP'
        
        # Store payload information
        features['has_payload'] = 1 if payload else 0
        features['payload_size'] = len(payload) if payload else 0
        features['payload_layer'] = payload_layer
        
        # Include actual payload if requested
        if payload and self.include_raw_payload:
            # Try to decode as UTF-8, fallback to binary
            try:
                features['payload'] = payload.decode('utf-8', errors='replace')
            except (AttributeError, UnicodeDecodeError):
                features['payload'] = payload
        
        # Include hex payload if requested
        if payload and self.include_hex_payload:
            try:
                features['payload_hex'] = payload.hex()
            except AttributeError:
                features['payload_hex'] = None
        
        return features
    
    def _calculate_packet_lengths(self, packet: Packet) -> Dict[str, int]:
        """
        Calculate various packet length measurements.
        
        Args:
            packet: A Scapy packet object
            
        Returns:
            Dict[str, int]: Dictionary with length measurements
        """
        features = {}
        
        # Total packet length
        features['packet_len'] = len(packet)
        
        # Layer-specific lengths
        if IP in packet:
            features['ip_header_len'] = packet[IP].ihl * 4
            features['ip_total_len'] = packet[IP].len
        elif IPv6 in packet:
            # IPv6 has a fixed header length of 40 bytes
            features['ip_header_len'] = 40
            features['ip_total_len'] = 40 + packet[IPv6].plen
        
        # Transport layer lengths
        if TCP in packet:
            features['transport_header_len'] = packet[TCP].dataofs * 4
        elif UDP in packet:
            features['transport_header_len'] = 8  # UDP header is always 8 bytes
        elif ICMP in packet:
            features['transport_header_len'] = 8  # Basic ICMP header is 8 bytes
        
        # Calculate header and payload sizes
        header_len = 0
        if 'ip_header_len' in features:
            header_len += features['ip_header_len']
        if 'transport_header_len' in features:
            header_len += features['transport_header_len']
        
        features['header_len'] = header_len
        features['payload_len'] = features['packet_len'] - header_len if header_len > 0 else 0
        
        return features
    
    def _identify_service(self, src_port: int, dst_port: int, protocol: str) -> Optional[str]:
        """
        Identify the service based on port numbers and protocol.
        
        Args:
            src_port: Source port number
            dst_port: Destination port number
            protocol: Transport protocol ('TCP' or 'UDP')
            
        Returns:
            Optional[str]: Identified service or None
        """
        # Common port to service mapping
        well_known_ports = {
            'TCP': {
                20: 'FTP-DATA',
                21: 'FTP',
                22: 'SSH',
                23: 'TELNET',
                25: 'SMTP',
                53: 'DNS',
                80: 'HTTP',
                110: 'POP3',
                143: 'IMAP',
                443: 'HTTPS',
                465: 'SMTPS',
                587: 'SUBMISSION',
                993: 'IMAPS',
                995: 'POP3S',
                3306: 'MYSQL',
                3389: 'RDP',
                5432: 'POSTGRESQL',
                8080: 'HTTP-ALT'
            },
            'UDP': {
                53: 'DNS',
                67: 'DHCP-SERVER',
                68: 'DHCP-CLIENT',
                69: 'TFTP',
                123: 'NTP',
                161: 'SNMP',
                162: 'SNMP-TRAP',
                514: 'SYSLOG',
                1900: 'SSDP',
                5353: 'MDNS'
            }
        }
        
        # Check if either port matches a well-known service
        if protocol in well_known_ports:
            if src_port in well_known_ports[protocol]:
                return well_known_ports[protocol][src_port]
            if dst_port in well_known_ports[protocol]:
                return well_known_ports[protocol][dst_port]
        
        # No match found
        return None


# Utility functions for direct feature extraction

def extract_ip_addresses(packet: Packet) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract source and destination IP addresses from a packet.
    
    Args:
        packet: A Scapy packet object
        
    Returns:
        Tuple[Optional[str], Optional[str]]: Source and destination IP addresses
    """
    src_ip, dst_ip = None, None
    
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    elif IPv6 in packet:
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
    elif ARP in packet:
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst
    
    return src_ip, dst_ip


def extract_ports(packet: Packet) -> Tuple[Optional[int], Optional[int]]:
    """
    Extract source and destination port numbers from a packet.
    
    Args:
        packet: A Scapy packet object
        
    Returns:
        Tuple[Optional[int], Optional[int]]: Source and destination ports
    """
    src_port, dst_port = None, None
    
    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    
    return src_port, dst_port


def identify_protocol(packet: Packet) -> str:
    """
    Identify the highest level protocol in the packet.
    
    Args:
        packet: A Scapy packet object
        
    Returns:
        str: Protocol name
    """
    if TCP in packet:
        return "TCP"
    elif UDP in packet:
        return "UDP"
    elif ICMP in packet:
        return "ICMP"
    elif ICMPv6 in packet:
        return "ICMPv6"
    elif IP in packet:
        proto_num = packet[IP].proto
        protocol_map = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
            47: "GRE",
            50: "ESP",
            51: "AH",
            89: "OSPF",
            132: "SCTP"
        }
        return protocol_map.get(proto_num, f"IP-{proto_num}")
    elif IPv6 in packet:
        next_header = packet[IPv6].nh
        protocol_map = {
            6: "TCP",
            17: "UDP",
            58: "ICMPv6",
            43: "IPv6-Route",
            44: "IPv6-Frag",
            50: "ESP",
            51: "AH"
        }
        return protocol_map.get(next_header, f"IPv6-{next_header}")
    elif ARP in packet:
        return "ARP"
    elif Ether in packet:
        return "Ethernet"
    else:
        return "Unknown"


def get_packet_lengths(packet: Packet) -> Dict[str, int]:
    """
    Calculate various packet length measurements.
    
    Args:
        packet: A Scapy packet object
        
    Returns:
        Dict[str, int]: Dictionary with length measurements
    """
    lengths = {
        'total': len(packet),
        'header': 0,
        'payload': 0
    }
    
    # Calculate header lengths
    if IP in packet:
        lengths['header'] += packet[IP].ihl * 4
    elif IPv6 in packet:
        lengths['header'] += 40  # IPv6 has a fixed header length of 40 bytes
    
    if TCP in packet:
        lengths['header'] += packet[TCP].dataofs * 4
    elif UDP in packet:
        lengths['header'] += 8  # UDP header is always 8 bytes
    elif ICMP in packet:
        lengths['header'] += 8  # Basic ICMP header is 8 bytes
    
    # Calculate payload length
    lengths['payload'] = lengths['total'] - lengths['header']
    
    return lengths


def extract_ttl(packet: Packet) -> Optional[int]:
    """
    Extract Time To Live (TTL) or Hop Limit value from a packet.
    
    Args:
        packet: A Scapy packet object
        
    Returns:
        Optional[int]: TTL/Hop Limit value or None
    """
    if IP in packet:
        return packet[IP].ttl
    elif IPv6 in packet:
        return packet[IPv6].hlim
    return None


def extract_ip_flags(packet: Packet) -> List[str]:
    """
    Extract IP flags from a packet.
    
    Args:
        packet: A Scapy packet object
        
    Returns:
        List[str]: List of flag names
    """
    flags = []
    
    if IP in packet:
        flag_value = int(packet[IP].flags)
        if flag_value & 0x1:  # Reserved bit
            flags.append('RB')
        if flag_value & 0x2:  # Don't Fragment
            flags.append('DF')
        if flag_value & 0x4:  # More Fragments
            flags.append('MF')
    
    return flags


def extract_tcp_flags(packet: Packet) -> List[str]:
    """
    Extract TCP flags from a packet.
    
    Args:
        packet: A Scapy packet object
        
    Returns:
        List[str]: List of flag names
    """
    flags = []
    
    if TCP in packet:
        flag_str = packet[TCP].flags.value if hasattr(packet[TCP].flags, 'value') else str(packet[TCP].flags)
        
        # Common TCP flags
        flag_map = {
            'F': 'FIN',
            'S': 'SYN',
            'R': 'RST',
            'P': 'PSH',
            'A': 'ACK',
            'U': 'URG',
            'E': 'ECE',
            'C': 'CWR'
        }
        
        for flag_char, flag_name in flag_map.items():
            if flag_char in flag_str:
                flags.append(flag_name)
    
    return flags


def get_packet_timestamp(packet: Packet) -> Optional[float]:
    """
    Get the timestamp of a packet.
    
    Args:
        packet: A Scapy packet object
        
    Returns:
        Optional[float]: Timestamp as a float or None
    """
    if hasattr(packet, 'time'):
        return packet.time
    return None


# Example usage
if __name__ == "__main__":
    from scapy.all import rdpcap
    
    def print_packet_features(packet):
        """Print extracted features for a packet."""
        extractor = BasicFeatureExtractor(include_hex_payload=True)
        features = extractor.extract_features(packet)
        
        print("\n" + "="*80)
        print(f"Packet: {packet.summary()}")
        print("="*80)
        
        for key, value in features.items():
            print(f"{key}: {value}")
    
    # Example 1: Process a packet capture file
    try:
        packets = rdpcap("example.pcap")
        if packets:
            # Process first 5 packets
            for i, packet in enumerate(packets[:5]):
                print_packet_features(packet)
                if i >= 4:
                    break
    except Exception as e:
        print(f"Error processing PCAP file: {e}")
        
        # Example 2: Create a sample packet and process it
        from scapy.all import IP, TCP, Raw
        
        sample_packet = IP(src="192.168.1.1", dst="10.0.0.1")/TCP(sport=12345, dport=80, flags="S")/Raw(load="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        print_packet_features(sample_packet)