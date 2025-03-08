#!/usr/bin/env python3
"""
Basic Feature Extraction Module

This module provides functionality to extract fundamental features from network packets
captured by Scapy. It handles different packet types and provides normalized features
suitable for further analysis or detection algorithms.
"""

import time
import socket
from typing import Dict, Any, Optional, Union, List, Tuple
from datetime import datetime
import logging
import ipaddress

try:
    from scapy.all import Packet, IP, IPv6, TCP, UDP, ICMP, ICMPv6, ARP, Ether
    from scapy.layers.inet6 import IPv6
    from scapy.layers.inet import ICMP as ICMPv4
except ImportError:
    raise ImportError("Scapy is required for feature extraction. Install it using: pip install scapy")
except Exception as e:
    raise ImportError(f"Scapy import error: {str(e)}. Ensure you have Scapy 2.4.3+ installed.")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("BasicFeatureExtractor")

class BasicFeatureExtractor:
    """
    A class for extracting fundamental features from network packets.
    
    This class analyzes network packets and extracts basic information such as
    addresses, ports, protocol types, and other fundamental packet characteristics.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the BasicFeatureExtractor with optional configuration.
        
        Args:
            config: Dictionary containing configuration parameters (optional)
        """
        self.config = config or {}
        self.protocol_map = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            58: 'ICMPv6',
            # Add more protocol numbers as needed
        }
        logger.info("BasicFeatureExtractor initialized")
    
    def extract_from_packet(self, packet: Packet) -> Dict[str, Any]:
        """
        Extract basic features from a network packet.
        
        This method handles different packet types (IPv4, IPv6, ARP, etc.) and
        extracts relevant features from each. It gracefully handles malformed packets.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            Dictionary containing extracted features
        """
        try:
            # Initialize features dictionary with timestamp
            features = {
                'timestamp': datetime.now().timestamp(),
                'packet_time': packet.time if hasattr(packet, 'time') else time.time(),
            }
            
            # Add Ethernet layer features if present
            if packet.haslayer(Ether):
                eth_features = self._extract_ethernet_features(packet[Ether])
                features.update(eth_features)
            
            # Extract IP layer features
            if packet.haslayer(IP):
                ip_features = self._extract_ipv4_features(packet[IP])
                features.update(ip_features)
            elif packet.haslayer(IPv6):
                ip_features = self._extract_ipv6_features(packet[IPv6])
                features.update(ip_features)
            elif packet.haslayer(ARP):
                arp_features = self._extract_arp_features(packet[ARP])
                features.update(arp_features)
            else:
                # Handle non-IP packets (could be other network layer protocols)
                features.update({
                    'ip_version': None,
                    'protocol': self._identify_protocol(packet),
                    'src_ip': None,
                    'dst_ip': None,
                    'ttl': None,
                })
            
            # Extract transport layer features
            if packet.haslayer(TCP):
                tcp_features = self._extract_tcp_features(packet[TCP])
                features.update(tcp_features)
            elif packet.haslayer(UDP):
                udp_features = self._extract_udp_features(packet[UDP])
                features.update(udp_features)
            elif packet.haslayer(ICMP) or packet.haslayer(ICMPv4):
                icmp_features = self._extract_icmp_features(packet[ICMP if packet.haslayer(ICMP) else ICMPv4])
                features.update(icmp_features)
            elif packet.haslayer(ICMPv6):
                icmpv6_features = self._extract_icmpv6_features(packet[ICMPv6])
                features.update(icmpv6_features)
            else:
                # For packets with no recognized transport layer
                features.update({
                    'src_port': None,
                    'dst_port': None,
                })
            
            # General packet features
            features.update({
                'packet_size': len(packet),
                'header_size': self._calculate_header_size(packet),
                'payload_size': self._calculate_payload_size(packet),
            })
            
            # Normalize and clean up features
            features = self._normalize_features(features)
            
            return features
            
        except Exception as e:
            # Handle malformed packets or extraction errors
            logger.warning(f"Error extracting features from packet: {str(e)}")
            # Return basic features with error indication
            return {
                'timestamp': time.time(),
                'packet_size': len(packet) if packet else 0,
                'extraction_error': str(e),
                'packet_summary': packet.summary() if packet else 'None',
            }
    
    def _extract_ethernet_features(self, eth_layer: Ether) -> Dict[str, Any]:
        """Extract features from Ethernet layer."""
        return {
            'eth_src': eth_layer.src,
            'eth_dst': eth_layer.dst,
            'eth_type': eth_layer.type,
        }
    
    def _extract_ipv4_features(self, ip_layer: IP) -> Dict[str, Any]:
        """Extract features from IPv4 layer."""
        return {
            'ip_version': 4,
            'protocol': self._get_protocol_name(ip_layer.proto),
            'protocol_num': ip_layer.proto,
            'src_ip': ip_layer.src,
            'dst_ip': ip_layer.dst,
            'ttl': ip_layer.ttl,
            'ip_id': ip_layer.id,
            'ip_flags': self._extract_ip_flags(ip_layer),
            'ip_frag': ip_layer.frag,
            'ip_tos': ip_layer.tos,
            'ip_len': ip_layer.len,
            'ip_options': bool(ip_layer.options),
        }
    
    def _extract_ipv6_features(self, ipv6_layer: IPv6) -> Dict[str, Any]:
        """Extract features from IPv6 layer."""
        return {
            'ip_version': 6,
            'protocol': self._get_protocol_name(ipv6_layer.nh),
            'protocol_num': ipv6_layer.nh,
            'src_ip': ipv6_layer.src,
            'dst_ip': ipv6_layer.dst,
            'ttl': ipv6_layer.hlim,  # Hop limit in IPv6 is equivalent to TTL
            'ip_flow_label': ipv6_layer.fl,
            'ip_plen': ipv6_layer.plen,
            'ip_tc': ipv6_layer.tc,  # Traffic class
        }
    
    def _extract_arp_features(self, arp_layer: ARP) -> Dict[str, Any]:
        """Extract features from ARP layer."""
        return {
            'protocol': 'ARP',
            'protocol_num': 0,  # ARP doesn't have a protocol number like IP protocols
            'src_ip': arp_layer.psrc,
            'dst_ip': arp_layer.pdst,
            'src_mac': arp_layer.hwsrc,
            'dst_mac': arp_layer.hwdst,
            'arp_op': arp_layer.op,
            'arp_op_name': 'request' if arp_layer.op == 1 else 'reply' if arp_layer.op == 2 else str(arp_layer.op),
        }
    
    def _extract_tcp_features(self, tcp_layer: TCP) -> Dict[str, Any]:
        """Extract features from TCP layer."""
        return {
            'src_port': tcp_layer.sport,
            'dst_port': tcp_layer.dport,
            'tcp_seq': tcp_layer.seq,
            'tcp_ack': tcp_layer.ack,
            'tcp_flags': self._extract_tcp_flags(tcp_layer),
            'tcp_window': tcp_layer.window,
            'tcp_urgptr': tcp_layer.urgptr,
            'tcp_options': bool(tcp_layer.options),
        }
    
    def _extract_udp_features(self, udp_layer: UDP) -> Dict[str, Any]:
        """Extract features from UDP layer."""
        return {
            'src_port': udp_layer.sport,
            'dst_port': udp_layer.dport,
            'udp_len': udp_layer.len,
        }
    
    def _extract_icmp_features(self, icmp_layer: Union[ICMP, ICMPv4]) -> Dict[str, Any]:
        """Extract features from ICMP layer."""
        return {
            'src_port': None,
            'dst_port': None,
            'icmp_type': icmp_layer.type,
            'icmp_code': icmp_layer.code,
            'icmp_type_name': self._get_icmp_type_name(icmp_layer.type, icmp_layer.code),
        }
    
    def _extract_icmpv6_features(self, icmpv6_layer: ICMPv6) -> Dict[str, Any]:
        """Extract features from ICMPv6 layer."""
        return {
            'src_port': None,
            'dst_port': None,
            'icmp_type': icmpv6_layer.type,
            'icmp_code': icmpv6_layer.code,
            'icmp_type_name': self._get_icmpv6_type_name(icmpv6_layer.type, icmpv6_layer.code),
        }
    
    def _extract_tcp_flags(self, tcp_layer: TCP) -> Dict[str, bool]:
        """Extract TCP flags as a dictionary of booleans."""
        return {
            'fin': bool(tcp_layer.flags & 0x01),  # FIN flag
            'syn': bool(tcp_layer.flags & 0x02),  # SYN flag
            'rst': bool(tcp_layer.flags & 0x04),  # RST flag
            'psh': bool(tcp_layer.flags & 0x08),  # PSH flag
            'ack': bool(tcp_layer.flags & 0x10),  # ACK flag
            'urg': bool(tcp_layer.flags & 0x20),  # URG flag
            'ece': bool(tcp_layer.flags & 0x40),  # ECE flag
            'cwr': bool(tcp_layer.flags & 0x80),  # CWR flag
        }
    
    def _extract_ip_flags(self, ip_layer: IP) -> Dict[str, bool]:
        """Extract IP flags as a dictionary of booleans."""
        # IP flags are 3 bits: Reserved(0), Don't Fragment(1), More Fragments(2)
        flags = ip_layer.flags
        return {
            'df': bool(flags & 0x02),  # Don't Fragment flag
            'mf': bool(flags & 0x01),  # More Fragments flag
        }
    
    def _get_protocol_name(self, protocol_num: int) -> str:
        """Convert protocol number to string name."""
        return self.protocol_map.get(protocol_num, f"PROTO:{protocol_num}")
    
    def _identify_protocol(self, packet: Packet) -> str:
        """Identify the protocol of the packet."""
        for layer in packet.layers():
            layer_name = layer.__name__
            if layer_name != 'Packet':
                return layer_name
        return "Unknown"
    
    def _calculate_header_size(self, packet: Packet) -> int:
        """Calculate the total header size of the packet."""
        try:
            if packet.haslayer(IP):
                ip_hdr_len = packet[IP].ihl * 4  # IP header length in bytes
                if packet.haslayer(TCP):
                    tcp_hdr_len = packet[TCP].dataofs * 4  # TCP header length in bytes
                    return ip_hdr_len + tcp_hdr_len
                elif packet.haslayer(UDP):
                    return ip_hdr_len + 8  # UDP header is always 8 bytes
                return ip_hdr_len
            elif packet.haslayer(IPv6):
                ipv6_hdr_len = 40  # Fixed IPv6 header size
                if packet.haslayer(TCP):
                    tcp_hdr_len = packet[TCP].dataofs * 4
                    return ipv6_hdr_len + tcp_hdr_len
                elif packet.haslayer(UDP):
                    return ipv6_hdr_len + 8
                return ipv6_hdr_len
            # For non-IP packets, estimate header size as difference between total and payload
            return len(packet) - len(packet.payload)
        except Exception as e:
            logger.debug(f"Error calculating header size: {str(e)}")
            return 0
    
    def _calculate_payload_size(self, packet: Packet) -> int:
        """Calculate the payload size of the packet."""
        try:
            # Start with the assumption that we're looking at an IP packet
            if packet.haslayer(IP):
                ip_total_len = packet[IP].len
                ip_hdr_len = packet[IP].ihl * 4
                
                if packet.haslayer(TCP):
                    tcp_hdr_len = packet[TCP].dataofs * 4
                    return max(0, ip_total_len - ip_hdr_len - tcp_hdr_len)
                elif packet.haslayer(UDP):
                    # UDP header is always 8 bytes
                    return max(0, ip_total_len - ip_hdr_len - 8)
                else:
                    # Just IP layer with some other protocol
                    return max(0, ip_total_len - ip_hdr_len)
            elif packet.haslayer(IPv6):
                if packet.haslayer(TCP) and hasattr(packet[TCP], 'payload'):
                    return len(packet[TCP].payload)
                elif packet.haslayer(UDP) and hasattr(packet[UDP], 'payload'):
                    return len(packet[UDP].payload)
                # For other IPv6 packets
                return packet[IPv6].plen
            
            # For non-IP packets, just get the raw payload length if available
            if hasattr(packet, 'payload'):
                return len(packet.payload)
            
            return 0
        except Exception as e:
            logger.debug(f"Error calculating payload size: {str(e)}")
            return 0
    
    def _normalize_features(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize and clean up features for consistency."""
        # Convert IP addresses to standard format
        if features.get('src_ip'):
            try:
                features['src_ip'] = str(ipaddress.ip_address(features['src_ip']))
            except ValueError:
                pass
                
        if features.get('dst_ip'):
            try:
                features['dst_ip'] = str(ipaddress.ip_address(features['dst_ip']))
            except ValueError:
                pass
        
        # Create a simplified protocol category
        protocol = features.get('protocol', 'Unknown')
        if protocol in ['TCP', 'UDP', 'ICMP', 'ICMPv6', 'ARP']:
            features['protocol_category'] = protocol
        else:
            features['protocol_category'] = 'Other'
        
        # Create a consolidated port feature (useful for some analysis)
        src_port = features.get('src_port')
        dst_port = features.get('dst_port')
        
        if src_port is not None and dst_port is not None:
            # Sort ports to create a consistent feature regardless of direction
            features['port_pair'] = f"{min(src_port, dst_port)}-{max(src_port, dst_port)}"
        else:
            features['port_pair'] = None
        
        # Create a direction-agnostic flow identifier
        src_ip = features.get('src_ip')
        dst_ip = features.get('dst_ip')
        if src_ip and dst_ip:
            # Sort IPs to make the flow ID consistent regardless of direction
            ip_pair = sorted([src_ip, dst_ip])
            if src_port is not None and dst_port is not None:
                port_pair = sorted([src_port, dst_port])
                features['flow_id'] = f"{ip_pair[0]}:{port_pair[0]}-{ip_pair[1]}:{port_pair[1]}"
            else:
                features['flow_id'] = f"{ip_pair[0]}-{ip_pair[1]}"
        else:
            features['flow_id'] = None
            
        return features
    
    def _get_icmp_type_name(self, icmp_type: int, icmp_code: int) -> str:
        """Convert ICMP type and code to descriptive name."""
        icmp_types = {
            0: 'Echo Reply',
            3: {
                0: 'Network Unreachable',
                1: 'Host Unreachable',
                2: 'Protocol Unreachable',
                3: 'Port Unreachable',
                4: 'Fragmentation Required',
                5: 'Source Route Failed',
                6: 'Destination Network Unknown',
                7: 'Destination Host Unknown',
                13: 'Communication Administratively Prohibited'
            },
            5: 'Redirect',
            8: 'Echo Request',
            11: {
                0: 'TTL Expired in Transit',
                1: 'Fragment Reassembly Time Exceeded'
            },
            13: 'Timestamp Request',
            14: 'Timestamp Reply',
        }
        
        if icmp_type in icmp_types:
            if isinstance(icmp_types[icmp_type], dict):
                return icmp_types[icmp_type].get(icmp_code, f"Type {icmp_type}, Code {icmp_code}")
            else:
                return icmp_types[icmp_type]
        return f"Type {icmp_type}, Code {icmp_code}"
    
    def _get_icmpv6_type_name(self, icmp_type: int, icmp_code: int) -> str:
        """Convert ICMPv6 type and code to descriptive name."""
        icmpv6_types = {
            1: {
                0: 'No Route to Destination',
                1: 'Communication with Destination Administratively Prohibited',
                3: 'Address Unreachable',
                4: 'Port Unreachable'
            },
            2: 'Packet Too Big',
            3: {
                0: 'Hop Limit Exceeded in Transit',
                1: 'Fragment Reassembly Time Exceeded'
            },
            4: {
                0: 'Erroneous Header Field',
                1: 'Unrecognized Next Header Type',
                2: 'Unrecognized IPv6 Option'
            },
            128: 'Echo Request',
            129: 'Echo Reply',
            130: 'Multicast Listener Query',
            131: 'Multicast Listener Report',
            132: 'Multicast Listener Done',
            133: 'Router Solicitation',
            134: 'Router Advertisement',
            135: 'Neighbor Solicitation',
            136: 'Neighbor Advertisement',
            137: 'Redirect Message',
        }
        
        if icmp_type in icmpv6_types:
            if isinstance(icmpv6_types[icmp_type], dict):
                return icmpv6_types[icmp_type].get(icmp_code, f"Type {icmp_type}, Code {icmp_code}")
            else:
                return icmpv6_types[icmp_type]
        return f"Type {icmp_type}, Code {icmp_code}"
    
    def get_feature_names(self) -> List[str]:
        """Return a list of all possible feature names."""
        # This could be made dynamic based on packet types supported
        return [
            'timestamp', 'packet_time', 'ip_version', 'protocol', 'protocol_num',
            'src_ip', 'dst_ip', 'src_port', 'dst_port', 'ttl', 'packet_size',
            'header_size', 'payload_size', 'eth_src', 'eth_dst', 'eth_type',
            # TCP-specific features
            'tcp_seq', 'tcp_ack', 'tcp_window', 'tcp_urgptr', 'tcp_options',
            # TCP flags
            'fin', 'syn', 'rst', 'psh', 'ack', 'urg', 'ece', 'cwr',
            # UDP-specific features
            'udp_len',
            # ICMP-specific features
            'icmp_type', 'icmp_code', 'icmp_type_name',
            # IP-specific features
            'ip_id', 'ip_flags', 'ip_frag', 'ip_tos', 'ip_len', 'ip_options', 'ip_flow_label', 'ip_plen', 'ip_tc',
            # ARP-specific features
            'src_mac', 'dst_mac', 'arp_op', 'arp_op_name',
            # Derived features
            'protocol_category', 'port_pair', 'flow_id',
        ]


# Example usage (only executed when run directly)
if __name__ == "__main__":
    from scapy.all import rdpcap
    import sys
    import json
    
    # Check if a PCAP file was provided
    if len(sys.argv) < 2:
        print("Usage: python basic_features.py <pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    feature_extractor = BasicFeatureExtractor()
    
    print(f"Analyzing PCAP file: {pcap_file}")
    try:
        packets = rdpcap(pcap_file)
        print(f"Loaded {len(packets)} packets")
        
        # Extract features from the first few packets
        for i, packet in enumerate(packets[:5]):
            features = feature_extractor.extract_from_packet(packet)
            print(f"\nPacket {i+1}:")
            for key, value in features.items():
                print(f"  {key}: {value}")
        
        # Show a summary of protocol distribution
        protocol_counts = {}
        for packet in packets:
            features = feature_extractor.extract_from_packet(packet)
            protocol = features.get('protocol_category', 'Unknown')
            if protocol in protocol_counts:
                protocol_counts[protocol] += 1
            else:
                protocol_counts[protocol] = 1
        
        print("\nProtocol Distribution:")
        for protocol, count in protocol_counts.items():
            print(f"  {protocol}: {count} ({count/len(packets)*100:.1f}%)")
            
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)