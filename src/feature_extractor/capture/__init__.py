"""
Feature Extractor Capture Module

This package provides functionality for capturing and processing network packets.
It includes tools for both live network capture and PCAP file analysis.
"""

from .packet_capturer import (
    PacketCapturer,
    CaptureStatistics,
    PacketCaptureError
)

__all__ = [
    'PacketCapturer',
    'CaptureStatistics',
    'PacketCaptureError'
]

# Version information
__version__ = '1.0.0'
__author__ = 'NIDS Team'
__description__ = 'Network packet capture and analysis module'
