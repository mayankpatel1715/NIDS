#!/usr/bin/env python3
"""
Network Intrusion Detection System (NIDS) - Utility Helper Functions

This module provides a collection of utility functions for the NIDS application,
including configuration management, network utilities, time handling, 
data structure operations, logging setup, exception handling, and performance
measurement tools.
"""

import ipaddress
import json
import logging
import os
import socket
import time
import traceback
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Set, Tuple, TypeVar, Union

# Type aliases for improved readability
IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
JSONDict = Dict[str, Any]
T = TypeVar('T')  # Generic type for function return values

# Protocol number to name mapping based on IANA assignments
# https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
PROTOCOL_MAP = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "IPv6-ICMP",
    89: "OSPF",
    103: "PIM",
    132: "SCTP"
}

# Common log levels for easy access
LOG_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL
}


# Configuration Loading and Validation Functions
def load_config(file_path: str) -> Dict[str, Any]:
    """
    Load and parse a JSON configuration file.
    
    Args:
        file_path: Path to the JSON configuration file
        
    Returns:
        A dictionary containing the configuration data
        
    Raises:
        FileNotFoundError: If the configuration file doesn't exist
        json.JSONDecodeError: If the configuration file contains invalid JSON
    """
    try:
        with open(file_path, 'r') as config_file:
            return json.load(config_file)
            
    except FileNotFoundError:
        raise FileNotFoundError(f"Configuration file not found: {file_path}")
    
    except json.JSONDecodeError as e:
        raise json.JSONDecodeError(f"Invalid JSON in configuration file: {str(e)}", e.doc, e.pos)


def save_config(config: Dict[str, Any], file_path: str, indent: int = 4) -> None:
    """
    Save a configuration dictionary to a JSON file.
    
    Args:
        config: Configuration dictionary to save
        file_path: Path to the output JSON file
        indent: Number of spaces for indentation (for pretty printing)
        
    Raises:
        IOError: If the file cannot be written
    """
    # Ensure directory exists
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    
    try:
        with open(file_path, 'w') as config_file:
            json.dump(config, config_file, indent=indent)
            
    except IOError as e:
        raise IOError(f"Failed to write configuration file: {str(e)}")


def validate_config(config: Dict[str, Any], required_fields: Dict[str, Any]) -> List[str]:
    """
    Validate that a configuration contains all required fields with valid values.
    
    Args:
        config: The configuration dictionary to validate
        required_fields: A dictionary specifying required fields and their expected types
                        (e.g., {"capture.interface": str, "logging.level": str})
    
    Returns:
        A list of validation error messages, empty if validation succeeded
    """
    errors = []
    
    for field_path, expected_type in required_fields.items():
        # Split the field path into components
        components = field_path.split('.')
        
        # Traverse the configuration to find the field
        current = config
        for component in components[:-1]:
            if component not in current or not isinstance(current[component], dict):
                errors.append(f"Missing required configuration section: {component}")
                break
            current = current[component]
        else:
            # Check if the final field exists and has the correct type
            final_component = components[-1]
            if final_component not in current:
                errors.append(f"Missing required configuration field: {field_path}")
            elif not isinstance(current[final_component], expected_type):
                errors.append(
                    f"Invalid type for {field_path}: expected {expected_type.__name__}, "
                    f"got {type(current[final_component]).__name__}"
                )
    
    return errors


# Network Address Handling Utilities
def normalize_ip_address(address: str) -> IPAddress:
    """
    Normalize an IP address string to an IPv4Address or IPv6Address object.
    
    Args:
        address: IP address string (IPv4 or IPv6)
        
    Returns:
        An IPv4Address or IPv6Address object
        
    Raises:
        ValueError: If the address is invalid
    """
    try:
        return ipaddress.ip_address(address)
    except ValueError:
        raise ValueError(f"Invalid IP address: {address}")


def is_ip_in_subnet(ip: Union[str, IPAddress], subnet: Union[str, IPNetwork]) -> bool:
    """
    Check if an IP address is within a given subnet.
    
    Args:
        ip: IP address (string or IPv4/IPv6Address object)
        subnet: Subnet (string in CIDR notation or IPv4/IPv6Network object)
        
    Returns:
        True if the IP is in the subnet, False otherwise
        
    Raises:
        ValueError: If the IP address or subnet is invalid
    """
    # Normalize IP address
    if isinstance(ip, str):
        ip = normalize_ip_address(ip)
    
    # Normalize subnet
    if isinstance(subnet, str):
        try:
            subnet = ipaddress.ip_network(subnet)
        except ValueError:
            raise ValueError(f"Invalid subnet: {subnet}")
    
    # Check if IP is in subnet
    return ip in subnet


def get_protocol_name(protocol_number: int) -> str:
    """
    Convert a protocol number to its corresponding name.
    
    Args:
        protocol_number: IANA protocol number
        
    Returns:
        Protocol name or "UNKNOWN" if the protocol number is not recognized
    """
    return PROTOCOL_MAP.get(protocol_number, f"UNKNOWN({protocol_number})")


def resolve_hostname(hostname: str) -> List[str]:
    """
    Resolve a hostname to its IP addresses.
    
    Args:
        hostname: Hostname to resolve
        
    Returns:
        List of IP addresses (as strings)
        
    Raises:
        socket.gaierror: If the hostname cannot be resolved
    """
    try:
        # Get address info for the hostname
        addr_info = socket.getaddrinfo(hostname, None)
        
        # Extract unique IP addresses
        ip_addresses = set()
        for info in addr_info:
            ip_addresses.add(info[4][0])
        
        return list(ip_addresses)
    
    except socket.gaierror as e:
        raise socket.gaierror(f"Failed to resolve hostname '{hostname}': {str(e)}")


# Time-related Utilities
def get_current_timestamp() -> float:
    """
    Get the current Unix timestamp with microsecond precision.
    
    Returns:
        Current timestamp as a float
    """
    return time.time()


def timestamp_to_datetime(timestamp: float) -> datetime:
    """
    Convert a Unix timestamp to a datetime object in UTC.
    
    Args:
        timestamp: Unix timestamp (seconds since epoch)
        
    Returns:
        Datetime object in UTC timezone
    """
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


def format_timestamp(timestamp: float, format_str: str = "%Y-%m-%d %H:%M:%S.%f %Z") -> str:
    """
    Format a Unix timestamp according to the specified format string.
    
    Args:
        timestamp: Unix timestamp (seconds since epoch)
        format_str: Format string as per datetime.strftime()
        
    Returns:
        Formatted timestamp string
    """
    dt = timestamp_to_datetime(timestamp)
    return dt.strftime(format_str)


def parse_timestamp(timestamp_str: str, format_str: str = "%Y-%m-%d %H:%M:%S.%f %Z") -> float:
    """
    Parse a timestamp string into a Unix timestamp.
    
    Args:
        timestamp_str: Timestamp string
        format_str: Format string as per datetime.strptime()
        
    Returns:
        Unix timestamp (seconds since epoch)
        
    Raises:
        ValueError: If the timestamp string does not match the format
    """
    try:
        dt = datetime.strptime(timestamp_str, format_str)
        # Add UTC timezone if not specified
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    
    except ValueError:
        raise ValueError(f"Invalid timestamp format: '{timestamp_str}' does not match '{format_str}'")


# Data Structure Helpers
def deep_merge(dict1: Dict[str, Any], dict2: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively merge two dictionaries, with values from dict2 taking precedence.
    
    Args:
        dict1: First dictionary
        dict2: Second dictionary (values override dict1)
        
    Returns:
        Merged dictionary
    """
    result = dict1.copy()
    
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            # Recursively merge nested dictionaries
            result[key] = deep_merge(result[key], value)
        else:
            # Override or add value
            result[key] = value
    
    return result


def safe_get(data: Dict[str, Any], path: str, default: Any = None) -> Any:
    """
    Safely access a nested value in a dictionary using a dot-separated path.
    
    Args:
        data: Dictionary to access
        path: Dot-separated path (e.g., "section.subsection.field")
        default: Default value to return if the path doesn't exist
        
    Returns:
        Value at the specified path or default if the path doesn't exist
    """
    keys = path.split('.')
    result = data
    
    for key in keys:
        if not isinstance(result, dict) or key not in result:
            return default
        result = result[key]
    
    return result


def flatten_dict(nested_dict: Dict[str, Any], separator: str = '.', prefix: str = '') -> Dict[str, Any]:
    """
    Flatten a nested dictionary into a single-level dictionary with key paths.
    
    Args:
        nested_dict: Nested dictionary to flatten
        separator: Separator for key path components
        prefix: Prefix for the keys in the resulting dictionary
        
    Returns:
        Flattened dictionary
    """
    result = {}
    
    for key, value in nested_dict.items():
        new_key = f"{prefix}{separator}{key}" if prefix else key
        
        if isinstance(value, dict):
            # Recursively flatten nested dictionaries
            result.update(flatten_dict(value, separator, new_key))
        else:
            # Add leaf value
            result[new_key] = value
    
    return result


def nested_defaultdict() -> defaultdict:
    """
    Create a nested defaultdict for arbitrary depth dictionaries.
    
    Returns:
        A nested defaultdict
    """
    return defaultdict(nested_defaultdict)


# Logging Setup and Configuration
def setup_logger(
    name: str,
    level: Union[int, str] = "INFO",
    log_file: Optional[str] = None,
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
) -> logging.Logger:
    """
    Configure and return a logger with console and optional file handlers.
    
    Args:
        name: Logger name
        level: Logging level (name or constant)
        log_file: Path to log file (None for console only)
        log_format: Log message format
        
    Returns:
        Configured logger
    """
    # Convert string level to numeric if needed
    if isinstance(level, str):
        level = LOG_LEVELS.get(level.upper(), logging.INFO)
    
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.handlers = []  # Remove any existing handlers
    
    # Create formatter
    formatter = logging.Formatter(log_format)
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Create file handler if log file is specified
    if log_file:
        # Ensure directory exists
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


# Exception Handling Utilities
def format_exception(exc: Exception) -> str:
    """
    Format an exception into a readable error message with traceback.
    
    Args:
        exc: Exception to format
        
    Returns:
        Formatted error message
    """
    return f"{type(exc).__name__}: {str(exc)}\n{''.join(traceback.format_tb(exc.__traceback__))}"


def safe_execute(func: Callable[..., T], *args, **kwargs) -> Tuple[Optional[T], Optional[Exception]]:
    """
    Execute a function and catch any exceptions.
    
    Args:
        func: Function to execute
        *args: Positional arguments to pass to the function
        **kwargs: Keyword arguments to pass to the function
        
    Returns:
        Tuple containing (result, None) if successful or (None, exception) if an error occurred
    """
    try:
        result = func(*args, **kwargs)
        return result, None
    except Exception as e:
        return None, e


# Performance Measurement Functions
@contextmanager
def timer() -> Iterator[Callable[[], float]]:
    """
    Context manager for timing code execution.
    
    Yields:
        A function that returns the elapsed time in seconds when called
    """
    start_time = time.time()
    
    def get_elapsed() -> float:
        return time.time() - start_time
    
    try:
        yield get_elapsed
    finally:
        pass


def timed(func: Callable) -> Callable:
    """
    Decorator for timing function execution.
    
    Args:
        func: Function to time
        
    Returns:
        Wrapped function that logs execution time
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        logger = logging.getLogger(func.__module__)
        start_time = time.time()
        
        try:
            result = func(*args, **kwargs)
            elapsed = time.time() - start_time
            logger.debug(f"Function {func.__name__} took {elapsed:.6f} seconds")
            return result
        
        except Exception as e:
            elapsed = time.time() - start_time
            logger.error(f"Function {func.__name__} failed after {elapsed:.6f} seconds: {str(e)}")
            raise
    
    return wrapper


def measure_rate(interval: float = 1.0) -> Callable:
    """
    Decorator to measure the rate of function calls (calls per second).
    
    Args:
        interval: Interval in seconds for rate calculation
        
    Returns:
        Decorated function
    """
    def decorator(func: Callable) -> Callable:
        last_time = [0.0]  # Use a list to allow modification in nested function
        count = [0]
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Update count and check if interval has elapsed
            count[0] += 1
            current_time = time.time()
            
            # Calculate and log rate if interval has elapsed
            if current_time - last_time[0] >= interval:
                rate = count[0] / (current_time - last_time[0])
                logging.getLogger(func.__module__).debug(
                    f"Function {func.__name__} call rate: {rate:.2f} calls/second"
                )
                
                # Reset counters
                count[0] = 0
                last_time[0] = current_time
            
            # Call the original function
            return func(*args, **kwargs)
        
        return wrapper
    
    return decorator