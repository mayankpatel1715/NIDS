"""
Feature Extractor Package

This package provides functionality for extracting features from network traffic
for use in intrusion detection systems.
"""

# Import submodules to make them available through the package
from . import capture
from . import features

# Define what gets imported with "from feature_extractor import *"
__all__ = ['capture', 'features']

# Version information
__version__ = '1.0.0'
