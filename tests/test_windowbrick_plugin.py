#!/usr/bin/env python3
"""
Test script for Windowbrick Plugin
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from cumpyl_package.cumpyl import BinaryRewriter
from plugins.plugin_registry import PluginRegistry
from plugins.windowbrick_plugin import WindowbrickAnalysisPlugin, WindowbrickTransformationPlugin
from cumpyl_package.config import ConfigManager

def test_windowbrick_plugin():
    """Test the windowbrick plugin functionality"""
    print("Testing Windowbrick Plugin...")

    # Create a proper ConfigManager instance
    config_manager = ConfigManager()

    # Update with custom plugin configuration
    config_manager.plugins.windowbrick_analysis = {
        'rotation_amount': 3,
        'enable_anti_analysis': False,
        'obfuscation_mode': 'full'
    }

    config_manager.plugins.windowbrick_transform = {
        'rotation_amount': 3,
        'enable_anti_analysis': False,
        'obfuscation_mode': 'full'
    }

    # Test analysis plugin
    analysis_plugin = WindowbrickAnalysisPlugin(config_manager)
    print(f"Analysis Plugin Name: {analysis_plugin.name}")
    print(f"Analysis Plugin Version: {analysis_plugin.version}")
    print(f"Analysis Plugin Description: {analysis_plugin.description}")

    # Test transformation plugin
    transform_plugin = WindowbrickTransformationPlugin(config_manager)
    print(f"Transformation Plugin Name: {transform_plugin.name}")
    print(f"Transformation Plugin Version: {transform_plugin.version}")
    print(f"Transformation Plugin Description: {transform_plugin.description}")

    # Test obfuscation functions
    print("\nTesting obfuscation functions...")
    test_data = b"Hello, World!"
    key = 42  # Fixed key for testing

    obfuscated = analysis_plugin._obfuscate_data(test_data, key)
    deobfuscated = analysis_plugin._deobfuscate_data(obfuscated, key)

    print(f"Original: {test_data}")
    print(f"Obfuscated: {obfuscated.hex()}")
    print(f"Deobfuscated: {deobfuscated}")
    print(f"Match: {test_data == deobfuscated}")

    # Test string finding
    sample_data = b"This is a test string\0Another string here\0And another one\0"
    found_strings = analysis_plugin._find_strings(sample_data)
    print(f"\nFound strings: {found_strings}")

    # Test plugin registry
    print(f"\nTesting plugin registry...")
    # Create minimal config for the registry call
    registry_config = {
        'rotation_amount': 3,
        'enable_anti_analysis': False,
        'obfuscation_mode': 'full'
    }
    analysis_plugin_from_registry = PluginRegistry.get_plugin('analysis', 'windowbrick_analysis', registry_config)
    print(f"Retrieved analysis plugin from registry: {analysis_plugin_from_registry.name}")

    transform_plugin_from_registry = PluginRegistry.get_plugin('transformation', 'windowbrick_transform', registry_config)
    print(f"Retrieved transformation plugin from registry: {transform_plugin_from_registry.name}")

    print("\nWindowbrick Plugin test completed successfully!")

if __name__ == "__main__":
    test_windowbrick_plugin()