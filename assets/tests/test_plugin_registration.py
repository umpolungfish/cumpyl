#!/usr/bin/env python3
"""
Simple test to check plugin registration
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from plugins.plugin_registry import PluginRegistry
from cumpyl_package.config import ConfigManager

def test_plugin_registration():
    """Test plugin registration"""
    print("Testing plugin registration...")
    
    # List all registered plugins
    all_plugins = PluginRegistry.list_plugins()
    print(f"All registered plugins: {all_plugins}")
    
    # List analysis plugins specifically
    analysis_plugins = PluginRegistry.list_plugins('analysis')
    print(f"Analysis plugins: {analysis_plugins}")
    
    # Check if windowbrick plugins are registered
    if 'windowbrick_analysis' in analysis_plugins:
        print("Windowbrick analysis plugin is registered!")
    else:
        print("Windowbrick analysis plugin is NOT registered")
        
    # Test transformation plugins
    transform_plugins = PluginRegistry.list_plugins('transformation')
    print(f"Transformation plugins: {transform_plugins}")
    
    if 'windowbrick_transform' in transform_plugins:
        print("Windowbrick transformation plugin is registered!")
    else:
        print("Windowbrick transformation plugin is NOT registered")

if __name__ == "__main__":
    test_plugin_registration()