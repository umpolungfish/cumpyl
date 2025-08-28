#!/usr/bin/env python3
"""
Test script to check what plugins are being discovered
"""

import sys
import os
import importlib

# Add the plugins directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'plugins'))

def test_plugin_discovery():
    """Test what plugins are being discovered"""
    plugins_dir = os.path.join(os.path.dirname(__file__), 'plugins')
    analysis_plugins = []
    transformation_plugins = []
    
    # Look for plugin files
    for filename in os.listdir(plugins_dir):
        if filename.endswith('_plugin.py') and filename not in ['base_plugin.py']:
            plugin_name = filename.replace('_plugin.py', '')
            # Exclude test plugins and transmuter plugin (has its own menu)
            if plugin_name.startswith('test_') or plugin_name == 'transmuter':
                continue
            # Special handling for packer plugin - it has both analysis and transformation capabilities
            if plugin_name == 'packer':
                analysis_plugins.append('packer')
                transformation_plugins.append('packer')
            # Try to determine if it's an analysis or transformation plugin
            elif 'transform' in filename:
                transformation_plugins.append(plugin_name)
            else:
                analysis_plugins.append(plugin_name)
    
    # Add transformation capabilities for plugins that have them
    # Check if go_packer has transformation capability
    if 'go_packer' in analysis_plugins:
        try:
            module = importlib.import_module('plugins.go_packer_plugin')
            if hasattr(module, 'get_transformation_plugin'):
                transformation_plugins.append('go_packer')
        except:
            pass
    
    # Add packer_transform separately
    if 'packer_transform' not in transformation_plugins:
        transformation_plugins.append('packer_transform')
    
    print(f"Analysis plugins: {analysis_plugins}")
    print(f"Transformation plugins: {transformation_plugins}")
    
    return {
        'analysis': analysis_plugins,
        'transformation': transformation_plugins
    }

if __name__ == "__main__":
    plugins = test_plugin_discovery()
    print("\nPlugin discovery test completed")