#!/usr/bin/env python3
"""
Debug script to check what plugins are actually being discovered by the menu
"""

import sys
import os

# Add the current directory to the path so we can import the plugin_packer_menu
sys.path.insert(0, os.path.dirname(__file__))

def test_menu_plugin_discovery():
    """Test what plugins the menu is actually discovering"""
    try:
        from plugin_packer_menu import list_available_plugins
        
        # Call the actual function used by the menu
        plugins = list_available_plugins()
        
        print("Plugins discovered by menu:")
        print(f"Analysis plugins: {plugins['analysis']}")
        print(f"Transformation plugins: {plugins['transformation']}")
        
        return plugins
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    test_menu_plugin_discovery()