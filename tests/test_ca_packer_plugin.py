#!/usr/bin/env python3
"""
Test script to verify that the CA packer plugin can be imported and instantiated correctly.
"""

import sys
import os

# Add the project root to the Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

def test_ca_packer_import():
    """Test that the CA packer plugin can be imported."""
    try:
        # Try to import the plugin
        from plugins.ca_packer_plugin import get_plugin, get_transform_plugin
        
        # Try to instantiate the plugins
        config = {}  # Empty config for testing
        analysis_plugin = get_plugin(config)
        transform_plugin = get_transform_plugin(config)
        
        print("✓ CA packer plugins imported and instantiated successfully")
        print(f"  Analysis plugin: {analysis_plugin.name} v{analysis_plugin.version}")
        print(f"  Transform plugin: {transform_plugin.name} v{transform_plugin.version}")
        
        return True
    except Exception as e:
        print(f"✗ Failed to import or instantiate CA packer plugins: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("Testing CA packer plugin import...")
    success = test_ca_packer_import()
    if success:
        print("All tests passed!")
        sys.exit(0)
    else:
        print("Tests failed!")
        sys.exit(1)