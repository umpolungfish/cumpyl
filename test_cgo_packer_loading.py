#!/usr/bin/env python3
"""
Test script to verify that the CGO packer plugin can be loaded as a transformation plugin
"""

import sys
import os

# Add the plugins directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'plugins'))

def test_cgo_packer_plugin_loading():
    """Test that the CGO packer plugin can be loaded as a transformation plugin"""
    try:
        # Test loading the CGO packer transformation plugin
        from plugin_packer_menu import load_plugin
        
        # Try to load the CGO packer transformation plugin
        plugin_factory = load_plugin('cgo_packer', 'transformation')
        
        if plugin_factory:
            print("✓ CGO packer transformation plugin loaded successfully")
            return True
        else:
            print("✗ Failed to load CGO packer transformation plugin")
            return False
    except Exception as e:
        print(f"✗ Error loading CGO packer transformation plugin: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run the test"""
    print("Testing CGO packer plugin loading...\n")
    
    if test_cgo_packer_plugin_loading():
        print("\n✓ CGO packer plugin loading test passed")
        return True
    else:
        print("\n✗ CGO packer plugin loading test failed")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)