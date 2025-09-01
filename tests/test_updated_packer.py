#!/usr/bin/env python3
"""
Test script to verify that the updated packer plugin works with the new CA packer implementation.
"""

import sys
import os

# Add the project root to the Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

def test_packer_plugin_import():
    """Test that the updated packer plugin can be imported."""
    try:
        # Try to import the plugin
        from plugins.packer_plugin import get_plugin, get_transform_plugin
        
        # Try to instantiate the plugins
        config = {}  # Empty config for testing
        analysis_plugin = get_plugin(config)
        transform_plugin = get_transform_plugin(config)
        
        print("✓ Packer plugins imported and instantiated successfully")
        print(f"  Analysis plugin: {analysis_plugin.name} v{analysis_plugin.version}")
        print(f"  Transform plugin: {transform_plugin.name} v{transform_plugin.version}")
        
        # Check that the version has been updated
        if analysis_plugin.version == "1.2.0":
            print("✓ Plugin version correctly updated to 1.2.0")
        else:
            print(f"✗ Plugin version not updated correctly: {analysis_plugin.version}")
            return False
            
        return True
    except Exception as e:
        print(f"✗ Failed to import or instantiate packer plugins: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_ca_packer_import():
    """Test that the CA packer modules can be imported."""
    try:
        # Add utils to path
        utils_path = os.path.join(project_root, 'utils')
        if utils_path not in sys.path:
            sys.path.insert(0, utils_path)
            
        # Try to import the CA packer modules
        import ca_packer
        import ca_engine
        import crypto_engine
        
        print("✓ CA packer modules imported successfully")
        
        # Test that we can access key functions
        if hasattr(ca_engine, 'generate_mask') and hasattr(crypto_engine, 'encrypt_payload'):
            print("✓ CA packer modules have expected functions")
        else:
            print("✗ CA packer modules missing expected functions")
            return False
            
        return True
    except Exception as e:
        print(f"✗ Failed to import CA packer modules: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("Testing updated packer plugin with CA packer implementation...")
    
    success1 = test_packer_plugin_import()
    success2 = test_ca_packer_import()
    
    if success1 and success2:
        print("All tests passed!")
        sys.exit(0)
    else:
        print("Some tests failed!")
        sys.exit(1)