#!/usr/bin/env python3
"""
Simple test script to verify the fixes work
"""

import sys
import os

# Add the cumpyl directory to the path
sys.path.insert(0, '/home/mrnob0dy666/cumpyl')

def test_plugin_config():
    """Test that the plugins are properly configured"""
    try:
        # Import required modules
        from cumpyl_package.config import ConfigManager
        from plugins.go_packer_plugin import get_analysis_plugin, get_transformation_plugin
        from plugins.cgo_packer_plugin import get_plugin, get_transformation_plugin as get_cgo_transformation_plugin
        
        # Test Go packer plugin
        print("[+] Testing Go packer plugin configuration...")
        config_manager = ConfigManager()
        config = config_manager.config_data if hasattr(config_manager, 'config_data') else {}
        
        # Set some test configuration values
        config['dry_run'] = False
        config['output_path'] = 'test_output.exe'
        
        # Create plugin instances
        analysis_plugin = get_analysis_plugin(config)
        transform_plugin = get_transformation_plugin(config)
        
        print(f"[+] Go packer analysis plugin created: {analysis_plugin.name}")
        print(f"[+] Go packer transform plugin created: {transform_plugin.name}")
        
        # Test CGo packer plugin
        print("[+] Testing CGo packer plugin configuration...")
        cgo_analysis_plugin = get_plugin(config)
        cgo_transform_plugin = get_cgo_transformation_plugin(config)
        
        print(f"[+] CGo packer analysis plugin created: {cgo_analysis_plugin.name}")
        print(f"[+] CGo packer transform plugin created: {cgo_transform_plugin.name}")
        
        print("[+] All plugins configured successfully")
        return True
        
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("Testing plugin configurations...")
    success = test_plugin_config()
    if success:
        print("[+] Plugin configuration test passed")
    else:
        print("[-] Plugin configuration test failed")