#!/usr/bin/env python3
"""
Final test to verify the plugin packer menu works correctly
"""

import sys
import os

# Add the cumpyl directory to the path
sys.path.insert(0, '/home/mrnob0dy666/cumpyl')

def test_plugin_packer_menu():
    """Test that the plugin packer menu loads correctly"""
    try:
        # Import the plugin packer menu module to check for syntax errors
        import plugin_packer_menu
        
        # Check that the module has the expected functions
        assert hasattr(plugin_packer_menu, 'main'), "Missing main function"
        assert hasattr(plugin_packer_menu, 'list_available_plugins'), "Missing list_available_plugins function"
        assert hasattr(plugin_packer_menu, 'load_plugin'), "Missing load_plugin function"
        assert hasattr(plugin_packer_menu, 'configure_plugin'), "Missing configure_plugin function"
        
        print("[+] Plugin packer menu module loaded successfully")
        print("[+] All required functions are present")
        
        # Test listing available plugins
        plugins = plugin_packer_menu.list_available_plugins()
        print(f"[+] Available plugins: {plugins}")
        
        # Check that we have the expected plugins
        assert 'go_packer' in plugins['transformation'], "go_packer not in transformation plugins"
        assert 'cgo_packer' in plugins['transformation'], "cgo_packer not in transformation plugins"
        
        print("[+] All expected plugins are available")
        return True
        
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("Testing plugin packer menu...")
    success = test_plugin_packer_menu()
    if success:
        print("[+] Plugin packer menu is working correctly!")
    else:
        print("[-] Plugin packer menu has issues.")