#!/usr/bin/env python3
"""
Fix for the CGo packer plugin configuration issue
"""

import os
import sys

def fix_cgo_packer_plugin():
    """Fix the CGo packer plugin to properly handle configuration"""
    plugin_file = "/home/mrnob0dy666/cumpyl/plugins/cgo_packer_plugin.py"
    
    # Read the current content
    with open(plugin_file, 'r') as f:
        content = f.read()
    
    # Find the problematic line in the transform method
    # Look for the line that's causing the error: 'dict' object has no attribute 'get_plugin_config'
    if "plugin_config = self.get_config()" in content:
        # Replace with direct config access
        content = content.replace(
            "plugin_config = self.get_config()",
            "# plugin_config = self.get_config()\n        # Use config directly instead\n        plugin_config = getattr(self, 'config', {})"
        )
        
        # Write the fixed content back to the file
        with open(plugin_file, 'w') as f:
            f.write(content)
        print("[+] Successfully fixed cgo_packer_plugin.py")
        return True
    else:
        print("[-] Could not find the problematic line in cgo_packer_plugin.py")
        return False

if __name__ == "__main__":
    fix_cgo_packer_plugin()