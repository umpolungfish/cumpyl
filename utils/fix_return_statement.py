#!/usr/bin/env python3
"""
Fix for the extra return statement in plugin_packer_menu.py
"""

import os
import sys

def fix_return_statement():
    """Fix the extra return statement in plugin_packer_menu.py"""
    menu_file = "/home/mrnob0dy666/cumpyl/plugin_packer_menu.py"
    
    # Read the current content
    with open(menu_file, 'r') as f:
        content = f.read()
    
    # Find the problematic section
    if "\n    \nreturn config\n\ndef analyze_binary_with_plugin" in content:
        # Fix the extra return statement by removing it
        content = content.replace(
            "\n    \nreturn config\n\ndef analyze_binary_with_plugin",
            "\n    return config\n\ndef analyze_binary_with_plugin"
        )
    elif "\n\nreturn config\n\ndef analyze_binary_with_plugin" in content:
        # Fix the extra return statement by removing one newline
        content = content.replace(
            "\n\nreturn config\n\ndef analyze_binary_with_plugin",
            "\n    return config\n\ndef analyze_binary_with_plugin"
        )
        
    # Write the fixed content back to the file
    with open(menu_file, 'w') as f:
        f.write(content)
    print("[+] Successfully fixed return statement in plugin_packer_menu.py")
    return True

if __name__ == "__main__":
    fix_return_statement()