#!/usr/bin/env python3
"""
Fix for the syntax error in plugin_packer_menu.py
"""

import os
import sys

def fix_syntax_error():
    """Fix the syntax error in plugin_packer_menu.py"""
    menu_file = "/home/mrnob0dy666/cumpyl/plugin_packer_menu.py"
    
    # Read the current content
    with open(menu_file, 'r') as f:
        content = f.read()
    
    # Find the problematic section
    if "\n    \nelif plugin_name == 'go_packer':" in content:
        # Fix the extra blank line
        content = content.replace(
            "\n    \nelif plugin_name == 'go_packer':",
            "\nelif plugin_name == 'go_packer':"
        )
        
        # Write the fixed content back to the file
        with open(menu_file, 'w') as f:
            f.write(content)
        print("[+] Successfully fixed syntax error in plugin_packer_menu.py")
        return True
    else:
        print("[-] Could not find the syntax error in plugin_packer_menu.py")
        return False

if __name__ == "__main__":
    fix_syntax_error()