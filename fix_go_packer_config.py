#!/usr/bin/env python3
"""
Fix for the plugin packer menu to properly configure the go_packer plugin
"""

import os
import sys

def fix_plugin_packer_menu():
    """Add a configuration section for the go_packer plugin"""
    menu_file = "/home/mrnob0dy666/cumpyl/plugin_packer_menu.py"
    
    # Read the current content
    with open(menu_file, 'r') as f:
        content = f.read()
    
    # Find the cgo_packer configuration section
    cgo_section_start = content.find("elif plugin_name == 'cgo_packer':")
    
    if cgo_section_start != -1:
        # Find the end of the cgo_packer section (next elif or return statement)
        next_elif = content.find("elif plugin_name ==", cgo_section_start + 1)
        return_statement = content.find("return config", cgo_section_start)
        
        # Determine where the cgo_packer section ends
        if next_elif != -1 and return_statement != -1:
            cgo_section_end = min(next_elif, return_statement)
        elif next_elif != -1:
            cgo_section_end = next_elif
        elif return_statement != -1:
            cgo_section_end = return_statement
        else:
            # If neither found, find the next blank line or end of function
            cgo_section_end = content.find("\n\n", cgo_section_start)
            if cgo_section_end == -1:
                cgo_section_end = len(content)
        
        # Extract the cgo_packer section
        cgo_section = content[cgo_section_start:cgo_section_end]
        
        # Create a go_packer section based on the cgo_packer section
        go_packer_section = cgo_section.replace(
            "elif plugin_name == 'cgo_packer':",
            "elif plugin_name == 'go_packer':"
        ).replace(
            "# CGO packer specific configuration",
            "# Go packer specific configuration"
        ).replace(
            "# For CGO packer, disable dry run by default to actually save files",
            "# For Go packer, disable dry run by default to actually save files"
        )
        
        # Insert the go_packer section after the cgo_packer section
        insert_position = cgo_section_end
        content = content[:insert_position] + "\n" + go_packer_section + "\n" + content[insert_position:]
        
        # Write the fixed content back to the file
        with open(menu_file, 'w') as f:
            f.write(content)
        print("[+] Successfully added go_packer configuration section to plugin_packer_menu.py")
        return True
    else:
        print("[-] Could not find cgo_packer configuration section in plugin_packer_menu.py")
        return False

if __name__ == "__main__":
    fix_plugin_packer_menu()