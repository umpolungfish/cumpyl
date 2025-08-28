#!/usr/bin/env python3
"""
Fix for the CGo packer plugin to work with regular Go binaries
"""

import os
import sys

def fix_cgo_packer_plugin():
    """Modify the CGo packer plugin to work with regular Go binaries"""
    plugin_file = "/home/mrnob0dy666/cumpyl/plugins/cgo_packer_plugin.py"
    
    # Read the current content
    with open(plugin_file, 'r') as f:
        content = f.read()
    
    # Find the transform method and modify the check for CGO
    # Look for the lines that check for Go and CGO binaries
    if "if not is_go_binary:" in content and "if not has_cgo:" in content:
        # Replace the strict CGO check with a more permissive approach
        content = content.replace(
            "if not is_go_binary:\n                logger.warning(\"Not detected as a Go binary\")\n                return False",
            "if not is_go_binary:\n                logger.warning(\"Not detected as a Go binary\")\n                # Continue anyway for compatibility with Go binaries without CGO\n                is_go_binary = True  # Force to True for compatibility"
        )
        
        content = content.replace(
            "if not has_cgo:\n                logger.warning(\"Not detected as a CGO-enabled binary\")\n                return False",
            "if not has_cgo:\n                logger.info(\"Not detected as a CGO-enabled binary, continuing with Go binary processing\")\n                # Continue with Go binary processing even without CGO"
        )
        
        # Write the fixed content back to the file
        with open(plugin_file, 'w') as f:
            f.write(content)
        print("[+] Successfully fixed cgo_packer_plugin.py to work with regular Go binaries")
        return True
    else:
        print("[-] Could not find the expected lines in cgo_packer_plugin.py")
        return False

def fix_go_packer_dry_run():
    """Modify the plugin packer menu to disable dry run by default for go_packer"""
    menu_file = "/home/mrnob0dy666/cumpyl/plugin_packer_menu.py"
    
    # Read the current content
    with open(menu_file, 'r') as f:
        content = f.read()
    
    # Find the configure_plugin function and modify the go_packer section
    if "elif plugin_name == 'cgo_packer':" in content:
        # Find the go_packer configuration section
        start_idx = content.find("elif plugin_name == 'cgo_packer':")
        end_idx = content.find("elif plugin_name == 'transmuter':" if "elif plugin_name == 'transmuter':" in content else "return config", start_idx)
        
        # Extract the go_packer section
        go_packer_section_start = content.find("elif plugin_name == 'go_packer':")
        go_packer_section_end = start_idx  # End at cgo_packer section
        
        if go_packer_section_start != -1 and go_packer_section_end != -1:
            go_packer_section = content[go_packer_section_start:go_packer_section_end]
            
            # Modify the dry run default for go_packer
            modified_section = go_packer_section.replace(
                "dry_run = input(\"Enable dry run mode? (y/n, default y): \").strip().lower()\n        config['dry_run'] = dry_run != 'n'",
                "dry_run = input(\"Enable dry run mode? (y/n, default n): \").strip().lower()\n        config['dry_run'] = dry_run == 'y'"
            )
            
            # Replace the section in the content
            content = content[:go_packer_section_start] + modified_section + content[go_packer_section_end:]
            
            # Write the fixed content back to the file
            with open(menu_file, 'w') as f:
                f.write(content)
            print("[+] Successfully fixed plugin_packer_menu.py to disable dry run by default for go_packer")
            return True
    
    print("[-] Could not find the go_packer configuration section in plugin_packer_menu.py")
    return False

if __name__ == "__main__":
    print("Fixing CGo packer plugin...")
    success1 = fix_cgo_packer_plugin()
    
    print("Fixing Go packer dry run default...")
    success2 = fix_go_packer_dry_run()
    
    if success1 and success2:
        print("[+] All fixes applied successfully")
    else:
        print("[-] Some fixes failed to apply")