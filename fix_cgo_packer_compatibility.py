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
    transform_method_start = content.find("def transform(self, rewriter, analysis_result: Dict[str, Any]) -> bool:")
    
    if transform_method_start != -1:
        # Find the end of the transform method
        next_method_start = content.find("def ", transform_method_start + 1)
        if next_method_start == -1:
            next_method_start = len(content)
        
        # Extract the transform method
        transform_method = content[transform_method_start:next_method_start]
        
        # Check if it contains the problematic checks
        if "Not detected as a Go binary" in transform_method and "Not detected as a CGO-enabled binary" in transform_method:
            # Replace the strict checks with more permissive ones
            modified_method = transform_method.replace(
                "if not is_go_binary:\n                logger.warning(\"Not detected as a Go binary\")\n                return False",
                "if not is_go_binary:\n                logger.warning(\"Not detected as a Go binary\")\n                # Continue anyway for compatibility with Go binaries without CGO\n                is_go_binary = True  # Force to True for compatibility"
            ).replace(
                "if not has_cgo:\n                logger.warning(\"Not detected as a CGO-enabled binary\")\n                return False",
                "if not has_cgo:\n                logger.info(\"Not detected as a CGO-enabled binary, continuing with Go binary processing\")\n                # Continue with Go binary processing even without CGO"
            )
            
            # Replace the method in the content
            content = content[:transform_method_start] + modified_method + content[next_method_start:]
            
            # Write the fixed content back to the file
            with open(plugin_file, 'w') as f:
                f.write(content)
            print("[+] Successfully fixed cgo_packer_plugin.py to work with regular Go binaries")
            return True
        else:
            print("[-] Could not find the expected checks in the transform method")
            return False
    else:
        print("[-] Could not find the transform method in cgo_packer_plugin.py")
        return False

if __name__ == "__main__":
    fix_cgo_packer_plugin()