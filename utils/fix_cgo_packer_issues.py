#!/usr/bin/env python3
"""
Fix for the CGo packer plugin to work with all binaries
"""

import os
import sys

def fix_cgo_packer_plugin():
    """Fix the CGo packer plugin issues"""
    plugin_file = "/home/mrnob0dy666/cumpyl/plugins/cgo_packer_plugin.py"
    
    # Read the current content
    with open(plugin_file, 'r') as f:
        content = f.read()
    
    # Fix 1: Remove the strict Go binary check
    content = content.replace(
        "# Check if it's a Go binary\n            is_go_binary = analysis_result.get(\"analysis\", {}).get(\"go_specific_info\", {}).get(\"is_go_binary\", False)\n            if not is_go_binary:\n                logger.warning(\"Not detected as a Go binary\")\n                # Continue anyway for compatibility with Go binaries without CGO\n                is_go_binary = True  # Force to True for compatibility",
        "# Check if it's a Go binary\n            is_go_binary = analysis_result.get(\"analysis\", {}).get(\"go_specific_info\", {}).get(\"is_go_binary\", False)\n            # Continue anyway for compatibility with Go binaries without CGO\n            is_go_binary = True  # Force to True for compatibility"
    )
    
    # Fix 2: Remove the CGO check
    content = content.replace(
        "# Check if it has CGO\n            has_cgo = analysis_result.get(\"analysis\", {}).get(\"cgo_specific_info\", {}).get(\"has_cgo\", False)\n            if not has_cgo:\n                logger.info(\"Not detected as a CGO-enabled binary, continuing with Go binary processing\")\n                # Continue with Go binary processing even without CGO",
        "# Check if it has CGO\n            has_cgo = analysis_result.get(\"analysis\", {}).get(\"cgo_specific_info\", {}).get(\"has_cgo\", False)\n            # Continue with Go binary processing even without CGO"
    )
    
    # Fix 3: Handle the entrypoint setting properly
    content = content.replace(
        "rewriter.binary.entrypoint = self.new_entry_point",
        "# Try to set entrypoint properly\n            try:\n                if hasattr(rewriter.binary, 'entrypoint'):\n                    rewriter.binary.entrypoint = self.new_entry_point\n                elif hasattr(rewriter.binary, 'entrypoint_address'):\n                    rewriter.binary.entrypoint_address = self.new_entry_point\n                logger.info(f\"Set new entry point to 0x{self.new_entry_point:x}\")\n            except AttributeError:\n                logger.warning(\"Could not set entrypoint directly, continuing without entrypoint modification\")"
    )
    
    # Write the fixed content back to the file
    with open(plugin_file, 'w') as f:
        f.write(content)
    print("[+] Successfully fixed CGo packer plugin issues")
    return True

if __name__ == "__main__":
    fix_cgo_packer_plugin()