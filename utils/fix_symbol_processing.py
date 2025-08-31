#!/usr/bin/env python3
"""
Fix for the symbol processing issue in CGo packer plugin
"""

import os
import sys

def fix_symbol_processing():
    """Fix the symbol processing issue in CGo packer plugin"""
    plugin_file = "/home/mrnob0dy666/cumpyl/plugins/cgo_packer_plugin.py"
    
    # Read the current content
    with open(plugin_file, 'r') as f:
        content = f.read()
    
    # Fix 1: Handle symbol.name properly in Go build ID detection
    content = content.replace(
        "if pattern in symbol.name:\n                            return f\"Go binary detected via symbol: {symbol.name}\"",
        "symbol_name = getattr(symbol, 'name', str(symbol))\n                        if pattern in symbol_name:\n                            return f\"Go binary detected via symbol: {symbol_name}\""
    )
    
    # Fix 2: Handle symbol.name properly in CGO detection
    content = content.replace(
        "if pattern in symbol.name:\n                            cgo_info[\"has_cgo\"] = True\n                            cgo_info[\"cgo_symbols\"].append(symbol.name)",
        "symbol_name = getattr(symbol, 'name', str(symbol))\n                        if pattern in symbol_name:\n                            cgo_info[\"has_cgo\"] = True\n                            cgo_info[\"cgo_symbols\"].append(symbol_name)"
    )
    
    # Fix 3: Handle symbol.name properly in symbol obfuscation
    content = content.replace(
        "if any(pattern in symbol.name for pattern in cgo_patterns):",
        "symbol_name = getattr(symbol, 'name', str(symbol))\n                    if any(pattern in symbol_name for pattern in cgo_patterns):"
    )
    
    content = content.replace(
        "if symbol.name and len(symbol.name) > 2 and not symbol.name.startswith(\".\"):",
        "symbol_name = getattr(symbol, 'name', str(symbol))\n                if symbol_name and len(symbol_name) > 2 and not symbol_name.startswith(\".\"):"
    )
    
    content = content.replace(
        "original_name = symbol.name\n                    obfuscated_name = f\"_{os.urandom(4).hex()}_{original_name[:4]}\"\n                    symbol.name = obfuscated_name",
        "original_name = symbol_name\n                    obfuscated_name = f\"_{os.urandom(4).hex()}_{original_name[:4]}\"\n                    # Only try to set name if it's a writable attribute\n                    try:\n                        symbol.name = obfuscated_name\n                    except AttributeError:\n                        pass  # Continue if we can't modify the symbol name"
    )
    
    # Fix 4: Handle library.name properly
    content = content.replace(
        "if \"cgo\" in lib.name.lower():",
        "lib_name = getattr(lib, 'name', str(lib))\n                    if \"cgo\" in lib_name.lower():"
    )
    
    # Write the fixed content back to the file
    with open(plugin_file, 'w') as f:
        f.write(content)
    print("[+] Successfully fixed symbol processing issues in CGo packer plugin")
    return True

if __name__ == "__main__":
    fix_symbol_processing()