#!/usr/bin/env python3
"""
Debug test for obfuscation functions
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from plugins.windowbrick_plugin import WindowbrickAnalysisPlugin
from cumpyl_package.config import ConfigManager

def debug_obfuscation():
    """Debug the obfuscation functions"""
    print("Debugging obfuscation functions...")
    
    # Create a config manager
    config_manager = ConfigManager()
    config_manager.plugins.windowbrick_analysis = {
        'rotation_amount': 3,
        'enable_anti_analysis': False,
        'obfuscation_mode': 'full'
    }
    
    # Create plugin instance
    plugin = WindowbrickAnalysisPlugin(config_manager)
    
    # Test data
    test_data = b"Hello"
    key = 42
    print(f"Test data: {test_data}")
    print(f"Key: {key}")
    print(f"Rotation amount: {plugin.rotation_amount}")
    print(f"Mode: {plugin.obfuscation_mode}")
    
    # Step 1: Apply XOR
    xor_result = plugin._apply_xor(test_data, key)
    print(f"After XOR: {xor_result.hex()} -> {repr(xor_result)}")
    
    # Step 2: Apply Rotation
    rot_result = plugin._apply_rotation(xor_result, plugin.rotation_amount)
    print(f"After Rotation: {rot_result.hex()} -> {repr(rot_result)}")
    
    # Step 3: Apply Substitution
    table = plugin._get_default_substitution_table()
    sub_result = plugin._apply_substitution(rot_result, table)
    print(f"After Substitution: {sub_result.hex()} -> {repr(sub_result)}")
    
    # Now let's reverse the process
    print("\nReversing the process...")
    
    # Reverse 1: Undo Substitution
    reverse_table = [0] * 256
    for i in range(256):
        reverse_table[table[i]] = i
    un_sub_result = bytes(reverse_table[b] for b in sub_result)
    print(f"After Un-Substitution: {un_sub_result.hex()} -> {repr(un_sub_result)}")
    
    # Reverse 2: Undo Rotation
    un_rot_result = plugin._apply_rotation(un_sub_result, -plugin.rotation_amount)
    print(f"After Un-Rotation: {un_rot_result.hex()} -> {repr(un_rot_result)}")
    
    # Reverse 3: Undo XOR
    un_xor_result = plugin._apply_xor(un_rot_result, key)
    print(f"After Un-XOR: {un_xor_result.hex()} -> {repr(un_xor_result)}")
    
    print(f"Original: {test_data}")
    print(f"Final: {un_xor_result}")
    print(f"Match: {test_data == un_xor_result}")
    
    # Test with full function
    print(f"\nTesting with full function...")
    full_obfuscated = plugin._obfuscate_data(test_data, key)
    print(f"Full obfuscated: {full_obfuscated.hex()}")
    full_deobfuscated = plugin._deobfuscate_data(full_obfuscated, key)
    print(f"Full deobfuscated: {full_deobfuscated}")
    print(f"Full match: {test_data == full_deobfuscated}")

if __name__ == "__main__":
    debug_obfuscation()