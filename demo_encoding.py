#!/usr/bin/env python3
"""
Example script demonstrating the encoding/decoding functionality of cumpyl
"""

import tempfile
import os
import sys
sys.path.insert(0, '.')

from cumpyl_package.cumpyl import BinaryRewriter, EncodingPlugin

def create_test_binary():
    """Create a simple test binary with identifiable data"""
    # Create a simple ELF binary with some identifiable strings
    with tempfile.NamedTemporaryFile(suffix='.c', delete=False) as f:
        f.write(b'''
#include <stdio.h>
#include <string.h>

int main() {
    char secret[] = "SECRET_DATA";
    char hidden[] = "HIDDEN_PAYLOAD";
    
    printf("Normal program output\\n");
    printf("Secret: %s\\n", secret);
    printf("Hidden: %s\\n", hidden);
    
    return 0;
}
        ''')
        c_file = f.name
    
    # Compile to binary
    binary_file = c_file.replace('.c', '')
    os.system(f'gcc -o {binary_file} {c_file}')
    
    # Clean up C file
    os.unlink(c_file)
    
    return binary_file

def demo_encoding():
    """Demonstrate encoding functionality"""
    # Create test binary
    binary_path = create_test_binary()
    
    try:
        # Load binary
        rewriter = BinaryRewriter(binary_path)
        if not rewriter.load_binary():
            print("Failed to load binary")
            return
            
        # Initialize encoding plugin
        plugin = EncodingPlugin()
        
        # Find a section that likely contains our strings (.rodata for ELF)
        print("[*] Available sections:")
        for section in rewriter.binary.sections:
            print(f"  - {section.name}")
            
        # Try to encode data in the .rodata section (contains strings in ELF)
        section_name = ".rodata"
        offset = 0
        length = 20  # Encode first 20 bytes
        
        print(f"[*] Encoding {length} bytes from {section_name} section...")
        encoded = plugin.encode_section_portion(rewriter, section_name, offset, length, "hex")
        
        if encoded:
            print(f"[+] Hex encoded data: {encoded}")
            
            # Demonstrate decoding and applying back
            print("[*] Decoding and applying back to binary...")
            success = plugin.decode_and_apply(rewriter, section_name, offset, encoded, "hex")
            if success:
                print("[+] Successfully decoded and applied back to binary")
            else:
                print("[-] Failed to decode and apply")
        else:
            print("[-] Failed to encode data")
            
        # Save modified binary
        output_path = binary_path + "_modified"
        if rewriter.save_binary(output_path):
            print(f"[+] Modified binary saved to {output_path}")
        else:
            print("[-] Failed to save modified binary")
            
    finally:
        # Clean up
        if os.path.exists(binary_path):
            os.unlink(binary_path)

if __name__ == "__main__":
    demo_encoding()