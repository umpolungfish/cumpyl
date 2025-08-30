#!/usr/bin/env python3
"""
Script to pack a binary using the assembly debug test
"""

import os
import sys
import subprocess

def create_test_binary():
    """Create a simple test binary"""
    print("Creating test binary...")
    test_c_code = '''#include <stdio.h>

int main() {
    printf("Hello, World! This is a test binary.\\n");
    return 0;
}
'''
    
    with open("test_binary.c", "w") as f:
        f.write(test_c_code)
    
    # Compile the test binary
    print("Compiling test binary...")
    result = subprocess.run(["gcc", "-o", "test_binary", "test_binary.c"], 
                          capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Compilation failed: {result.stderr}")
        return False
    
    return True

def pack_with_assembly_test():
    """Pack the binary with our assembly debug test"""
    print("Packing binary with assembly debug test...")
    
    # Copy the assembly test blob to where the packer expects it
    import shutil
    shutil.copy(
        "/home/mrnob0dy666/cumpyl/greenbay/ca_packer/assembly_debug_test_compiled.bin",
        "/home/mrnob0dy666/cumpyl/greenbay/ca_packer/minimal_exit_stub_v2_compiled.bin"
    )
    
    # Run the packer
    result = subprocess.run([
        sys.executable, "-m", "ca_packer.packer", 
        "test_binary", "assembly_debug_test_packed_binary"
    ], capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"Packing failed: {result.stderr}")
        return False
    
    print("Packing successful!")
    return True

if __name__ == "__main__":
    # Create test binary
    if not create_test_binary():
        sys.exit(1)
    
    # Pack with assembly test
    if not pack_with_assembly_test():
        sys.exit(1)
    
    print("Assembly debug test packed binary created successfully!")