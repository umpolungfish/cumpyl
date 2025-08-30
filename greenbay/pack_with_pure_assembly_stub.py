#!/usr/bin/env python3
"""
Script to pack a binary using the pure assembly stub
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

def pack_with_pure_assembly_stub():
    """Pack the binary with our pure assembly stub"""
    print("Packing binary with pure assembly stub...")
    
    # Run the packer
    result = subprocess.run([
        sys.executable, "-m", "ca_packer.packer", 
        "test_binary", "pure_assembly_stub_packed_binary"
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
    
    # Pack with pure assembly stub
    if not pack_with_pure_assembly_stub():
        sys.exit(1)
    
    print("Pure assembly stub packed binary created successfully!")
