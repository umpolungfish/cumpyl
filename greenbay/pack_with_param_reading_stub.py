#!/usr/bin/env python3
"""
Script to pack a binary using the parameter reading stub
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

def pack_with_param_reading_stub():
    """Pack the binary with our parameter reading stub"""
    print("Packing binary with parameter reading stub...")
    
    # Run the packer
    result = subprocess.run([
        sys.executable, "-m", "ca_packer.packer", 
        "test_binary", "param_reading_stub_packed_binary"
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
    
    # Pack with parameter reading stub
    if not pack_with_param_reading_stub():
        sys.exit(1)
    
    print("Parameter reading stub packed binary created successfully!")
