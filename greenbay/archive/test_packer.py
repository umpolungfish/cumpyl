#!/usr/bin/env python3
"""
Test script for the CA-Packer.
This script verifies that the packer is working correctly.
"""

import os
import sys
import subprocess

def test_packer():
    """Test the CA-Packer with a simple binary."""
    print("Testing CA-Packer...")
    
    # Create a simple test binary
    print("Creating test binary...")
    test_c_code = """
#include <stdio.h>

int main() {
    printf("Hello, World! This is a test binary.\\n");
    return 0;
}
"""
    
    with open("test_binary.c", "w") as f:
        f.write(test_c_code)
    
    # Compile the test binary
    print("Compiling test binary...")
    result = subprocess.run(["gcc", "-o", "test_binary", "test_binary.c"], 
                          capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Compilation failed: {result.stderr}")
        return False
    
    # Test packing
    print("Packing test binary...")
    result = subprocess.run([
        sys.executable, "-m", "ca_packer.packer", 
        "test_binary", "packed_test_binary"
    ], capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"Packing failed: {result.stderr}")
        return False
    
    print("Packing successful!")
    print("Test completed.")
    return True

if __name__ == "__main__":
    success = test_packer()
    if success:
        print("All tests passed!")
        sys.exit(0)
    else:
        print("Tests failed!")
        sys.exit(1)