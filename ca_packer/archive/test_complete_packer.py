#!/usr/bin/env python3
"""
Test script for the complete CA packer.
"""

import subprocess
import sys
import os

def main():
    # Get the directory of this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Define paths
    test_program_source = os.path.join(script_dir, "test_program.c")
    test_program_binary = os.path.join(script_dir, "test_program")
    packed_binary = os.path.join(script_dir, "packed_test_program")
    
    # Create a simple test program
    print("Creating test program...")
    with open(test_program_source, "w") as f:
        f.write("""
#include <stdio.h>

int main() {
    printf("Hello, World! This is a test program.\\n");
    return 0;
}
""")
    
    # Compile the test program
    print("Compiling test program...")
    result = subprocess.run([
        "gcc", test_program_source, "-o", test_program_binary
    ], capture_output=True, text=True)
    
    if result.returncode != 0:
        print("Error: Failed to compile test program.")
        print(f"stderr: {result.stderr}")
        return 1
    
    # Make sure the test program is executable
    os.chmod(test_program_binary, 0o755)
    
    # Test the original program
    print("Testing original program...")
    result = subprocess.run([test_program_binary], capture_output=True, text=True)
    print(f"Original program output: {result.stdout}")
    
    # Pack the test program
    print("Packing test program...")
    packer_script = os.path.join(script_dir, "packer.py")
    result = subprocess.run([
        "python3", packer_script, test_program_binary, packed_binary
    ], capture_output=True, text=True)
    
    if result.returncode != 0:
        print("Error: Failed to pack test program.")
        print(f"stderr: {result.stderr}")
        return 1
    
    print(f"Successfully packed test program: {packed_binary}")
    
    # Make sure the packed program is executable
    os.chmod(packed_binary, 0o755)
    
    # Test the packed program
    print("Testing packed program...")
    result = subprocess.run([packed_binary], capture_output=True, text=True)
    print(f"Packed program exit code: {result.returncode}")
    print(f"Packed program stdout: {result.stdout}")
    print(f"Packed program stderr: {result.stderr}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())