#!/usr/bin/env python3
"""
Compilation script for the complete unpacking stub.
"""

import subprocess
import sys
import os

def main():
    # Get the directory of this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Define paths
    stub_source = os.path.join(script_dir, "complete_unpacking_stub.s")
    ca_evolution_source = os.path.join(script_dir, "ca_evolution_complete.s")
    chacha20_poly1305_source = os.path.join(script_dir, "chacha20_poly1305_minimal.s")
    stub_object = os.path.join(script_dir, "complete_unpacking_stub.o")
    ca_evolution_object = os.path.join(script_dir, "ca_evolution_complete.o")
    chacha20_poly1305_object = os.path.join(script_dir, "chacha20_poly1305_minimal.o")
    stub_elf = os.path.join(script_dir, "complete_unpacking_stub.elf")
    stub_binary = os.path.join(script_dir, "complete_unpacking_stub_compiled.bin")
    
    # Check if source files exist
    if not os.path.exists(stub_source):
        print(f"Error: Source file {stub_source} not found.")
        return 1
    
    if not os.path.exists(ca_evolution_source):
        print(f"Error: CA evolution source file {ca_evolution_source} not found.")
        return 1
    
    if not os.path.exists(chacha20_poly1305_source):
        print(f"Error: ChaCha20-Poly1305 source file {chacha20_poly1305_source} not found.")
        return 1
    
    # Compile the stub
    print("Compiling complete unpacking stub...")
    result = subprocess.run([
        "as", "--64", stub_source, "-o", stub_object
    ], capture_output=True, text=True)
    
    if result.returncode != 0:
        print("Error: Failed to compile stub.")
        print(f"stderr: {result.stderr}")
        return 1
    
    # Compile the CA evolution implementation
    print("Compiling CA evolution implementation...")
    result = subprocess.run([
        "as", "--64", ca_evolution_source, "-o", ca_evolution_object
    ], capture_output=True, text=True)
    
    if result.returncode != 0:
        print("Error: Failed to compile CA evolution implementation.")
        print(f"stderr: {result.stderr}")
        return 1
    
    # Compile the ChaCha20-Poly1305 implementation
    print("Compiling ChaCha20-Poly1305 implementation...")
    result = subprocess.run([
        "as", "--64", chacha20_poly1305_source, "-o", chacha20_poly1305_object
    ], capture_output=True, text=True)
    
    if result.returncode != 0:
        print("Error: Failed to compile ChaCha20-Poly1305 implementation.")
        print(f"stderr: {result.stderr}")
        return 1
    
    # Link the objects to create an ELF executable
    print("Linking objects to create ELF executable...")
    result = subprocess.run([
        "ld", "-n", "-Ttext=0x400000", 
        stub_object, 
        ca_evolution_object, 
        chacha20_poly1305_object, 
        "-o", stub_elf
    ], capture_output=True, text=True)
    
    if result.returncode != 0:
        print("Error: Failed to link objects.")
        print(f"stderr: {result.stderr}")
        return 1
    
    # Extract the raw binary data
    print("Extracting raw binary data...")
    result = subprocess.run([
        "objcopy", "-O", "binary", stub_elf, stub_binary
    ], capture_output=True, text=True)
    
    if result.returncode != 0:
        print("Error: Failed to extract raw binary data.")
        print(f"stderr: {result.stderr}")
        return 1
    
    print(f"Successfully compiled complete unpacking stub: {stub_binary}")
    print(f"ELF executable: {stub_elf}")
    return 0

if __name__ == "__main__":
    sys.exit(main())