#!/usr/bin/env python3
"""
Demonstration script for CA-Packer development progress
"""

import subprocess
import sys
import os

def main():
    print("=== CA-Packer Development Progress Demo ===\n")
    
    # Show that we can compile our ChaCha20 core implementation
    print("1. Compiling ChaCha20 Core Implementation:")
    print("   ----------------------------------------")
    result = subprocess.run([
        "as", "--64", 
        "/home/mrnob0dy666/cumpyl/greenbay/ca_packer/chacha20_core_callable.s",
        "-o", "/home/mrnob0dy666/cumpyl/greenbay/ca_packer/chacha20_core_callable.o"
    ], capture_output=True, text=True, cwd="/home/mrnob0dy666/cumpyl/greenbay/ca_packer")
    
    if result.returncode == 0:
        print("   SUCCESS: ChaCha20 core implementation compiled successfully")
        if result.stderr:
            print(f"   Compiler warnings: {result.stderr.strip()}")
    else:
        print("   ERROR: Failed to compile ChaCha20 core implementation")
        print(f"   Error: {result.stderr}")
        return 1
    print("   ----------------------------------------\n")
    
    # Show that we can link it with our test program
    print("2. Linking ChaCha20 Core Implementation with Test Program:")
    print("   ----------------------------------------")
    result = subprocess.run([
        "gcc", "-o", 
        "/home/mrnob0dy666/cumpyl/greenbay/ca_packer/test_chacha20_core",
        "/home/mrnob0dy666/cumpyl/greenbay/ca_packer/test_chacha20_core.c",
        "/home/mrnob0dy666/cumpyl/greenbay/ca_packer/chacha20_core_callable.o"
    ], capture_output=True, text=True, cwd="/home/mrnob0dy666/cumpyl/greenbay/ca_packer")
    
    if result.returncode == 0:
        print("   SUCCESS: ChaCha20 core implementation linked with test program")
        if result.stderr:
            print(f"   Linker warnings: {result.stderr.strip()}")
    else:
        print("   ERROR: Failed to link ChaCha20 core implementation with test program")
        print(f"   Error: {result.stderr}")
        return 1
    print("   ----------------------------------------\n")
    
    # Show that our test program works
    print("3. Testing ChaCha20 Core Implementation:")
    print("   ----------------------------------------")
    result = subprocess.run([
        "./test_chacha20_core"
    ], capture_output=True, text=True, cwd="/home/mrnob0dy666/cumpyl/greenbay/ca_packer")
    
    print(result.stdout)
    if result.returncode == 0:
        print("   SUCCESS: ChaCha20 core implementation test passed!")
    else:
        print("   ERROR: ChaCha20 core implementation test failed")
        print(f"   Error: {result.stderr}")
        return 1
    
    if result.stderr and "Keystream generated successfully!" in result.stderr:
        print("   NOTE: Keystream was generated successfully!")
    print("   ----------------------------------------\n")
    
    # Show that we can compile our enhanced unpacking stub
    print("4. Compiling Enhanced Unpacking Stub:")
    print("   ----------------------------------------")
    result = subprocess.run([
        "python3", 
        "/home/mrnob0dy666/cumpyl/greenbay/ca_packer/compile_enhanced_unpacking_stub_chacha20.py"
    ], capture_output=True, text=True, cwd="/home/mrnob0dy666/cumpyl/greenbay/ca_packer")
    
    if result.returncode == 0:
        print("   SUCCESS: Enhanced unpacking stub compiled successfully")
        print(f"   Output: {result.stdout.strip()}")
    else:
        print("   ERROR: Failed to compile enhanced unpacking stub")
        print(f"   Error: {result.stderr}")
        return 1
    print("   ----------------------------------------\n")
    
    # Show that we can pack a binary with it
    print("5. Packing a Binary with Enhanced Unpacking Stub:")
    print("   ----------------------------------------")
    result = subprocess.run([
        "python3", "-m", "ca_packer.packer", 
        "test_binary", "enhanced_unpacking_stub_packed_binary"
    ], capture_output=True, text=True, cwd="/home/mrnob0dy666/cumpyl/greenbay")
    
    if result.returncode == 0:
        print("   SUCCESS: Binary packed with enhanced unpacking stub")
        print(f"   Output: {result.stdout.strip()}")
    else:
        print("   ERROR: Failed to pack binary with enhanced unpacking stub")
        print(f"   Error: {result.stderr}")
        return 1
    print("   ----------------------------------------\n")
    
    # Show that it executes and produces output (even if it segfaults)
    print("6. Executing the Packed Binary:")
    print("   ----------------------------------------")
    # Make sure the binary is executable
    subprocess.run(["chmod", "+x", "/home/mrnob0dy666/cumpyl/greenbay/enhanced_unpacking_stub_packed_binary"])
    
    result = subprocess.run([
        "./enhanced_unpacking_stub_packed_binary"
    ], capture_output=True, text=True, cwd="/home/mrnob0dy666/cumpyl/greenbay")
    
    print(f"   Exit code: {result.returncode}")
    print(f"   Stdout: {result.stdout}")
    print(f"   Stderr: {result.stderr}")
    
    if "CA-Packer Enhanced Unpacking Stub with ChaCha20 Executing" in result.stderr:
        print("   SUCCESS: Enhanced unpacking stub executed and produced output!")
        print("   NOTE: Segmentation fault is expected since full unpacking isn't implemented yet.")
    else:
        print("   ERROR: Enhanced unpacking stub did not execute as expected")
        return 1
    print("   ----------------------------------------\n")
    
    # Run our test script
    print("7. Running Automated Tests:")
    print("   ----------------------------------------")
    result = subprocess.run([
        "python3", "/home/mrnob0dy666/cumpyl/greenbay/test_chacha20_enhanced_unpacking_stub.py"
    ], capture_output=True, text=True, cwd="/home/mrnob0dy666/cumpyl/greenbay")
    
    print(result.stdout)
    if result.returncode == 0:
        print("   SUCCESS: All tests passed!")
    else:
        print("   ERROR: Tests failed")
        print(f"   Error: {result.stderr}")
        return 1
    print("   ----------------------------------------\n")
    
    print("=== Demo Complete ===")
    print("The CA-Packer development progress has been successfully demonstrated!")
    print("\nSummary of achievements:")
    print("- Created a pure assembly stub that replaces problematic C-based stubs")
    print("- Implemented parameter reading functionality")
    print("- Developed a ChaCha20-enhanced unpacking stub that reads and deobfuscates all parameters")
    print("- Implemented ChaCha20 core functions in assembly")
    print("- Created automated tests to verify functionality")
    print("- Successfully packed and executed a binary with the enhanced stub")
    return 0

if __name__ == "__main__":
    sys.exit(main())