#!/usr/bin/env python3
"""
Demonstration script for CA-Packer stub development progress
"""

import subprocess
import sys
import os

def main():
    print("=== CA-Packer Stub Development Progress Demo ===\n")
    
    # Show the functional unpacking stub source
    print("1. Functional Unpacking Stub Source (functional_unpacking_stub.s):")
    print("   ----------------------------------------")
    with open("/home/mrnob0dy666/cumpyl/greenbay/ca_packer/functional_unpacking_stub.s", "r") as f:
        content = f.read()
        # Show only the first 50 lines to keep output manageable
        lines = content.split('\n')
        for i, line in enumerate(lines[:50]):
            print(f"   {i+1:2d}: {line}")
        if len(lines) > 50:
            print("   ... (truncated for brevity)")
    print("   ----------------------------------------\n")
    
    # Show that we can compile it
    print("2. Compiling the Functional Unpacking Stub:")
    print("   ----------------------------------------")
    result = subprocess.run([
        "python3", "/home/mrnob0dy666/cumpyl/greenbay/ca_packer/compile_functional_unpacking_stub.py"
    ], capture_output=True, text=True, cwd="/home/mrnob0dy666/cumpyl/greenbay/ca_packer")
    
    if result.returncode == 0:
        print("   SUCCESS: Functional unpacking stub compiled successfully")
        print(f"   Output: {result.stdout.strip()}")
    else:
        print("   ERROR: Failed to compile functional unpacking stub")
        print(f"   Error: {result.stderr}")
        return 1
    print("   ----------------------------------------\n")
    
    # Show that we can pack a binary with it
    print("3. Packing a Binary with the Functional Unpacking Stub:")
    print("   ----------------------------------------")
    result = subprocess.run([
        "python3", "/home/mrnob0dy666/cumpyl/greenbay/pack_with_functional_unpacking_stub.py"
    ], capture_output=True, text=True, cwd="/home/mrnob0dy666/cumpyl/greenbay")
    
    if result.returncode == 0:
        print("   SUCCESS: Binary packed with functional unpacking stub")
        print(f"   Output: {result.stdout.strip()}")
    else:
        print("   ERROR: Failed to pack binary with functional unpacking stub")
        print(f"   Error: {result.stderr}")
        return 1
    print("   ----------------------------------------\n")
    
    # Show that it executes correctly
    print("4. Executing the Packed Binary:")
    print("   ----------------------------------------")
    # Make sure the binary is executable
    subprocess.run(["chmod", "+x", "/home/mrnob0dy666/cumpyl/greenbay/functional_unpacking_stub_packed_binary"])
    
    result = subprocess.run([
        "./functional_unpacking_stub_packed_binary"
    ], capture_output=True, text=True, cwd="/home/mrnob0dy666/cumpyl/greenbay")
    
    print(f"   Exit code: {result.returncode}")
    print(f"   Stdout: {result.stdout}")
    print(f"   Stderr: {result.stderr}")
    
    if result.returncode == 42 and "CA-Packer Functional Unpacking Stub Executing" in result.stderr:
        print("   SUCCESS: Functional unpacking stub executed correctly!")
    else:
        print("   ERROR: Functional unpacking stub did not execute as expected")
        return 1
    print("   ----------------------------------------\n")
    
    # Run our test script
    print("5. Running Automated Tests:")
    print("   ----------------------------------------")
    result = subprocess.run([
        "python3", "/home/mrnob0dy666/cumpyl/greenbay/test_functional_unpacking_stub.py"
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
    print("The CA-Packer stub development progress has been successfully demonstrated!")
    print("\nSummary of achievements:")
    print("- Created a pure assembly stub that replaces problematic C-based stubs")
    print("- Implemented parameter reading functionality")
    print("- Developed a functional unpacking stub that reads all parameters")
    print("- Created automated tests to verify functionality")
    print("- Documented the parameter structure and usage")
    return 0

if __name__ == "__main__":
    sys.exit(main())