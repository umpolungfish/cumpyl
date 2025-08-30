#!/usr/bin/env python3
"""
Test script to verify that our functional unpacking stub is working correctly
"""

import os
import subprocess
import sys

def test_functional_unpacking_stub():
    """Test that the functional unpacking stub works correctly"""
    print("Testing functional unpacking stub...")
    
    # Make sure the packed binary exists and is executable
    if not os.path.exists("functional_unpacking_stub_packed_binary"):
        print("ERROR: functional_unpacking_stub_packed_binary not found")
        return False
        
    # Make sure it's executable
    os.chmod("functional_unpacking_stub_packed_binary", 0o755)
    
    # Run the packed binary and check the output and exit code
    try:
        result = subprocess.run(["./functional_unpacking_stub_packed_binary"], 
                              capture_output=True, timeout=5)
        
        # Check that it exited with code 42
        if result.returncode == 42:
            # Check that we got the expected output
            output = result.stderr.decode('utf-8')
            if ("CA-Packer Functional Unpacking Stub Executing" in output and 
                "Base address: 0x" in output and
                "OEP: 0x" in output and
                "Key Part 1: 0x" in output and
                "Key Part 2: 0x" in output and
                "Key Part 3: 0x" in output and
                "Key Part 4: 0x" in output and
                "Nonce: 0x" in output and
                "CA Steps: 0x" in output and
                "Payload RVA: 0x" in output and
                "Payload Size: 0x" in output):
                print("SUCCESS: Functional unpacking stub works correctly")
                print(f"Exit code: {result.returncode}")
                print(f"Stdout: {result.stdout}")
                print(f"Stderr: {result.stderr}")
                return True
            else:
                print(f"ERROR: Expected output not found in stderr='{result.stderr}'")
                print(f"Exit code: {result.returncode}")
                return False
        else:
            print(f"ERROR: Expected exit code 42, got {result.returncode}")
            print(f"Stdout: {result.stdout}")
            print(f"Stderr: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("ERROR: Packed binary timed out")
        return False
    except Exception as e:
        print(f"ERROR: Failed to run packed binary: {e}")
        return False

if __name__ == "__main__":
    success = test_functional_unpacking_stub()
    sys.exit(0 if success else 1)