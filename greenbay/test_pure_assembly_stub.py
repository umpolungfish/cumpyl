#!/usr/bin/env python3
"""
Test script to verify that our pure assembly stub is working correctly
"""

import os
import subprocess
import sys

def test_pure_assembly_stub():
    """Test that the pure assembly stub works correctly"""
    print("Testing pure assembly stub...")
    
    # Make sure the packed binary exists and is executable
    if not os.path.exists("pure_assembly_stub_packed_binary"):
        print("ERROR: pure_assembly_stub_packed_binary not found")
        return False
        
    # Make sure it's executable
    os.chmod("pure_assembly_stub_packed_binary", 0o755)
    
    # Run the packed binary and check the output and exit code
    try:
        result = subprocess.run(["./pure_assembly_stub_packed_binary"], 
                              capture_output=True, timeout=5)
        
        # Check that it exited with code 42
        if result.returncode == 42:
            # Check that we got the expected output
            expected_text = "CA-Packer Enhanced Error Tracking Stub Executing"
            if expected_text in result.stderr.decode('utf-8'):
                print("SUCCESS: Pure assembly stub works correctly")
                print(f"Exit code: {result.returncode}")
                print(f"Stdout: {result.stdout}")
                print(f"Stderr: {result.stderr}")
                return True
            else:
                print(f"ERROR: Expected text '{expected_text}' not found in stderr='{result.stderr}'")
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
    success = test_pure_assembly_stub()
    sys.exit(0 if success else 1)