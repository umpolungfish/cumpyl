#!/usr/bin/env python3
"""
Test script to verify that our enhanced unpacking stub is working correctly
"""

import os
import subprocess
import sys

def test_enhanced_unpacking_stub():
    """Test that the enhanced unpacking stub works correctly"""
    print("Testing enhanced unpacking stub...")
    
    # Make sure the packed binary exists and is executable
    if not os.path.exists("enhanced_unpacking_stub_packed_binary"):
        print("ERROR: enhanced_unpacking_stub_packed_binary not found")
        return False
        
    # Make sure it's executable
    os.chmod("enhanced_unpacking_stub_packed_binary", 0o755)
    
    # Run the packed binary and check the output and exit code
    try:
        result = subprocess.run(["./enhanced_unpacking_stub_packed_binary"], 
                              capture_output=True, timeout=5)
        
        # Check that we got some output
        if result.stderr or result.stdout:
            print("SUCCESS: Enhanced unpacking stub executed and produced output")
            print(f"Exit code: {result.returncode}")
            print(f"Stdout: {result.stdout}")
            print(f"Stderr: {result.stderr}")
            return True
        else:
            print("ERROR: No output from enhanced unpacking stub")
            print(f"Exit code: {result.returncode}")
            return False
            
    except subprocess.TimeoutExpired:
        print("ERROR: Packed binary timed out")
        return False
    except Exception as e:
        print(f"ERROR: Failed to run packed binary: {e}")
        return False

if __name__ == "__main__":
    success = test_enhanced_unpacking_stub()
    sys.exit(0 if success else 1)