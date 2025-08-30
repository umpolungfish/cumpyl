#!/usr/bin/env python3
"""
Test script to verify that our enhanced error tracking stub is working correctly
"""

import os
import subprocess
import sys

def test_enhanced_error_tracking_stub():
    """Test that the enhanced error tracking stub works correctly"""
    print("Testing enhanced error tracking stub...")
    
    # Make sure the packed binary exists and is executable
    if not os.path.exists("enhanced_error_tracking_packed_binary"):
        print("ERROR: enhanced_error_tracking_packed_binary not found")
        return False
        
    # Make sure it's executable
    os.chmod("enhanced_error_tracking_packed_binary", 0o755)
    
    # Run the packed binary and check the exit code
    try:
        result = subprocess.run(["./enhanced_error_tracking_packed_binary"], 
                              capture_output=True, timeout=5)
        
        # Check that it exited with code 42
        if result.returncode == 42:
            print("SUCCESS: Enhanced error tracking stub works correctly")
            print(f"Exit code: {result.returncode}")
            print(f"Stdout: {result.stdout}")
            print(f"Stderr: {result.stderr}")
            return True
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
    success = test_enhanced_error_tracking_stub()
    sys.exit(0 if success else 1)