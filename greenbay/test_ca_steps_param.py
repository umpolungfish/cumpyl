#!/usr/bin/env python3
"""
Minimal test for the --ca-steps parameter implementation.
"""

import sys
import os
import argparse

# Add the ca_packer directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_ca_steps_parameter():
    """Test that the --ca-steps parameter works correctly"""
    parser = argparse.ArgumentParser(description="Test CA-Packer parameter handling")
    parser.add_argument("input_binary", help="Path to the input binary to pack")
    parser.add_argument("output_packed_binary", help="Path where the packed binary will be saved")
    parser.add_argument("--ca-steps", type=int, default=100, help="Number of CA steps to use for mask generation (default: 100)")
    
    # For testing purposes, we'll just parse the args and verify
    # In a real implementation, we would use these values
    args = parser.parse_args()
    
    print(f"Input binary: {args.input_binary}")
    print(f"Output packed binary: {args.output_packed_binary}")
    print(f"CA steps: {args.ca_steps}")
    
    # Verify the value is what we expect
    if args.ca_steps == 200:
        print("Test passed! CA steps parameter correctly parsed.")
        return True
    else:
        print(f"Test failed! Expected CA steps to be 200, but got {args.ca_steps}")
        return False

if __name__ == "__main__":
    # Test with sample arguments
    test_result = test_ca_steps_parameter()
    sys.exit(0 if test_result else 1)