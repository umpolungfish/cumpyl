#!/usr/bin/env python3
"""
Simple test script to run the packer on our test binary.
"""

import sys
import os

# Add the ca_packer directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'ca_packer'))

from ca_packer import packer

def main():
    input_path = os.path.join(os.path.dirname(__file__), 'test_binary.exe')
    output_path = os.path.join(os.path.dirname(__file__), 'test_binary_packed.exe')

    if not os.path.exists(input_path):
        print(f"Error: Test binary not found at {input_path}")
        sys.exit(1)

    try:
        print(f"Packing '{input_path}' -> '{output_path}'")
        packer.pack_binary(input_path, output_path)
        print("Packing completed successfully.")
    except Exception as e:
        print(f"Error during packing: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()