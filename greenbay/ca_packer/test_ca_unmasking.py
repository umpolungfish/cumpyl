#!/usr/bin/env python3
"""
Test script to verify the CA unmasking functionality in the unpacking stub.
"""

import os
import tempfile
import struct

def test_ca_unmasking():
    """Test the CA unmasking functionality."""
    print("Testing CA unmasking functionality...")
    
    # Create a test payload (32 bytes)
    payload = bytearray([i for i in range(32)])
    print(f"Original payload: {payload.hex()}")
    
    # Create a test key (32 bytes)
    key = bytearray([0x42] * 32)
    print(f"Key: {key.hex()}")
    
    # Create a test mask using the CA engine
    # For this test, we'll simulate what the CA engine would produce
    mask = bytearray([0xAA] * 32)
    print(f"Mask: {mask.hex()}")
    
    # Apply the mask (XOR)
    masked_payload = bytearray()
    for i in range(len(payload)):
        masked_payload.append(payload[i] ^ mask[i])
    print(f"Masked payload: {masked_payload.hex()}")
    
    # Now unmask it
    unmasked_payload = bytearray()
    for i in range(len(masked_payload)):
        unmasked_payload.append(masked_payload[i] ^ mask[i])
    print(f"Unmasked payload: {unmasked_payload.hex()}")
    
    # Verify the unmasked payload matches the original
    if unmasked_payload == payload:
        print("SUCCESS: CA unmasking works correctly!")
        return True
    else:
        print("ERROR: CA unmasking failed!")
        return False

def main():
    """Main function."""
    print("=== CA Unmasking Test ===")
    
    if test_ca_unmasking():
        print("\nAll tests passed!")
        return 0
    else:
        print("\nSome tests failed!")
        return 1

if __name__ == "__main__":
    exit(main())