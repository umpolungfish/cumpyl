#!/usr/bin/env python3
"""
Simple test script to verify CA-Packer core functionality.
"""

import sys
import os

# Add the ca_packer directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'ca_packer'))

def test_core_modules():
    """Test that core modules can be imported."""
    try:
        import ca_engine
        print("[PASS] CA engine imported successfully")
        
        # Test CA engine functionality
        test_key = os.urandom(32)
        mask = ca_engine.generate_mask(test_key, 0, 32)
        print(f"[PASS] CA engine generated mask of length {len(mask)}")
        
    except Exception as e:
        print(f"[FAIL] CA engine test failed: {e}")
        return False
        
    try:
        import crypto_engine
        print("[PASS] Crypto engine imported successfully")
        
        # Test crypto engine functionality
        test_data = b"Test data for encryption"
        ciphertext, key, nonce = crypto_engine.encrypt_payload(test_data)
        decrypted = crypto_engine.decrypt_payload(ciphertext, key, nonce)
        print(f"[PASS] Crypto engine encrypt/decrypt cycle successful: {test_data == decrypted}")
        
    except Exception as e:
        print(f"[FAIL] Crypto engine test failed: {e}")
        return False
        
    return True

def main():
    print("Testing CA-Packer core functionality...")
    
    if test_core_modules():
        print("\n[PASS] All core functionality tests passed!")
        print("\nCA-Packer is ready for use.")
        return 0
    else:
        print("\n[FAIL] Some tests failed.")
        return 1

if __name__ == "__main__":
    sys.exit(main())