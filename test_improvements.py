#!/usr/bin/env python3
"""Test script to verify the improvements made to the plugins."""

import os
import sys
import tempfile
from plugins.consolidated_utils import detect_format, calculate_entropy
from plugins.crypto_utils import safe_hash, generate_metadata_key
from plugins.packer_plugin import load_key_from_file

def test_consolidated_utils():
    """Test the consolidated utilities."""
    print("Testing consolidated utilities...")
    
    # Test calculate_entropy
    test_data = b"Hello, World! " * 100  # Repeated data should have low entropy
    entropy = calculate_entropy(test_data)
    print(f"Entropy of test data: {entropy}")
    assert 0 <= entropy <= 8, "Entropy should be between 0 and 8"
    
    # Test with empty data
    empty_entropy = calculate_entropy(b"")
    print(f"Entropy of empty data: {empty_entropy}")
    assert empty_entropy == 0, "Entropy of empty data should be 0"
    
    print("Consolidated utilities tests passed!")

def test_crypto_utils():
    """Test the crypto utilities."""
    print("Testing crypto utilities...")
    
    # Test safe_hash
    test_data = b"test data"
    hash_result = safe_hash(test_data)
    assert isinstance(hash_result, str), "Hash result should be a string"
    assert len(hash_result.split(':')) == 3, "Hash result should have three parts (hash:salt:key)"
    print(f"Safe hash result: {hash_result[:20]}...")
    
    # Test generate_metadata_key
    key = generate_metadata_key()
    assert isinstance(key, bytes), "Generated key should be bytes"
    assert len(key) == 32, "Generated key should be 32 bytes"
    print(f"Generated metadata key length: {len(key)}")
    
    # Test generate_metadata_key with password
    password = b"test_password"
    key_from_password = generate_metadata_key(password)
    assert isinstance(key_from_password, bytes), "Generated key should be bytes"
    assert len(key_from_password) == 32, "Generated key should be 32 bytes"
    print(f"Generated key from password length: {len(key_from_password)}")
    
    print("Crypto utilities tests passed!")

def test_packer_plugin():
    """Test the packer plugin utilities."""
    print("Testing packer plugin utilities...")
    
    # Test load_key_from_file with a temporary file
    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
        tmp_file.write(b"0" * 32)  # 32-byte key
        tmp_file_path = tmp_file.name
    
    try:
        key = load_key_from_file(tmp_file_path)
        assert isinstance(key, bytes), "Loaded key should be bytes"
        assert len(key) == 32, "Loaded key should be 32 bytes"
        print(f"Loaded key length: {len(key)}")
    finally:
        os.unlink(tmp_file_path)
    
    # Test error handling for non-existent file
    try:
        load_key_from_file("/non/existent/file")
        assert False, "Should have raised FileNotFoundError"
    except FileNotFoundError:
        print("FileNotFoundError correctly raised for non-existent file")
    
    # Test error handling for invalid key length
    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
        tmp_file.write(b"0" * 10)  # 10-byte key (invalid)
        tmp_file_path = tmp_file.name
    
    try:
        load_key_from_file(tmp_file_path)
        assert False, "Should have raised ValueError"
    except ValueError:
        print("ValueError correctly raised for invalid key length")
    finally:
        os.unlink(tmp_file_path)
    
    print("Packer plugin utilities tests passed!")

if __name__ == "__main__":
    print("Running tests for plugin improvements...")
    test_consolidated_utils()
    test_crypto_utils()
    test_packer_plugin()
    print("All tests passed!")