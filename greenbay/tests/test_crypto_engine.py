#!/usr/bin/env python3
"""
Unit tests for the Crypto Engine module (crypto_engine.py).
"""

import sys
import os

# Add the ca_packer directory to the path so we can import modules from it
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'ca_packer'))

import unittest
import crypto_engine

class TestCryptoEngine(unittest.TestCase):

    def test_encrypt_decrypt_success(self):
        """Test successful encryption and decryption cycle."""
        plaintext = b"This is a test message for encryption and decryption."
        ciphertext, key, nonce = crypto_engine.encrypt_payload(plaintext)

        # Ensure components are the correct length
        self.assertEqual(len(key), 32) # ChaCha20-Poly1305 key size
        self.assertEqual(len(nonce), 12) # ChaCha20-Poly1305 nonce size
        # Ciphertext should be longer than plaintext due to the authentication tag
        self.assertGreater(len(ciphertext), len(plaintext))

        # Decrypt
        decrypted_text = crypto_engine.decrypt_payload(ciphertext, key, nonce)

        # Check if the decrypted text matches the original
        self.assertEqual(plaintext, decrypted_text)

    def test_encrypt_decrypt_with_provided_key(self):
        """Test encryption/decryption with a provided key."""
        plaintext = b"Data encrypted with a specific key."
        key = crypto_engine.generate_key() # Generate a valid key
        self.assertEqual(len(key), 32)

        ciphertext, returned_key, nonce = crypto_engine.encrypt_payload(plaintext, key=key)
        # The returned key should be the same as the provided key
        self.assertEqual(key, returned_key)

        decrypted_text = crypto_engine.decrypt_payload(ciphertext, key, nonce)
        self.assertEqual(plaintext, decrypted_text)

    def test_decrypt_with_wrong_key(self):
        """Test that decryption fails with an incorrect key."""
        plaintext = b"Secret message."
        ciphertext, correct_key, nonce = crypto_engine.encrypt_payload(plaintext)
        wrong_key = crypto_engine.generate_key() # A different key
        self.assertNotEqual(correct_key, wrong_key)

        # Decryption with wrong key should raise an exception (likely InvalidTag)
        with self.assertRaises(Exception): # cryptography.exceptions.InvalidTag or similar
            crypto_engine.decrypt_payload(ciphertext, wrong_key, nonce)

    def test_decrypt_with_wrong_nonce(self):
        """Test that decryption fails with an incorrect nonce."""
        plaintext = b"Another secret message."
        ciphertext, key, correct_nonce = crypto_engine.encrypt_payload(plaintext)
        wrong_nonce = b"wrong_nonce_12" # 12 bytes, but different value
        self.assertNotEqual(correct_nonce, wrong_nonce)

        # Decryption with wrong nonce should raise an exception
        with self.assertRaises(Exception): # cryptography.exceptions.InvalidTag or similar
             crypto_engine.decrypt_payload(ciphertext, key, wrong_nonce)

    def test_encrypt_with_invalid_key_length(self):
        """Test that encryption fails with an invalid key length."""
        plaintext = b"Message with bad key."
        invalid_short_key = b"short_key" # < 32 bytes
        invalid_long_key = b"This_key_is_way_too_long_and_invalid_for_Chacha20Poly1305_see" # > 32 bytes

        with self.assertRaises(ValueError):
            crypto_engine.encrypt_payload(plaintext, key=invalid_short_key)

        with self.assertRaises(ValueError):
            crypto_engine.encrypt_payload(plaintext, key=invalid_long_key)

    def test_decrypt_with_invalid_key_length(self):
        """Test that decryption fails with an invalid key length."""
        ciphertext = b"some_encrypted_data"
        nonce = b"123456789012" # 12 bytes
        invalid_key = b"bad_key" # Not 32 bytes

        with self.assertRaises(ValueError):
            crypto_engine.decrypt_payload(ciphertext, invalid_key, nonce)

    def test_decrypt_with_invalid_nonce_length(self):
        """Test that decryption fails with an invalid nonce length."""
        ciphertext = b"some_encrypted_data"
        key = crypto_engine.generate_key() # 32 bytes
        invalid_nonce = b"bad_nonce" # Not 12 bytes

        with self.assertRaises(ValueError):
            crypto_engine.decrypt_payload(ciphertext, key, invalid_nonce)

if __name__ == '__main__':
    unittest.main()
