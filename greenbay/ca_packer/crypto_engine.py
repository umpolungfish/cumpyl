#!/usr/bin/env python3
"""
Crypto Engine Module for the CA-Packer project.
Handles encryption and decryption of the payload using the chosen cipher (ChaCha20-Poly1305).
"""

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os
import logging

def generate_key():
    """
    Generates a new, random 256-bit key for ChaCha20-Poly1305.
    """
    return ChaCha20Poly1305.generate_key()

def encrypt_payload(plaintext: bytes, key: bytes = None) -> tuple[bytes, bytes, bytes]:
    """
    Encrypts the given plaintext using ChaCha20-Poly1305.

    Args:
        plaintext (bytes): The data to encrypt.
        key (bytes, optional): The 32-byte key. If None, a new key is generated.

    Returns:
        tuple[bytes, bytes, bytes]: A tuple containing:
            - ciphertext (bytes): The encrypted data (including the authentication tag).
            - key (bytes): The 32-byte encryption key.
            - nonce (bytes): The 12-byte nonce used for encryption.
    """
    if key is None:
        key = generate_key()
    elif len(key) != 32:
        raise ValueError("ChaCha20-Poly1305 key must be 32 bytes long.")

    nonce = os.urandom(12) # 96-bit nonce for ChaCha20-Poly1305
    aead = ChaCha20Poly1305(key)

    try:
        ciphertext = aead.encrypt(nonce, plaintext, None) # No associated data
        logging.debug(f"Payload encrypted. Plaintext size: {len(plaintext)}, Ciphertext size: {len(ciphertext)}")
        return ciphertext, key, nonce
    except Exception as e:
        logging.error(f"Encryption failed: {e}")
        raise

def decrypt_payload(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    Decrypts the given ciphertext using ChaCha20-Poly1305.

    Args:
        ciphertext (bytes): The data to decrypt (including the authentication tag).
        key (bytes): The 32-byte encryption key.
        nonce (bytes): The 12-byte nonce used for encryption.

    Returns:
        bytes: The decrypted plaintext.

    Raises:
        cryptography.exceptions.InvalidTag: If the integrity check fails.
    """
    if len(key) != 32:
        raise ValueError("ChaCha20-Poly1305 key must be 32 bytes long.")
    if len(nonce) != 12:
        raise ValueError("ChaCha20Poly1305 nonce must be 12 bytes long.")

    aead = ChaCha20Poly1305(key)
    try:
        plaintext = aead.decrypt(nonce, ciphertext, None) # No associated data
        logging.debug(f"Payload decrypted. Ciphertext size: {len(ciphertext)}, Plaintext size: {len(plaintext)}")
        return plaintext
    except Exception as e:
        logging.error(f"Decryption failed (integrity check or other error): {e}")
        raise # Re-raise the exception (likely InvalidTag)

# Example usage (if run as a script)
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

    test_data = b"This is a test payload for encryption."
    print(f"Original data: {test_data}")

    # --- Encrypt ---
    ciphertext, key, nonce = encrypt_payload(test_data)
    print(f"Encrypted data (len={len(ciphertext)}): {ciphertext.hex()}")
    print(f"Key (len={len(key)}): {key.hex()}")
    print(f"Nonce (len={len(nonce)}): {nonce.hex()}")

    # --- Decrypt ---
    try:
        decrypted_data = decrypt_payload(ciphertext, key, nonce)
        print(f"Decrypted data: {decrypted_data}")
        print(f"Match: {test_data == decrypted_data}")
    except Exception as e:
        print(f"Decryption failed: {e}")
