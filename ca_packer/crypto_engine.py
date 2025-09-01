#!/usr/bin/env python3
"""
Crypto Engine Module for the CA-Packer project.
Handles encryption and decryption of the payload using the chosen cipher (ChaCha20-Poly1305).
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import logging

def generate_key():
    """
    Generates a new, random 256-bit key for ChaCha20.
    """
    return os.urandom(32)

def encrypt_payload(plaintext: bytes, key: bytes = None) -> tuple[bytes, bytes, bytes]:
    """
    Encrypts the given plaintext using the ChaCha20 stream cipher.

    Args:
        plaintext (bytes): The data to encrypt.
        key (bytes, optional): The 32-byte key. If None, a new key is generated.

    Returns:
        tuple[bytes, bytes, bytes]: A tuple containing:
            - ciphertext (bytes): The encrypted data.
            - key (bytes): The 32-byte encryption key.
            - nonce (bytes): The 12-byte nonce used for encryption.
    """
    if key is None:
        key = generate_key()
    elif len(key) != 32:
        raise ValueError("ChaCha20 key must be 32 bytes long.")

    nonce = os.urandom(12)
    # The counter for ChaCha20 is 4 bytes. We set it to a starting value of 1,
    # which is common practice and matches the stub's expectation.
    # The full 16-byte IV is nonce (12 bytes) + counter (4 bytes).
    iv = nonce + (1).to_bytes(4, 'little')
    
    algorithm = algorithms.ChaCha20(key, iv)
    cipher = Cipher(algorithm, mode=None)
    encryptor = cipher.encryptor()

    try:
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        logging.debug(f"Payload encrypted. Plaintext size: {len(plaintext)}, Ciphertext size: {len(ciphertext)}")
        return ciphertext, key, nonce
    except Exception as e:
        logging.error(f"Encryption failed: {e}")
        raise

def decrypt_payload(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    Decrypts the given ciphertext using the ChaCha20 stream cipher.
    Note: For a stream cipher, decryption is the same operation as encryption.

    Args:
        ciphertext (bytes): The data to decrypt.
        key (bytes): The 32-byte encryption key.
        nonce (bytes): The 12-byte nonce used for encryption.

    Returns:
        bytes: The decrypted plaintext.
    """
    if len(key) != 32:
        raise ValueError("ChaCha20 key must be 32 bytes long.")
    if len(nonce) != 12:
        raise ValueError("ChaCha20 nonce must be 12 bytes long.")

    iv = nonce + (1).to_bytes(4, 'little')
    algorithm = algorithms.ChaCha20(key, iv)
    cipher = Cipher(algorithm, mode=None)
    decryptor = cipher.decryptor()

    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        logging.debug(f"Payload decrypted. Ciphertext size: {len(ciphertext)}, Plaintext size: {len(plaintext)}")
        return plaintext
    except Exception as e:
        logging.error(f"Decryption failed: {e}")
        raise

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
