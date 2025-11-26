"""
Encryption engine for CA-based binary packing
Provides cryptographic functionality for securing packed binaries.
"""

import os
import secrets
import hashlib
import hmac
from typing import Optional, Tuple, Union
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

def derive_key_from_password(password: bytes, salt: bytes = None, iterations: int = 100000) -> Tuple[bytes, bytes]:
    """
    Derive a cryptographic key from a password using PBKDF2.
    
    Args:
        password: Password to derive key from
        salt: Salt for key derivation (generated if not provided)
        iterations: Number of PBKDF2 iterations
        
    Returns:
        Tuple of (derived key, salt used)
    """
    if salt is None:
        salt = secrets.token_bytes(16)  # 128-bit salt
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    
    key = kdf.derive(password)
    return key, salt

def encrypt_payload(payload: bytes, key: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypt a payload using AES in CBC mode.
    
    Args:
        payload: Data to encrypt
        key: Encryption key (32 bytes for AES-256)
        
    Returns:
        Tuple of (encrypted_data, iv, padding_length)
    """
    # Generate a random IV
    iv = secrets.token_bytes(16)  # 128-bit IV for AES
    
    # Pad the payload to be a multiple of 16 bytes (AES block size)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(payload)
    padded_data += padder.finalize()
    
    # Encrypt the data
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    return encrypted_data, iv, len(payload) % 16

def decrypt_payload(encrypted_data: bytes, iv: bytes, key: bytes, original_padding: int = 0) -> bytes:
    """
    Decrypt a payload encrypted with encrypt_payload.
    
    Args:
        encrypted_data: Data to decrypt
        iv: Initialization vector used during encryption
        key: Encryption key (32 bytes for AES-256)
        original_padding: Original padding length (for future use)
        
    Returns:
        Decrypted data
    """
    # Decrypt the data
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # Unpad the data
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data)
    data += unpadder.finalize()
    
    return data

def create_authentication_tag(data: bytes, key: bytes) -> bytes:
    """
    Create an HMAC-SHA256 authentication tag for data integrity verification.
    
    Args:
        data: Data to authenticate
        key: Key for HMAC calculation
        
    Returns:
        Authentication tag
    """
    h = hmac.new(key, data, hashlib.sha256)
    return h.digest()

def verify_authentication_tag(data: bytes, key: bytes, tag: bytes) -> bool:
    """
    Verify the HMAC-SHA256 authentication tag.
    
    Args:
        data: Data to authenticate
        key: Key for HMAC calculation
        tag: Expected authentication tag
        
    Returns:
        True if authentication succeeds, False otherwise
    """
    expected_tag = create_authentication_tag(data, key)
    return hmac.compare_digest(expected_tag, tag)

def generate_secure_key(size: int = 32) -> bytes:
    """
    Generate a cryptographically secure random key.
    
    Args:
        size: Size of the key in bytes (default: 32 bytes = 256 bits)
        
    Returns:
        Random bytes of specified size
    """
    return secrets.token_bytes(size)

def encrypt_data_with_password(data: bytes, password: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypt data using a password (derives key internally).
    
    Args:
        data: Data to encrypt
        password: Password for encryption
        
    Returns:
        Tuple of (encrypted_data, salt, iv)
    """
    key, salt = derive_key_from_password(password)
    iv = secrets.token_bytes(16)
    
    # Pad the data
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data)
    padded_data += padder.finalize()
    
    # Encrypt the data
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    return encrypted_data, salt, iv

def decrypt_data_with_password(encrypted_data: bytes, salt: bytes, iv: bytes, password: bytes) -> bytes:
    """
    Decrypt data encrypted with encrypt_data_with_password.
    
    Args:
        encrypted_data: Data to decrypt
        salt: Salt used during encryption
        iv: Initialization vector used during encryption
        password: Password for decryption
        
    Returns:
        Decrypted data
    """
    key, _ = derive_key_from_password(password, salt)
    
    # Decrypt the data
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # Unpad the data
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data)
    data += unpadder.finalize()
    
    return data

def create_encrypted_payload_container(payload: bytes, key: bytes, auth_key: Optional[bytes] = None) -> bytes:
    """
    Create a container with encrypted payload and optional authentication.
    
    Format: [IV(16) | EncryptedSize(4) | EncryptedPayload(n) | AuthTag(32, optional)]
    
    Args:
        payload: Data to encrypt and contain
        key: Encryption key
        auth_key: Authentication key (optional)
        
    Returns:
        Encrypted payload container
    """
    # Encrypt the payload
    encrypted_data, iv, _ = encrypt_payload(payload, key)
    
    # Create the container
    container = iv
    container += len(encrypted_data).to_bytes(4, 'little')  # Size of encrypted data
    container += encrypted_data
    
    # Add authentication tag if key provided
    if auth_key:
        auth_tag = create_authentication_tag(encrypted_data, auth_key)
        container += auth_tag
    
    return container

def parse_encrypted_payload_container(container: bytes, key: bytes, auth_key: Optional[bytes] = None) -> bytes:
    """
    Parse and decrypt a container created with create_encrypted_payload_container.
    
    Args:
        container: Encrypted payload container
        key: Encryption key
        auth_key: Authentication key (optional, for verification)
        
    Returns:
        Decrypted payload
    """
    # Extract IV (first 16 bytes)
    iv = container[:16]
    container = container[16:]
    
    # Extract encrypted data size (next 4 bytes)
    encrypted_size = int.from_bytes(container[:4], 'little')
    container = container[4:]
    
    # Extract encrypted data and optional auth tag
    encrypted_data = container[:encrypted_size]
    auth_tag = container[encrypted_size:] if auth_key else None
    
    # Verify authentication if auth_key provided
    if auth_key and auth_tag:
        if not verify_authentication_tag(encrypted_data, auth_key, auth_tag):
            raise ValueError("Authentication failed: Invalid auth tag")
    
    # Decrypt the payload
    return decrypt_payload(encrypted_data, iv, key)

def hash_data(data: bytes, algorithm: str = 'sha256') -> bytes:
    """
    Create a cryptographic hash of the input data.
    
    Args:
        data: Data to hash
        algorithm: Hash algorithm to use ('sha256', 'sha512', 'md5', etc.)
        
    Returns:
        Hash of the input data
    """
    h = hashlib.new(algorithm)
    h.update(data)
    return h.digest()

def generate_symmetric_keys() -> Tuple[bytes, bytes]:
    """
    Generate a pair of symmetric keys for encryption/decryption.
    
    Returns:
        Tuple of (encryption_key, authentication_key)
    """
    encryption_key = generate_secure_key(32)  # 256-bit key for AES-256
    auth_key = generate_secure_key(32)        # Key for HMAC authentication
    return encryption_key, auth_key

def xor_bytes(data: bytes, key: bytes) -> bytes:
    """
    XOR data with a key (cyclically if key is shorter than data).
    
    Args:
        data: Data to XOR
        key: Key to XOR with
        
    Returns:
        XORed data
    """
    if not key:
        return data  # No-op if no key
    
    result = bytearray()
    for i, byte in enumerate(data):
        result.append(byte ^ key[i % len(key)])
    
    return bytes(result)

def ca_based_encrypt(data: bytes, ca_seed: bytes, key: bytes) -> bytes:
    """
    Encrypt data using a combination of CA-based scrambling and AES encryption.
    
    Args:
        data: Data to encrypt
        ca_seed: Seed for CA-based scrambling
        key: AES encryption key
        
    Returns:
        CA-based encrypted data
    """
    # Generate a CA-based XOR mask
    from . import ca_engine
    ca_mask = ca_engine.create_ca_based_xor_key(ca_seed, len(data))
    
    # XOR the data with the CA mask
    xored_data = xor_bytes(data, ca_mask)
    
    # Encrypt the xored data with AES
    encrypted, iv, _ = encrypt_payload(xored_data, key)
    
    # Return IV + encrypted data
    return iv + encrypted

def ca_based_decrypt(data: bytes, ca_seed: bytes, key: bytes) -> bytes:
    """
    Decrypt data encrypted with ca_based_encrypt.
    
    Args:
        data: Data to decrypt (IV + encrypted content)
        ca_seed: Seed for CA-based scrambling
        key: AES encryption key
        
    Returns:
        Decrypted data
    """
    # Extract IV (first 16 bytes)
    iv = data[:16]
    encrypted_content = data[16:]
    
    # Decrypt with AES
    xored_data = decrypt_payload(encrypted_content, iv, key)
    
    # Generate the same CA-based XOR mask
    from . import ca_engine
    ca_mask = ca_engine.create_ca_based_xor_key(ca_seed, len(xored_data))
    
    # XOR back to get original data
    return xor_bytes(xored_data, ca_mask)

if __name__ == "__main__":
    # Test the crypto engine
    print("Testing crypto engine...")
    
    # Test basic encryption/decryption
    original_data = b"Hello, Crypto World!"
    key = generate_secure_key(32)
    
    encrypted, iv, orig_pad = encrypt_payload(original_data, key)
    decrypted = decrypt_payload(encrypted, iv, key, orig_pad)
    
    print(f"Original: {original_data}")
    print(f"Decrypted: {decrypted}")
    print(f"Match: {original_data == decrypted}")
    
    # Test password-based encryption
    password = b"my_secure_password"
    encrypted_data, salt, iv = encrypt_data_with_password(original_data, password)
    decrypted_data = decrypt_data_with_password(encrypted_data, salt, iv, password)
    
    print(f"Password-decrypted: {decrypted_data}")
    print(f"Password Match: {original_data == decrypted_data}")
    
    # Test hashing
    data_hash = hash_data(original_data)
    print(f"SHA256 hash: {data_hash.hex()}")
    
    print("Crypto engine test completed.")