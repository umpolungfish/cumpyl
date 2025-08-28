"""Secure crypto utilities."""
import logging
import os
import hmac
import hashlib
from typing import Tuple

logger = logging.getLogger(__name__)

def safe_hash(data: bytes, salt: bytes = None, key: bytes = None) -> str:
    """Create HMAC-based integrity hash with optional salt/key."""
    try:
        if salt is None:
            salt = os.urandom(16)
        key = key or os.urandom(32)  # Derive if not provided
        mac = hmac.new(key, salt + data, hashlib.sha256)
        return mac.hexdigest() + ':' + salt.hex() + ':' + key.hex()  # For verification
    except Exception as e:
        logger.error(f"Error creating hash: {e}")
        return ""

def generate_metadata_key(password: bytes = None, iterations: int = 100000) -> bytes:
    """Generate or derive a secure key using PBKDF2 if password provided."""
    try:
        if password:
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.backends import default_backend
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(), 
                length=32, 
                salt=salt, 
                iterations=iterations, 
                backend=default_backend()
            )
            return kdf.derive(password)
        return os.urandom(32)
    except Exception as e:
        logger.error(f"Error generating metadata key: {e}")
        return b""