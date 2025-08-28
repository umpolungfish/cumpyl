"""Secure crypto utilities."""
import logging
import os
import hmac
import hashlib
import secrets
from typing import Tuple, Dict, Any
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, constant_time
from cryptography.hazmat.backends import default_backend
from tenacity import retry, stop_after_attempt, wait_fixed

logger = logging.getLogger(__name__)

@retry(stop=stop_after_attempt(3), wait=wait_fixed(1))
def load_and_derive_key(key_path: str, password: bytes = None, iterations: int = 1000000, config: Dict[Any, Any] = None) -> bytes:
    """Load key from file, verify integrity with HMAC, and derive using PBKDF2 if password provided."""
    if not os.path.isfile(key_path):
        raise FileNotFoundError(f"Key file not found: {key_path}")
    
    # Use a secure default integrity key if not provided
    integrity_key = os.environ.get("INTEGRITY_KEY", config.get("integrity_key", None) if config else None)
    if not integrity_key:
        logger.warning("No integrity key provided; generating ephemeral key")
        integrity_key = secrets.token_bytes(32)
    if isinstance(integrity_key, str):
        integrity_key = integrity_key.encode()
    
    try:
        with open(key_path, "rb") as f:
            data = f.read()
    except IOError as e:
        logger.error(f"Failed to read key file: {e}")
        raise
    
    if len(data) < 48:  # Min key (16) + HMAC (32)
        raise ValueError("Invalid key file format")
    
    key_data = data[:-32]
    expected_hmac = data[-32:]
    computed_hmac = hmac.new(integrity_key, key_data, hashlib.sha256).digest()
    if not constant_time.bytes_eq(computed_hmac, expected_hmac):
        raise ValueError("Key file integrity check failed")
    
    if len(key_data) not in (16, 24, 32):
        raise ValueError(f"Invalid key length: {len(key_data)}")
    
    if password:
        salt = config.get("pbkdf2_salt", secrets.token_bytes(16)) if config else secrets.token_bytes(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        return kdf.derive(password + key_data)
    
    return key_data

def safe_hash(data: bytes, salt: bytes = None) -> str:
    """Create HMAC-based integrity hash without exposing key."""
    try:
        salt = salt or secrets.token_bytes(16)
        key = secrets.token_bytes(32)  # Ephemeral key, not stored
        mac = hmac.new(key, salt + data, hashlib.sha256)
        return mac.hexdigest() + ':' + salt.hex()
    except Exception as e:
        logger.error(f"Error creating hash: {e}")
        return ""

def derive_secure_key(key_path: str, password: bytes = None, config: Dict = None, binary_context: bytes = None) -> Tuple[bytes, bytes, bytes]:
    """Securely derive key with proper key separation and binary-specific context."""
    try:
        key_data = load_and_derive_key(key_path, password, config=config)
        
        # Use binary-specific context if provided, else use a default
        binary_context = binary_context or b"default_binary_context"
        
        # Derive encryption key
        encryption_salt = secrets.token_bytes(16)
        encryption_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=encryption_salt,
            info=b'encryption:' + binary_context,  # Include binary context
            backend=default_backend()
        ).derive(key_data)
        
        # Derive HMAC key
        hmac_salt = secrets.token_bytes(16)
        hmac_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=hmac_salt,
            info=b'hmac:' + binary_context,  # Include binary context
            backend=default_backend()
        ).derive(key_data)
        
        return encryption_key, hmac_key, encryption_salt + hmac_salt
        
    except Exception as e:
        logger.error(f"Key derivation failed: {e}")
        raise ValueError("Secure key derivation failed")

def generate_metadata_key(password: bytes = None, iterations: int = 1000000) -> bytes:
    """Generate or derive a secure key using PBKDF2 if password provided."""
    try:
        if password:
            salt = secrets.token_bytes(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(), 
                length=32, 
                salt=salt, 
                iterations=iterations, 
                backend=default_backend()
            )
            return kdf.derive(password)
        return secrets.token_bytes(32)
    except Exception as e:
        logger.error(f"Error generating metadata key: {e}")
        return b""