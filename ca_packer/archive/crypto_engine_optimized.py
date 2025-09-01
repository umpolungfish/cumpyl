#!/usr/bin/env python3
"""
Nonce-safe Crypto Engine for ChaCha20-Poly1305.

Strategy:
  nonce = nonce_prefix(8 bytes random per key) || counter(4 bytes, big-endian)
  - Unique per message as long as counter never repeats for a given key.
  - Up to 2^32 messages per key. Rotate key before counter wraps.
"""

from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Optional, Tuple, Dict
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidTag
import os
import json
import logging

# --------------------------
# Data model
# --------------------------

@dataclass
class KeyRecord:
    key_id: str            # stable identifier (e.g., HMAC of key)
    key: bytes             # 32 bytes
    nonce_prefix: bytes    # 8 random bytes, fixed per key
    counter: int           # 0..2^32-1

    def next_nonce(self) -> bytes:
        if self.counter >= 0xFFFFFFFF:
            raise RuntimeError("Nonce counter exhausted; rotate key.")
        self.counter += 1
        return self.nonce_prefix + self.counter.to_bytes(4, "big")

# --------------------------
# Engine
# --------------------------

class NonceSafeEngine:
    def __init__(self, state_path: Optional[str] = None):
        self._keys: Dict[str, KeyRecord] = {}
        self._state_path = state_path
        if state_path and os.path.exists(state_path):
            self._load_state(state_path)

    # --- Key management ---

    @staticmethod
    def _derive_key_id(key: bytes) -> str:
        # Deterministic, non-reversible ID for the key (HMAC-SHA256 over a label)
        h = hmac.HMAC(b"ca-packer-key-id", hashes.SHA256())
        h.update(key)
        return h.finalize().hex()

    def new_key(self) -> KeyRecord:
        key = ChaCha20Poly1305.generate_key()
        nonce_prefix = os.urandom(8)  # 64-bit per-key random prefix
        key_id = self._derive_key_id(key)
        rec = KeyRecord(key_id=key_id, key=key, nonce_prefix=nonce_prefix, counter=0)
        self._keys[key_id] = rec
        self._save_state()
        return rec

    def import_key(self, key: bytes, nonce_prefix: Optional[bytes] = None, counter: int = 0) -> KeyRecord:
        if len(key) != 32:
            raise ValueError("ChaCha20Poly1305 key must be 32 bytes.")
        if nonce_prefix is None:
            nonce_prefix = os.urandom(8)
        if len(nonce_prefix) != 8:
            raise ValueError("nonce_prefix must be 8 bytes.")
        if counter < 0 or counter > 0xFFFFFFFF:
            raise ValueError("counter must be in [0, 2^32-1].")
        key_id = self._derive_key_id(key)
        rec = KeyRecord(key_id=key_id, key=key, nonce_prefix=nonce_prefix, counter=counter)
        self._keys[key_id] = rec
        self._save_state()
        return rec

    def get_key(self, key_id: str) -> KeyRecord:
        if key_id not in self._keys:
            raise KeyError(f"Unknown key_id: {key_id}")
        return self._keys[key_id]

    # --- Encrypt / Decrypt ---

    def encrypt(self, plaintext: bytes, *, key_id: Optional[str] = None, aad: Optional[bytes] = None
               ) -> Tuple[bytes, str, bytes]:
        """
        Returns: (ciphertext_with_tag, key_id, nonce)
        """
        if key_id is None:
            # autogenerate a key if caller didn't specify one
            rec = self.new_key()
        else:
            rec = self.get_key(key_id)

        nonce = rec.next_nonce()
        aead = ChaCha20Poly1305(rec.key)
        ciphertext = aead.encrypt(nonce, plaintext, aad)
        self._save_state()  # persist updated counter
        logging.debug(f"Encrypted: pt={len(plaintext)} ct={len(ciphertext)} key_id={rec.key_id} ctr={rec.counter}")
        return ciphertext, rec.key_id, nonce

    def decrypt(self, ciphertext: bytes, *, key_id: str, nonce: bytes, aad: Optional[bytes] = None) -> bytes:
        if len(nonce) != 12:
            raise ValueError("nonce must be 12 bytes (8-byte prefix + 4-byte counter).")
        rec = self.get_key(key_id)
        aead = ChaCha20Poly1305(rec.key)
        try:
            pt = aead.decrypt(nonce, ciphertext, aad)
            logging.debug(f"Decrypted: ct={len(ciphertext)} pt={len(pt)} key_id={key_id}")
            return pt
        except InvalidTag:
            logging.error("Decryption failed: Invalid authentication tag (wrong key/nonce/AAD or corrupted data).")
            raise
        except Exception as e:
            logging.error(f"Unexpected decryption error: {e}")
            raise

    # --- State persistence (JSON). Minimal; swap for sqlite if concurrency matters. ---

    def _save_state(self):
        if not self._state_path:
            return
        state = {
            kid: {
                "key": rec.key.hex(),
                "nonce_prefix": rec.nonce_prefix.hex(),
                "counter": rec.counter,
            } for kid, rec in self._keys.items()
        }
        tmp = self._state_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(state, f)
        os.replace(tmp, self._state_path)

    def _load_state(self, path: str):
        with open(path, "r") as f:
            state = json.load(f)
        for kid, v in state.items():
            self._keys[kid] = KeyRecord(
                key_id=kid,
                key=bytes.fromhex(v["key"]),
                nonce_prefix=bytes.fromhex(v["nonce_prefix"]),
                counter=int(v["counter"]),
            )

# --------------------------
# Backward compatibility functions
# --------------------------

def generate_key():
    """
    Generates a new, random 32-bit key for ChaCha20-Poly1305.
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

    nonce = os.urandom(12)  # 96-bit nonce for ChaCha20Poly1305
    aead = ChaCha20Poly1305(key)

    try:
        ciphertext = aead.encrypt(nonce, plaintext, None)  # No associated data
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
        raise ValueError("ChaCha20Poly1305 key must be 32 bytes long.")
    if len(nonce) != 12:
        raise ValueError("ChaCha20Poly1305 nonce must be 12 bytes long.")

    aead = ChaCha20Poly1305(key)
    try:
        plaintext = aead.decrypt(nonce, ciphertext, None)  # No associated data
        logging.debug(f"Payload decrypted. Ciphertext size: {len(ciphertext)}, Plaintext size: {len(plaintext)}")
        return plaintext
    except Exception as e:
        logging.error(f"Decryption failed (integrity check or other error): {e}")
        raise  # Re-raise the exception (likely InvalidTag)

# --------------------------
# Quick self-test
# --------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(message)s")
    eng = NonceSafeEngine(state_path="crypto_state.json")

    # Create/import key
    rec = eng.new_key()
    aad = b"header:v1|file:payload.bin"

    # Encrypt twice with same key, nonces will be unique & monotonic
    ct1, kid, n1 = eng.encrypt(b"hello world", key_id=rec.key_id, aad=aad)
    ct2, kid, n2 = eng.encrypt(b"another message", key_id=rec.key_id, aad=aad)
    assert n1 != n2 and n1[:8] == n2[:8]

    # Decrypt
    assert eng.decrypt(ct1, key_id=kid, nonce=n1, aad=aad) == b"hello world"
    assert eng.decrypt(ct2, key_id=kid, nonce=n2, aad=aad) == b"another message"
    print("OK")