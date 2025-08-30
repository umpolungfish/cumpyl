#!/usr/bin/env python3
"""
Test script to demonstrate the basic functionality of the CA-Packer components.
This script will:
1. Generate a random payload.
2. Encrypt it using the crypto engine.
3. Apply CA masking using the CA engine.
4. Verify that unmasking and decryption work correctly.
"""

import sys
import os

# Add the ca_packer directory to the path so we can import modules from it
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'ca_packer'))

import ca_engine
import crypto_engine
import os

def main():
    print("--- CA-Packer Component Integration Test ---")

    # --- Step 1: Generate Payload ---
    original_payload = os.urandom(128) # 128 random bytes
    block_size = 32 # Match the CA grid output size
    print(f"1. Generated original payload (size: {len(original_payload)} bytes)")

    # --- Step 2: Encrypt Payload ---
    ciphertext, key, nonce = crypto_engine.encrypt_payload(original_payload)
    print(f"2. Encrypted payload (ciphertext size: {len(ciphertext)} bytes)")

    # --- Step 3: Segment into Blocks ---
    # Pad ciphertext to be a multiple of block_size if necessary
    padded_ciphertext = ciphertext + b'\x00' * ((block_size - len(ciphertext) % block_size) % block_size)
    blocks = [padded_ciphertext[i:i + block_size] for i in range(0, len(padded_ciphertext), block_size)]
    print(f"3. Segmented into {len(blocks)} blocks (block size: {block_size} bytes)")

    # --- Step 4: Apply CA Masking ---
    masked_blocks = []
    for i, block in enumerate(blocks):
        mask = ca_engine.generate_mask(key, i, block_size)
        masked_block = bytes(a ^ b for a, b in zip(block, mask))
        masked_blocks.append(masked_block)
    obfuscated_payload = b''.join(masked_blocks)
    print(f"4. Applied CA masking (obfuscated payload size: {len(obfuscated_payload)} bytes)")

    # --- Step 5: Reverse Process (Unmasking & Decryption) ---
    print("5. Reversing the process...")
    unmasked_blocks = []
    for i, masked_block in enumerate(masked_blocks):
        # Regenerate the same mask
        mask = ca_engine.generate_mask(key, i, block_size)
        # Unmask
        unmasked_block = bytes(a ^ b for a, b in zip(masked_block, mask))
        unmasked_blocks.append(unmasked_block)

    # Reassemble ciphertext (remove padding if it was added)
    reassembled_ciphertext = b''.join(unmasked_blocks)
    if len(ciphertext) < len(reassembled_ciphertext):
        reassembled_ciphertext = reassembled_ciphertext[:len(ciphertext)]

    # Decrypt
    try:
        decrypted_payload = crypto_engine.decrypt_payload(reassembled_ciphertext, key, nonce)
        print(f"   Decrypted payload (size: {len(decrypted_payload)} bytes)")
    except Exception as e:
        print(f"   ERROR: Decryption failed: {e}")
        return

    # --- Step 6: Verify ---
    if original_payload == decrypted_payload:
        print("6. SUCCESS: Original payload matches decrypted payload!")
    else:
        print("6. FAILURE: Payloads do not match!")
        print(f"   Original:  {original_payload[:32].hex()}...")
        print(f"   Decrypted: {decrypted_payload[:32].hex()}...")

if __name__ == "__main__":
    main()
