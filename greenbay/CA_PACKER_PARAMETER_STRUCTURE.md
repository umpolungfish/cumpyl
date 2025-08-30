# CA-Packer Parameter Structure

## Overview
This document describes the structure of parameters embedded by the CA-packer in the unpacking stub. These parameters are essential for the stub to correctly decrypt and execute the original binary.

## Parameter Layout
Parameters are embedded at a fixed offset (0x400) from the base address of the stub. The layout is as follows:

| Offset | Size (bytes) | Description | Format |
|--------|--------------|-------------|--------|
| 0x400 | 8 | Original Entry Point (OEP) | 64-bit little-endian |
| 0x408 | 8 | Key Part 1 (XOR obfuscated) | 64-bit little-endian |
| 0x410 | 8 | Key Part 2 (XOR obfuscated) | 64-bit little-endian |
| 0x418 | 8 | Key Part 3 (XOR obfuscated) | 64-bit little-endian |
| 0x420 | 8 | Key Part 4 (XOR obfuscated) | 64-bit little-endian |
| 0x428 | 12 | Nonce | Raw bytes |
| 0x434 | 4 | CA Steps | 32-bit little-endian |
| 0x438 | 4 | Payload Section RVA | 32-bit little-endian |
| 0x43C | 4 | Payload Size | 32-bit little-endian |

## Detailed Description

### Original Entry Point (OEP)
- **Offset**: 0x400
- **Size**: 8 bytes
- **Format**: 64-bit little-endian
- **Description**: The relative virtual address (RVA) of the original entry point of the binary before packing. After decryption and unmasking, the stub should jump to this address.

### Encryption Key Parts
- **Offsets**: 0x408, 0x410, 0x418, 0x420
- **Size**: 8 bytes each (32 bytes total)
- **Format**: 64-bit little-endian
- **Description**: The encryption key is split into four 64-bit parts, each XOR obfuscated with a fixed key (0xCABEFEBEEFBEADDE). To get the actual key parts, each part must be XORed with this fixed key.

### Nonce
- **Offset**: 0x428
- **Size**: 12 bytes
- **Format**: Raw bytes
- **Description**: The nonce used for ChaCha20-Poly1305 encryption. This is used in conjunction with the key to decrypt the payload.

### CA Steps
- **Offset**: 0x434
- **Size**: 4 bytes
- **Format**: 32-bit little-endian
- **Description**: The number of steps used in the cellular automaton (Rule 30) for obfuscation. This is needed to correctly unmask the decrypted payload.

### Payload Section RVA
- **Offset**: 0x438
- **Size**: 4 bytes
- **Format**: 32-bit little-endian
- **Description**: The relative virtual address (RVA) of the section containing the encrypted payload. The stub needs to read the payload from this location.

### Payload Size
- **Offset**: 0x43C
- **Size**: 4 bytes
- **Format**: 32-bit little-endian
- **Description**: The size of the encrypted payload in bytes. The stub needs this to know how much data to read and process.

## Usage in Unpacking Stub
The unpacking stub should:

1. **Detect Base Address**: Use RIP-relative addressing and mask to page boundary to find its base address.
2. **Read Parameters**: Read each parameter from the specified offset relative to the base address.
3. **Deobfuscate Key**: XOR each key part with the fixed key (0xCABEFEBEEFBEADDE) to get the actual key parts.
4. **Allocate Memory**: Allocate memory for the decrypted payload.
5. **Read Payload**: Read the encrypted payload from the specified RVA.
6. **Decrypt Payload**: Use ChaCha20-Poly1305 with the deobfuscated key and nonce to decrypt the payload.
7. **Unmask Payload**: Apply reverse cellular automaton (Rule 30) for the specified number of steps to unmask the decrypted payload.
8. **Jump to OEP**: Transfer execution to the original entry point.