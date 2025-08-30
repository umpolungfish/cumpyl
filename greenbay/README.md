# CA-Packer - Clean Implementation

This directory contains the clean, most advanced working implementation of the CA-Packer project.

## Directory Structure

- `ca_packer/` - Core implementation files
- `tests/` - Test files
- `LICENSE` - License file
- `requirements.txt` - Python dependencies

## Core Components

The core implementation consists of:

1. `ca_packer/packer.py` - Main packer implementation
2. `ca_packer/ca_engine.py` - Cellular automaton engine (Rule 30)
3. `ca_packer/crypto_engine.py` - ChaCha20-Poly1305 encryption engine
4. `ca_packer/complete_unpacking_stub.s` - Assembly unpacking stub
5. `ca_packer/__init__.py` - Package initialization

## Archived Files

All development files, intermediate implementations, and test binaries have been moved to the `archive/` directory to keep the main implementation clean and focused.

## Usage

To use the CA-Packer:

```bash
python3 ca_packer/packer.py <input_binary> <output_packed_binary>
```

## Requirements

- Python 3.7+
- LIEF library
- Cryptography library

Install dependencies with:
```bash
pip install -r requirements.txt
```