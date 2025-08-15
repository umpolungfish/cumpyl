# Cumpyl - Binary Rewriting Tool

Cumpyl is a Python-based binary rewriting tool that allows you to analyze, modify, and rewrite binary files. It features encoding/decoding capabilities that let you take portions of a binary, encode them in various formats (hex, octal, base64, etc.), and put them back into the binary.

## Features

- Load and parse binary files (PE, ELF, Mach-O) using LIEF
- Disassemble code sections using Capstone
- Apply modifications to binaries
- Encode/decode binary data in various formats:
  - Hexadecimal
  - Octal
  - Base64
  - Null bytes
- Plugin architecture for extensibility
- Command-line interface

## Installation

### Using Conda/Mamba (Recommended)

```bash
# Create a conda environment
mamba create -n cumpyl -c conda-forge python=3.9
mamba activate cumpyl

# Install dependencies
pip install lief capstone keystone-engine

# Install cumpyl in development mode
pip install -e .
```

### Using pip

```bash
# Create a virtual environment
python -m venv cumpyl-env
source cumpyl-env/bin/activate  # On Windows: cumpyl-env\Scripts\activate

# Install dependencies
pip install lief capstone keystone-engine

# Install cumpyl in development mode
pip install -e .
```

## Usage

### Command Line Interface

```bash
# Basic usage
cumpyl input_binary -o output_binary

# Encode a section of the binary
cumpyl input_binary --encode-section .rodata --encoding hex --print-encoded

# Encode a specific portion of a section
cumpyl input_binary --encode-section .text --encode-offset 0x100 --encode-length 32 --encoding base64
```

### Python API

```python
from cumpyl_package.cumpyl import BinaryRewriter, EncodingPlugin

# Load a binary
rewriter = BinaryRewriter("input_binary")
rewriter.load_binary()

# Encode a portion of a section
plugin = EncodingPlugin()
encoded_data = plugin.encode_section_portion(rewriter, ".rodata", 0, 20, "hex")
print(f"Encoded data: {encoded_data}")

# Apply modifications back to the binary
plugin.decode_and_apply(rewriter, ".rodata", 0, encoded_data, "hex")

# Save the modified binary
rewriter.save_binary("output_binary")
```

## Example

To see the encoding functionality in action, you can run the demo script:

```bash
python demo_encoding.py
```

This will create a test binary, encode a portion of it in hex format, and demonstrate the decoding functionality.

## Dependencies

- [LIEF](https://lief.quarkslab.com/) - Library to Instrument Executable Formats
- [Capstone](https://www.capstone-engine.org/) - Disassembly framework
- [Keystone](https://www.keystone-engine.org/) - Assembly framework

## License

This project is licensed under the MIT License - see the LICENSE file for details.