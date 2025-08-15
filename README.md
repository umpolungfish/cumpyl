# Cumpyl - Binary Rewriting Tool

Cumpyl is a Python-based binary rewriting tool that allows you to analyze, modify, and rewrite binary files. It features encoding/decoding capabilities that let you take portions of a binary, encode them in various formats (hex, octal, base64, etc.), and put them back into the binary.

## Features

- Load and parse binary files (PE, ELF, Mach-O) using LIEF
- **Section Analysis** - Detailed inspection of binary sections with type identification and content preview
- **Obfuscation Suggestions** - Intelligent tiered recommendations for optimal obfuscation locations with encoding options
- **Multi-Section Encoding** - Support for encoding multiple sections simultaneously or with different encodings
- **Smart Safety Checks** - Prevents corruption by refusing to expand executable sections and warning about size increases
- **Compressed Encoding** - Space-efficient compressed base64 encoding to minimize section expansion
- Disassemble code sections using Capstone
- Apply modifications to binaries
- Encode/decode binary data in various formats:
  - Hexadecimal
  - Octal
  - Base64
  - Null bytes
  - Compressed Base64
- Plugin architecture for extensibility
- Command-line interface
- Cross-platform compatibility (Windows PE, Linux ELF, macOS Mach-O)

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
# Analyze binary sections first (recommended)
cumpyl input_binary --analyze-sections

# Get intelligent obfuscation suggestions
cumpyl input_binary --suggest-obfuscation

# Basic usage
cumpyl input_binary -o output_binary

# Encode a section of the binary
cumpyl input_binary --encode-section .rodata --encoding hex --print-encoded

# Encode a specific portion of a section
cumpyl input_binary --encode-section .text --encode-offset 0x100 --encode-length 32 --encoding base64

# Use space-efficient compressed encoding for larger sections
cumpyl input_binary --encode-section .rdata --encode-length 1000 --encoding compressed_base64 --print-encoded

# Multiple sections with same encoding (comma-separated)
cumpyl input_binary --encode-section ".text,.data,.rdata" --encoding base64 -o output_binary

# Different encodings on different sections (sequential operations)
cumpyl input_binary --encode-section .text --encoding base64 --encode-section .data --encoding hex --encode-section .rdata --encoding octal -o output_binary

# Working with Windows PE files
cumpyl malware.exe --analyze-sections
cumpyl malware.exe --suggest-obfuscation
cumpyl malware.exe --encode-section .text --encoding base64 -o obfuscated.exe

# Working with Linux ELF files
cumpyl ./program --encode-section .rodata --encoding hex --print-encoded
```

### Section Analysis

The `--analyze-sections` flag provides detailed information about each section in the binary:

```bash
cumpyl binary.exe --analyze-sections
```

Output includes:
- **Section Type**: Automatic identification (Executable Code, Data, Read-only Data, etc.)
- **Size**: Section size in bytes
- **Virtual Address**: Memory address where section loads
- **Characteristics**: Section flags and permissions
- **Content Preview**: First 32 bytes in both hex and ASCII format

Common section types:
- `.text` / `.code` - Executable code (good for obfuscation)
- `.data` - Initialized data
- `.rdata` / `.rodata` - Read-only data (strings, constants)
- `.idata` - Import tables
- `.reloc` - Relocation information

### Obfuscation Suggestions

The `--suggest-obfuscation` flag provides intelligent, tiered recommendations for optimal obfuscation:

```bash
cumpyl binary.exe --suggest-obfuscation
```

This feature analyzes the binary and provides:

1. **Tiered Section Classification**:
   - **Advanced Tier**: Large, safe sections like `.rdata`, `.rodata` - best for heavy obfuscation
   - **Intermediate Tier**: Medium-size data sections and resource/debug data - good for moderate obfuscation
   - **Basic Tier**: Small sections like exception data - suitable for light obfuscation
   - **Avoid Tier**: Critical sections like executable code, import data, relocation data

2. **Detailed Recommendations**:
   - Section name, type, and size information
   - Specific encoding options for each tier (hex, octal, base64, compressed_base64)
   - Overall best section for maximum obfuscation
   - Warnings about sections that would break the program

3. **Example Output**:
   ```
   [*] Obfuscation Suggestions for binary.exe
   ============================================================

   Advanced Tier (Large, High-Impact Sections):
   ----------------------------------------
     Section: .rdata
       Type: Read-only Data
       Size: 1.37 MB
       Suggestion: Best for heavy obfuscation. Large capacity for complex encoding.
       Encoding Options: base64, compressed_base64, hex

   [*] Overall Recommendations:
   ----------------------------------------
     Best section for maximum obfuscation: .rdata (Read-only Data)
       Size: 1432696 bytes
       Command example: --encode-section .rdata --encoding compressed_base64
   ```

This feature makes it easy to identify the best sections for obfuscation without needing to understand the binary format in detail.

### Python API

```python
from cumpyl_package.cumpyl import BinaryRewriter, EncodingPlugin

# Load a binary
rewriter = BinaryRewriter("input_binary")
rewriter.load_binary()

# Analyze sections programmatically
rewriter.analyze_sections()

# Get obfuscation suggestions
rewriter.suggest_obfuscation()

# Encode a portion of a section
plugin = EncodingPlugin()
encoded_data = plugin.encode_section_portion(rewriter, ".rodata", 0, 20, "hex")
print(f"Encoded data: {encoded_data}")

# Use compressed encoding for better space efficiency
encoded_compressed = plugin.encode_section_portion(rewriter, ".rdata", 0, 1000, "compressed_base64")
print(f"Compressed encoded data: {encoded_compressed}")

# Apply modifications back to the binary
plugin.decode_and_apply(rewriter, ".rodata", 0, encoded_data, "hex")

# Save the modified binary
rewriter.save_binary("output_binary")
```

## Examples

### Basic Workflow

```bash
# 1. First, analyze the binary to understand its structure
cumpyl malware.exe --analyze-sections

# 2. Based on the analysis, encode a specific section
cumpyl malware.exe --encode-section .text --encoding base64 -o obfuscated.exe

# 3. Or just print the encoded data without saving
cumpyl malware.exe --encode-section .rdata --encoding hex --print-encoded
```

### Multi-Section Encoding

You can encode multiple sections in two different ways:

**Same encoding on multiple sections (comma-separated list):**
```bash
# Encode .text, .data, and .rdata sections all with base64
cumpyl binary.exe --encode-section ".text,.data,.rdata" --encoding base64 -o output.exe

# With specific parameters
cumpyl binary.exe --encode-section ".text,.data" --encode-length 100 --encoding hex -o output.exe
```

**Different encodings on different sections (sequential operations):**
```bash
# Apply base64 to .text, hex to .data, and octal to .rdata
cumpyl binary.exe \
  --encode-section .text --encoding base64 \
  --encode-section .data --encoding hex \
  --encode-section .rdata --encoding octal \
  -o output.exe

# With different parameters for each section
cumpyl binary.exe \
  --encode-section .text --encoding base64 --encode-length 50 \
  --encode-section .data --encoding hex --encode-offset 10 --encode-length 30 \
  -o output.exe
```

### Demo Script

To see the encoding functionality in action with a test binary:

```bash
python demo_encoding.py
```

This will create a test binary, encode a portion of it in hex format, and demonstrate the decoding functionality.

## Recent Updates

- **v0.1.4**: Added obfuscation suggestions feature with tiered recommendations and intelligent encoding options
- **v0.1.3**: Added compressed base64 encoding and smart safety checks to prevent binary corruption
- **v0.1.2**: Added multi-section encoding support - encode multiple sections with same or different encodings
- **v0.1.1**: Added section analyzer with `--analyze-sections` flag
- **v0.1.0**: Fixed compatibility issues with newer LIEF versions
- **v0.1.0**: Improved error handling for different binary formats

## Dependencies

- [LIEF](https://lief.quarkslab.com/) - Library to Instrument Executable Formats
- [Capstone](https://www.capstone-engine.org/) - Disassembly framework
- [Keystone](https://www.keystone-engine.org/) - Assembly framework

## License

This project is licensed under the MIT License - see the LICENSE file for details.