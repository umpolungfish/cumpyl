# Cumpyl Project Context

## Overview

This project is a Python-based binary rewriting tool. It leverages libraries like `lief` for binary parsing and modification, `capstone` for disassembly, and `keystone` for assembly. The core functionality is encapsulated within the `BinaryRewriter` class, which handles loading, analyzing, modifying, and saving binary files.

The tool also supports a plugin architecture via the `RewriterPlugin` class, allowing for modular analysis and transformation phases. A specialized `EncodingPlugin` enables encoding/decoding portions of binaries in various formats.

Cumpyl now includes intelligent obfuscation suggestions that help users identify optimal sections for encoding operations, with tiered recommendations based on section type and size.

## Key Components

- **`BinaryRewriter` Class**:
  - Manages the lifecycle of a binary rewriting task.
  - Loads binaries using `lief`.
  - Performs static analysis (architecture, entry point, sections, functions).
  - Disassembles sections using `capstone`.
  - Queues and applies modifications (patches, hooks).
  - Validates the modified binary.
  - Saves the output binary.
  - Provides methods for encoding/decoding binary data.
  - Includes intelligent obfuscation suggestion engine.

- **`RewriterPlugin` Class**:
  - Provides a base for extending functionality.
  - Includes `analyze` and `transform` methods that operate on a `BinaryRewriter` instance.
  - Example implementation detects buffer overflow vulnerabilities and adds NOP sled patches.

- **`EncodingPlugin` Class**:
  - Extends `RewriterPlugin` with encoding/decoding capabilities.
  - Allows encoding portions of binary sections in hex, octal, base64, null bytes, or compressed base64.
  - Supports decoding and applying encoded data back to binaries.
  - Includes safety checks to prevent binary corruption.

- **Main Function**:
  - Provides a command-line interface using `argparse`.
  - Takes an input binary and optional output path.
  - Supports encoding/decoding operations through command-line arguments.
  - Includes section analysis and obfuscation suggestion features.

## Dependencies

- `lief`: For parsing and modifying binary formats (PE, ELF, Mach-O).
- `capstone`: For disassembling machine code.
- `keystone`: For assembling machine code.

## Running the Tool

**Recommended workflow - analyze first:**

```bash
# 1. Analyze the binary structure
cumpyl <input_binary> --analyze-sections

# 2. Get intelligent obfuscation suggestions
cumpyl <input_binary> --suggest-obfuscation

# 3. Based on analysis or suggestions, encode specific sections
cumpyl <input_binary> --encode-section .text --encoding base64 -o <output_binary>
```

**Basic commands:**

```bash
# Basic rewriting
cumpyl <input_binary> [-o <output_binary>]

# Encode a section of the binary
cumpyl <input_binary> --encode-section .rodata --encoding hex --print-encoded

# Encode a specific portion of a section with space-efficient compression
cumpyl <input_binary> --encode-section .rdata --encode-length 1000 --encoding compressed_base64 --print-encoded

# Get intelligent obfuscation suggestions
cumpyl <input_binary> --suggest-obfuscation
```

If no output file is specified, the tool will create a file named `modified_<input_binary>`.

## Section Analysis Feature

The `--analyze-sections` flag provides detailed information about each section:

- **Section identification**: Automatically identifies section types (.text = code, .rdata = strings, etc.)
- **Size and address information**: Virtual addresses and section sizes
- **Content preview**: First 32 bytes shown in both hex and ASCII
- **Section characteristics**: Permissions and flags
- **Safety recommendations**: Indicates which sections are safe for encoding

This helps choose the right section for encoding operations.

## Obfuscation Suggestions Feature

The `--suggest-obfuscation` flag provides intelligent, tiered recommendations for optimal obfuscation:

- **Tiered Section Classification**: 
  - Advanced Tier: Large, safe sections like `.rdata`, `.rodata` - best for heavy obfuscation
  - Intermediate Tier: Medium-size data sections and resource/debug data - good for moderate obfuscation
  - Basic Tier: Small sections like exception data - suitable for light obfuscation
  - Avoid Tier: Critical sections like executable code, import data, relocation data

- **Detailed Recommendations**:
  - Section name, type, and size information
  - Specific encoding options for each tier
  - Overall best section for maximum obfuscation
  - Warnings about sections that would break the program

- **Smart Safety Features**:
  - Refuses to encode executable sections with larger data to prevent binary corruption
  - Warns when encoding data that's larger than the original
  - Suggests using compressed encoding methods to reduce data size
  - Provides clear guidance on which sections are safe to modify

This feature makes it easy to identify the best sections for obfuscation without needing to understand the binary format in detail.

## Development Notes

- The project is written in Python and structured as a package.
- The plugin system allows for easy extension of analysis and transformation capabilities.
- Modifications are queued and applied in a batch process.
- Encoding/decoding features allow for flexible manipulation of binary data.
- **Recent improvements**: Fixed LIEF compatibility issues and added comprehensive section analysis.

## Recent Updates

- **v0.1.4**: Added obfuscation suggestions feature with tiered recommendations and intelligent encoding options
- **v0.1.3**: Added compressed base64 encoding and smart safety checks to prevent binary corruption
- **v0.1.2**: Added multi-section encoding support - encode multiple sections with same or different encodings
- **v0.1.1**: Added section analyzer with `--analyze-sections` flag
- **v0.1.0**: Fixed compatibility issues with newer LIEF versions
- **v0.1.0**: Improved error handling for different binary formats