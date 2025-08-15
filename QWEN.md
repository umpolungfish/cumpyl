# Cumpyl Project Context

## Overview

This project is a Python-based binary rewriting tool. It leverages libraries like `lief` for binary parsing and modification, `capstone` for disassembly, and `keystone` for assembly. The core functionality is encapsulated within the `BinaryRewriter` class, which handles loading, analyzing, modifying, and saving binary files.

The tool also supports a plugin architecture via the `RewriterPlugin` class, allowing for modular analysis and transformation phases. A specialized `EncodingPlugin` enables encoding/decoding portions of binaries in various formats.

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

- **`RewriterPlugin` Class**:
  - Provides a base for extending functionality.
  - Includes `analyze` and `transform` methods that operate on a `BinaryRewriter` instance.
  - Example implementation detects buffer overflow vulnerabilities and adds NOP sled patches.

- **`EncodingPlugin` Class**:
  - Extends `RewriterPlugin` with encoding/decoding capabilities.
  - Allows encoding portions of binary sections in hex, octal, base64, or null bytes.
  - Supports decoding and applying encoded data back to binaries.

- **Main Function**:
  - Provides a command-line interface using `argparse`.
  - Takes an input binary and optional output path.
  - Supports encoding/decoding operations through command-line arguments.

## Dependencies

- `lief`: For parsing and modifying binary formats (PE, ELF, Mach-O).
- `capstone`: For disassembling machine code.
- `keystone`: For assembling machine code.

## Running the Tool

**Recommended workflow - analyze first:**

```bash
# 1. Analyze the binary structure
cumpyl <input_binary> --analyze-sections

# 2. Based on analysis, encode specific sections
cumpyl <input_binary> --encode-section .text --encoding base64 -o <output_binary>
```

**Basic commands:**

```bash
# Basic rewriting
cumpyl <input_binary> [-o <output_binary>]

# Encode a section of the binary
cumpyl <input_binary> --encode-section .rodata --encoding hex --print-encoded

# Encode a specific portion of a section
cumpyl <input_binary> --encode-section .text --encode-offset 0x100 --encode-length 32 --encoding base64
```

If no output file is specified, the tool will create a file named `modified_<input_binary>`.

## Section Analysis Feature

The `--analyze-sections` flag provides detailed information about each section:

- **Section identification**: Automatically identifies section types (.text = code, .rdata = strings, etc.)
- **Size and address information**: Virtual addresses and section sizes
- **Content preview**: First 32 bytes shown in both hex and ASCII
- **Section characteristics**: Permissions and flags

This helps choose the right section for encoding operations.

## Development Notes

- The project is written in Python and structured as a package.
- The plugin system allows for easy extension of analysis and transformation capabilities.
- Modifications are queued and applied in a batch process.
- Encoding/decoding features allow for flexible manipulation of binary data.
- **Recent improvements**: Fixed LIEF compatibility issues and added comprehensive section analysis.

## Recent Updates (v0.1.1)

- **Section Analyzer**: New `--analyze-sections` flag for detailed binary inspection
- **LIEF Compatibility**: Fixed issues with newer LIEF versions (section.content vs section.data)
- **PE Support**: Improved Windows PE binary handling with correct machine type constants
- **Error Handling**: Better validation and attribute checking for different binary formats
- **Cross-platform**: Enhanced support for PE, ELF, and Mach-O formats