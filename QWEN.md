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

To rewrite a binary, use the following command:

```bash
cumpyl <input_binary> [-o <output_binary>]
```

To encode a section of the binary:

```bash
cumpyl <input_binary> --encode-section .rodata --encoding hex --print-encoded
```

To encode a specific portion of a section:

```bash
cumpyl <input_binary> --encode-section .text --encode-offset 0x100 --encode-length 32 --encoding base64
```

If no output file is specified, the tool will create a file named `modified_<input_binary>`.

## Development Notes

- The project is written in Python and structured as a package.
- The plugin system allows for easy extension of analysis and transformation capabilities.
- Modifications are queued and applied in a batch process.
- Encoding/decoding features allow for flexible manipulation of binary data.