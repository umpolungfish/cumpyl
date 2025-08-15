# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Cumpyl is a Python-based binary rewriting tool that analyzes, modifies, and rewrites binary files (PE, ELF, Mach-O). It features encoding/decoding capabilities for binary data manipulation and uses a plugin architecture for extensibility.

## Development Setup

### Installation Commands
```bash
# Using conda/mamba (recommended)
mamba create -n cumpyl -c conda-forge python=3.9
mamba activate cumpyl
pip install lief capstone keystone-engine rich tqdm
pip install -e .

# Using pip
python -m venv cumpyl-env
source cumpyl-env/bin/activate  # On Windows: cumpyl-env\Scripts\activate
pip install lief capstone keystone-engine rich tqdm
pip install -e .
```

### Running the Tool
```bash
# Analyze sections first (recommended workflow)
cumpyl input_binary --analyze-sections

# Basic usage
cumpyl input_binary -o output_binary

# Encode a section
cumpyl input_binary --encode-section .rodata --encoding hex --print-encoded

# Encode specific portion
cumpyl input_binary --encode-section .text --encode-offset 0x100 --encode-length 32 --encoding base64

# Run demo
python demo_encoding.py
```

## Architecture

### Core Components

**BinaryRewriter Class** (`cumpyl_package/cumpyl.py:14-320`)
- Main orchestrator for binary analysis and modification
- Uses LIEF for binary parsing, Capstone for disassembly
- Manages modification queue and applies patches
- Handles encoding/decoding operations
- **NEW**: `analyze_sections()` method provides detailed section analysis with type identification and content preview
- **ENHANCED**: `suggest_obfuscation()` method now features rich console output with color-coded tiers and progress spinners

**RewriterPlugin Class** (`cumpyl_package/cumpyl.py:190-219`)
- Base plugin class with `analyze()` and `transform()` methods
- Example implementation detects buffer overflow vulnerabilities
- Extensible architecture for custom analysis and transformations

**EncodingPlugin Class** (`cumpyl_package/cumpyl.py:221-281`)
- Specialized plugin for encoding/decoding binary data
- Supports hex, octal, base64, and null byte encodings
- Can encode specific portions of binary sections

### Key Dependencies
- **lief**: Binary format parsing and modification (PE, ELF, Mach-O)
- **capstone**: Disassembly framework for machine code
- **keystone**: Assembly framework for code generation
- **rich**: Enhanced console output with colors, tables, and progress bars
- **tqdm**: Progress bar library for long-running operations

### Plugin System
Plugins follow a two-phase approach:
1. **Analysis phase**: Scan binary for patterns, vulnerabilities, or targets
2. **Transform phase**: Apply modifications based on analysis results

Modifications are queued and applied in batch to maintain binary integrity.

## File Structure
- `cumpyl_package/cumpyl.py`: Core binary rewriting functionality
- `demo_encoding.py`: Example script demonstrating encoding features
- `setup.py`: Package configuration with entry points
- Test files: `hello.c`, `test_binary.c` for testing purposes

## Testing
No formal test framework is configured. Testing is done through:
- Running `demo_encoding.py` for encoding functionality
- Manual testing with sample binaries (use `--analyze-sections` first)
- Validation through the built-in `validate_binary()` method

## Recent Updates

### v0.2.0 - Rich UI Enhancement
- **Rich Console Interface**: Beautiful color-coded output with panels, tables, and borders
- **Progress Visualization**: Real-time spinners during binary analysis operations
- **Copy-Ready Commands**: Each obfuscation suggestion includes exact execution commands
- **Enhanced UX**: Professional console experience with tier-based color schemes
- **Dependencies**: Added `rich` and `tqdm` for enhanced UI capabilities

### v0.1.1 - Foundation Fixes
- Fixed `'Section' object has no attribute 'data'` error by using `bytes(section.content)`
- Fixed LIEF PE compatibility issues with `FILE_MACHINE_TYPE` constants
- Improved binary validation with proper attribute checking
- Added comprehensive section analyzer with `--analyze-sections` flag

## Common Workflow
1. Use `--analyze-sections` to understand binary structure
2. **NEW**: Use `--suggest-obfuscation` for intelligent recommendations with rich visual output
3. Copy the suggested command directly from the rich console output
4. Apply encoding with appropriate parameters
5. Verify output with validation checks

## Rich Console Features
- **Color-coded tiers**: Green (Advanced), Yellow (Intermediate), Blue (Basic), Red (Avoid)
- **Professional tables**: Clean data presentation with borders and styling
- **Progress spinners**: Real-time feedback during analysis
- **Copy-ready commands**: Each suggestion includes exact execution syntax
- **Rich panels**: Beautiful bordered sections for different content types