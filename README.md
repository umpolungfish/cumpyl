# Cumpyl - Binary Rewriting Tool

**Cumpyl** is a Python-based binary rewriting framework for analyzing, modifying, and obfuscating binary files. It provides intelligent analysis and a clean console interface.

## Key Features

- **Intelligent Obfuscation**: AI-powered section analysis with tiered recommendations.
- **Rich Console Interface**: Color-coded output with progress indicators.
- **Multi-Format Support**: Works with PE, ELF, and Mach-O binaries.
- **Safety-First Design**: Smart checks prevent binary corruption.
- **High Performance**: Optimized encoding with compression support.

## Installation

### Conda/Mamba (Recommended)

```bash
# Create a fresh conda environment
mamba create -n cumpyl -c conda-forge python=3.9
mamba activate cumpyl

# Install dependencies
pip install lief capstone keystone-engine rich tqdm

# Install cumpyl in development mode
pip install -e .
```

### Standard pip Installation

```bash
# Create a virtual environment
python -m venv cumpyl-env
source cumpyl-env/bin/activate  # Windows: cumpyl-env\\Scripts\\activate

# Install dependencies
pip install lief capstone keystone-engine rich tqdm

# Install cumpyl in development mode
pip install -e .
```

## Quick Start

```bash
# Test your installation
cumpyl --help

# Analyze binary sections
cumpyl input_binary --analyze-sections

# Get obfuscation suggestions
cumpyl input_binary --suggest-obfuscation

# Basic usage
cumpyl input_binary -o output_binary
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

### Enhanced Obfuscation Suggestions

The `--suggest-obfuscation` flag provides intelligent recommendations:

```bash
cumpyl binary.exe --suggest-obfuscation
```

#### Intelligent Tier System:

🟢 **Advanced Tier** (Green)
- Large, safe sections like `.rdata`, `.rodata`
- Best for heavy obfuscation with complex encoding
- Recommended: `base64`, `compressed_base64`, `hex`

🟡 **Intermediate Tier** (Yellow)  
- Medium-size data sections and resource/debug data
- Good for moderate obfuscation with balanced safety
- Recommended: `base64`, `compressed_base64`

🔵 **Basic Tier** (Blue)
- Small sections like exception data
- Suitable for light obfuscation with minimal impact
- Recommended: `hex`, `octal`

🔴 **Avoid Tier** (Red)
- Critical sections (executable code, imports, relocations)
- **DO NOT OBFUSCATE** - Will break program execution

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
cumpyl binary.exe \\
  --encode-section .text --encoding base64 \\
  --encode-section .data --encoding hex \\
  --encode-section .rdata --encoding octal \\
  -o output.exe

# With different parameters for each section
cumpyl binary.exe \\
  --encode-section .text --encoding base64 --encode-length 50 \\
  --encode-section .data --encoding hex --encode-offset 10 --encode-length 30 \\
  -o output.exe
```

### Demo Script

To see the encoding functionality in action with a test binary:

```bash
python demo_encoding.py
```

This will create a test binary, encode a portion of it in hex format, and demonstrate the decoding functionality.

## Recent Updates

### v0.2.0 - Rich UI Revolution *(Latest)*
- Rich console interface with panels and tables.
- Progress visualization during analysis.
- Copy-ready commands in suggestions.
- Enhanced user experience.

### v0.1.4 - Intelligence Upgrade
- Added obfuscation suggestions with tiered recommendations.
- Intelligent encoding options based on section analysis.
- Advanced section categorization system.

### v0.1.3 - Safety & Performance
- Compressed base64 encoding for space efficiency.
- Smart safety checks to prevent binary corruption.
- Performance optimizations for large binaries.

### v0.1.2 - Multi-Section Support
- Multi-section encoding with same or different algorithms.
- Sequential operation support.
- Enhanced command-line parameter handling.

### v0.1.1 - Analysis Foundation
- Section analyzer with `--analyze-sections` flag.
- Automatic section type identification.
- Content preview capabilities.

### v0.1.0 - Stable Foundation
- LIEF compatibility improvements.
- Enhanced error handling across binary formats.
- Core architecture stabilization.

## Dependencies

### Core Engine
- [LIEF](https://lief.quarkslab.com/) - Library to Instrument Executable Formats
- [Capstone](https://www.capstone-engine.org/) - Multi-architecture disassembly framework
- [Keystone](https://www.keystone-engine.org/) - Lightweight assembly framework

### Rich User Interface
- [Rich](https://github.com/Textualize/rich) - Beautiful console formatting and progress bars
- [tqdm](https://github.com/tqdm/tqdm) - Fast, extensible progress meter

### Quick Install Command
```bash
pip install lief capstone keystone-engine rich tqdm
```

## License

This project is released into the public domain under the Unlicense. See the LICENSE file for details.