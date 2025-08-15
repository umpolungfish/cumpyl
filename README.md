# 🚀 Cumpyl - Advanced Binary Rewriting Tool

**Cumpyl** is a powerful Python-based binary rewriting framework that revolutionizes how you analyze, modify, and obfuscate binary files. With intelligent analysis capabilities and beautiful rich console output, Cumpyl makes binary manipulation accessible and efficient.

✨ **Key Highlights:**
- 🎯 **Intelligent Obfuscation** - AI-powered section analysis with tiered recommendations
- 🎨 **Rich Console Interface** - Beautiful, color-coded output with progress indicators
- 🔧 **Multi-Format Support** - PE, ELF, Mach-O binaries across all platforms
- 🛡️ **Safety-First Design** - Smart checks prevent binary corruption
- ⚡ **High Performance** - Optimized encoding with compression support

## ✨ Features

### 🎯 **Intelligent Analysis Engine**
- 📊 **Advanced Section Analysis** - Deep inspection with automatic type identification and content preview
- 🧠 **AI-Powered Obfuscation Suggestions** - Intelligent tiered recommendations with rich visual output
- 🔍 **Smart Pattern Recognition** - Automatic detection of critical vs. safe sections
- 📈 **Progress Visualization** - Real-time progress spinners and status updates

### 🎨 **Rich User Interface**
- 🌈 **Color-Coded Output** - Tier-based color schemes (Green=Advanced, Yellow=Intermediate, Blue=Basic, Red=Avoid)
- 📋 **Professional Tables** - Clean, organized data presentation with borders and styling
- 🔲 **Rich Panels** - Beautiful bordered sections for different content types
- ⚡ **Interactive Progress** - Animated spinners during analysis operations

### 🔧 **Powerful Encoding Capabilities**
- 🎭 **Multi-Section Encoding** - Simultaneous or sequential encoding with different algorithms
- 🗜️ **Compressed Encoding** - Space-efficient compressed base64 to minimize binary expansion
- 🛡️ **Smart Safety Checks** - Prevents corruption with intelligent section validation
- 📝 **Format Support**:
  - 🔢 Hexadecimal
  - 8️⃣ Octal  
  - 📋 Base64
  - 🗜️ Compressed Base64
  - ⚫ Null bytes

### 🏗️ **Architecture & Compatibility**
- 🧩 **Plugin Architecture** - Extensible framework for custom analysis and transformations
- 🖥️ **Cross-Platform** - Windows PE, Linux ELF, macOS Mach-O support
- 🔌 **API Integration** - Both CLI and Python API interfaces
- ⚙️ **Modern Dependencies** - Built on LIEF, Capstone, and Keystone engines

## 📦 Installation

### 🌟 **Conda/Mamba (Recommended)**

```bash
# 🐍 Create a fresh conda environment
mamba create -n cumpyl -c conda-forge python=3.9
mamba activate cumpyl

# 📚 Install core dependencies
pip install lief capstone keystone-engine

# 🎨 Install UI enhancement libraries
pip install rich tqdm

# 🔧 Install cumpyl in development mode
pip install -e .
```

### 📋 **Standard pip Installation**

```bash
# 🏠 Create a virtual environment
python -m venv cumpyl-env
source cumpyl-env/bin/activate  # 🪟 Windows: cumpyl-env\Scripts\activate

# 📚 Install all dependencies
pip install lief capstone keystone-engine rich tqdm

# 🔧 Install cumpyl in development mode
pip install -e .
```

### 🚀 **Quick Start Verification**

```bash
# ✅ Test your installation
cumpyl --help

# 🎯 Try the enhanced suggestions feature
cumpyl some_binary.exe --suggest-obfuscation
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

### 🎯 **Enhanced Obfuscation Suggestions**

**NEW!** The `--suggest-obfuscation` flag now features a stunning rich console interface with intelligent recommendations:

```bash
cumpyl binary.exe --suggest-obfuscation
```

#### 🌟 **What's New in v0.2.0:**
- 🎨 **Rich Visual Interface** - Beautiful color-coded panels and tables
- ⚡ **Progress Spinners** - Real-time analysis feedback
- 📋 **Copy-Ready Commands** - Each suggestion includes the exact command to execute
- 🏷️ **Smart Categorization** - Color-coded tiers for easy identification

#### 🎭 **Intelligent Tier System:**

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

#### 🖼️ **Rich Console Preview:**

```
╭──────────────────────────────────────────────────────────────────────────────╮
│                                                                              │
│  Obfuscation Suggestions for binary.exe                                     │
│                                                                              │
╰──────────────────────────────────────────────────────────────────────────────╯
⠇ Analyzing binary sections...

╭──────────────────────────────────────────────────────────────────────────────╮
│ Advanced Tier (Large, High-Impact Sections)                                 │
╰──────────────────────────────────────────────────────────────────────────────╯
┏━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Section ┃ Type           ┃ Size    ┃ Address  ┃ Command                      ┃
┡━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ .rdata  │ Read-only Data │ 1.37 MB │ 0x125000 │ cumpyl binary.exe            │
│         │                │         │          │ --encode-section .rdata      │
│         │                │         │          │ --encoding compressed_base64 │
│         │                │         │          │ -o obfuscated_binary.exe     │
└─────────┴────────────────┴─────────┴──────────┴──────────────────────────────┘
```

Each suggestion now includes **copy-ready commands** you can execute immediately!

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

## 📈 Recent Updates

### 🎨 **v0.2.0** - Rich UI Revolution *(Latest)*
- ✨ **Rich Console Interface** - Beautiful color-coded output with panels and tables
- ⚡ **Progress Visualization** - Real-time spinners during analysis
- 📋 **Copy-Ready Commands** - Each suggestion includes exact execution commands
- 🎯 **Enhanced UX** - Professional, visually appealing console experience

### 🧠 **v0.1.4** - Intelligence Upgrade
- 🎭 Added obfuscation suggestions with tiered recommendations
- 🔍 Intelligent encoding options based on section analysis
- 📊 Advanced section categorization system

### 🛡️ **v0.1.3** - Safety & Performance
- 🗜️ Compressed base64 encoding for space efficiency  
- 🛡️ Smart safety checks to prevent binary corruption
- ⚡ Performance optimizations for large binaries

### 🔧 **v0.1.2** - Multi-Section Support
- 🎛️ Multi-section encoding with same or different algorithms
- 🔄 Sequential operation support
- 📝 Enhanced command-line parameter handling

### 🔍 **v0.1.1** - Analysis Foundation
- 📊 Section analyzer with `--analyze-sections` flag
- 🏷️ Automatic section type identification
- 👀 Content preview capabilities

### 🏗️ **v0.1.0** - Stable Foundation
- 🔧 LIEF compatibility improvements
- 🛠️ Enhanced error handling across binary formats
- 🎯 Core architecture stabilization

## 🔗 Dependencies

### 🏗️ **Core Engine**
- 🔧 **[LIEF](https://lief.quarkslab.com/)** - Library to Instrument Executable Formats
- 🔍 **[Capstone](https://www.capstone-engine.org/)** - Multi-architecture disassembly framework
- ⚙️ **[Keystone](https://www.keystone-engine.org/)** - Lightweight assembly framework

### 🎨 **Rich User Interface**
- 🌈 **[Rich](https://github.com/Textualize/rich)** - Beautiful console formatting and progress bars
- ⏳ **[tqdm](https://github.com/tqdm/tqdm)** - Fast, extensible progress meter

### 📋 **Quick Install Command**
```bash
pip install lief capstone keystone-engine rich tqdm
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.