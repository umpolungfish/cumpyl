# Cumpyl / ·𐑒𐑳𐑥𐑐𐑲𐑤

![Cumpyl Demo](images/sexy1.png)

Cumpyl is a powerful Python-based binary analysis framework for analyzing, modifying, and rewriting binary files (PE, ELF, Mach-O). It features a plugin architecture, batch processing capabilities, and comprehensive reporting functions.

## Table of Contents

1. [Key Features](#key-features)
2. [Obfuscation Tiers](#obfuscation-tiers)
3. [Installation](#installation)
4. [Quick Start](#quick-start)
5. [Interactive Menu System](#interactive-menu-system)
6. [Command Line Interface](#command-line-interface)
7. [Plugin System](#plugin-system)
8. [Batch Processing](#batch-processing)
9. [Encoding and Obfuscation](#encoding-and-obfuscation)
10. [Hex Viewer](#hex-viewer)
11. [Configuration](#configuration)
12. [Reporting](#reporting)
13. [Binary Packers](#binary-packers)
14. [Cellular Automata Packer](#cellular-automata-packer)
15. [Payload Transmutation](#payload-transmutation)
16. [Documentation](#documentation)
17. [Contributing](#contributing)
18. [License](#license)

## Key Features

- **Multi-format Support**: Native support for PE, ELF, and Mach-O binaries
- **Plugin Architecture**: Extensible plugin system for analysis and transformation
- **Interactive Menu System**: Guided interface for all framework capabilities
- **Batch Processing**: Multi-threaded processing of multiple files
- **Advanced Encoding**: Multiple encoding methods for obfuscation
- **Dual-Mode Hex Viewer**: Terminal TUI and browser-based hex viewing
- **Comprehensive Reporting**: HTML, JSON, YAML, and XML report generation
- **YAML Configuration**: Flexible configuration with predefined profiles

## Obfuscation Tiers

Cumpyl provides intelligent obfuscation suggestions with color-coded tiers to help you choose the best approach for your binary:

- 🟢 **Advanced Tier (Large, High-Impact Sections)**: Best for heavy obfuscation. Large capacity for complex encoding. Recommended for sections like `.rdata` and `.rodata`.
- 🟡 **Intermediate Tier (Medium-Size Data Sections)**: Good for moderate obfuscation. Balanced size and safety. Suitable for sections like `.data` and `.bss`.
- 🔵 **Basic Tier (Small, Low-Impact Sections)**: Suitable for light obfuscation. Small sections, minimal impact. Good for sections like `.pdata` and `.xdata`.
- 🔴 **Avoid (Critical Sections)**: Critical for program execution. Avoid obfuscation. Includes sections like `.text`, `.code`, `.idata`, and `.reloc`.

## Installation

### Prerequisites

- Python 3.9 or higher
- pip or uv package manager

### Modern Installation (Recommended with uv)

```bash
# Install uv package manager
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone and install
git clone https://github.com/umpolungfish/cumpyl.git
cd cumpyl
uv sync  # Creates virtual environment and installs all dependencies

# Activate environment
source .venv/bin/activate  # Windows: .venv\Scripts\activate
```

### Traditional Installation

```bash
git clone https://github.com/umpolungfish/cumpyl.git
cd cumpyl
pip install -e .
```

### Dependencies

Cumpyl relies on several key libraries:

- **lief**: Binary parsing and manipulation library
- **capstone**: Disassembly framework
- **keystone-engine**: Assembly framework
- **rich**: Rich text and beautiful formatting in the terminal
- **tqdm**: Progress bar library
- **pyyaml**: YAML parsing and generation
- **textual**: Text User Interface (TUI) framework for interactive hex viewer
- **numpy**: For entropy analysis plugin

## Quick Start

The easiest way to get started with Cumpyl is to use the interactive menu system:

```bash
cumpyl sample.exe --menu
```

This will launch a guided interface that provides access to all of Cumpyl's features.

### Obfuscation Quick Start

To quickly identify the best sections for obfuscation in your binary:

```bash
cumpyl sample.exe --suggest-obfuscation
```

This command will analyze your binary and provide color-coded suggestions for optimal obfuscation according to the tier system.

## Interactive Menu System

Cumpyl features a rich interactive menu system that provides guided access to all framework capabilities:

1. **Quick Analysis**: Fast section analysis and obfuscation suggestions
2. **Deep Analysis**: Comprehensive plugin-based analysis with reporting
3. **Interactive Hex Viewer**: Explore binary with interactive hex dump
4. **Batch Processing**: Process multiple files with automated workflows
5. **Encoding Operations**: Obfuscate specific sections with various encodings
6. **Binary Packers**: Analyze and pack binaries with compression and encryption
7. **Report Generation**: Create detailed analysis reports in multiple formats
8. **Configuration**: View and modify framework settings
9. **Change Target**: Select a different binary file

### Menu Navigation

The interactive menu system provides a text-based user interface with the following options:

```bash
# Launch the main menu
cumpyl binary.exe --menu

# Menu options include:
1. Quick Analysis
2. Deep Analysis
3. Interactive Hex Viewer
4. Batch Processing
5. Encoding Operations
6. Binary Packers
7. Report Generation
8. Configuration
9. Change Target
0. Exit
```

### Plugin-Based Packer Menu (𐑜𐑴 𐑐𐑨𐑒)

The Binary Packers option includes a plugin-based packer menu that supports:
- Analysis with packer plugins
- Transformation with packer plugins
- Real packer integration as fallback
- Support for PE, ELF, and Mach-O formats

To access the plugin packer menu directly, run:

```bash
python3 plugin_packer_menu.py [binary_file]
```

#### Menu Structure Diagram

Below is a diagram showing the structure of Cumpyl's interactive menu system:

```
Cumpyl Main Menu
├── 1. Quick Analysis
├── 2. Deep Analysis
├── 3. Interactive Hex Viewer
├── 4. Batch Processing
├── 5. Encoding Operations
├── 6. Binary Packers
│   ├── Plugin Packer Menu
│   │   ├── 1. Analyze binary
│   │   │   ├── Select analysis plugin
│   │   │   │   ├── packer plugin
│   │   │   │   ├── cgo_packer plugin
│   │   │   │   └── go_packer plugin
│   │   │   └── Configure plugin
│   │   ├── 2. Transform binary
│   │   │   ├── Select transformation plugin
│   │   │   │   ├── packer_transform plugin
│   │   │   │   ├── cgo_packer plugin
│   │   │   │   └── go_packer plugin
│   │   │   └── Configure plugin
│   │   ├── 3. Change binary file
│   │   └── 4. List available plugins
│   └── Real Packer Integration
├── 7. Report Generation
├── 8. Configuration
├── 9. Change Target
└── 0. Exit
```

The plugin packer menu provides a specialized interface for working with binary packers and transformation plugins. Each plugin offers unique capabilities for analyzing and transforming binary files.

## Command Line Interface

Cumpyl provides a comprehensive command-line interface for binary analysis and manipulation.

### Basic Analysis

```bash
# Analyze binary structure and sections
cumpyl binary.exe --analyze-sections

# Analyze with detailed output
cumpyl binary.exe --analyze-sections --verbose

# Save analysis to file
cumpyl binary.exe --analyze-sections --output analysis.txt
```

### Obfuscation Suggestions

```bash
# Get intelligent section encoding recommendations
cumpyl binary.exe --suggest-obfuscation

# Get suggestions with verbose output
cumpyl binary.exe --suggest-obfuscation --verbose

# Export suggestions to JSON
cumpyl binary.exe --suggest-obfuscation --output suggestions.json
```

### Hex View

```bash
# Generate interactive hex viewer
cumpyl binary.exe --hex-view

# Generate hex view with specific byte count
cumpyl binary.exe --hex-view --hex-bytes 4096

# Save hex view to HTML file
cumpyl binary.exe --hex-view --output hex_view.html
```

### Comprehensive Analysis

```bash
# Run comprehensive analysis with interactive hex view
cumpyl binary.exe --hex-view --run-analysis --suggest-obfuscation

# Comprehensive analysis with all plugins
cumpyl binary.exe --run-analysis --all-plugins --verbose

# Run specific plugins only
cumpyl binary.exe --run-analysis --plugins entropy_analysis,string_extraction
```

### Reporting

```bash
# Run comprehensive analysis with HTML report output
cumpyl binary.exe --run-analysis --report-format html --report-output analysis.html

# Generate JSON report
cumpyl binary.exe --run-analysis --report-format json --report-output analysis.json

# Generate YAML report
cumpyl binary.exe --run-analysis --report-format yaml --report-output analysis.yaml

# Generate XML report
cumpyl binary.exe --run-analysis --report-format xml --report-output analysis.xml
```

### Output Control

```bash
# Suppress all output
cumpyl binary.exe --analyze-sections --quiet

# Enable debug output
cumpyl binary.exe --analyze-sections --debug

# Verbose output with detailed information
cumpyl binary.exe --analyze-sections --verbose
```

## Plugin System

Cumpyl's plugin system allows for extensible analysis and transformation capabilities:

### Analysis Plugins

- **Entropy Analysis**: Calculate Shannon entropy for packed binary detection
- **String Extraction**: Advanced string extraction with context scoring
- **Section Analysis**: Automatic classification and safety assessment
- **Packer Detection**: Identify potential packing techniques
- **Go Binary Analysis**: Specialized analysis for Go binaries
- **CGO Analysis**: Analysis for CGO-enabled Go binaries

### Transformation Plugins

- **Encoder Plugins**: Transform binary sections with various encoding methods
- **Packer Plugins**: Compress and encrypt binary sections

### Plugin Management

```bash
# List available plugins
cumpyl --list-plugins

# List only analysis plugins
cumpyl --list-analysis-plugins

# List only transformation plugins
cumpyl --list-transformation-plugins

# Show plugin details
cumpyl --plugin-info entropy_analysis
```

### Packer Plugins

Cumpyl includes several specialized packer plugins for different binary types:

1. **Universal Packer Plugin**: General-purpose binary packer and obfuscator with compression and encryption
2. **Go Binary Analysis Plugin**: Analysis-only detection of Go binaries and packing opportunities
3. **CGO-Aware Packer Plugin**: Specialized packer for CGO-enabled Go binaries with anti-detection techniques

Each plugin can be configured with options such as:
- Compression level (1-9)
- Encryption key path for secure transformations
- Safe mode and dry run options for testing
- Section skipping preferences

### Plugin Configuration

Plugins can be configured through the `cumpyl.yaml` configuration file:

```yaml
plugins:
  entropy_analysis:
    enabled: true
    min_entropy: 7.0
    max_entropy: 8.0
  string_extraction:
    enabled: true
    min_length: 4
    max_length: 1024
  packer_plugin:
    compression_level: 6
    encryption_enabled: false
```

### Obfuscation Tier Integration

The plugin system integrates with Cumpyl's obfuscation tier system:

- 🟢 **Advanced Tier**: Plugins suggest heavy obfuscation for large read-only data sections
- 🟡 **Intermediate Tier**: Plugins recommend moderate obfuscation for medium-size data sections
- 🔵 **Basic Tier**: Plugins identify small sections suitable for light obfuscation
- 🔴 **Avoid Tier**: Plugins warn against obfuscating critical executable sections

## Batch Processing

Process multiple files efficiently with Cumpyl's batch processing capabilities.

### Directory Processing

```bash
# Process all binaries in a specified directory
cumpyl --batch-directory /samples --batch-operation plugin_analysis --report-format json

# Process with custom extensions
cumpyl --batch-directory /samples --batch-extensions ".exe,.dll,.so" --batch-operation analyze_sections

# Process with verbose output
cumpyl --batch-directory /samples --batch-operation plugin_analysis --verbose
```

### Pattern-based Processing

```bash
# Process files matching glob patterns
cumpyl --batch-pattern "*.exe" --batch-pattern "*.dll" --batch-operation analyze_sections

# Process with multiple patterns
cumpyl --batch-pattern "/samples/*.exe" --batch-pattern "/binaries/*.dll" --batch-operation plugin_analysis
```

### Recursive Processing

```bash
# Recursive processing with custom extensions
cumpyl --batch-directory /dataset --batch-extensions ".exe,.dll" --batch-recursive

# Recursive processing with all default extensions
cumpyl --batch-directory /dataset --batch-recursive --batch-operation plugin_analysis
```

### Batch Output

```bash
# Save batch results to a single report
cumpyl --batch-directory /samples --batch-operation plugin_analysis --report-format json --report-output batch_results.json

# Save individual reports for each file
cumpyl --batch-directory /samples --batch-operation plugin_analysis --report-format html --report-output /reports/
```

### Batch Configuration

Batch processing can be configured in `cumpyl.yaml`:

```yaml
batch:
  max_workers: 4
  default_extensions: [".exe", ".dll", ".so", ".bin", ".elf"]
  recursive: false
  output_directory: "batch_results"
```

## Encoding and Obfuscation

Cumpyl provides advanced encoding and obfuscation capabilities for binary sections, organized by obfuscation tier:

### Supported Encodings

1. **Hex**: Simple hexadecimal encoding
   ```bash
   cumpyl binary.exe --encode-section .data --encoding hex -o encoded.exe
   ```

2. **Octal**: Octal escape sequence encoding
   ```bash
   cumpyl binary.exe --encode-section .data --encoding octal -o encoded.exe
   ```

3. **Null**: Null byte padding
   ```bash
   cumpyl binary.exe --encode-section .data --encoding null -o encoded.exe
   ```

4. **Base64**: Standard Base64 encoding
   ```bash
   cumpyl binary.exe --encode-section .data --encoding base64 -o encoded.exe
   ```

5. **Compressed Base64**: Zlib compression + Base64 encoding
   ```bash
   cumpyl binary.exe --encode-section .data --encoding compressed_base64 -o encoded.exe
   ```

### Section Encoding

```bash
# Encode specific sections
cumpyl binary.exe --encode-section .text --encoding base64 -o encoded.exe

# Encode multiple sections with different encodings
cumpyl binary.exe --encode-section .text --encoding base64 --encode-section .data --encoding hex -o encoded.exe

# Encode with compression level
cumpyl binary.exe --encode-section .data --encoding compressed_base64 --compression-level 9 -o encoded.exe
```

### Multi-section Encoding

```bash
# Apply encodings to multiple sections
cumpyl binary.exe --encode-section .text --encoding base64 --encode-section .data --encoding hex -o encoded.exe

# Encode all non-critical sections
cumpyl binary.exe --encode-all-safe --encoding base64 -o encoded.exe
```

### Encoding Safety

Cumpyl includes safety features to prevent encoding critical sections:

```bash
# Safe mode prevents encoding critical sections
cumpyl binary.exe --encode-section .text --encoding base64 --safe-mode -o encoded.exe

# Dry run to see what would be encoded
cumpyl binary.exe --encode-section .text --encoding base64 --dry-run
```

## Hex Viewer

![Cumpyl Interface](images/sexy2.png)

Cumpyl includes a dual-mode hex viewer for exploring binary files:

### Terminal-based Hex Viewer (Textual TUI)

```bash
# Launch interactive terminal hex viewer
cumpyl binary.exe --hex-view

# View specific byte range
cumpyl binary.exe --hex-view --hex-start 0x1000 --hex-end 0x2000

# View with custom byte count
cumpyl binary.exe --hex-view --hex-bytes 4096
```

### Browser-based Hex Viewer

```bash
# Generate HTML hex viewer
cumpyl binary.exe --hex-view --output hex_viewer.html

# Generate hex viewer with custom styling
cumpyl binary.exe --hex-view --hex-theme dark --output hex_viewer.html
```

### Hex Viewer Features

- Syntax highlighting for different data types
- Search functionality
- Bookmarking capabilities
- Export to various formats
- Side-by-side comparison mode

## Configuration

Cumpyl uses YAML-based configuration for flexible customization.

### Configuration File

The default configuration file is `cumpyl.yaml`:

```yaml
framework:
  version: "0.3.0"
  debug_mode: false
  verbose_logging: false
  max_file_size_mb: 100

plugins:
  enabled: true
  plugin_directory: "plugins"
  auto_discovery: true

batch:
  max_workers: 4
  default_extensions: [".exe", ".dll", ".so", ".bin", ".elf"]

hex_viewer:
  default_bytes: 2048
  max_bytes: 16384
```

### Configuration Commands

```bash
# Show current configuration
cumpyl --show-config

# Validate configuration file
cumpyl --validate-config

# Reset configuration to defaults
cumpyl --reset-config
```

### Obfuscation Tier System

The obfuscation tier system can be configured in the `cumpyl.yaml` file:

```yaml
obfuscation:
  tier_system:
    enabled: true
    color_coding: true
    copy_ready_commands: true
    
  recommendations:
    prefer_safe_sections: true
    warn_dangerous_operations: true
    suggest_alternatives: true
```

### Analysis Profiles

Cumpyl includes predefined analysis profiles:

- **malware_analysis**: Advanced malware detection and analysis
- **forensics**: Digital forensics and evidence collection
- **research**: Academic research and reverse engineering

Use profiles with:
```bash
cumpyl binary.exe --profile malware_analysis --run-analysis

# Available profiles:
# - malware_analysis
# - forensics
# - research
# - default
```

## Reporting

Cumpyl generates comprehensive analysis reports in multiple formats:

### Report Formats

1. **HTML**: Rich interactive reports with visualizations
   ```bash
   cumpyl binary.exe --run-analysis --report-format html --report-output analysis.html
   ```

2. **JSON**: Machine-readable structured data
   ```bash
   cumpyl binary.exe --run-analysis --report-format json --report-output analysis.json
   ```

3. **YAML**: Human-readable structured data
   ```bash
   cumpyl binary.exe --run-analysis --report-format yaml --report-output analysis.yaml
   ```

4. **XML**: Standardized structured data format
   ```bash
   cumpyl binary.exe --run-analysis --report-format xml --report-output analysis.xml
   ```

### Report Content

Reports include:
- File metadata and basic information
- Section analysis with obfuscation recommendations
- Plugin analysis results
- Entropy analysis
- String extraction results
- Packer detection results
- Security assessment

### Report Customization

```bash
# Include only specific sections in report
cumpyl binary.exe --run-analysis --report-sections metadata,sections,plugins --report-format html

# Exclude sensitive information
cumpyl binary.exe --run-analysis --report-exclude-strings --report-format html

# Custom report template
cumpyl binary.exe --run-analysis --report-template custom_template.html --report-format html
```

## Binary Packers

Cumpyl includes advanced binary packing capabilities:

### Packer Types

1. **Universal Packer**: General-purpose binary packer
   ```bash
   cumpyl binary.exe --pack --packer universal --compression-level 9 -o packed.exe
   ```

2. **Go Binary Packer**: Specialized for Go binaries
   ```bash
   cumpyl binary.exe --pack --packer go --anti-detection true -o packed.exe
   ```

3. **CGO-Aware Packer**: For CGO-enabled Go binaries
   ```bash
   cumpyl binary.exe --pack --packer cgo --compression-level 6 -o packed.exe
   ```

### Packer Options

```bash
# Set compression level (1-9)
cumpyl binary.exe --pack --compression-level 7 -o packed.exe

# Enable encryption
cumpyl binary.exe --pack --encrypt --key-file secret.key -o packed.exe

# Safe mode packing
cumpyl binary.exe --pack --safe-mode -o packed.exe

# Dry run to see what would be packed
cumpyl binary.exe --pack --dry-run
```

### Packer Analysis

```bash
# Analyze binary for packing opportunities
cumpyl binary.exe --analyze-packing

# Detailed packing analysis
cumpyl binary.exe --analyze-packing --verbose

# Export packing analysis
cumpyl binary.exe --analyze-packing --output packing_analysis.json
```

## Cellular Automata Packer

Cumpyl includes a specialized Cellular Automata (CA) based packer that uses Rule 30 to generate pseudo-random masks for obfuscation. This packer provides an additional layer of security by using deterministic chaos theory principles for encryption.

### How It Works

The CA packer operates through the following stages:

1. **Loading**: The target binary is loaded using LIEF for analysis and modification
2. **Analysis**: Initial binary analysis identifies key sections and the Original Entry Point (OEP)
3. **Payload Preparation**: Raw binary data is encrypted using ChaCha20-Poly1305
4. **CA-Based Masking**: Each encrypted block is XORed with a pseudo-random mask generated by a 1D Cellular Automaton (Rule 30)
5. **Stub Generation**: A minimal unpacking stub is generated to restore the original binary at runtime
6. **Integration**: The stub and obfuscated payload are integrated into new sections of the binary

### CA Engine Details

The CA engine implements a 1D Cellular Automaton using Rule 30:
- Grid size: 256 cells (32 bytes)
- Default steps: 100 iterations
- Seeding: Uses SHA-256 hash of key material and block index
- Mask generation: Applies Rule 30 to evolve the cellular automaton

### Encryption

The packer uses ChaCha20-Poly1305 for payload encryption:
- 256-bit keys generated using the cryptography library
- 96-bit random nonces for each encryption operation
- Authenticated encryption with integrity checking

### Usage Examples

```bash
# Basic CA packing
cumpyl binary.exe --pack --packer ca -o packed.exe

# CA packing with custom CA steps
cumpyl binary.exe --pack --packer ca --ca-steps 150 -o packed.exe

# CA packing with encryption
cumpyl binary.exe --pack --packer ca --encrypt -o packed.exe

# Analyze binary for CA packing suitability
cumpyl binary.exe --analyze-packing --packer ca
```

### CA Packer Options

```bash
# Set number of CA steps (default: 100)
cumpyl binary.exe --pack --packer ca --ca-steps 200 -o packed.exe

# Enable safe mode for CA packing
cumpyl binary.exe --pack --packer ca --safe-mode -o packed.exe

# Perform dry run to see what would be packed
cumpyl binary.exe --pack --packer ca --dry-run
```

### CA Packer Architecture

#### Packing Process Diagram

Below is a diagram illustrating the CA packing process:

![CA Packing Process](images/ca_packing_process.svg)


The CA packer consists of several modules:

1. **ca_engine.py**: Implements the 1D Cellular Automaton (Rule 30) for PRNG mask generation
2. **ca_packer.py**: Main packer module that orchestrates the packing process
3. **crypto_engine.py**: Handles encryption/decryption using ChaCha20-Poly1305
4. **Unpacking Stub**: Minimal assembly code that restores the original binary at runtime

### Security Features

- **Deterministic Chaos**: Rule 30 provides cryptographically secure pseudo-random sequences
- **Authenticated Encryption**: ChaCha20-Poly1305 ensures data integrity
- **Key Derivation**: SHA-256 hashing for secure key material generation
- **Block-level Obfuscation**: Each data block is masked with a unique CA-generated mask

### Supported Formats

The CA packer supports both PE and ELF binary formats:
- **PE (Windows)**: Creates new sections for stub and payload
- **ELF (Linux)**: Adds sections with appropriate flags for execution

## Payload Transmutation

Cumpyl integrates the sc8r payload transmutation tool, which provides additional encoding methods specifically for security research:

### Transmutation Methods

1. **Unicode Encoding**: Convert payloads to Unicode escape sequences
   ```bash
   cumpyl --transmute "Hello World" --method unicode
   ```

2. **URL Encoding**: Encode payloads for URL contexts
   ```bash
   cumpyl --transmute "Hello World" --method url
   ```

3. **ROT13**: Classic ROT13 cipher
   ```bash
   cumpyl --transmute "Hello World" --method rot13
   ```

4. **Reverse Encoding**: Reverse string encoding
   ```bash
   cumpyl --transmute "Hello World" --method reverse
   ```

5. **Environment Variable Substitution**: Replace characters with environment variables
   ```bash
   cumpyl --transmute "Hello World" --method env_substitution
   ```

6. **Compound Encoding**: Chain multiple encoding methods together
   ```bash
   cumpyl --transmute "Hello World" --method compound --compound-methods "base64,rot13,url"
   ```

7. **Mixed Encoding**: Apply multiple encoding methods and output all variants
   ```bash
   cumpyl --transmute "Hello World" --method mixed
   ```

### Transmutation Commands

```bash
# Basic transmutation
cumpyl --transmute "payload" --method base64

# Transmute from file
cumpyl --transmute-file payload.txt --method base64

# Transmute with custom alphabet
cumpyl --transmute "payload" --method base64 --custom-alphabet "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

# Batch transmutation
cumpyl --transmute-batch payloads.txt --method base64 --output results.txt
```

### Transmutation Output

```bash
# Output to stdout (default)
cumpyl --transmute "Hello World" --method base64

# Output to file
cumpyl --transmute "Hello World" --method base64 --output result.txt

# Output in JSON format
cumpyl --transmute "Hello World" --method base64 --output-format json
```

## Documentation

For detailed information about Cumpyl's features and usage, please refer to the documentation:

- [User Guide](docs/CUMPYL_USER_GUIDE.md) - Comprehensive guide for using Cumpyl
- [Developer Guide](docs/CUMPYL_DEVELOPER_GUIDE.md) - Information for extending Cumpyl with custom plugins
- [API Reference](docs/CUMPYL_API_REFERENCE.md) - Detailed API documentation
- [Release Notes](docs/CUMPYL_RELEASE_NOTES.md) - Version history and changes

### User Guide Contents

The User Guide covers:
- Installation and setup
- Basic usage patterns
- Advanced features
- Troubleshooting
- Best practices

### Developer Guide Contents

The Developer Guide covers:
- Plugin development
- API usage
- Custom analysis modules
- Extending core functionality
- Contributing guidelines

### API Reference

The API Reference provides:
- Class documentation
- Method signatures
- Return value descriptions
- Usage examples
- Error handling

## Contributing

We welcome contributions to Cumpyl! Please see the [Developer Guide](docs/CUMPYL_DEVELOPER_GUIDE.md) for information on how to contribute.

### Contribution Process

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Update documentation
6. Submit a pull request

### Code Style

- Follow PEP 8 guidelines
- Use type hints where possible
- Write clear docstrings
- Include unit tests for new functionality

### Reporting Issues

Please report bugs and feature requests through the GitHub issue tracker.

## License

This project is released into the public domain under the Unlicense.