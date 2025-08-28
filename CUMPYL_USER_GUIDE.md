# Cumpyl User Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Interactive Menu System](#interactive-menu-system)
5. [Command Line Interface](#command-line-interface)
6. [Binary Analysis](#binary-analysis)
7. [Hex Viewer](#hex-viewer)
8. [Batch Processing](#batch-processing)
9. [Encoding and Obfuscation](#encoding-and-obfuscation)
10. [Reporting](#reporting)
11. [Configuration](#configuration)

## Introduction

Cumpyl is a powerful Python-based binary analysis framework for analyzing, modifying, and rewriting binary files (PE, ELF, Mach-O). It features a plugin architecture, batch processing capabilities, and comprehensive reporting functions.

Whether you're a security researcher, reverse engineer, or malware analyst, Cumpyl provides the tools you need to understand and manipulate binary files.

## Installation

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

## Quick Start

The easiest way to get started with Cumpyl is to use the interactive menu system:

```bash
cumpyl sample.exe --menu
```

This will launch a guided interface that provides access to all of Cumpyl's features.

## Interactive Menu System

Cumpyl features a rich interactive menu system that provides guided access to all framework capabilities through an intuitive console interface.

### Launching the Menu

```bash
cumpyl binary.exe --menu
```

Or without a target file:

```bash
cumpyl --menu
```

### Menu Options

1. **Quick Analysis**: Fast section analysis and obfuscation suggestions
2. **Deep Analysis**: Comprehensive plugin-based analysis with reporting
3. **Interactive Hex Viewer**: Explore binary with interactive hex dump
4. **Batch Processing**: Process multiple files with automated workflows
5. **Encoding Operations**: Obfuscate specific sections with various encodings
6. **Binary Packers**: Analyze and pack binaries with compression and encryption
7. **Report Generation**: Create detailed analysis reports in multiple formats
8. **Configuration**: View and modify framework settings
9. **Change Target**: Select a different binary file

### Plugin-Based Packer Menu

The Binary Packers option includes a plugin-based packer menu that supports:
- Analysis with packer plugins
- Transformation with packer plugins
- Real packer integration as fallback
- Support for PE, ELF, and Mach-O formats

#### Using the Plugin Packer Menu

To access the plugin packer menu directly, run:

```bash
python3 plugin_packer_menu.py [binary_file]
```

The menu provides:
1. **Analyze Binary**: Run analysis plugins on your binary to identify packing opportunities
2. **Transform Binary**: Apply transformation plugins to modify your binary
3. **Change Binary File**: Switch to a different target binary
4. **List Available Plugins**: View all registered analysis and transformation plugins

Each plugin can be configured with options such as:
- Compression level (1-9)
- Encryption key path for secure transformations
- Safe mode and dry run options for testing
- Section skipping preferences

The menu system automatically detects available plugins in the `plugins/` directory and provides a guided interface for their use.

#### Plugin Menu Improvements

Recent improvements to the plugin packer menu include:
- Fixed binary saving functionality in transformation plugins
- Enhanced compatibility with Go and CGO packer plugins
- Improved error handling and user feedback
- Better configuration options for different plugin types
- Support for dry run mode to test transformations without modifying files

## Command Line Interface

Cumpyl provides a comprehensive command-line interface for binary analysis and manipulation.

### Basic Analysis

```bash
cumpyl binary.exe --analyze-sections
```

Analyze binary structure and sections.

### Obfuscation Suggestions

```bash
cumpyl binary.exe --suggest-obfuscation
```

Get intelligent section encoding recommendations.

### Hex View

```bash
cumpyl binary.exe --hex-view
```

Generate interactive hex viewer.

### Comprehensive Analysis

```bash
cumpyl binary.exe --hex-view --run-analysis --suggest-obfuscation
```

Run comprehensive analysis with interactive hex view.

### Reporting

```bash
cumpyl binary.exe --run-analysis --report-format html --report-output analysis.html
```

Run comprehensive analysis with HTML report output.

## Binary Analysis

Cumpyl provides comprehensive binary analysis capabilities through its plugin system.

### Plugin-Based Analysis

Cumpyl's plugin system allows for extensible analysis capabilities:

- **Entropy Analysis**: Calculate Shannon entropy for packed binary detection
- **String Extraction**: Advanced string extraction with context scoring
- **Section Analysis**: Automatic classification and safety assessment
- **Packer Detection**: Identify potential packing techniques
- **Go Binary Analysis**: Specialized analysis for Go binaries
- **CGO Analysis**: Analysis for CGO-enabled Go binaries

### Analysis Results

Analysis results include:
- Binary format detection (PE/ELF/Mach-O)
- Section information and characteristics
- Entropy calculations
- Packing opportunities
- Obfuscation suggestions
- Security-related findings

## Hex Viewer

Cumpyl features a dual-mode hex viewer for comprehensive binary exploration.

### Terminal TUI Viewer

The new Textual-based terminal hex viewer provides:
- Vim-like navigation controls
- Real-time search functionality
- Color-coded annotations
- Section overview panel
- Interactive range selection

Launch with:
```bash
cumpyl binary.exe --hex-view --hex-view-interactive
```

### Browser-Based Viewer

Traditional browser-based hex viewer with:
- Interactive tooltips
- Color-coded annotations
- Section highlighting
- Entropy visualization

Generate with:
```bash
cumpyl binary.exe --hex-view
```

## Batch Processing

Process multiple files efficiently with Cumpyl's batch processing capabilities.

### Directory Processing

```bash
cumpyl --batch-directory /samples --batch-operation plugin_analysis --report-format json
```

Process all binaries in a specified directory.

### Pattern-based Processing

```bash
cumpyl --batch-pattern "*.exe" --batch-pattern "*.dll" --batch-operation analyze_sections
```

Process files matching glob patterns.

### Recursive Processing

```bash
cumpyl --batch-directory /dataset --batch-extensions ".exe,.dll" --batch-recursive
```

Recursive processing with custom extensions.

### Multi-threaded Processing

Cumpyl supports multi-threaded batch processing with configurable worker pools for improved performance.

## Encoding and Obfuscation

Cumpyl provides advanced encoding and obfuscation capabilities for binary sections.

### Supported Encodings

- **Hex**: Simple hexadecimal encoding
- **Octal**: Octal escape sequence encoding
- **Null**: Null byte padding
- **Base64**: Standard Base64 encoding
- **Compressed Base64**: Zlib compression + Base64 encoding

### Section Encoding

```bash
cumpyl binary.exe --encode-section .text --encoding base64 -o encoded.exe
```

Encode specific sections.

### Multi-section Encoding

```bash
cumpyl binary.exe --encode-section .text --encoding base64 --encode-section .data --encoding hex
```

Apply encodings to multiple sections.

### Obfuscation Suggestions

Cumpyl provides intelligent obfuscation suggestions based on section analysis:
- **Advanced Tier**: Large read-only data sections suitable for heavy obfuscation
- **Intermediate Tier**: Medium-size data sections good for moderate obfuscation
- **Basic Tier**: Small sections suitable for light obfuscation
- **Avoid Tier**: Critical sections that should not be obfuscated

## Reporting

Cumpyl generates comprehensive analysis reports in multiple formats.

### Supported Formats

- **HTML**: Rich, interactive reports with visualizations
- **JSON**: Structured data for programmatic processing
- **YAML**: Human-readable structured data
- **XML**: Standardized format for enterprise integration

### Report Generation

```bash
cumpyl binary.exe --run-analysis --report-format html --report-output analysis.html
```

Generate HTML report.

### Batch Reporting

```bash
cumpyl --batch-directory /samples --batch-operation plugin_analysis --report-format json --report-output reports/
```

Generate reports for multiple files.

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

### Analysis Profiles

Cumpyl includes predefined analysis profiles:

- **malware_analysis**: Advanced malware detection and analysis
- **forensics**: Digital forensics and evidence collection
- **research**: Academic research and reverse engineering

Use profiles with:
```bash
cumpyl binary.exe --profile malware_analysis --run-analysis
```

### Custom Configuration

```bash
cumpyl binary.exe --config custom.yaml --run-analysis
```