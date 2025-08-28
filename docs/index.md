# Cumpyl - Binary Analysis & Rewriting Framework

Cumpyl is a powerful Python-based binary analysis framework for analyzing, modifying, and rewriting binary files (PE, ELF, Mach-O). It features a plugin architecture, batch processing capabilities, and comprehensive reporting functions.

## Key Features

- **Plugin Architecture**: Dynamic plugin discovery with standardized interfaces
- **Multi-Format Support**: Native support for PE, ELF, and Mach-O binaries
- **Dual-Mode Hex Viewer**: Terminal TUI viewer + traditional browser-based hex dumps
- **Interactive Terminal Interface**: Full-featured TUI hex viewer with vim-like controls and real-time search
- **Batch Processing**: Multi-threaded processing with configurable worker pools
- **Comprehensive Reporting**: HTML, JSON, YAML, and XML report generation
- **YAML Configuration**: Centralized configuration with predefined analysis profiles

## Quick Start

To get started with Cumpyl, install it using pip:

```bash
pip install cumpyl
```

Or clone the repository and install in development mode:

```bash
git clone https://github.com/umpolungfish/cumpyl.git
cd cumpyl
pip install -e .
```

Analyze a binary file with the interactive menu:

```bash
cumpyl sample.exe --menu
```

## Documentation

Cumpyl includes comprehensive documentation to help you get started and make the most of its features:

### User Guide
- **[CUMPYL_USER_GUIDE.md](../CUMPYL_USER_GUIDE.md)** - Complete guide for end users covering installation, basic usage, menu system, CLI commands, and all major features

### Developer Guide
- **[CUMPYL_DEVELOPER_GUIDE.md](../CUMPYL_DEVELOPER_GUIDE.md)** - Detailed guide for developers covering plugin development, API usage, testing, and contribution guidelines

### API Reference
- **[CUMPYL_API_REFERENCE.md](../CUMPYL_API_REFERENCE.md)** - Technical documentation of all core modules, classes, methods, and interfaces

### Release Notes
- **[CUMPYL_RELEASE_NOTES.md](../CUMPYL_RELEASE_NOTES.md)** - Detailed release notes for all versions, including new features, breaking changes, bug fixes, and upgrade guides

Check out these documentation files for detailed information on installation, usage, configuration, and development.