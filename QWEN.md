# Cumpyl Framework - Qwen Code Context

## Project Overview

Cumpyl is a powerful Python-based binary analysis framework designed for analyzing, modifying, and rewriting binary files (PE, ELF, Mach-O). It features a plugin architecture, batch processing capabilities, and comprehensive reporting functions. The framework is particularly useful for security researchers, reverse engineers, and malware analysts who need to understand and manipulate binary files.

Key features include:
- Multi-format binary support (PE, ELF, Mach-O)
- Plugin-based architecture for extensibility
- Interactive menu system and command-line interface
- Batch processing capabilities
- Advanced encoding and obfuscation techniques
- Comprehensive reporting in multiple formats
- Interactive hex viewer with both terminal (Textual) and browser-based interfaces

## Project Structure

```
cumpyl/
├── cumpyl_package/          # Main framework package
│   ├── __init__.py
│   ├── cumpyl.py           # Main BinaryRewriter class and entry point
│   ├── config.py           # Configuration management
│   ├── plugin_manager.py   # Plugin system management
│   ├── batch_processor.py  # Batch processing capabilities
│   ├── reporting.py         # Report generation
│   ├── hex_viewer.py       # Hex viewing functionality
│   ├── menu_system.py      # Interactive menu system
│   └── transmuter.py       # Encoding/transmutation functionality
├── plugins/                # Plugin directory
│   ├── plugin_registry.py  # Centralized plugin registration
│   ├── packer_plugin.py    # Main packer analysis/transformation plugin
│   ├── go_packer_plugin.py # Go binary analysis plugin
│   ├── cgo_packer_plugin.py # CGO-aware Go binary packer
│   ├── entropy_analysis.py # Entropy analysis plugin
│   ├── string_extraction.py # String extraction plugin
│   └── transmuter_plugin.py # Encoding/transmutation plugin
├── tests/                  # Test suite
├── docs/                   # Documentation
├── data/                   # Sample data
└── cumpyl.yaml            # Main configuration file
```

## Building and Running

### Prerequisites

- Python 3.9 or higher
- pip or uv package manager

### Installation

#### Modern Installation (Recommended with uv)

```bash
# Install uv package manager
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone and install
git clone <repository_url>
cd cumpyl
uv sync  # Creates virtual environment and installs all dependencies

# Activate environment
source .venv/bin/activate  # Windows: .venv\Scripts\activate
```

#### Traditional Installation

```bash
git clone <repository_url>
cd cumpyl
pip install -e .
```

### Running the Framework

#### Command Line Interface

```bash
# Basic usage
cumpyl binary.exe --analyze-sections

# Interactive menu system
cumpyl binary.exe --menu

# Comprehensive analysis with HTML report
cumpyl binary.exe --run-analysis --report-format html --report-output analysis.html

# Hex view
cumpyl binary.exe --hex-view

# Batch processing
cumpyl --batch-directory /samples --batch-operation plugin_analysis --report-format json
```

#### Plugin Packer Menu

The framework includes a dedicated plugin packer menu for interacting with packer plugins:

```bash
# Run the plugin packer menu
python3 plugin_packer_menu.py [binary_file]
```

This menu provides:
- Analysis with packer plugins
- Transformation with packer plugins
- Real packer integration as fallback
- Support for PE, ELF, and Mach-O formats

### Key Dependencies

- **lief**: Binary parsing and manipulation library
- **capstone**: Disassembly framework
- **keystone-engine**: Assembly framework
- **rich**: Rich text and beautiful formatting in the terminal
- **tqdm**: Progress bar library
- **pyyaml**: YAML parsing and generation
- **textual**: Text User Interface (TUI) framework for interactive hex viewer

Development dependencies:
- **numpy**: For entropy analysis plugin
- **pytest**: Testing framework
- **pytest-cov**: Coverage reporting
- **black**: Code formatting
- **flake8**: Code linting

## Development Conventions

### Plugin Architecture

Cumpyl uses a flexible plugin architecture that allows for extensibility:

1. **Plugin Types**: 
   - Analysis plugins (perform analysis without modifying binaries)
   - Transformation plugins (can modify binaries)

2. **Plugin Interface**: All plugins must implement:
   - `analyze(rewriter)` method for analysis
   - `transform(rewriter, analysis_result)` method for transformations
   - Standard properties (name, version, description, author, dependencies)

3. **Plugin Registration**: Plugins are registered in `plugins/plugin_registry.py`

4. **Factory Functions**: Plugins should implement standard factory functions:
   ```python
   def get_analysis_plugin(config):
       return MyAnalysisPlugin(config)

   def get_transformation_plugin(config):
       return MyTransformationPlugin(config)
   ```

### Configuration

The framework uses YAML-based configuration (`cumpyl.yaml`) with the following sections:
- Framework settings
- Plugin configuration
- Analysis profiles (malware_analysis, forensics, research)
- Output settings
- Security settings
- Performance settings
- Binary format support
- Encoding settings
- Section analysis
- Obfuscation settings
- Logging configuration

### Testing

Tests are written using pytest and organized in the `tests/` directory. Run tests with:

```bash
pytest tests/
```

### Code Style

The project uses:
- **black** for code formatting
- **flake8** for linting
- **pytest** for testing

### Documentation

Documentation is maintained in Markdown format:
- User Guide (`CUMPYL_USER_GUIDE.md`)
- Developer Guide (`CUMPYL_DEVELOPER_GUIDE.md`)
- API Reference (`CUMPYL_API_REFERENCE.md`)
- Release Notes (`CUMPYL_RELEASE_NOTES.md`)

## Key Components

### BinaryRewriter (cumpyl_package/cumpyl.py)

The main class for binary analysis and manipulation. It provides:
- Binary loading and parsing
- Plugin execution
- Modification tracking
- Analysis result storage
- Binary saving capabilities

### PluginManager (cumpyl_package/plugin_manager.py)

Manages plugin discovery, loading, and execution:
- Dynamic plugin discovery
- Dependency validation
- Plugin lifecycle management
- Analysis and transformation phase execution

### PluginRegistry (plugins/plugin_registry.py)

Centralized plugin registration system that maintains a registry of all available plugins.

### Configuration System (cumpyl_package/config.py)

Handles configuration loading, validation, and management with support for profiles and environment variables.

### BatchProcessor (cumpyl_package/batch_processor.py)

Enables processing of multiple files with configurable worker pools for improved performance.

### ReportGenerator (cumpyl_package/reporting.py)

Generates comprehensive analysis reports in multiple formats (HTML, JSON, YAML, XML).

## Security Context

This framework is designed for authorized security research and testing only. It contains functionality that can modify binary files and should only be used on systems you own or have explicit permission to test. Running this software on systems you do not own or explicitly have permission to test is illegal and unethical.