# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Cumpyl is a state-of-the-art Python-based binary rewriting framework that analyzes, modifies, and rewrites binary files (PE, ELF, Mach-O). Originally a simple encoding tool, it has evolved into a comprehensive binary analysis platform featuring advanced plugin architecture, batch processing capabilities, intelligent reporting systems, and enterprise-grade configuration management.

## 🚀 Major Framework Evolution (v0.3.0)

The framework has undergone a **complete architectural transformation** with the following revolutionary enhancements:

### 🔧 Advanced Configuration System
- **YAML-based configuration**: Centralized `cumpyl.yaml` for all framework settings
- **Predefined analysis profiles**: `malware_analysis`, `forensics`, `research` profiles
- **Granular control**: Plugin configurations, performance tuning, safety checks
- **Configuration validation**: Built-in validation with detailed error reporting

### 🔌 Enterprise Plugin Architecture
- **Dynamic plugin discovery**: Automatic loading from `plugins/` directory
- **Standardized interfaces**: `PluginInterface` base class with analyze/transform phases
- **Dependency management**: Plugin ordering and conflict resolution
- **Advanced plugins included**:
  - **Entropy Analysis**: Detects packed/encrypted sections using Shannon entropy
  - **String Extraction**: Context-aware string analysis with scoring algorithms

### 📊 Structured Reporting System
- **Multi-format output**: JSON, YAML, XML, HTML reports
- **Rich HTML reports**: CSS-styled with interactive tables, charts, and panels
- **Metadata enrichment**: Timestamps, framework version, file information
- **Batch reporting**: Comprehensive summaries for multi-file operations

### ⚡ Batch Processing Engine
- **Multi-threaded processing**: Configurable worker pools for parallel execution
- **Directory crawling**: Recursive file discovery with extension filtering
- **Operation chaining**: Multiple analysis/transformation operations per batch
- **Progress visualization**: Real-time progress bars with Rich console integration

### 🧪 Comprehensive Testing Framework
- **Unit tests**: Individual component testing with pytest integration
- **Integration tests**: Full workflow validation with real/synthetic binaries
- **Plugin testing**: Automated plugin functionality verification
- **Coverage reporting**: Code coverage analysis for quality assurance

## Development Setup

### Installation Commands
```bash
# Using conda/mamba (recommended)
mamba create -n cumpyl -c conda-forge python=3.9
mamba activate cumpyl
pip install lief capstone keystone-engine rich tqdm pyyaml
pip install -e .

# Install with development dependencies
pip install -e ".[dev]"

# Install test dependencies
pip install -e ".[test]"

# Using pip only
python -m venv cumpyl-env
source cumpyl-env/bin/activate  # On Windows: cumpyl-env\Scripts\activate
pip install lief capstone keystone-engine rich tqdm pyyaml
pip install -e .
```

### Configuration Setup
```bash
# Initialize default configuration
cumpyl --show-config

# Validate configuration
cumpyl --validate-config

# Use custom configuration
cumpyl binary.exe --config custom_config.yaml

# Use predefined profiles
cumpyl binary.exe --profile malware_analysis
```

## 🎯 Interactive Menu System (NEW!)

### 🚀 Guided Framework Usage
```bash
# Launch interactive menu system
cumpyl --menu

# Launch menu with pre-selected target file
cumpyl --menu path/to/binary.exe
```

The interactive menu provides a beautiful, user-friendly interface for accessing all framework features:

#### 🌟 Menu Features
- **🔍 Quick Analysis**: Fast section analysis and obfuscation suggestions
- **🧪 Deep Analysis**: Comprehensive plugin-based analysis with reporting
- **🔧 Interactive Hex Viewer**: Explore binaries with visual tooltips and annotations
- **⚡ Batch Processing**: Process multiple files with automated workflows
- **🎯 Encoding Operations**: Obfuscate sections with various encoding methods
- **📊 Report Generation**: Create detailed reports in multiple formats
- **⚙️ Configuration**: View and modify framework settings
- **📁 Smart File Selection**: Auto-discovery of binary files in current directory

#### 💡 Menu Benefits
- **Beginner-Friendly**: Guided workflows with parameter suggestions
- **Expert-Efficient**: Quick access to advanced features with command preview
- **Visual Interface**: Rich console tables, panels, and color-coded options
- **Command Learning**: Shows exact CLI commands for each operation
- **Error Prevention**: Built-in validation and safety checks

## Advanced Usage Examples

### 🔍 Comprehensive Analysis
```bash
# Basic section analysis with rich output
cumpyl binary.exe --analyze-sections

# Full plugin-based analysis with HTML report
cumpyl binary.exe --run-analysis --report-format html --report-output analysis.html

# Intelligent obfuscation suggestions
cumpyl binary.exe --suggest-obfuscation

# Analysis with custom profile
cumpyl binary.exe --run-analysis --profile forensics --generate-report
```

### 📦 Batch Processing Operations
```bash
# Process entire directory with plugin analysis
cumpyl --batch-directory /path/to/binaries --batch-operation plugin_analysis --report-format json --report-output batch_results.json

# Multi-pattern processing with encoding
cumpyl --batch-pattern "*.exe" --batch-pattern "*.dll" --batch-operation encode_section --encode-section .text --encoding base64

# Recursive directory processing with custom extensions
cumpyl --batch-directory /malware/samples --batch-extensions ".exe,.dll,.so" --batch-recursive --batch-operation analyze_sections

# Parallel processing with custom worker count
cumpyl --batch-directory /large/dataset --max-workers 8 --batch-operation plugin_analysis
```

### 📋 Structured Reporting
```bash
# Generate comprehensive HTML report
cumpyl binary.exe --run-analysis --report-format html --report-output comprehensive_analysis.html

# Export analysis data as JSON for automation
cumpyl binary.exe --run-analysis --report-format json --report-output api_data.json

# YAML report for configuration management
cumpyl binary.exe --run-analysis --report-format yaml --report-output config_export.yaml

# XML report for enterprise integration
cumpyl binary.exe --run-analysis --report-format xml --report-output enterprise_report.xml
```

### 🔍 Interactive Hex Viewer
```bash
# Generate interactive hex dump with analysis overlay
cumpyl binary.exe --hex-view

# Interactive hex view with comprehensive analysis and obfuscation suggestions
cumpyl binary.exe --hex-view --run-analysis --suggest-obfuscation

# Custom hex view with specific byte limit and output file
cumpyl binary.exe --hex-view --hex-view-bytes 4096 --hex-view-output custom_hex.html

# Hex view with analysis profiles
cumpyl binary.exe --hex-view --profile malware_analysis --run-analysis

# Interactive section/range selection after analysis
cumpyl binary.exe --hex-view-interactive

# View specific section with hex viewer
cumpyl binary.exe --hex-view --hex-view-section .text

# View specific offset range (supports hex notation)
cumpyl binary.exe --hex-view --hex-view-offset 0x1000 --hex-view-bytes 2048

# View custom range with interactive analysis
cumpyl binary.exe --hex-view --run-analysis --hex-view-offset 0x600 --hex-view-bytes 1024

# Batch hex view generation for multiple files
cumpyl --batch-directory /samples --batch-operation hex_view --hex-view-bytes 2048
```

### 🔐 Advanced Encoding Operations
```bash
# Multi-section encoding with different formats
cumpyl binary.exe --encode-section .text --encoding base64 --encode-section .data --encoding hex -o obfuscated.exe

# Precise portion encoding
cumpyl binary.exe --encode-section .rodata --encode-offset 0x100 --encode-length 256 --encoding compressed_base64

# Print encoded data for verification
cumpyl binary.exe --encode-section .text --encoding hex --print-encoded
```

## Architecture Deep Dive

### 🏗️ Core Components

**BinaryRewriter Class** (`cumpyl_package/cumpyl.py`)
- Central orchestrator for all binary operations
- LIEF integration for cross-platform binary parsing
- Capstone disassembly engine integration
- Modification queue with atomic batch application
- Rich console integration for beautiful output
- Plugin lifecycle management

**ConfigManager Class** (`cumpyl_package/config.py`)
- YAML configuration parsing and validation
- Dataclass-based configuration sections
- Profile management system
- Environment variable integration
- Configuration validation with detailed error reporting

**PluginManager Class** (`cumpyl_package/plugin_manager.py`)
- Dynamic plugin discovery and loading
- Dependency resolution and ordering
- Plugin interface enforcement
- Error isolation and reporting
- Performance monitoring

**BatchProcessor Class** (`cumpyl_package/batch_processor.py`)
- Multi-threaded file processing
- Progress visualization with Rich
- Operation chaining and parameterization
- Error handling and recovery
- Statistical reporting

**ReportGenerator Class** (`cumpyl_package/reporting.py`)
- Multi-format report generation
- Rich HTML formatting with CSS
- Metadata enrichment
- Batch and individual analysis reporting
- Template-based output formatting

**HexViewer Class** (`cumpyl_package/hex_viewer.py`)
- Interactive hex dump visualization with working hover tooltips
- Color-coded annotations by severity and type (sections, entropy, strings, suggestions)
- Support for custom offset ranges and section-specific viewing
- Interactive section selection with tabular overview
- Proper file offset mapping for accurate annotation placement
- Real-time annotation counting and display
- Configurable display options and themes
- JavaScript-powered interactivity with escape-safe JSON embedding
- Base offset support for viewing arbitrary file ranges

### 🔌 Advanced Plugin System

**Available Plugins:**
- **Entropy Analysis** (`plugins/entropy_analysis.py`): Shannon entropy calculation for packed binary detection
- **String Extraction** (`plugins/string_extraction.py`): Advanced string discovery with context analysis and scoring

**Plugin Interface:**
```python
class PluginInterface(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        pass
    
    @property
    @abstractmethod
    def version(self) -> str:
        pass
    
    @abstractmethod
    def analyze(self, rewriter) -> Dict[str, Any]:
        pass
    
    @abstractmethod
    def transform(self, rewriter, analysis_result: Dict[str, Any]) -> bool:
        pass
```

### 📊 Reporting Formats

**JSON Format**: Structured data for programmatic consumption
```json
{
  "metadata": {
    "timestamp": "2023-12-07T10:30:00",
    "framework_version": "0.3.0",
    "target_file": "/path/to/binary.exe"
  },
  "analysis_results": { ... },
  "plugin_results": { ... }
}
```

**HTML Format**: Rich visual reports with:
- Interactive tables with sorting
- Color-coded severity indicators
- CSS-styled panels and sections
- Responsive design for all devices
- Copy-paste ready command suggestions

## 🗂️ Enhanced File Structure

```
cumpyl/
├── cumpyl_package/           # Core framework
│   ├── cumpyl.py            # Main binary rewriter
│   ├── config.py            # Configuration management
│   ├── plugin_manager.py    # Plugin architecture
│   ├── batch_processor.py   # Batch processing engine
│   ├── reporting.py         # Multi-format reporting
│   ├── hex_viewer.py        # Interactive hex dump viewer
│   └── menu_system.py       # Interactive menu interface (NEW!)
├── plugins/                 # Plugin ecosystem
│   ├── entropy_analysis.py  # Entropy-based analysis
│   └── string_extraction.py # Advanced string extraction
├── tests/                   # Comprehensive test suite
│   ├── test_config.py       # Configuration tests
│   ├── test_plugins.py      # Plugin system tests
│   ├── test_batch.py        # Batch processing tests
│   ├── test_reporting.py    # Reporting tests
│   └── test_integration.py  # End-to-end tests
├── cumpyl.yaml             # Default configuration
├── setup.py                # Package configuration
└── demo_encoding.py        # Feature demonstration
```

## 🧪 Testing Framework

### Running Tests
```bash
# Run all tests
python -m pytest tests/

# Run with coverage
python -m pytest tests/ --cov=cumpyl_package --cov-report=html

# Run specific test categories
python -m pytest tests/test_plugins.py -v
python -m pytest tests/test_integration.py -v

# Run with detailed output
python -m pytest tests/ -v -s
```

### Test Categories
- **Unit Tests**: Individual component functionality
- **Integration Tests**: Full workflow validation
- **Plugin Tests**: Plugin system verification
- **Configuration Tests**: YAML configuration validation
- **Batch Processing Tests**: Multi-file operation testing

## 📈 Version History & Achievements

### 🎉 v0.3.0 - Major Framework Revolution (Current)
**🏆 MASSIVE ARCHITECTURAL OVERHAUL - This release represents a complete transformation of Cumpyl from a simple encoding tool into a comprehensive binary analysis platform!**

#### 🎯 Interactive Menu System (NEW!)
- **Guided User Interface**: Beautiful Rich console-based menu system with `--menu` option
- **Smart File Discovery**: Automatic binary file detection and selection
- **10 Comprehensive Menus**: Quick Analysis, Deep Analysis, Hex Viewer, Batch Processing, Encoding, Reports, Configuration, and more
- **Command Learning**: Shows exact CLI commands for each operation
- **Beginner-Friendly**: Guided workflows with parameter suggestions and validation
- **Expert-Efficient**: Quick access to advanced features with visual feedback

#### 🔧 Configuration System (COMPLETED)
- **YAML-based configuration management** with `cumpyl.yaml`
- **Predefined analysis profiles** for different use cases
- **Comprehensive validation** with detailed error reporting
- **Environment variable integration** for deployment flexibility

#### 🔌 Plugin Architecture (COMPLETED)
- **Dynamic plugin discovery** with automatic loading
- **Standardized interfaces** with `PluginInterface` base class
- **Advanced entropy analysis plugin** for packed binary detection
- **Intelligent string extraction plugin** with context scoring
- **Dependency management** and conflict resolution

#### 📊 Structured Reporting (COMPLETED)
- **Multi-format output**: JSON, YAML, XML, HTML
- **Rich HTML reports** with CSS styling and interactive elements
- **Comprehensive metadata** including timestamps and version info
- **Batch processing reports** with statistical summaries

#### ⚡ Batch Processing (COMPLETED)
- **Multi-threaded processing** with configurable worker pools
- **Directory crawling** with recursive pattern matching
- **Operation chaining** for complex workflow automation
- **Progress visualization** with Rich console integration

#### 🧪 Testing Framework (COMPLETED)
- **Comprehensive test suite** with pytest integration
- **Unit and integration tests** covering all components
- **Plugin testing infrastructure** for extensibility validation
- **Coverage reporting** for quality assurance

#### 🔍 Interactive Hex Viewer (COMPLETED)
- **Interactive hex dump visualization** with hover tooltips
- **Analysis overlay integration** showing sections, strings, entropy, and suggestions
- **Color-coded annotations** with severity-based styling
- **Configurable display options** through YAML configuration
- **CLI integration** with `--hex-view` command options
- **HTML report embedding** for comprehensive analysis reports

### v0.2.1 - Encoding Method Fixes
- **CRITICAL FIX**: Fixed octal encoding/decoding round-trip functionality
- **Improved Reliability**: All 5 encoding methods (hex, octal, base64, compressed_base64, null) now work correctly
- **Bug Fix**: Corrected regex pattern in octal decoding logic
- **Validation**: Added comprehensive encoding method testing and verification

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

## 🏃‍♂️ Recommended Workflows

### 🎯 Interactive Menu Workflow (RECOMMENDED FOR BEGINNERS)
1. **Launch Menu**: `cumpyl --menu`
2. **Select Target**: Choose from auto-discovered binaries or specify custom path
3. **Quick Start**: Use "Quick Analysis" for immediate insights
4. **Explore Visually**: Try "Interactive Hex Viewer" for visual exploration
5. **Generate Reports**: Use "Deep Analysis" with HTML reports for comprehensive results
6. **Learn Commands**: Menu shows exact CLI commands for each operation

### 🔍 Traditional CLI Workflow (FOR EXPERTS)
1. **Initial Assessment**: `cumpyl binary.exe --analyze-sections`
2. **Intelligence Gathering**: `cumpyl binary.exe --suggest-obfuscation`
3. **Interactive Exploration**: `cumpyl binary.exe --hex-view --run-analysis`
4. **Deep Analysis**: `cumpyl binary.exe --run-analysis --profile forensics`
5. **Report Generation**: `cumpyl binary.exe --run-analysis --report-format html --report-output analysis.html`

### 🔍 Interactive Hex Analysis Workflow
1. **Quick Hex Overview**: `cumpyl binary.exe --hex-view`
2. **Interactive Section Selection**: `cumpyl binary.exe --hex-view-interactive` → Choose sections interactively
3. **Comprehensive Hex Analysis**: `cumpyl binary.exe --hex-view --run-analysis --suggest-obfuscation`
4. **Targeted Section Analysis**: `cumpyl binary.exe --hex-view --hex-view-section .text --run-analysis`
5. **Custom Range Investigation**: `cumpyl binary.exe --hex-view --hex-view-offset 0x1000 --hex-view-bytes 2048 --run-analysis`
6. **Detailed Investigation**: Open generated HTML file in browser and hover over color-coded annotated bytes for detailed analysis tooltips

### 📦 Batch Processing Workflow
1. **Setup Configuration**: Create custom `cumpyl.yaml` for your environment
2. **Directory Processing**: `cumpyl --batch-directory /samples --batch-operation plugin_analysis`
3. **Report Aggregation**: Use `--report-format json` for automated processing
4. **Quality Assurance**: Review batch reports for anomalies and errors

### 🔐 Obfuscation Workflow
1. **Section Analysis**: Identify safe encoding targets
2. **Tier Assessment**: Use color-coded recommendations
3. **Gradual Application**: Start with green (safe) sections
4. **Validation**: Verify binary integrity after each modification

## 🆕 Recent Improvements (Latest Update)

### ✅ Enhanced Hex Viewer
- **Fixed Hover Tooltips**: Interactive tooltips now work properly with detailed annotation data
- **Interactive Section Selection**: Use `--hex-view-interactive` for guided section/range selection
- **Custom Range Support**: Specify exact offsets with `--hex-view-offset 0x1000 --hex-view-bytes 2048`
- **Section-Specific Viewing**: Target specific sections with `--hex-view-section .text`
- **Proper File Offset Mapping**: Annotations now correctly map to file positions
- **Real-time Annotation Counting**: See exactly how many annotations are found

### ✅ Improved Reporting Tables
- **Fixed Section Classification**: Tables now show proper types like "Executable Code", "Data", "Read-only Data"
- **Accurate File Offsets**: Binary sections table displays correct file offsets instead of "0x0"
- **Enhanced Section Analysis**: Better integration between analysis and reporting components

### ✅ Command Concatenation
- **Working Multi-Flag Commands**: `--hex-view --run-analysis --suggest-obfuscation` now works seamlessly
- **Integrated Workflows**: Analysis results and obfuscation suggestions properly integrate with hex viewer
- **Flexible Command Combinations**: Mix and match analysis, suggestions, and hex viewing options

## 🌟 Rich Console Features

- **Color-coded tiers**: Green (Advanced), Yellow (Intermediate), Blue (Basic), Red (Avoid)
- **Professional tables**: Clean data presentation with borders and styling
- **Progress spinners**: Real-time feedback during analysis
- **Copy-ready commands**: Each suggestion includes exact execution syntax
- **Rich panels**: Beautiful bordered sections for different content types
- **Interactive progress bars**: Multi-threaded batch processing visualization
- **Interactive Menu System**: Guided interface with visual feedback and command learning

## 📖 CLI Reference

### Core Commands
```bash
# Basic operations
cumpyl binary.exe --analyze-sections          # Analyze binary sections
cumpyl binary.exe --suggest-obfuscation       # Get obfuscation suggestions
cumpyl binary.exe --run-analysis              # Run plugin analysis
cumpyl binary.exe --hex-view                  # Generate hex dump

# Interactive menu (NEW!)
cumpyl --menu                                 # Launch interactive menu
cumpyl --menu binary.exe                      # Launch menu with target file

# Configuration
cumpyl --show-config                          # Display current configuration
cumpyl --validate-config                      # Validate configuration file
cumpyl --list-plugins                         # List available plugins
```

## 🔮 Future Roadmap

### Next Priority Features:
1. **Enhanced Disassembly**: CFG analysis, function annotations, and advanced static analysis
2. **Performance Optimization**: Memory management, large file handling, and processing speed improvements
3. **API Documentation**: Comprehensive developer guides and API reference materials

### Plugin Ecosystem Expansion:
- Malware family detection plugins
- Packer identification and unpacking
- Vulnerability scanning capabilities
- Custom signature detection
- Network behavior analysis

## ⚙️ Hex Viewer Configuration

The interactive hex viewer can be customized through the `cumpyl.yaml` configuration file:

```yaml
output:
  hex_viewer:
    enabled: true
    default_bytes_per_row: 16
    max_display_bytes: 2048
    show_ascii: true
    show_offsets: true
    auto_add_section_annotations: true
    auto_add_analysis_annotations: true
    auto_add_suggestion_annotations: true
    color_scheme: "dark"  # "light" or "dark"
    annotation_priority: ["suggestions", "entropy", "strings", "sections"]
```

### Configuration Options

| Setting | Description | Default |
|---------|-------------|---------|
| `enabled` | Enable/disable hex viewer functionality | `true` |
| `default_bytes_per_row` | Number of bytes displayed per row | `16` |
| `max_display_bytes` | Maximum bytes to display in hex view | `2048` |
| `show_ascii` | Display ASCII representation alongside hex | `true` |
| `show_offsets` | Show byte offset addresses | `true` |
| `auto_add_section_annotations` | Automatically annotate binary sections | `true` |
| `auto_add_analysis_annotations` | Include plugin analysis results | `true` |
| `auto_add_suggestion_annotations` | Include obfuscation suggestions | `true` |
| `color_scheme` | Visual theme ("light" or "dark") | `"dark"` |
| `annotation_priority` | Order of annotation types for display | `["suggestions", "entropy", "strings", "sections"]` |

### Interactive Features

- **Hover Tooltips**: Display detailed information when hovering over annotated bytes
- **Color Coding**: Different colors for different annotation types and severities
- **Responsive Design**: Adapts to different screen sizes
- **Copy-Friendly**: Easy to copy hex values and offsets
- **Analysis Integration**: Seamlessly displays results from plugins and analysis phases
- **Interactive Section Selection**: Choose specific sections or ranges interactively
- **Custom Range Viewing**: Specify exact offset ranges with hex notation support
- **Real-time Annotation Count**: Shows total number of annotations found
- **Multiple Annotation Types**: Supports sections, entropy analysis, strings, and obfuscation suggestions
- **Proper File Offset Mapping**: Correctly maps virtual addresses to file offsets for accurate annotation placement

### CLI Options for Hex Viewer

| Option | Description | Example |
|--------|-------------|---------|
| `--hex-view` | Generate interactive hex dump | `--hex-view` |
| `--hex-view-interactive` | Interactive section/range selection | `--hex-view-interactive` |
| `--hex-view-offset OFFSET` | Starting offset (supports hex) | `--hex-view-offset 0x1000` |
| `--hex-view-bytes BYTES` | Number of bytes to display | `--hex-view-bytes 4096` |
| `--hex-view-section SECTION` | View specific section | `--hex-view-section .text` |
| `--hex-view-output FILE` | Output HTML file path | `--hex-view-output analysis.html` |

### Interactive Selection Options

When using `--hex-view-interactive`, you can:
- **Enter section index** (0-N) → View specific section
- **Enter 'all'** → View entire file (up to 16KB limit)
- **Enter range** like '0x1000-0x2000' or '4096-8192' → Custom byte ranges
- **Press Enter** → Default view (first 2048 bytes)

## 🎯 Development Philosophy

Cumpyl follows these core principles:
- **KISS (Keep It Simple, Stupid)**: Simple, intuitive interfaces
- **DRY (Don't Repeat Yourself)**: Reusable components and configurations
- **YAML-first configuration**: Granular control through declarative configuration
- **Plugin-driven extensibility**: Modular architecture for custom functionality
- **Rich user experience**: Beautiful console output and comprehensive reporting

---

**🔥 This framework has evolved from a simple binary encoding tool into a comprehensive binary analysis platform suitable for malware research, forensics, and security analysis. The v0.3.0 release represents months of intensive development and architectural refinement!**