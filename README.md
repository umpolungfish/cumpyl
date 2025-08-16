# 🔥 Cumpyl - Advanced Binary Analysis & Rewriting Framework

[![Framework Version](https://img.shields.io/badge/version-0.3.0-brightgreen.svg)](https://github.com/yourusername/cumpyl)
[![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-Unlicense-green.svg)](LICENSE)
[![Architecture](https://img.shields.io/badge/architecture-Plugin--Based-orange.svg)](#plugin-architecture)

**Cumpyl** has evolved from a simple binary encoding tool into a **state-of-the-art binary analysis framework** featuring enterprise-grade plugin architecture, intelligent batch processing, comprehensive reporting systems, and advanced configuration management.

## 🚀 Revolutionary v0.3.0 Features

### 🔧 **YAML-Driven Configuration System**
- **Centralized configuration** with `cumpyl.yaml`
- **Predefined analysis profiles** for malware research, forensics, and security analysis
- **Environment variable integration** for enterprise deployment
- **Built-in validation** with detailed error reporting

### 🔌 **Enterprise Plugin Architecture**  
- **Dynamic plugin discovery** with automatic loading from `plugins/` directory
- **Standardized interfaces** with comprehensive `PluginInterface` base class
- **Advanced entropy analysis** for packed/encrypted binary detection
- **Intelligent string extraction** with context-aware scoring algorithms
- **Dependency management** and conflict resolution

### 📊 **Multi-Format Reporting Engine**
- **Rich HTML reports** with interactive CSS styling and responsive design
- **Structured data export** in JSON, YAML, XML formats for automation
- **Comprehensive metadata** including timestamps, framework version, and file information
- **Batch processing summaries** with statistical analysis and error reporting

### ⚡ **High-Performance Batch Processing**
- **Multi-threaded processing** with configurable worker pools
- **Directory crawling** with recursive pattern matching and extension filtering
- **Operation chaining** for complex workflow automation
- **Real-time progress visualization** with Rich console integration

### 🧪 **Comprehensive Testing Framework**
- **pytest integration** with unit and integration tests
- **Plugin testing infrastructure** for extensibility validation
- **Coverage reporting** for quality assurance
- **Synthetic binary generation** for testing edge cases

## 🎯 Key Capabilities

- **🔍 Intelligent Binary Analysis**: AI-powered section analysis with tiered obfuscation recommendations
- **🎨 Rich Console Interface**: Color-coded output with progress indicators and beautiful tables
- **🛡️ Multi-Format Support**: Native support for PE, ELF, and Mach-O binaries
- **⚡ Safety-First Design**: Smart validation checks prevent binary corruption
- **🚀 High Performance**: Optimized encoding with compression support and parallel processing
- **📈 Enterprise Ready**: Configuration management, reporting, and batch processing for production use

## 📦 Installation

### 🐍 Conda/Mamba (Recommended)

```bash
# Create a fresh conda environment with optimized dependencies
mamba create -n cumpyl -c conda-forge python=3.9
mamba activate cumpyl

# Install core dependencies
pip install lief capstone keystone-engine rich tqdm pyyaml

# Install cumpyl with all features
pip install -e .

# Optional: Install development dependencies
pip install -e ".[dev]"
```

### 🔧 Standard pip Installation

```bash
# Create and activate virtual environment
python -m venv cumpyl-env
source cumpyl-env/bin/activate  # Windows: cumpyl-env\\Scripts\\activate

# Install all dependencies
pip install lief capstone keystone-engine rich tqdm pyyaml

# Install cumpyl in development mode
pip install -e .
```

### 🧪 Development Setup

```bash
# Install with testing capabilities
pip install -e ".[dev,test]"

# Run comprehensive test suite
python -m pytest tests/ --cov=cumpyl_package --cov-report=html

# Validate installation
cumpyl --show-config
```

## 🚀 Quick Start Guide

### 🔍 Basic Analysis Workflow

```bash
# 1. Validate your installation and configuration
cumpyl --show-config

# 2. Analyze binary structure with rich output
cumpyl malware.exe --analyze-sections

# 3. Get intelligent obfuscation recommendations
cumpyl malware.exe --suggest-obfuscation

# 4. Run comprehensive plugin-based analysis with HTML report
cumpyl malware.exe --run-analysis --report-format html --report-output analysis.html
```

### 📊 Advanced Analysis & Reporting

```bash
# Generate comprehensive analysis reports in multiple formats
cumpyl binary.exe --run-analysis --report-format json --report-output analysis.json
cumpyl binary.exe --run-analysis --report-format html --report-output analysis.html
cumpyl binary.exe --run-analysis --report-format yaml --report-output analysis.yaml

# Use predefined analysis profiles
cumpyl malware.exe --run-analysis --profile malware_analysis --generate-report
cumpyl binary.exe --run-analysis --profile forensics --report-format html

# Advanced plugin analysis with custom configuration
cumpyl binary.exe --run-analysis --config custom_config.yaml --report-output detailed_report.html
```

### ⚡ Batch Processing Operations

```bash
# Process entire directories with comprehensive reporting
cumpyl --batch-directory /malware/samples --batch-operation plugin_analysis --report-format json --report-output batch_results.json

# Multi-pattern processing with parallel execution
cumpyl --batch-pattern "*.exe" --batch-pattern "*.dll" --max-workers 8 --batch-operation analyze_sections

# Recursive directory processing with custom filters
cumpyl --batch-directory /binary/dataset --batch-extensions ".exe,.dll,.so" --batch-recursive --batch-operation plugin_analysis

# Complex batch operations with encoding
cumpyl --batch-directory /samples --batch-operation encode_section --encode-section .text --encoding base64 --report-format html
```

## 🔧 Advanced Configuration

### 📝 YAML Configuration System

Create a `cumpyl.yaml` configuration file for customized behavior:

```yaml
framework:
  version: "0.3.0"
  debug_mode: false
  verbose_logging: true
  max_file_size_mb: 100

plugins:
  enabled: true
  plugin_directory: "plugins"
  auto_discover: true
  entropy_analysis:
    enabled: true
    threshold: 7.5
  string_extraction:
    enabled: true
    min_length: 4
    max_results: 1000

performance:
  enable_parallel_processing: true
  max_worker_threads: 4
  batch_size: 50

analysis_profiles:
  malware_analysis:
    plugins: ["entropy_analysis", "string_extraction"]
    safety_checks: true
    detailed_logging: true
  
  forensics:
    plugins: ["string_extraction"]
    safety_checks: true
    preserve_metadata: true
```

### 🎛️ Configuration Management

```bash
# Validate configuration file
cumpyl --validate-config

# Show current configuration
cumpyl --show-config

# Use custom configuration
cumpyl binary.exe --config /path/to/custom.yaml --run-analysis

# Use predefined profiles
cumpyl binary.exe --profile malware_analysis --run-analysis
```

## 🔌 Plugin Development

### 🛠️ Creating Custom Plugins

```python
# plugins/my_custom_plugin.py
from cumpyl_package.plugin_manager import PluginInterface
from typing import Dict, Any

class MyCustomPlugin(PluginInterface):
    @property
    def name(self) -> str:
        return "my_custom_plugin"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    def analyze(self, rewriter) -> Dict[str, Any]:
        """Perform custom analysis on the binary"""
        results = {
            "plugin_name": self.name,
            "binary_size": len(rewriter.binary.content) if rewriter.binary else 0,
            "custom_analysis": self._perform_custom_analysis(rewriter)
        }
        return results
    
    def transform(self, rewriter, analysis_result: Dict[str, Any]) -> bool:
        """Apply transformations based on analysis"""
        # Implement your custom transformations
        return True
    
    def _perform_custom_analysis(self, rewriter):
        # Your custom analysis logic here
        return {"status": "completed"}

# Register the plugin (automatic discovery)
def get_plugin():
    return MyCustomPlugin()
```

### 🔍 Available Plugins

#### **Entropy Analysis Plugin**
- **Shannon entropy calculation** for detecting packed/encrypted sections
- **Threshold-based classification** with configurable sensitivity
- **Statistical analysis** with detailed reporting

#### **String Extraction Plugin**
- **Advanced pattern matching** for URLs, email addresses, file paths
- **Context-aware scoring** with relevance algorithms
- **Unicode support** with encoding detection

## 🎨 Rich Console Features

### 🌈 Intelligent Tier System

**🟢 Advanced Tier (Green)**
- Large, safe sections like `.rdata`, `.rodata`
- Recommended for heavy obfuscation with complex encoding
- Suggested encodings: `base64`, `compressed_base64`, `hex`

**🟡 Intermediate Tier (Yellow)**
- Medium-size data sections and resource/debug data
- Good for moderate obfuscation with balanced safety
- Suggested encodings: `base64`, `compressed_base64`

**🔵 Basic Tier (Blue)**
- Small sections like exception data
- Suitable for light obfuscation with minimal impact
- Suggested encodings: `hex`, `octal`

**🔴 Avoid Tier (Red)**
- Critical sections (executable code, imports, relocations)
- **DO NOT OBFUSCATE** - Will break program execution

### 📊 Console Output Features

- **Color-coded tiers** with intuitive visual indicators
- **Professional tables** with borders, styling, and alignment
- **Progress spinners** with real-time feedback during analysis
- **Copy-ready commands** with exact execution syntax
- **Rich panels** with beautiful bordered sections
- **Interactive progress bars** for multi-threaded operations

## 🔐 Advanced Binary Operations

### 🎯 Precision Encoding

```bash
# Multi-section encoding with different algorithms
cumpyl binary.exe --encode-section .text --encoding base64 --encode-section .data --encoding hex -o obfuscated.exe

# Precise portion encoding with byte-level control
cumpyl binary.exe --encode-section .rodata --encode-offset 0x100 --encode-length 256 --encoding compressed_base64

# Multiple operations with different parameters
cumpyl binary.exe \\
  --encode-section .text --encoding base64 --encode-length 100 \\
  --encode-section .data --encoding hex --encode-offset 50 --encode-length 200 \\
  -o multi_encoded.exe

# Print encoded data for verification and debugging
cumpyl binary.exe --encode-section .text --encoding hex --print-encoded
```

### 🔍 Section Analysis Capabilities

```bash
# Comprehensive section analysis with type identification
cumpyl binary.exe --analyze-sections

# Intelligent obfuscation suggestions with visual output
cumpyl binary.exe --suggest-obfuscation

# List available plugins and their capabilities
cumpyl binary.exe --list-plugins

# Plugin-based comprehensive analysis
cumpyl binary.exe --run-analysis
```

## 🐍 Python API Integration

### 🔧 Basic API Usage

```python
from cumpyl_package.cumpyl import BinaryRewriter
from cumpyl_package.config import ConfigManager
from cumpyl_package.reporting import ReportGenerator

# Initialize with custom configuration
config = ConfigManager("custom_config.yaml")
rewriter = BinaryRewriter("malware.exe", config)

# Load and analyze binary
if rewriter.load_binary():
    # Run comprehensive analysis
    analysis_results = rewriter.run_plugin_analysis()
    
    # Generate structured reports
    report_generator = ReportGenerator(config)
    report_data = report_generator.create_analysis_report(
        "malware.exe", 
        rewriter.analyze_binary(),
        analysis_results
    )
    
    # Export in multiple formats
    report_generator.generate_report(report_data, "html", "analysis.html")
    report_generator.generate_report(report_data, "json", "analysis.json")
```

### ⚡ Batch Processing API

```python
from cumpyl_package.batch_processor import BatchProcessor
from cumpyl_package.config import ConfigManager

# Initialize batch processor
config = ConfigManager()
batch_processor = BatchProcessor(config)

# Add files and configure operations
batch_processor.add_directory("/malware/samples", [".exe", ".dll"])
batch_processor.configure_operation("plugin_analysis")

# Process with progress tracking
results = batch_processor.process_all()

# Generate batch report
report_generator = ReportGenerator(config)
batch_report = report_generator.create_batch_report(results)
report_generator.generate_report(batch_report, "html", "batch_analysis.html")
```

## 🧪 Testing & Quality Assurance

### 🔬 Running Tests

```bash
# Run complete test suite
python -m pytest tests/

# Run with coverage reporting
python -m pytest tests/ --cov=cumpyl_package --cov-report=html

# Run specific test categories
python -m pytest tests/test_plugins.py -v
python -m pytest tests/test_integration.py -v
python -m pytest tests/test_batch.py -v

# Run with detailed output and debugging
python -m pytest tests/ -v -s --tb=long
```

### 📊 Test Categories

- **Unit Tests**: Individual component functionality validation
- **Integration Tests**: End-to-end workflow testing with real binaries
- **Plugin Tests**: Plugin system verification and interface compliance
- **Configuration Tests**: YAML configuration validation and error handling
- **Batch Processing Tests**: Multi-file operation testing and performance validation

## 📈 Version History & Achievements

### 🎉 **v0.3.0 - Major Framework Revolution** *(Current)*

**🏆 MASSIVE ARCHITECTURAL OVERHAUL - Complete transformation from simple encoding tool to comprehensive binary analysis platform!**

#### 🔧 **Configuration System** ✅ COMPLETED
- ✨ **YAML-based configuration management** with centralized `cumpyl.yaml`
- 🎯 **Predefined analysis profiles** for malware analysis, forensics, and research
- ✅ **Comprehensive validation** with detailed error reporting and suggestions
- 🌐 **Environment variable integration** for flexible deployment scenarios

#### 🔌 **Plugin Architecture** ✅ COMPLETED  
- 🔍 **Dynamic plugin discovery** with automatic loading and dependency resolution
- 📋 **Standardized interfaces** with robust `PluginInterface` base class
- 📊 **Advanced entropy analysis plugin** for detecting packed/encrypted binaries
- 🔤 **Intelligent string extraction plugin** with context scoring and pattern matching
- ⚖️ **Dependency management** with conflict resolution and load ordering

#### 📊 **Structured Reporting** ✅ COMPLETED
- 🎨 **Multi-format output**: Beautiful HTML, structured JSON, YAML, XML
- 📱 **Rich HTML reports** with responsive CSS styling and interactive elements
- 📝 **Comprehensive metadata** with timestamps, versions, and file information
- 📦 **Batch processing reports** with statistical summaries and error analysis

#### ⚡ **Batch Processing** ✅ COMPLETED
- 🔀 **Multi-threaded processing** with configurable worker pools for parallel execution
- 📂 **Directory crawling** with recursive pattern matching and extension filtering
- 🔗 **Operation chaining** for complex workflow automation and pipeline processing
- 📊 **Progress visualization** with Rich console integration and real-time updates

#### 🧪 **Testing Framework** ✅ COMPLETED
- ✅ **Comprehensive test suite** with pytest integration and fixtures
- 🔬 **Unit and integration tests** covering all framework components
- 🔌 **Plugin testing infrastructure** for extensibility validation
- 📈 **Coverage reporting** with HTML output for quality assurance

### **v0.2.1** - Encoding Method Fixes
- 🔧 **CRITICAL FIX**: Fixed octal encoding/decoding round-trip functionality
- 🛡️ **Improved Reliability**: All 5 encoding methods now work correctly
- 🐛 **Bug Fix**: Corrected regex pattern in octal decoding logic
- ✅ **Validation**: Added comprehensive encoding method testing

### **v0.2.0** - Rich UI Enhancement
- 🎨 **Rich Console Interface**: Beautiful color-coded output with panels and tables
- ⏱️ **Progress Visualization**: Real-time spinners during binary analysis
- 📋 **Copy-Ready Commands**: Each suggestion includes exact execution syntax
- 🌈 **Enhanced UX**: Professional console experience with tier-based color schemes

### **v0.1.1** - Foundation Fixes
- 🔧 Fixed binary compatibility issues with LIEF and different formats
- 📊 Added comprehensive section analyzer with `--analyze-sections`
- 🛡️ Improved binary validation with proper attribute checking

## 🗂️ Project Structure

```
cumpyl/
├── 🏗️ cumpyl_package/           # Core framework architecture
│   ├── cumpyl.py               # Main binary rewriter & orchestrator
│   ├── config.py               # YAML configuration management
│   ├── plugin_manager.py       # Plugin architecture & discovery
│   ├── batch_processor.py      # Multi-threaded batch processing
│   └── reporting.py            # Multi-format reporting engine
├── 🔌 plugins/                  # Extensible plugin ecosystem
│   ├── entropy_analysis.py     # Shannon entropy analysis
│   └── string_extraction.py    # Advanced string discovery
├── 🧪 tests/                    # Comprehensive testing suite
│   ├── test_config.py          # Configuration validation tests
│   ├── test_plugins.py         # Plugin system tests
│   ├── test_batch.py           # Batch processing tests
│   ├── test_reporting.py       # Reporting engine tests
│   └── test_integration.py     # End-to-end integration tests
├── ⚙️ cumpyl.yaml              # Default framework configuration
├── 📦 setup.py                 # Package configuration & dependencies
├── 🎮 demo_encoding.py         # Interactive feature demonstration
└── 📖 README.md               # This comprehensive documentation
```

## 🛠️ Core Dependencies

### 🔧 **Binary Analysis Engine**
- **[LIEF](https://lief.quarkslab.com/)** - Advanced library for parsing PE, ELF, Mach-O formats
- **[Capstone](https://www.capstone-engine.org/)** - Multi-architecture disassembly framework
- **[Keystone](https://www.keystone-engine.org/)** - Lightweight multi-architecture assembly framework

### 🎨 **Rich User Interface**
- **[Rich](https://github.com/Textualize/rich)** - Beautiful console formatting, tables, and progress bars
- **[tqdm](https://github.com/tqdm/tqdm)** - Fast, extensible progress meter for batch operations

### ⚙️ **Configuration & Data**
- **[PyYAML](https://pyyaml.org/)** - YAML configuration parsing and validation
- **[pytest](https://pytest.org/)** - Professional testing framework with fixtures and coverage

### 📦 **Quick Install Command**
```bash
pip install lief capstone keystone-engine rich tqdm pyyaml
```

## 🔮 Future Roadmap

### 🎯 **Next Priority Features**
1. **🔍 Enhanced Disassembly**: Control flow graph analysis, function annotations, advanced static analysis
2. **⚡ Performance Optimization**: Memory management, large file handling, processing speed improvements  
3. **📚 API Documentation**: Comprehensive developer guides, tutorials, and API reference materials

### 🌟 **Plugin Ecosystem Expansion**
- 🦠 **Malware family detection** with signature-based classification
- 📦 **Packer identification** and automated unpacking capabilities
- 🛡️ **Vulnerability scanning** with CVE database integration
- 🔍 **Custom signature detection** with YARA rule support
- 🌐 **Network behavior analysis** with traffic pattern recognition

### 🏢 **Enterprise Features**
- 🔐 **Role-based access control** for multi-user environments
- 📊 **Dashboard interfaces** with web-based reporting
- 🔗 **REST API endpoints** for integration with existing security tools
- 📈 **Metrics collection** with performance monitoring and alerting

## 🤝 Contributing

We welcome contributions! Here's how you can help:

1. **🐛 Bug Reports**: Submit detailed issue reports with reproduction steps
2. **✨ Feature Requests**: Propose new features with use cases and requirements
3. **🔌 Plugin Development**: Create new analysis plugins following our interface standards
4. **📝 Documentation**: Improve documentation, tutorials, and examples
5. **🧪 Testing**: Add test cases and improve test coverage

### 🛠️ Development Setup

```bash
# Fork and clone the repository
git clone https://github.com/yourusername/cumpyl.git
cd cumpyl

# Set up development environment
pip install -e ".[dev,test]"

# Run tests before making changes
python -m pytest tests/

# Make your changes and test thoroughly
python -m pytest tests/ --cov=cumpyl_package

# Submit a pull request with detailed description
```

## 📄 License

This project is released into the **public domain** under the [Unlicense](LICENSE). You are free to use, modify, and distribute this software without any restrictions.

## 🎯 Project Philosophy

Cumpyl embodies these core principles:

- **🎯 KISS (Keep It Simple, Stupid)**: Intuitive interfaces that just work
- **♻️ DRY (Don't Repeat Yourself)**: Reusable components and configurations  
- **📝 YAML-first Configuration**: Granular control through declarative configuration
- **🔌 Plugin-driven Extensibility**: Modular architecture for unlimited customization
- **🎨 Rich User Experience**: Beautiful console output and comprehensive reporting
- **🏢 Enterprise Ready**: Professional-grade architecture for production environments

---

**🔥 From humble beginnings as a simple binary encoding tool, Cumpyl has evolved into a comprehensive binary analysis platform suitable for malware research, digital forensics, and security analysis. The v0.3.0 release represents a complete architectural transformation and months of intensive development!**

**⭐ Star this repository if you find it useful, and join us in revolutionizing binary analysis!**