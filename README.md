# Cumpyl - Binary Analysis & Rewriting Framework

[![Framework Version](https://img.shields.io/badge/version-0.3.0-brightgreen.svg)](https://github.com/yourusername/cumpyl)
[![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-Unlicense-green.svg)](LICENSE)

Cumpyl is a Python-based binary analysis framework for analyzing, modifying, and rewriting binary files (PE, ELF, Mach-O). It features plugin architecture, batch processing, and comprehensive reporting capabilities.

## Key Features

- **Plugin Architecture**: Dynamic plugin discovery with standardized interfaces
- **Multi-Format Support**: Native support for PE, ELF, and Mach-O binaries
- **Batch Processing**: Multi-threaded processing with configurable worker pools
- **Comprehensive Reporting**: HTML, JSON, YAML, and XML report generation
- **YAML Configuration**: Centralized configuration with predefined analysis profiles
- **Rich Console Interface**: Color-coded output with progress indicators

## Installation

### Using Conda/Mamba (Recommended)

```bash
mamba create -n cumpyl -c conda-forge python=3.9
mamba activate cumpyl
pip install lief capstone keystone-engine rich tqdm pyyaml
pip install -e .
```

### Using pip

```bash
python -m venv cumpyl-env
source cumpyl-env/bin/activate  # Windows: cumpyl-env\Scripts\activate
pip install lief capstone keystone-engine rich tqdm pyyaml
pip install -e .
```

### Development Setup

```bash
pip install -e ".[dev,test]"
python -m pytest tests/
cumpyl --show-config
```

## Quick Start

### Basic Usage

```bash
# Analyze binary structure
cumpyl binary.exe --analyze-sections

# Get obfuscation recommendations
cumpyl binary.exe --suggest-obfuscation

# Run comprehensive analysis with HTML report
cumpyl binary.exe --run-analysis --report-format html --report-output analysis.html
```

### Batch Processing

```bash
# Process directory with plugin analysis
cumpyl --batch-directory /samples --batch-operation plugin_analysis --report-format json

# Multi-pattern processing
cumpyl --batch-pattern "*.exe" --batch-pattern "*.dll" --batch-operation analyze_sections

# Recursive processing with custom extensions
cumpyl --batch-directory /dataset --batch-extensions ".exe,.dll" --batch-recursive
```

### Encoding Operations

```bash
# Encode specific sections
cumpyl binary.exe --encode-section .text --encoding base64 -o encoded.exe

# Multi-section encoding
cumpyl binary.exe --encode-section .text --encoding base64 --encode-section .data --encoding hex
```

## Configuration

Create a `cumpyl.yaml` configuration file:

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

performance:
  enable_parallel_processing: true
  max_worker_threads: 4
  batch_size: 50

analysis_profiles:
  malware_analysis:
    plugins: ["entropy_analysis", "string_extraction"]
    safety_checks: true
  forensics:
    plugins: ["string_extraction"]
    safety_checks: true
```

### Configuration Commands

```bash
cumpyl --validate-config
cumpyl --show-config
cumpyl binary.exe --config custom.yaml --run-analysis
cumpyl binary.exe --profile malware_analysis --run-analysis
```

## Plugin Development

### Creating Custom Plugins

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
        results = {
            "plugin_name": self.name,
            "binary_size": len(rewriter.binary.content) if rewriter.binary else 0,
        }
        return results
    
    def transform(self, rewriter, analysis_result: Dict[str, Any]) -> bool:
        return True

def get_plugin():
    return MyCustomPlugin()
```

### Available Plugins

- **Entropy Analysis**: Shannon entropy calculation for detecting packed/encrypted sections
- **String Extraction**: Pattern matching for URLs, emails, file paths with context scoring

## Console Features

### Tier System

- **Green (Advanced)**: Large, safe sections (.rdata, .rodata) - Recommended encodings: base64, hex
- **Yellow (Intermediate)**: Medium data sections - Recommended encodings: base64, compressed_base64  
- **Blue (Basic)**: Small sections - Recommended encodings: hex, octal
- **Red (Avoid)**: Critical sections (code, imports) - DO NOT OBFUSCATE

### Console Output

- Color-coded tier indicators
- Professional tables with styling
- Real-time progress feedback
- Copy-ready command suggestions
- Interactive progress bars

## Python API

```python
from cumpyl_package.cumpyl import BinaryRewriter
from cumpyl_package.config import ConfigManager

# Initialize with configuration
config = ConfigManager("config.yaml")
rewriter = BinaryRewriter("binary.exe", config)

# Load and analyze
if rewriter.load_binary():
    analysis_results = rewriter.run_plugin_analysis()
```

## Testing

```bash
python -m pytest tests/
python -m pytest tests/ --cov=cumpyl_package --cov-report=html
```

## Project Structure

```
cumpyl/
├── cumpyl_package/          # Core framework
│   ├── cumpyl.py           # Main binary rewriter
│   ├── config.py           # Configuration management
│   ├── plugin_manager.py   # Plugin architecture
│   ├── batch_processor.py  # Batch processing
│   └── reporting.py        # Report generation
├── plugins/                 # Plugin ecosystem
├── tests/                   # Test suite
├── cumpyl.yaml             # Default configuration
└── setup.py                # Package configuration
```

## Dependencies

- [LIEF](https://lief.quarkslab.com/) - Binary parsing (PE, ELF, Mach-O)
- [Capstone](https://www.capstone-engine.org/) - Disassembly framework
- [Keystone](https://www.keystone-engine.org/) - Assembly framework
- [Rich](https://github.com/Textualize/rich) - Console formatting
- [PyYAML](https://pyyaml.org/) - Configuration parsing

## License

This project is released into the public domain under the [Unlicense](LICENSE).