# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Cumpyl is a binary analysis and obfuscation framework built on LIEF, Capstone, and Keystone. It provides:
- Multi-format binary parsing (PE, ELF, Mach-O)
- Extensible plugin architecture for analysis and transformation
- Advanced string obfuscation with runtime deobfuscation stubs
- Interactive menu-driven interface using Rich and Textual
- Batch processing capabilities for multiple binaries

## Installation & Setup

### Using uv (Recommended)
```bash
uv sync
source .venv/bin/activate  # Windows: .venv\Scripts\activate
```

### Using pip
```bash
pip install -e ".[dev,test]"
```

## Running Commands

### Launch the Application
```bash
# Default start menu (new modular system)
cumpyl

# Specific menu systems
cumpyl --start-menu      # New modular menu
cumpyl --menu <file>     # Legacy menu system
```

### Common Operations
```bash
# Launch interactive menu
cumpyl sample.exe --menu

# Get obfuscation recommendations
cumpyl sample.exe --suggest-obfuscation

# Run comprehensive analysis
cumpyl sample.exe --run-analysis --all-plugins --report-format html
```

### Testing
```bash
# Run all tests
pytest tests/

# Run specific test file
pytest tests/test_plugin_manager.py

# Run with coverage
pytest --cov=cumpyl_package tests/
```

### Code Quality
```bash
# Format code
black cumpyl_package/ plugins/

# Lint code
flake8 cumpyl_package/ plugins/
```

## Architecture

### Core Components

1. **BinaryRewriter** (`cumpyl_package/cumpyl.py`)
   - Main class for loading and manipulating binaries using LIEF
   - Coordinates plugin execution and modification tracking
   - Handles binary validation and serialization
   - Entry point: `BinaryRewriter(input_file, config)`

2. **PluginManager** (`cumpyl_package/plugin_manager.py`)
   - Discovers and loads plugins from `plugins/` directory
   - Validates plugin dependencies
   - Manages plugin lifecycle (discovery → loading → registration → execution)
   - Base class: `PluginInterface` with `analyze()` and `transform()` methods

3. **ConfigManager** (`cumpyl_package/config.py`)
   - Centralized configuration management
   - Reads from `cumpyl.yaml` in repository root
   - Supports environment variable overrides
   - Validates configuration at runtime

4. **Menu System** (`cumpyl_package/start_menu.py`)
   - Three-module architecture:
     - **Build-a-Binary**: Binary editor and obfuscator (`build_binary_menu.py`)
     - **Lucky Strikes**: Packers and compression (`lucky_strikes_menu.py`)
     - **Silly String**: Payload/string obfuscation (`silly_string_menu.py`)

### Plugin Architecture

Plugins are automatically discovered in the `plugins/` directory. Each plugin must:
- Inherit from `BasePlugin` (`plugins/base_plugin.py`)
- Implement `analyze(rewriter)` method returning `Dict[str, Any]`
- Optionally implement `transform(rewriter, analysis_result)` for transformations

**Key Plugins:**
- `entropy_analysis.py` - Shannon entropy calculation for packed binary detection
- `string_extraction.py` - Advanced string extraction with context scoring
- `ca_packer_plugin.py` - Cellular Automata-based packing with ChaCha20-Poly1305
- `cfg_extractor_plugin.py` - Control Flow Graph extraction using angr
- `pe_string_obfuscation.py` - PE string analysis (V2 - analysis only)
- `pe_string_obfuscation_v3.py` - PE string transformation with stub injection (V3 - functional)
- `go_packer_plugin.py` - Go binary analysis and packing
- `cgo_packer_plugin.py` - CGO-enabled binary analysis

### PE String Obfuscation V3 Architecture ✅ **FULLY FUNCTIONAL**

**Status: Production-ready as of latest commit. 100% success rate on tested binaries.**

V3 Components:
- **PEStringObfuscationV3Plugin** (`plugins/pe_string_obfuscation_v3.py`) - Orchestrates transformation
- **StubInjector** (`cumpyl_package/stub_injector.py`) - Injects deobfuscation code into `.stub` section
- **CodeAnalyzer** (`cumpyl_package/code_analyzer.py`) - Disassembles code to find string references
- **Key Storage** - Stores decryption keys in `.xdata` section

Workflow:
1. Analyze binary with V2 plugin to find strings
2. V3 plugin receives full analysis results (including V2's string analysis)
3. Select strings for obfuscation based on recommended methods
4. Inject deobfuscation stubs via StubInjector (creates `.stub` section)
5. Find code references to strings via CodeAnalyzer (Capstone disassembly)
6. Obfuscate strings in-place and store keys in `.xdata` section
7. Patch code references to call deobfuscation stubs
8. Validate modified binary maintains functionality

**Recent Fixes (2025-11-27):**
- ✅ Fixed missing `Any` import in code_analyzer.py
- ✅ Updated LIEF API calls: `lief.PE.SECTION_CHARACTERISTICS` → `lief.PE.Section.CHARACTERISTICS`
- ✅ Updated LIEF API calls: `lief.PE.MACHINE_TYPES` → `lief.PE.Header.MACHINE_TYPES`
- ✅ Fixed plugin_manager to pass full analysis results to transformation plugins
- ✅ V3 plugin now receives V2's string analysis correctly

**Important Notes:**
- **V3 is for transformation** - Creates functional obfuscated binaries
- **V2 is for analysis** - Identifies and categorizes strings
- V3 depends on V2's analysis output to select strings for obfuscation

### Obfuscation Tier System

Cumpyl classifies sections for safe obfuscation:
- **ADVANCED** - Large, high-impact sections (`.rdata`, `.rodata`) - safe for heavy obfuscation
- **INTERMEDIATE** - Medium sections (`.data`, `.bss`) - moderate obfuscation
- **BASIC** - Small sections (`.pdata`, `.xdata`) - light obfuscation only
- **AVOID** - Critical sections (`.text`, `.code`, `.idata`, `.reloc`) - DO NOT MODIFY

## Important File Locations

- **Main entry**: `scripts/cumpyl.py` or `cumpyl_package/cumpyl.py`
- **Configuration**: `cumpyl.yaml` (root directory)
- **Plugins**: `plugins/` directory
- **Tests**: `tests/` directory
- **Documentation**: `docs/` directory
- **Binary samples**: `BIG_EXE/` directory

## Development Guidelines

### Creating New Plugins

1. Create plugin file in `plugins/` directory
2. Inherit from `BasePlugin` or `PluginInterface`
3. Implement required methods:
   ```python
   from plugins.base_plugin import BasePlugin
   from typing import Dict, Any

   class MyPlugin(BasePlugin):
       def __init__(self, config: Dict[str, Any]):
           super().__init__(config)
           self.name = "my_plugin"
           self.version = "1.0.0"

       def analyze(self, rewriter) -> Dict[str, Any]:
           # Analysis logic using rewriter.binary (LIEF object)
           return {"results": "..."}
   ```

4. Plugin automatically discovered on next run
5. Test with: `pytest tests/test_plugin_manager.py`

### Working with LIEF Binaries

The `rewriter.binary` object is a LIEF Binary:
- PE: `lief.PE.Binary` - access via `rewriter.binary.header`, `rewriter.binary.sections`
- ELF: `lief.ELF.Binary` - access via `rewriter.binary.header`, `rewriter.binary.segments`
- Mach-O: `lief.MachO.Binary` - access via `rewriter.binary.header`

Always check binary format before accessing format-specific attributes:
```python
import lief
if isinstance(rewriter.binary, lief.PE.Binary):
    # PE-specific code
elif isinstance(rewriter.binary, lief.ELF.Binary):
    # ELF-specific code
```

### Disassembly with Capstone

For x86/x64 disassembly:
```python
import capstone
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
for instruction in md.disasm(bytes(section.content), section.virtual_address):
    print(f"{instruction.address:#x}: {instruction.mnemonic} {instruction.op_str}")
```

### Binary Modification Safety

**CRITICAL RULES:**
1. Never modify `.text` or `.code` sections without understanding implications
2. Always create backups before transformation (auto-created in `BIG_EXE/.cumpyl_backups/`)
3. Validate binary after modifications with `rewriter.validate_binary()`
4. Test obfuscated binaries actually execute before committing
5. Use tier system recommendations for section modifications

## Common Patterns

### Loading and Analyzing a Binary
```python
from cumpyl_package import BinaryRewriter, ConfigManager

config = ConfigManager()
rewriter = BinaryRewriter("path/to/binary.exe", config)
rewriter.load_binary()
analysis = rewriter.analyze_binary()
```

### Running Plugins
```python
plugin_manager = rewriter.plugin_manager
plugin_manager.discover_plugins()
plugin_manager.load_plugins()
results = plugin_manager.run_analysis_plugins(rewriter)
```

### Encoding Sections
```python
# Get encoding recommendations
rewriter.suggest_obfuscation()

# Encode specific section
rewriter.encode_section(".rdata", encoding="base64", output="encoded.exe")
```

## Important Warnings

### String Obfuscation
- **ONLY use V3 plugin** (`pe_string_obfuscation_v3.py`) for transformations
- V2 plugin is analysis-only and produces non-functional binaries
- Always enable warnings in Build-a-Binary menu option 9

### Binary Format Support
- PE (Windows): Full support for analysis and transformation
- ELF (Linux): Analysis support, limited transformation
- Mach-O (macOS): Basic analysis, experimental transformation

### Performance
- Binaries >100MB may be slow to process
- angr-based CFG extraction can take several minutes on large binaries
- Use batch processing with threading for multiple files

## Troubleshooting

### Plugin Not Loading
- Check plugin inherits from `BasePlugin` or `PluginInterface`
- Verify plugin file is in `plugins/` directory
- Check for import errors: `python -c "from plugins.my_plugin import MyPlugin"`

### LIEF Parse Failures
- Ensure binary format is supported (PE, ELF, Mach-O)
- Check file isn't corrupted or packed with unknown packer
- Try different LIEF versions if issues persist

### Modified Binary Won't Execute
- Check if critical sections (`.text`, `.idata`, `.reloc`) were modified
- Verify deobfuscation stubs were injected (V3 only)
- Review backup in `BIG_EXE/.cumpyl_backups/` and compare
- Use `lief` to validate PE headers: `python -c "import lief; lief.parse('binary.exe')"`

## References

- **User Guide**: `docs/CUMPYL_USER_GUIDE.md` - Complete usage documentation
- **Developer Guide**: `docs/CUMPYL_DEVELOPER_GUIDE.md` - Plugin development details
- **API Reference**: `docs/CUMPYL_API_REFERENCE.md` - Detailed API documentation
- **V3 Architecture**: `docs/STRING_OBFUSCATOR_V3_ARCHITECTURE.md` - String obfuscation internals
- **LIEF Documentation**: https://lief.re/doc/latest/index.html
- **Capstone Documentation**: http://www.capstone-engine.org/documentation.html
