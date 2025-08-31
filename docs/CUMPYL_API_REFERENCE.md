# Cumpyl API Reference

## Table of Contents
1. [Core Modules](#core-modules)
2. [Plugin System](#plugin-system)
3. [Binary Analysis](#binary-analysis)
4. [Configuration](#configuration)
5. [Batch Processing](#batch-processing)
6. [Hex Viewer](#hex-viewer)
7. [Reporting](#reporting)
8. [Menu System](#menu-system)
9. [Payload Transmutation](#payload-transmutation)

## Core Modules

### BinaryRewriter

The main class for binary analysis and manipulation.

#### Constructor
```python
BinaryRewriter(input_file: str, config: ConfigManager = None)
```

#### Methods

##### `load_binary() -> bool`
Load a binary file for analysis.

**Returns**: `bool` - True if successful, False otherwise

**Example**:
```python
rewriter = BinaryRewriter("binary.exe")
if rewriter.load_binary():
    print("Binary loaded successfully")
```

##### `analyze_binary() -> Dict`
Perform static analysis on the binary.

**Returns**: `Dict` - Analysis results including architecture, entry point, sections, etc.

##### `disassemble_section(section_name: str) -> List[str]`
Disassemble a specific section of the binary.

**Parameters**:
- `section_name`: Name of the section to disassemble

**Returns**: `List[str]` - List of disassembled instructions

##### `run_plugin_analysis() -> Dict[str, Any]`
Run all enabled analysis plugins on the binary.

**Returns**: `Dict[str, Any]` - Results from all analysis plugins

##### `run_plugin_transformations(analysis_results: Dict[str, Any]) -> bool`
Run all enabled transformation plugins on the binary.

**Parameters**:
- `analysis_results`: Results from analysis phase

**Returns**: `bool` - True if all transformations successful

##### `suggest_obfuscation(return_suggestions: bool = False) -> Optional[List[Dict[str, Any]]]`
Suggest optimal sections for obfuscation with different tiers.

**Parameters**:
- `return_suggestions`: Whether to return suggestion data

**Returns**: `Optional[List[Dict[str, Any]]]` - Suggestion data if requested

##### `get_section_data(section_name: str) -> bytes`
Extract raw bytes from a specific section.

**Parameters**:
- `section_name`: Name of the section

**Returns**: `bytes` - Raw section data

##### `modify_section_data(section_name: str, offset: int, new_data: bytes) -> bool`
Modify data in a specific section.

**Parameters**:
- `section_name`: Name of the section
- `offset`: Offset within the section
- `new_data`: New data to write

**Returns**: `bool` - True if successful

##### `save_binary(output_file: str) -> bool`
Save the modified binary to a file.

**Parameters**:
- `output_file`: Path to output file

**Returns**: `bool` - True if successful

##### `encode_bytes(data: bytes, encoding: str) -> str`
Encode bytes using specified encoding method.

**Parameters**:
- `data`: Bytes to encode
- `encoding`: Encoding method (hex, octal, null, base64, compressed_base64)

**Returns**: `str` - Encoded data

##### `decode_bytes(encoded_data: str, encoding: str) -> bytes`
Decode data using specified encoding method.

**Parameters**:
- `encoded_data`: Data to decode
- `encoding`: Encoding method

**Returns**: `bytes` - Decoded data

### ConfigManager

Handles configuration loading and validation.

#### Constructor
```python
ConfigManager(config_path: str = None)
```

#### Methods

##### `load_config(config_path: str = None) -> bool`
Load configuration from YAML file.

**Parameters**:
- `config_path`: Path to configuration file

**Returns**: `bool` - True if successful

##### `validate_config() -> List[str]`
Validate configuration settings.

**Returns**: `List[str]` - List of validation issues

##### `get_plugin_config(plugin_name: str) -> Dict[str, Any]`
Retrieve configuration for a specific plugin.

**Parameters**:
- `plugin_name`: Name of the plugin

**Returns**: `Dict[str, Any]` - Plugin configuration

##### `get_profile_config(profile_name: str) -> Dict[str, Any]`
Retrieve a specific analysis profile.

**Parameters**:
- `profile_name`: Name of the profile

**Returns**: `Dict[str, Any]` - Profile configuration

## Plugin System

### PluginInterface

Base class for all plugins.

#### Properties
- `name`: Unique identifier for the plugin
- `version`: Plugin version number
- `description`: Description of the plugin
- `author`: Plugin author
- `dependencies`: List of plugin dependencies

#### Methods

##### `analyze(rewriter) -> Dict[str, Any]`
Perform analysis on the binary.

**Parameters**:
- `rewriter`: BinaryRewriter instance

**Returns**: `Dict[str, Any]` - Analysis results

##### `transform(rewriter, analysis_result: Dict[str, Any]) -> bool`
Apply transformations to the binary.

**Parameters**:
- `rewriter`: BinaryRewriter instance
- `analysis_result`: Results from analysis phase

**Returns**: `bool` - True if successful

##### `get_config() -> Dict[str, Any]`
Get plugin-specific configuration.

**Returns**: `Dict[str, Any]` - Plugin configuration

### PluginManager

Manages plugin discovery and execution.

#### Constructor
```python
PluginManager(config: ConfigManager)
```

#### Methods

##### `discover_plugins() -> List[str]`
Find all available plugins.

**Returns**: `List[str]` - List of plugin names

##### `load_plugin(plugin_name: str) -> bool`
Load a specific plugin.

**Parameters**:
- `plugin_name`: Name of the plugin

**Returns**: `bool` - True if successful

##### `load_all_plugins() -> int`
Load all available plugins.

**Returns**: `int` - Number of plugins loaded

##### `execute_analysis_phase(rewriter) -> Dict[str, Any]`
Run analysis phase for all plugins.

**Parameters**:
- `rewriter`: BinaryRewriter instance

**Returns**: `Dict[str, Any]` - Analysis results from all plugins

##### `execute_transformation_phase(rewriter, analysis_results: Dict[str, Any]) -> bool`
Run transformation phase for all plugins.

**Parameters**:
- `rewriter`: BinaryRewriter instance
- `analysis_results`: Results from analysis phase

**Returns**: `bool` - True if all transformations successful

##### `get_analysis_plugins() -> List[PluginInterface]`
Get all analysis plugins.

**Returns**: `List[PluginInterface]` - List of analysis plugins

##### `get_transformation_plugins() -> List[PluginInterface]`
Get all transformation plugins.

**Returns**: `List[PluginInterface]` - List of transformation plugins

### PluginRegistry

Centralized registry for all plugins.

#### Class Methods

##### `register(plugin_type: str, name: str, factory: Callable)`
Register a plugin factory.

**Parameters**:
- `plugin_type`: Type of plugin (analysis/transformation)
- `name`: Plugin name
- `factory`: Factory function to create plugin instance

##### `get_plugin(plugin_type: str, name: str, config: Dict[str, Any])`
Get a plugin instance by type and name.

**Parameters**:
- `plugin_type`: Type of plugin
- `name`: Plugin name
- `config`: Configuration dictionary

**Returns**: Plugin instance

##### `list_plugins(plugin_type: str = None) -> Union[List[str], Dict[str, List[str]]]`
List all registered plugins.

**Parameters**:
- `plugin_type`: Optional plugin type to filter

**Returns**: List of plugin names or dictionary of plugin types

## Binary Analysis

### Analysis Plugins

#### PackerPlugin
Universal binary packer analysis plugin.

**Capabilities**:
- Simple packing detection
- Section encryption analysis
- Payload injection opportunities

**Methods**:
- `analyze(rewriter) -> Dict[str, Any]`: Analyze binary for packing opportunities

#### GoBinaryAnalysisPlugin
Analysis-only plugin for detecting Go binaries.

**Capabilities**:
- Go binary detection with confidence scoring
- Section analysis with entropy calculation
- Packing opportunity identification

**Methods**:
- `analyze(rewriter) -> Dict[str, Any]`: Analyze Go binary characteristics

#### CGoPackerPlugin
CGO-aware Go binary packer analysis plugin.

**Capabilities**:
- CGO binary detection
- CGO-specific section analysis
- Anti-detection technique identification

**Methods**:
- `analyze(rewriter) -> Dict[str, Any]`: Analyze CGO-enabled Go binary

### Analysis Utilities

#### Entropy Analysis
Calculate Shannon entropy for packed binary detection.

```python
from plugins.consolidated_utils import calculate_entropy_with_confidence

entropy_result = calculate_entropy_with_confidence(data)
entropy_value = entropy_result["value"]
confidence = entropy_result["confidence"]
```

#### String Extraction
Advanced string extraction with context scoring.

```python
from plugins.string_extraction import extract_strings_with_context

strings = extract_strings_with_context(binary_data)
```

## Configuration

### Configuration Structure

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
  load_order: []

batch:
  max_workers: 4
  default_extensions: [".exe", ".dll", ".so", ".bin", ".elf"]
  recursive: true

hex_viewer:
  default_bytes: 2048
  max_bytes: 16384
  theme: "default"

packer:
  compression_level: 6
  encryption_enabled: false
```

### Profile Configuration

```yaml
profiles:
  malware_analysis:
    plugins:
      - entropy_analysis
      - string_extraction
      - packer
    safety_checks: true
    
  forensics:
    plugins:
      - entropy_analysis
      - string_extraction
      - packer
      - go_binary_analyzer
    safety_checks: true
    
  research:
    plugins:
      - entropy_analysis
      - string_extraction
      - packer
      - go_binary_analyzer
      - cgo_packer
    safety_checks: false
```

## Batch Processing

### BatchProcessor

Handles batch processing of multiple files.

#### Constructor
```python
BatchProcessor(config: ConfigManager)
```

#### Methods

##### `add_directory(directory: str, extensions: List[str] = None, recursive: bool = True) -> int`
Add files from a directory to the batch.

**Parameters**:
- `directory`: Directory path
- `extensions`: List of file extensions to include
- `recursive`: Whether to process subdirectories

**Returns**: `int` - Number of files added

##### `add_files(pattern: str, recursive: bool = True) -> int`
Add files matching a pattern to the batch.

**Parameters**:
- `pattern`: Glob pattern
- `recursive`: Whether to process subdirectories

**Returns**: `int` - Number of files added

##### `configure_operation(operation: str, **kwargs)`
Configure batch operation.

**Parameters**:
- `operation`: Operation type
- `**kwargs`: Operation-specific parameters

##### `process_all() -> Dict[str, Any]`
Process all jobs in the batch.

**Returns**: `Dict[str, Any]` - Processing results

##### `print_summary(results: Dict[str, Any])`
Print batch processing summary.

**Parameters**:
- `results`: Processing results

## Hex Viewer

### HexViewer

Generates hex dumps and interactive viewers.

#### Constructor
```python
HexViewer(config: ConfigManager, base_offset: int = 0)
```

#### Methods

##### `load_binary_data(data: bytes)`
Load binary data for viewing.

**Parameters**:
- `data`: Binary data to view

##### `add_section_annotations(sections: List)`
Add section annotations to the hex view.

**Parameters**:
- `sections`: List of sections

##### `add_analysis_annotations(analysis_results: Dict[str, Any])`
Add analysis annotations to the hex view.

**Parameters**:
- `analysis_results`: Analysis results

##### `generate_html_report() -> str`
Generate HTML report with hex view.

**Returns**: `str` - HTML report

### TextualHexViewer

Interactive terminal hex viewer.

#### Functions

##### `launch_textual_hex_viewer(file_path: str)`
Launch the textual hex viewer.

**Parameters**:
- `file_path`: Path to binary file

## Reporting

### ReportGenerator

Generates analysis reports in various formats.

#### Constructor
```python
ReportGenerator(config: ConfigManager)
```

#### Methods

##### `create_analysis_report(input_file: str, basic_analysis: Dict, plugin_analysis: Dict) -> Dict`
Create structured analysis report.

**Parameters**:
- `input_file`: Input file path
- `basic_analysis`: Basic analysis results
- `plugin_analysis`: Plugin analysis results

**Returns**: `Dict` - Structured report data

##### `create_batch_report(batch_results: Dict[str, Any]) -> Dict`
Create batch processing report.

**Parameters**:
- `batch_results`: Batch processing results

**Returns**: `Dict` - Structured batch report

##### `generate_report(report_data: Dict, format: str, output_file: str = None) -> Union[str, bool]`
Generate report in specified format.

**Parameters**:
- `report_data`: Report data
- `format`: Output format (json, yaml, xml, html)
- `output_file`: Optional output file path

**Returns**: `Union[str, bool]` - Report content or success status

## Menu System

### CumpylMenu

Interactive menu system for Cumpyl.

#### Constructor
```python
CumpylMenu(config: ConfigManager = None)
```

#### Methods

##### `run()`
Run the interactive menu loop.

##### `select_target_file() -> bool`
Select target binary file.

**Returns**: `bool` - True if successful

##### `show_main_menu() -> str`
Display the main menu.

**Returns**: `str` - User selection

### PluginPackerMenu

Plugin-based packer menu system.

#### Constructor
```python
PluginPackerMenu(config: ConfigManager = None, target_file: str = None)
```

#### Methods

##### `run()`
Run the plugin packer menu loop.

##### `analyze_with_plugins()`
Run analysis using available packer plugins.

##### `transform_with_plugins()`
Apply transformations using available packer plugins.

##### `list_packer_plugins()`
List all available packer plugins.

##### `real_packer_integration()`
Integrate with the real packer tool as fallback.

### Standalone Plugin Packer Menu

The standalone plugin packer menu (`plugin_packer_menu.py`) can be run directly from the command line:

```bash
python3 plugin_packer_menu.py [binary_file]
```

#### Menu Options

1. **Analyze Binary**: Run analysis plugins on your binary to identify packing opportunities
2. **Transform Binary**: Apply transformation plugins to modify your binary
3. **Change Binary File**: Switch to a different target binary
4. **List Available Plugins**: View all registered analysis and transformation plugins

#### Plugin Menu Improvements

Recent improvements to the plugin packer menu include:
- Fixed binary saving functionality in transformation plugins
- Enhanced compatibility with Go and CGO packer plugins
- Improved error handling and user feedback
- Better configuration options for different plugin types
- Support for dry run mode to test transformations without modifying files

## Payload Transmutation

### PayloadTransmuter

Payload encoding and obfuscation tool.

#### Constructor
```python
PayloadTransmuter(config_path: str = None)
```

#### Methods

##### `encode_payload(payload: str, method: str) -> str`
Encode a payload using specified method.

**Parameters**:
- `payload`: Payload to encode
- `method`: Encoding method

**Returns**: `str` - Encoded payload

##### `encode_file(file_path: str, method: str, output_path: str = None) -> bool`
Encode payloads from a file.

**Parameters**:
- `file_path`: Input file path
- `method`: Encoding method
- `output_path`: Output file path

**Returns**: `bool` - True if successful

##### `transmute_payload(payload: str, template: str = None) -> Dict[str, str]`
Apply multiple encoding methods to a payload.

**Parameters**:
- `payload`: Payload to transmute
- `template`: Optional template to use

**Returns**: `Dict[str, str]` - Dictionary of encoded payloads

##### `load_payloads_from_file(file_path: str) -> List[str]`
Load payloads from a file.

**Parameters**:
- `file_path`: Path to payload file

**Returns**: `List[str]` - List of payloads

### Supported Methods

- `null_padding`: Null byte padding
- `hex`: Hexadecimal encoding
- `octal`: Octal escape sequences
- `unicode`: Unicode encoding
- `base64`: Standard Base64
- `base64_variants`: Base64 with custom alphabets
- `gzip_base64`: Gzip compression + Base64
- `zlib_base64`: Zlib compression + Base64
- `xor`: XOR encoding with key
- `rot13`: ROT13 cipher
- `caesar`: Caesar cipher with custom shift
- `mixed`: Combination of multiple methods