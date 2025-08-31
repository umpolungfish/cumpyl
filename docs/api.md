# API Reference

## Core Modules

### BinaryRewriter
The main class for binary analysis and manipulation.

#### Methods
- `load_binary()`: Load a binary file for analysis
- `run_plugin_analysis()`: Run all enabled plugins on the binary
- `generate_report()`: Generate analysis reports in various formats
- `apply_encoding()`: Apply encoding to specific sections
- `save_binary()`: Save the modified binary to a file

### ConfigManager
Handles configuration loading and validation.

#### Methods
- `load_config()`: Load configuration from YAML file
- `validate_config()`: Validate configuration settings
- `get_profile()`: Retrieve a specific analysis profile

### PluginManager
Manages plugin discovery and execution.

#### Methods
- `discover_plugins()`: Find all available plugins
- `load_plugin()`: Load a specific plugin
- `run_plugin()`: Execute a plugin's analysis or transformation

## Plugin Interface

### PluginInterface
Base class for all plugins.

#### Properties
- `name`: Unique identifier for the plugin
- `version`: Plugin version number

#### Methods
- `analyze(rewriter)`: Perform analysis on the binary
- `transform(rewriter, analysis_result)`: Apply transformations to the binary

## Batch Processor

### BatchProcessor
Handles batch processing of multiple files.

#### Methods
- `process_directory()`: Process all files in a directory
- `process_pattern()`: Process files matching a pattern
- `process_file()`: Process a single file

## Hex Viewer

### HexViewer
Generates hex dumps and interactive viewers.

#### Methods
- `generate_hex_view()`: Create a hex dump of the binary
- `generate_interactive_view()`: Create an interactive hex viewer
- `add_annotations()`: Add analysis annotations to the hex view

## Reporting

### ReportGenerator
Generates analysis reports in various formats.

#### Methods
- `generate_html_report()`: Create an HTML report
- `generate_json_report()`: Create a JSON report
- `generate_yaml_report()`: Create a YAML report
- `generate_xml_report()`: Create an XML report