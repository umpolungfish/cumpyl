# CLI Reference

Cumpyl provides a comprehensive command-line interface for binary analysis and manipulation.

## Main Commands

### Interactive Menu
```bash
cumpyl sample.bin --menu
```
Launches the interactive menu system for guided analysis.

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

## Batch Processing

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

## Encoding Operations

### Single Section Encoding
```bash
cumpyl binary.exe --encode-section .text --encoding base64 -o encoded.exe
```
Encode specific sections.

### Multi-section Encoding
```bash
cumpyl binary.exe --encode-section .text --encoding base64 --encode-section .data --encoding hex
```
Apply encodings to multiple sections.

## Configuration

### Validate Configuration
```bash
cumpyl --validate-config
```

### Show Configuration
```bash
cumpyl --show-config
```

### Custom Configuration
```bash
cumpyl binary.exe --config custom.yaml --run-analysis
```

### Analysis Profiles
```bash
cumpyl binary.exe --profile malware_analysis --run-analysis
```