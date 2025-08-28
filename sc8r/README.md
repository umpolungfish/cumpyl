# Payload Transmutation Tool 🔓

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Red Team Tool](https://img.shields.io/badge/Red%20Team-Tool-red.svg)](https://en.wikipedia.org/wiki/Red_team)

Advanced encoding/obfuscation utility for red team operations and security testing.

## Overview

The Payload Transmutation Tool is a Python-based utility designed for red team operations. Its primary function is to encode and obfuscate payloads to evade security mechanisms like WAFs, IDS, AV, and sandboxes. It offers various encoding methods and includes built-in templates for common payload categories.

**⚠️ Important Notice:** This tool is for authorized security testing only. Ensure you have proper authorization before using this tool on any system or network.

## Features

- **Multiple Encoding Methods**: Null padding, hex, unicode, octal, base64, URL encoding, and mixed encoding
- **Template System**: Predefined templates for SQLi, command injection, XSS, and path traversal
- **Configurable**: YAML-based configuration for customizing behavior
- **Batch Processing**: Process multiple payloads from files
- **Flexible Output**: Raw, JSON, or formatted output options
- **Environment Integration**: Conda environment setup script for easy deployment

## Screenshots

![Tool Demo](assets/demo.gif)
*Example of the tool in action*

![Encoding Example](assets/encoding_example.png)
*Various encoding methods applied to a simple payload*

## Installation

### Prerequisites

- Python 3.8 or higher
- Conda or Mamba package manager
- Git

### Quick Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/umpolungfish/sc8r.git
   cd sc8r
   ```

2. Run the setup script:
   ```bash
   ./setup_transmute.sh
   ```

3. Source your shell's RC file or restart your terminal:
   ```bash
   source ~/.bashrc
   ```

4. Activate the environment:
   ```bash
   transmute-activate
   # OR manually: source ./activate.sh
   ```

## Usage

### Basic Usage

```bash
# Basic payload encoding
python payload_transmute.py -p "cat /etc/passwd" -m null_padding -v

# List available methods
python payload_transmute.py --list-methods

# List available templates
python payload_transmute.py --list-templates
```

### Advanced Usage

```bash
# Use templates with mixed encoding
python payload_transmute.py -t sql_injection -m mixed -o results.json

# Process payloads from a file
python payload_transmute.py -f payloads/common_rce.txt -m unicode -v

# Custom configuration
python payload_transmute.py -p "test" -c configs/transmute_config.yaml
```

### Encoding Methods

| Method        | Description                    | Input Example      | Output Example                    |
|---------------|--------------------------------|--------------------|-----------------------------------|
| `null_padding`| Null byte padding              | `cat /etc/passwd`  | `c\0a\0t\0 \0/\0e\0t\0c\0/\0p\0a\0s\0s\0w\0d` |
| `hex`         | Hexadecimal encoding           | `cat /etc/passwd`  | `\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64` |
| `unicode`     | Unicode escape sequences       | `cat /etc/passwd`  | `\u0063\u0061\u0074\u0020\u002f\u0065\u0074\u0063\u002f\u0070\u0061\u0073\u0073\u0077\u0064` |
| `octal`       | Octal encoding                 | `cat /etc/passwd`  | `\143\141\164\040\057\145\164\143\057\160\141\163\163\167\144` |
| `base64`      | Base64 encoding                | `cat /etc/passwd`  | `Y2F0IC9ldGMvcGFzc3dk`            |
| `url_encode`  | URL encoding                   | `cat /etc/passwd`  | `cat%20%2Fetc%2Fpasswd`           |
| `mixed`       | Random combination of methods  | `cat /etc/passwd`  | Various                           |

### Templates

The tool includes predefined templates for common attack vectors:

- `sql_injection`: Common SQL injection payloads
- `command_injection`: Command injection payloads
- `xss`: Cross-site scripting payloads
- `path_traversal`: Path traversal payloads

## Configuration

Edit `configs/transmute_config.yaml` to customize behavior:

```yaml
# Default transmutation method
default_method: "null_padding"

# Output formatting options
output_format: "raw"  # raw, json, pretty
preserve_spacing: true

# Custom separators for different encoding methods
custom_separators:
  null: "\\0"           # Null byte separator
  space: " "            # Space separator  
  tab: "\\t"            # Tab separator
  custom: "|"           # Custom separator
  double_null: "\\0\\0" # Double null bytes
  hex_space: "\\x20"    # Hex encoded space

# Method-specific configurations
method_configs:
  unicode:
    prefix: "\\u"
    padding: 4
    uppercase: false
    
  hex:
    prefix: "\\x"
    padding: 2
    uppercase: false
```

## Development

### Project Structure

```
payload-transmutation-tool/
├── payload_transmute.py      # Main CLI tool
├── minimal_transmute.py      # Simplified version for testing
├── debug_transmute.py        # Debugging script
├── setup_transmute.sh        # Setup script
├── activate.sh               # Environment activation script
├── configs/
│   └── transmute_config.yaml # Configuration file
├── payloads/
│   ├── common_rce.txt        # RCE payloads
│   └── sql_injection.txt     # SQL injection payloads
├── tests/                    # Test cases
├── results/                  # Output directory
└── logs/                     # Log files
```

### Running Tests

```bash
# Run the debug script to verify functionality
python debug_transmute.py

# Run the minimal version for basic testing
python minimal_transmute.py -p "test" -m hex
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is intended for educational and authorized security testing purposes only. The developers are not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before testing any systems or networks.

## Acknowledgments

- Thanks to the red team community for their research and contributions
- Inspired by various payload encoding techniques used in the field