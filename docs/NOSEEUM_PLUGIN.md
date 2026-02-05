# Noseeum Plugin for Cumpyl Framework

## Overview

The Noseeum plugin integrates the powerful Unicode-based obfuscation and vulnerability detection capabilities of the Noseeum framework into the Cumpyl binary analysis and rewriting platform. This plugin enables users to detect Unicode vulnerabilities and apply advanced obfuscation techniques to binaries.

## Features

### Analysis Capabilities
- **Unicode Vulnerability Detection**: Identifies potential Unicode-based vulnerabilities in binaries
- **Bidi Attack Detection**: Detects bidirectional control characters that may indicate Trojan Source attacks
- **Homoglyph Detection**: Identifies visually similar characters that could be used for obfuscation
- **Invisible Character Detection**: Finds zero-width and other invisible characters
- **Obfuscation Opportunity Analysis**: Identifies sections and strings suitable for Unicode obfuscation

### Transformation Capabilities
- **Homoglyph Obfuscation**: Substitutes characters with visually similar Unicode equivalents
- **Bidi (Trojan Source) Obfuscation**: Applies bidirectional override characters for stealth
- **Invisible Character Embedding**: Hides payloads using zero-width characters
- **Normalization Attacks**: Exploits Unicode normalization inconsistencies
- **Unassigned Plane Characters**: Uses characters from unassigned Unicode planes
- **Variation Selectors**: Embeds metadata using Unicode variation selectors

## Installation

The Noseeum plugin is automatically integrated when you install the full Cumpyl framework with the noseeum submodule. The plugin requires the following dependencies:
- click
- importlib-resources
- requests

## Usage

### Command Line Interface

The plugin can be used through the Cumpyl CLI:

```bash
# Run noseeum analysis on a binary
cumpyl binary.exe --run-analysis

# Apply homoglyph obfuscation
cumpyl binary.exe --plugin noseeum_transform --obfuscation-method homoglyph

# Apply invisible character obfuscation
cumpyl binary.exe --plugin noseeum_transform --obfuscation-method invisible
```

### Interactive Menu System

The plugin is fully integrated into the Cumpyl interactive menu system:

1. Launch the menu: `cumpyl binary.exe --menu`
2. Navigate to "Build-a-Binary" → "Noseeum Unicode Obfuscation"
3. Choose from various analysis and transformation options:
   - Noseeum Analysis: Analyze binary for Unicode vulnerabilities
   - Interactive String Browser: Browse strings suitable for obfuscation
   - Preview Obfuscation: See how transformations would affect strings
   - Custom Obfuscation Settings: Configure obfuscation parameters
   - Apply Obfuscation: Apply transformations to the binary

## Configuration Options

### Analysis Plugin Configuration
- `enabled`: Whether the analysis plugin is enabled (default: true)

### Transformation Plugin Configuration
- `obfuscation_method`: Method to use ('homoglyph', 'bidi', 'invisible', 'normalization') (default: 'homoglyph')
- `target_section`: Binary section to obfuscate (default: '.rdata')
- `density`: Density of character substitution (0.0-1.0) (default: 0.1)
- `use_unassigned_planes`: Whether to use unassigned Unicode planes (default: false)
- `use_variation_selectors`: Whether to use variation selectors (default: false)
- `dry_run`: Whether to run without modifying the binary (default: true)

## Technical Details

### Analysis Process
The analysis plugin scans binary sections for:
- High-byte content that may indicate Unicode strings
- Bidirectional control characters
- Zero-width characters
- Unusual character distributions
- Strings that could be obfuscated

### Transformation Process
The transformation plugin:
1. Identifies suitable sections/strings for obfuscation
2. Applies the selected obfuscation method
3. Preserves binary functionality while applying obfuscation
4. Handles encoding/decoding appropriately

## Security Considerations

- **Binary Integrity**: Obfuscation may affect binary functionality; always test thoroughly
- **Detection Evasion**: Unicode obfuscation techniques are designed to evade static analysis
- **Reversibility**: Some transformations may be difficult to reverse
- **Compatibility**: Some obfuscation methods may affect cross-platform compatibility

## Integration Points

The Noseeum plugin integrates with:
- Cumpyl's plugin registry system
- The interactive menu system (Build-a-Binary → Noseeum Unicode Obfuscation)
- The analysis and transformation pipeline
- The reporting system for detailed output

## Troubleshooting

If the plugin fails to load:
1. Verify that noseeum dependencies are installed
2. Check that the noseeum data files (homoglyph_registry.json, etc.) are accessible
3. Ensure that the plugin files are in the correct location

For analysis issues:
- Verify that the binary format is supported (PE, ELF, Mach-O)
- Check that the binary is not corrupted
- Ensure sufficient permissions to read the binary

## Examples

### Basic Analysis
```bash
cumpyl sample.exe --run-analysis
# Look for 'noseeum_analysis' in the results
```

### Interactive Usage
```bash
cumpyl sample.exe --menu
# Navigate to Build-a-Binary → Noseeum Unicode Obfuscation → Noseeum Analysis
```

### Custom Transformation
```bash
# Use the interactive menu to configure custom settings
cumpyl sample.exe --menu
# Navigate to Build-a-Binary → Noseeum Unicode Obfuscation → Custom Obfuscation Settings
```

## Credits

The Noseeum plugin leverages the original Noseeum framework by the same author, integrating its Unicode-based obfuscation capabilities into the Cumpyl platform.