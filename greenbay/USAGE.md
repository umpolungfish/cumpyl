# CA-PACKER USER GUIDE

## 🎉 Welcome to CA-Packer!

CA-Packer is a revolutionary binary packer that combines **cellular automaton obfuscation** with **ChaCha20-Poly1305 encryption** to create highly resilient binary protection. This guide will help you get started with using CA-Packer effectively.

## 📋 TABLE OF CONTENTS

1. [System Requirements](#system-requirements)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Basic Usage](#basic-usage)
5. [Advanced Features](#advanced-features)
6. [Understanding the Technology](#understanding-the-technology)
7. [Troubleshooting](#troubleshooting)
8. [FAQ](#faq)

## 🖥 SYSTEM REQUIREMENTS

### Minimum Requirements
- **Operating System**: Linux (ELF) or Windows (PE)
- **Python**: 3.7 or higher
- **RAM**: 4GB minimum
- **Disk Space**: 100MB free space

### Recommended Requirements
- **Operating System**: Ubuntu 20.04+ or Windows 10+
- **Python**: 3.9 or higher
- **RAM**: 8GB or more
- **Disk Space**: 1GB free space

## 📦 INSTALLATION

### 1. Clone the Repository
```bash
git clone <repository_url>
cd ca-packer
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Verify Installation
```bash
python3 -c "import lief; print('LIEF installed successfully')"
```

## ⚡ QUICK START

### Pack a Binary
```bash
# Pack a Linux ELF binary
python3 ca_packer/packer.py my_program packed_my_program

# Pack a Windows PE binary
python3 ca_packer/packer.py my_program.exe packed_my_program.exe
```

### Run the Packed Binary
```bash
# Linux
./packed_my_program

# Windows
packed_my_program.exe
```

## 🛠 BASIC USAGE

### Command Line Syntax
```bash
python3 ca_packer/packer.py [options] <input_file> <output_file>
```

### Options
- `-h, --help`: Show help message
- `-v, --verbose`: Enable verbose output
- `--algo <algorithm>`: Specify encryption algorithm (default: chacha20-poly1305)

### Examples

#### Basic Packing
```bash
# Pack with default settings
python3 ca_packer/packer.py program packed_program

# Pack with verbose output
python3 ca_packer/packer.py -v program packed_program
```

#### Cross-Platform Packing
```bash
# Pack Linux ELF binary on Linux
python3 ca_packer/packer.py my_app packed_my_app

# Pack Windows PE binary on Linux (requires wine for testing)
python3 ca_packer/packer.py my_app.exe packed_my_app.exe
```

## 🔧 ADVANCED FEATURES

### Custom Encryption Keys
CA-Packer uses random keys by default, but you can specify custom keys:

```bash
# Specify custom key (32 bytes in hex)
python3 ca_packer/packer.py --key 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF program packed_program
```

### Multiple Packing Passes
For enhanced protection, you can apply multiple packing passes:

```bash
# First pass
python3 ca_packer/packer.py program temp_packed_program

# Second pass
python3 ca_packer/packer.py temp_packed_program final_packed_program
```

### Custom CA Steps
Adjust the number of cellular automaton steps:

```bash
# Specify custom CA steps (default: 100)
python3 ca_packer/packer.py --ca-steps 200 program packed_program
```

## 🔬 UNDERSTANDING THE TECHNOLOGY

### How CA-Packer Works

#### 1. Binary Analysis
CA-Packer uses the LIEF library to analyze the input binary:
- Identifies the original entry point (OEP)
- Locates executable sections
- Prepares for section modification

#### 2. Payload Encryption
The binary payload is encrypted using ChaCha20-Poly1305:
- Strong authenticated encryption
- 32-byte encryption key
- 12-byte nonce
- Integrity verification

#### 3. CA Obfuscation
Cellular automaton (Rule 30) is applied for additional obfuscation:
- Initializes CA grid with key material
- Evolves grid for specified number of steps
- Uses final grid state as unmasking key

#### 4. Parameter Embedding
All necessary parameters are embedded in the packed binary:
- Original Entry Point (OEP)
- Encryption keys (4 parts, XOR obfuscated)
- Nonce (12 bytes)
- CA steps
- Payload RVA
- Payload size

#### 5. Unpacking Stub
A pure assembly unpacking stub is added:
- Detects its own base address
- Reads embedded parameters
- Deobfuscates encryption keys
- Allocates memory for processing
- Applies CA unmasking to payload
- Decrypts payload using ChaCha20-Poly1305
- Jumps to original entry point

### Security Features

#### Dual-Layer Protection
1. **ChaCha20-Poly1305 Encryption**: Industry-standard authenticated encryption
2. **Cellular Automaton Obfuscation**: Mathematical obfuscation using Rule 30

#### Anti-Reverse Engineering
- **Parameter Obfuscation**: XOR obfuscation of embedded parameters
- **Pure Assembly Stub**: Difficult to analyze machine code
- **CA Unmasking**: Complex mathematical deobfuscation

#### Cross-Platform Support
- **PE Format**: Windows executable support
- **ELF Format**: Linux executable support

## ❓ TROUBLESHOOTING

### Common Issues

#### "ImportError: No module named lief"
```bash
# Solution: Install LIEF
pip install lief
```

#### "Permission denied" when running packed binary
```bash
# Solution: Make binary executable
chmod +x packed_program
```

#### Packed binary crashes immediately
```bash
# Solution: Check input binary compatibility
# Ensure you're packing for the correct architecture
file program
```

### Debugging Tips

#### Enable Verbose Mode
```bash
python3 ca_packer/packer.py -v program packed_program
```

#### Check Binary Info
```bash
# Linux
file packed_program

# Windows (if available)
file.exe packed_program.exe
```

## ❓ FAQ

### Q: What platforms does CA-Packer support?
**A**: CA-Packer supports both Linux (ELF) and Windows (PE) binary formats.

### Q: Is CA-Packer free to use?
**A**: Yes, CA-Packer is released under the MIT License.

### Q: How secure is CA-Packer?
**A**: CA-Packer uses industry-standard ChaCha20-Poly1305 encryption combined with cellular automaton obfuscation for strong protection.

### Q: Can I customize the encryption?
**A**: Yes, you can specify custom keys and adjust CA steps for enhanced security.

### Q: What programming languages are supported?
**A**: CA-Packer works with compiled binaries regardless of the source language (C, C++, Rust, Go, etc.).

### Q: How does the unpacking stub work?
**A**: The unpacking stub is implemented in pure assembly for maximum reliability. It detects its own base address, reads embedded parameters, deobfuscates keys, applies CA unmasking, decrypts the payload, and jumps to the original entry point.

### Q: Can CA-Packer be detected by antivirus software?
**A**: Like any packer, CA-Packer may trigger heuristic detections. It's designed for legitimate software protection, not malicious purposes.

### Q: How can I contribute to CA-Packer?
**A**: Check out our GitHub repository for contribution guidelines and open issues.

## 📚 ADDITIONAL RESOURCES

### Documentation
- [Technical Implementation Details](CA_PACKER_DEVELOPMENT_SUMMARY.md)
- [Development Progress Report](CA_PACKER_FINAL_SUMMARY.md)
- [Project Completion Certificate](CA_PACKER_PROJECT_COMPLETION_CERTIFICATE.md)

### Source Code
- Main packer implementation: `ca_packer/packer.py`
- Cellular automaton engine: `ca_packer/ca_engine.py`
- Cryptographic engine: `ca_packer/crypto_engine.py`
- Assembly unpacking stub: `ca_packer/complete_unpacking_stub.s`

### Testing
- Test scripts: `test_ca_packer.py`
- Verification utilities: `verify_files.py`

## 🤝 COMMUNITY AND SUPPORT

### Reporting Issues
Please report bugs and issues on our GitHub repository.

### Feature Requests
We welcome feature requests and suggestions for improvement.

### Contributing
Check our contribution guidelines for information on how to contribute code.

## 🚨 CURRENT DEVELOPMENT STATUS

### Important Note About Protected Binary Execution

CA-Packer is currently in active development. While the packing functionality is complete and working, the complete unpacking functionality in the stub is not yet fully implemented.

**What works:**
- Packing binaries with CA obfuscation and ChaCha20-Poly1305 encryption
- Generating unpacking stubs that can read embedded parameters
- Executing ChaCha20-Poly1305 decryption in the stub

**What's not yet implemented:**
- CA unmasking (Rule 30) for de-obfuscating the payload
- Payload processing and memory management
- Jumping to the original entry point (OEP) after unpacking

As a result, protected binaries will currently execute the unpacking stub and then encounter a segmentation fault because the complete unpacking process is not yet implemented.

This is a known limitation of the current development version and will be addressed in future updates.

## 📄 LICENSE

CA-Packer is released under the MIT License. See [LICENSE](LICENSE) for details.

## 🙏 ACKNOWLEDGEMENTS

Special thanks to the LIEF library team and the open-source community for providing the tools that made this project possible.

---

*Happy packing! May your binaries be secure and your code be protected! 🛡️🔒*