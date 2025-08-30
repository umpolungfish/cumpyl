# 🛠 CA-PACKER TROUBLESHOOTING GUIDE

## 🚨 OH NO! SOMETHING BROKE?

Don't panic! This guide helps you solve the most common CA-Packer issues quickly.

## 📋 QUICK REFERENCE

| Problem | Solution | Time |
|---------|----------|------|
| "ImportError: No module named lief" | `pip install lief` | 30 sec |
| Packed program crashes | Check architecture match | 1 min |
| "Permission denied" | `chmod +x packed_program` | 10 sec |
| Slow packing | Reduce CA steps | Instant |
| Large file size | Normal for first version | N/A |

## 🎯 COMMON ISSUES & SOLUTIONS

### ❌ "ImportError: No module named lief"

**Problem**: Missing LIEF library dependency.

**Solution**:
```bash
# Install LIEF
pip install lief

# Or install all requirements
pip install -r requirements.txt

# Verify installation
python3 -c "import lief; print('LIEF OK')"
```

### ❌ "Permission denied" when running packed binary

**Problem**: Packed binary doesn't have execute permissions.

**Solution**:
```bash
# Linux/macOS
chmod +x packed_program
./packed_program

# Windows (Command Prompt)
packed_program.exe

# Windows (PowerShell)
.\packed_program.exe
```

### ❌ Packed binary crashes immediately

**Problem**: Architecture mismatch or corrupted binary.

**Solution**:
```bash
# Check file information
file program
file packed_program

# Ensure architecture matches
# Example output:
# program: ELF 64-bit LSB executable, x86-64
# packed_program: ELF 64-bit LSB executable, x86-64

# If architectures don't match, recompile your source
gcc -m64 program.c -o program  # Force 64-bit
gcc -m32 program.c -o program  # Force 32-bit
```

### ❌ "Segmentation fault" when running packed binary

**Problem**: Unpacking stub issue or incomplete implementation.

**Solution**:
```bash
# Enable verbose mode for debugging
python3 ca_packer/packer.py -v program packed_program

# Check if original binary works
./program

# Try with a simple test program first
echo 'int main(){return 42;}' > test.c
gcc test.c -o test
python3 ca_packer/packer.py test test_packed
./test_packed

# Note: Segmentation faults are expected with the current development version
# as the full unpacking functionality has not been implemented yet.
# The stub correctly reads parameters and executes decryption but does not
# yet implement the complete unpacking process (CA unmasking, payload processing,
# and jumping to OEP).
```

### ❌ Packing takes too long

**Problem**: High number of CA steps (default: 100).

**Solution**:
```bash
# Reduce CA steps for faster packing
python3 ca_packer/packer.py --ca-steps 50 program packed_program

# For development, use minimal steps
python3 ca_packer/packer.py --ca-steps 10 program packed_program
```

### ❌ Packed binary is very large

**Problem**: First version includes debugging info.

**Solution**:
```bash
# This is normal for development version
# Future releases will optimize size

# For now, check approximate size increase
ls -lh program packed_program
```

### ❌ "No such file or directory" errors

**Problem**: Incorrect file paths.

**Solution**:
```bash
# Check current directory
pwd

# List files
ls -la

# Use absolute paths if needed
python3 /full/path/to/ca_packer/packer.py /full/path/to/program /full/path/to/packed_program

# Or navigate to correct directory
cd /path/to/ca_packer
python3 packer.py program packed_program
```

## 🔍 DEBUGGING COMMANDS

### Enable Verbose Output
```bash
# Get detailed packing information
python3 ca_packer/packer.py -v program packed_program
```

### Check Binary Information
```bash
# Linux
file program
readelf -h program  # For ELF files
objdump -h program   # For detailed section info

# Windows (if available)
file.exe program.exe
```

### Test with Simple Program
```bash
# Create minimal test
echo 'int main(){return 42;}' > test.c
gcc test.c -o test

# Pack and test
python3 ca_packer/packer.py test test_packed
./test_packed
echo $?  # Should print 42
```

### Debug Assembly Stub
```bash
# Check if stub compiles
cd ca_packer
python3 compile_complete_unpacking_stub.py

# Check compiled stub
ls -la complete_unpacking_stub_compiled.bin
```

## 🐛 ADVANCED DEBUGGING

### Enable LIEF Debugging
```bash
# Set LIEF logging level
export LIEF_LOG_LEVEL=DEBUG
python3 ca_packer/packer.py program packed_program
```

### Check Python Environment
```bash
# Verify Python version
python3 --version

# Check installed packages
pip list | grep -E "(lief|numpy)"

# Check Python path
python3 -c "import sys; print(sys.path)"
```

### Memory Debugging
```bash
# Run with memory checking (Linux)
valgrind ./packed_program

# Check for memory leaks
valgrind --leak-check=full ./packed_program
```

## 🆘 STILL NEED HELP?

### 1. Check Documentation
```bash
# Read main documentation
cat README.md

# Check technical details
cat CA_PACKER_DEVELOPMENT_SUMMARY.md
```

### 2. Run Test Suite
```bash
# Run basic tests
python3 test_ca_packer.py

# Run complete packer tests
python3 ca_packer/test_complete_packer.py
```

### 3. Create Issue Report
If you're still stuck, create a detailed issue report:

```markdown
**Issue**: [Brief description]
**Environment**: [OS, Python version, Architecture]
**Steps to Reproduce**:
1. [Step 1]
2. [Step 2]
3. [Step 3]

**Expected Result**: [What should happen]
**Actual Result**: [What actually happens]
**Error Messages**: [Copy-paste exact errors]
**Files Used**: [List any relevant files]
```

### 4. Community Support
- Check GitHub Issues
- Join Discord/Slack community
- Contact maintainers

## 🎯 PRO TIPS

### Speed Up Development
```bash
# Use minimal CA steps during development
python3 ca_packer/packer.py --ca-steps 5 program packed_program

# Skip encryption for testing (NOT FOR PRODUCTION)
# (Future feature)

# Use verbose mode for debugging
python3 ca_packer/packer.py -v program packed_program
```

### Verify Protection Works
```bash
# Original should be readable
strings program | grep "some_unique_string"

# Protected should hide strings
strings packed_program | grep "some_unique_string"

# They should be different!
```

### Batch Processing
```bash
# Pack multiple programs
for prog in *.out; do
    python3 ca_packer/packer.py "$prog" "${prog%.out}_packed"
done
```

## 🆗 EMERGENCY RESET

If nothing works, start fresh:

```bash
# Remove everything
cd ..
rm -rf ca-packer

# Re-clone
git clone <repository_url>
cd ca-packer

# Re-install
pip install -r requirements.txt

# Test with simple program
echo 'int main(){return 0;}' > test.c
gcc test.c -o test
python3 packer.py test test_packed
./test_packed
```

## 🎉 SUCCESS INDICATORS

You know CA-Packer is working when:

✅ **Packing completes without errors**
✅ **Packed binary has execute permissions**
✅ **Packed binary runs without crashing**
✅ **Packed binary produces same output as original**
✅ **File size is reasonable (slightly larger than original)**

## 🚀 TROUBLESHOOTING CHECKLIST

Before asking for help, check:

- [ ] Python 3.7+ installed (`python3 --version`)
- [ ] LIEF installed (`pip list | grep lief`)
- [ ] Correct file paths
- [ ] Matching architectures
- [ ] Execute permissions set
- [ ] Simple test program works
- [ ] Verbose output enabled (`-v` flag)
- [ ] Latest version of CA-Packer

## 🙋 NEED MORE HELP?

Contact us at:
- **GitHub Issues**: [Repository]/issues
- **Email**: support@ca-packer.org
- **Community**: Discord.gg/capacker

---

*Remember: Every expert was once a beginner. You've got this! 💪*