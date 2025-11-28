# PE String Obfuscator V3 - Quick Start Guide

**Get functional string obfuscation in 5 minutes!**

---

## Prerequisites

### Required

```bash
# Install Cumpyl framework (if not already installed)
cd cumpyl
pip install -e .

# OR with uv (recommended)
uv sync
source .venv/bin/activate
```

### Optional (but recommended)

```bash
# Install Capstone for better code analysis
pip install capstone

# Without Capstone, fallback pattern matching is used
```

---

## Quick Start

### Step 1: Prepare a Test Binary

```bash
# Create simple test program
cat > test.c << 'EOF'
#include <stdio.h>

int main() {
    const char *msg1 = "Hello, World!";
    const char *msg2 = "SECRET_PASSWORD";
    const char *msg3 = "http://example.com";

    printf("%s\n", msg1);
    printf("%s\n", msg2);
    printf("%s\n", msg3);

    return 0;
}
EOF

# Compile (32-bit for best compatibility)
gcc -o test.exe test.c -m32 -O0

# Test original
./test.exe
# Output:
# Hello, World!
# SECRET_PASSWORD
# http://example.com

# Check strings are visible
strings test.exe | grep SECRET
# Output: SECRET_PASSWORD
```

---

### Step 2: Configure V3 Plugin

Create or edit `cumpyl.yaml`:

```yaml
plugins:
  # V3 Configuration
  pe_string_obfuscation_v3:
    enabled_methods:
      - xor          # Fully implemented
      - rot13        # Fully implemented
      - reverse      # Fully implemented
    patch_references: true
    validate_after_transform: true
```

---

### Step 3: Run Analysis

```bash
# First, analyze the binary to see what strings exist
cumpyl test.exe --run-analysis --report-format json --report-output analysis.json

# Check analysis report
cat analysis.json | grep -A 5 "pe_string_obfuscation"
```

You should see strings detected:
```json
{
  "strings": [
    {"value": "Hello, World!", "section": ".rdata", ...},
    {"value": "SECRET_PASSWORD", "section": ".rdata", ...},
    {"value": "http://example.com", "section": ".rdata", ...}
  ]
}
```

---

### Step 4: Apply V3 Obfuscation

**Method A: Via CLI (Recommended)**

```bash
# Apply functional obfuscation with V3
python -c "
from cumpyl_package.cumpyl import BinaryRewriter
from cumpyl_package.config import get_config

config = get_config()
rewriter = BinaryRewriter('test.exe', config)
rewriter.load_binary()
rewriter.load_plugins()

# Run analysis
analysis = rewriter.run_plugin_analysis()

# Get V3 plugin
from plugins.pe_string_obfuscation_v3 import get_plugin
v3_plugin = get_plugin(config)

# Apply transformation
success = v3_plugin.transform(rewriter, analysis)

if success:
    rewriter.save_binary('test_obfuscated.exe')
    print('[+] Obfuscation complete!')
else:
    print('[-] Obfuscation failed')
"
```

**Method B: Via Build-a-Binary Menu** (if integrated)

```bash
cumpyl

# Navigate:
# [1] Build-a-Binary
# Select test.exe
# [7] PE String Obfuscation
# [7] Apply V3 Functional Obfuscation
```

---

### Step 5: Verify Functional Binary

```bash
# 1. Test execution (MOST IMPORTANT)
./test_obfuscated.exe

# Expected output (should be IDENTICAL to original):
# Hello, World!
# SECRET_PASSWORD
# http://example.com

# 2. Verify strings are obfuscated
strings test_obfuscated.exe | grep SECRET
# Expected: (no output - string is obfuscated!)

# 3. Check for new sections
objdump -h test_obfuscated.exe | grep -E '\.stub|\.xdata'
# Expected:
#   .stub    (deobfuscation code)
#   .xdata   (decryption keys)

# 4. Disassemble to see stub calls
objdump -d test_obfuscated.exe | grep -A 5 -B 5 "call.*stub"
# Should see: call instructions to .stub section
```

---

## Understanding the Output

### Console Output

```
[+] Starting Functional String Obfuscation V3...
[*] Enabled methods: xor, rot13, reverse

[+] Selected 3 strings for obfuscation

[*] Step 1/5: Injecting deobfuscation stubs...
[+] Created .stub section at RVA: 0x00450000
[+] Created .xdata section at RVA: 0x00460000
[+] Injected XOR stub at RVA: 0x00450000
[+] Injected ROT13 stub at RVA: 0x00450200
[+] Injected REVERSE stub at RVA: 0x00450300
[+] Successfully injected stubs

[*] Step 2/5: Analyzing code for string references...
[+] Found 6 code references to strings
    - Patchable: 6
    - Unpatchable: 0

[*] Step 3/5: Obfuscating strings and storing keys...
    [+] Obfuscated: Hello, World!
    [+] Obfuscated: SECRET_PASSWORD
    [+] Obfuscated: http://example.com
[+] Obfuscated 3 strings

[*] Step 4/5: Patching code references...
[+] Patched 6 code references

[*] Step 5/5: Finalizing stub injection...
[+] Stub injection finalized:
  - 3 stubs injected
  - 3 keys stored
  - .stub section at RVA 0x00450000
  - .xdata section at RVA 0x00460000

[*] Validating transformed binary...
[+] Binary validation passed

[+] ✓ Functional string obfuscation complete!
[+] Binary should now execute correctly with obfuscated strings
```

### New PE Sections

```bash
# Use PE viewer to inspect
objdump -h test_obfuscated.exe

# New sections:
Sections:
Idx Name          Size      VMA       LMA       File off  Algn
...
  6 .stub         00002000  00450000  00450000  00050000  2**12
                  CONTENTS, ALLOC, LOAD, READONLY, CODE
  7 .xdata        00001000  00460000  00460000  00052000  2**12
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
```

**`.stub` Section:**
- 8KB executable section
- Contains deobfuscation routines
- Called by patched code references

**`.xdata` Section:**
- 4KB read-only data section
- Contains decryption keys and metadata
- Accessed by deobfuscation stubs

---

## Troubleshooting

### Issue: "Binary crashes after obfuscation"

**Possible Causes:**
1. Capstone not installed (using less reliable pattern matching)
2. Complex reference types not detected
3. Binary has anti-debugging or integrity checks

**Solutions:**
```bash
# 1. Install Capstone
pip install capstone

# 2. Check analysis report for unpatchable references
python -c "
from cumpyl_package.cumpyl import BinaryRewriter
from cumpyl_package.code_analyzer import CodeAnalyzer

rewriter = BinaryRewriter('test.exe', None)
rewriter.load_binary()

analyzer = CodeAnalyzer(rewriter.binary)
analyzer.register_strings([...])  # Add string RVAs
analyzer.analyze_code_sections()

report = analyzer.generate_reference_report()
print(f'Unpatchable: {report[\"unpatchable_count\"]}')
"

# 3. Use debugger to find crash location
gdb test_obfuscated.exe
> run
> bt  # backtrace when it crashes
```

---

### Issue: "Strings still visible with strings command"

**Possible Causes:**
1. Only some strings were obfuscated (by design)
2. Strings deobfuscated during analysis tools

**Check:**
```bash
# See which strings were actually obfuscated
python -c "
# Load analysis results and check selected strings
"

# V3 limits to 50 strings by default
# Check configuration to increase
```

---

### Issue: "Obfuscation takes too long"

**Possible Causes:**
1. Large binary with many code sections
2. Capstone disassembly is thorough but slow

**Solutions:**
```bash
# Reduce number of strings
# In cumpyl.yaml:
plugins:
  pe_string_obfuscation_v3:
    max_strings_per_session: 20  # Default is 50

# Or disable code analysis (risky)
plugins:
  pe_string_obfuscation_v3:
    patch_references: false  # Not recommended!
```

---

### Issue: "ImportError: No module named 'capstone'"

**Solution:**
```bash
# Install Capstone
pip install capstone

# Or let framework use fallback
# (Less reliable but works)
```

---

## Advanced Usage

### Custom Method Selection

```python
# In Python script
from plugins.pe_string_obfuscation_v3 import PEStringObfuscationV3Plugin

class MyCustomV3(PEStringObfuscationV3Plugin):
    def _select_method_for_string(self, string_info):
        # Custom logic
        if 'password' in string_info['value'].lower():
            return 'xor'  # Always XOR passwords
        elif len(string_info['value']) < 10:
            return 'reverse'
        else:
            return 'rot13'
```

### Selective String Obfuscation

```python
# Only obfuscate specific strings
def _select_strings_for_obfuscation(self, analysis_result):
    pe_analysis = analysis_result['pe_string_obfuscation']
    all_strings = pe_analysis.get('strings', [])

    # Filter
    selected = [
        s for s in all_strings
        if 'password' in s['value'].lower()
        or 'secret' in s['value'].lower()
        or 'http://' in s['value'].lower()
    ]

    return selected[:10]  # Limit to 10
```

### Debug Mode

```python
# Enable detailed logging
import logging
logging.basicConfig(level=logging.DEBUG)

# Run obfuscation
# Will print detailed debug info about:
# - Stub injection offsets
# - Reference detection
# - Patch applications
```

---

## Testing Checklist

- [ ] Original binary executes correctly
- [ ] Obfuscated binary executes with SAME output
- [ ] `strings` command doesn't show obfuscated strings
- [ ] `.stub` and `.xdata` sections present
- [ ] File size increased by ~12KB (8KB stub + 4KB xdata)
- [ ] No crashes or errors during execution
- [ ] Code references properly patched (use disassembler)

---

## Next Steps

### Learn More

- **Architecture:** Read `STRING_OBFUSCATOR_V3_ARCHITECTURE.md`
- **Review:** See original analysis in `STRING_OBFUSCATOR_REVIEW.md`
- **Menu:** Try Build-a-Binary menu integration

### Contribute

- Implement Base64 decoder stub (currently placeholder)
- Add AES-CBC support
- Improve x64 support (currently limited)
- Add thread-safety to stubs
- Create comprehensive test suite

---

## Summary

✅ **V3 produces functional obfuscated binaries!**
✅ **Strings are hidden from static analysis**
✅ **Runtime deobfuscation is automatic and transparent**
✅ **No manual intervention needed**

**Before:**
```bash
strings binary.exe | grep password
# Output: my_secret_password
```

**After V3:**
```bash
strings binary_obfuscated.exe | grep password
# Output: (nothing!)

./binary_obfuscated.exe
# Still works perfectly!
```

---

**Happy Obfuscating! 🎉**

For issues or questions, check:
- `docs/STRING_OBFUSCATOR_V3_ARCHITECTURE.md`
- GitHub Issues: https://github.com/anthropics/cumpyl/issues
