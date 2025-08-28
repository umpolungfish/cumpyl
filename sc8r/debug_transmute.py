#!/usr/bin/env python3
"""
Simple debug script to identify transmutation issues 🔍
"""

import sys
import traceback
from pathlib import Path

print("🔍 DEBUG: Starting transmutation debug script...")

# Check Python version
print(f"🐍 Python version: {sys.version}")

# Check if we can import basic modules
try:
    import json
    import yaml
    print("✅ Basic imports (json, yaml) working")
except ImportError as e:
    print(f"❌ Basic import failed: {e}")
    sys.exit(1)

# Try to import our transmutation module
print("\n🔍 Attempting to import payload_transmute module...")
try:
    sys.path.insert(0, str(Path(__file__).parent))
    from payload_transmute import PayloadTransmuter, TransmuteConfig, TransmuteMethod
    print("✅ Successfully imported transmutation modules")
except Exception as e:
    print(f"❌ Failed to import transmutation modules: {e}")
    traceback.print_exc()
    sys.exit(1)

# Test basic configuration
print("\n🔍 Testing basic configuration...")
try:
    config = TransmuteConfig()
    print("✅ Configuration created successfully")
    print(f"   Default method: {config.default_method}")
    print(f"   Output format: {config.output_format}")
except Exception as e:
    print(f"❌ Configuration failed: {e}")
    traceback.print_exc()

# Test transmuter creation
print("\n🔍 Testing transmuter creation...")
try:
    transmuter = PayloadTransmuter(config, verbose=False)
    print("✅ Transmuter created successfully")
except Exception as e:
    print(f"❌ Transmuter creation failed: {e}")
    traceback.print_exc()
    sys.exit(1)

# Test simple null padding (safest method)
print("\n🔍 Testing null padding encoding...")
try:
    test_payload = "test"
    result = transmuter._null_padding(test_payload)
    print(f"✅ Null padding successful: '{test_payload}' -> '{result}'")
except Exception as e:
    print(f"❌ Null padding failed: {e}")
    traceback.print_exc()

# Test hex encoding
print("\n🔍 Testing hex encoding...")
try:
    result = transmuter._hex_encode("test")
    print(f"✅ Hex encoding successful: 'test' -> '{result}'")
except Exception as e:
    print(f"❌ Hex encoding failed: {e}")
    traceback.print_exc()

# Test unicode encoding
print("\n🔍 Testing unicode encoding...")
try:
    result = transmuter._unicode_encode("test")
    print(f"✅ Unicode encoding successful: 'test' -> '{result}'")
except Exception as e:
    print(f"❌ Unicode encoding failed: {e}")
    traceback.print_exc()

# Test main transmute method with simple payload
print("\n🔍 Testing main transmute method...")
try:
    result = transmuter.transmute("test", TransmuteMethod.NULL_PADDING)
    print(f"✅ Main transmute successful: 'test' -> '{result}'")
except Exception as e:
    print(f"❌ Main transmute failed: {e}")
    traceback.print_exc()

# Test mixed encoding (the problematic one)
print("\n🔍 Testing mixed encoding...")
try:
    result = transmuter.transmute("test", TransmuteMethod.MIXED)
    print(f"✅ Mixed encoding successful!")
    print(f"   Generated {len(result)} variants:")
    for method, encoded in result.items():
        print(f"     {method}: {encoded}")
except Exception as e:
    print(f"❌ Mixed encoding failed: {e}")
    traceback.print_exc()

# Test with verbose output
print("\n🔍 Testing verbose output...")
try:
    verbose_transmuter = PayloadTransmuter(config, verbose=True)
    result = verbose_transmuter.transmute("test", TransmuteMethod.HEX)
    print("✅ Verbose output test completed")
except Exception as e:
    print(f"❌ Verbose output failed: {e}")
    traceback.print_exc()

print("\n🎯 Debug completed! If you see this message, basic functionality is working.")
print("💡 Try running: python payload_transmute.py -p 'test' -m hex -v")
