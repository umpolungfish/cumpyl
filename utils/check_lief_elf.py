#!/usr/bin/env python3
import lief
import sys

# Check what's available in lief.ELF
print("LIEF version:", lief.__version__)
print("\nELF attributes:")
for attr in dir(lief.ELF):
    if not attr.startswith('_'):
        print(f"  {attr}")

print("\nTrying to access SECTION_FLAGS:")
try:
    print("lief.ELF.SECTION_FLAGS:", hasattr(lief.ELF, 'SECTION_FLAGS'))
except Exception as e:
    print(f"Error: {e}")

print("\nTrying to access sections attributes:")
try:
    # Create a simple ELF binary to check section attributes
    elf = lief.ELF.parse("/home/developer/cumpyl/greenbay/ca_packer/archive/minimal_exit_stub.elf")
    if elf and elf.sections:
        section = elf.sections[0]
        print("Section attributes:")
        for attr in dir(section):
            if not attr.startswith('_'):
                print(f"  {attr}")
        print("Section flags attribute:", hasattr(section, 'flags'))
except Exception as e:
    print(f"Error accessing ELF sections: {e}")