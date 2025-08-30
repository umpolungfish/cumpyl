#!/usr/bin/env python3
import lief
import sys

# Load the binary
binary = lief.parse(sys.argv[1])
print(f"Binary format: {binary.format}")

# Check if it's an ELF binary
if binary.format == lief.Binary.FORMATS.ELF:
    # Print available attributes in lief.ELF
    print("\nELF module attributes:")
    elf_attrs = [attr for attr in dir(lief.ELF) if not attr.startswith('_')]
    for attr in elf_attrs:
        print(f"  {attr}")
        
    # Check Section class
    print("\nELF Section attributes:")
    section_attrs = [attr for attr in dir(lief.ELF.Section) if not attr.startswith('_')]
    for attr in section_attrs:
        print(f"  {attr}")