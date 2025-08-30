#!/usr/bin/env python3
import lief
import sys

# Load the binary
binary = lief.parse(sys.argv[1])
print(f"Binary format: {binary.format}")

# Print available methods
methods = [method for method in dir(binary) if not method.startswith('_')]
print("Available methods:")
for method in methods:
    print(f"  {method}")

# Check if it's an ELF binary
if binary.format == lief.Binary.FORMATS.ELF:
    print("\nELF-specific attributes:")
    elf_methods = [method for method in dir(binary) if not method.startswith('_')]
    for method in elf_methods:
        print(f"  {method}")