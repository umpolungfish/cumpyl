#!/usr/bin/env python3
import lief
import sys

# Load the binary
binary = lief.parse(sys.argv[1])
print(f"Binary format: {binary.format}")

# Check if it's an ELF binary
if binary.format == lief.Binary.FORMATS.ELF:
    # Print available methods in the binary object
    print("\nBinary object methods:")
    binary_methods = [attr for attr in dir(binary) if not attr.startswith('_')]
    for method in binary_methods:
        print(f"  {method}")
        
    # Check if add_section method exists
    if hasattr(binary, 'add_section'):
        print("\nadd_section method exists")
    else:
        print("\nadd_section method does not exist")
        
    # Check if there's an 'add' method
    if hasattr(binary, 'add'):
        print("add method exists")
    else:
        print("add method does not exist")
        
    # Check if sections attribute has any methods
    print("\nSections attribute methods:")
    sections_methods = [attr for attr in dir(binary.sections) if not attr.startswith('_')]
    for method in sections_methods:
        print(f"  {method}")