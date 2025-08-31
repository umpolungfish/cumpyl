#!/usr/bin/env python3
import lief

# Check what's available in lief.ELF.Section
print("LIEF version:", lief.__version__)
print("\nELF.Section attributes:")
for attr in dir(lief.ELF.Section):
    if not attr.startswith('_'):
        print(f"  {attr}")

print("\nTrying to access FLAGS:")
try:
    print("lief.ELF.Section.FLAGS:", hasattr(lief.ELF.Section, 'FLAGS'))
    if hasattr(lief.ELF.Section, 'FLAGS'):
        print("FLAGS attributes:")
        for attr in dir(lief.ELF.Section.FLAGS):
            if not attr.startswith('_'):
                print(f"  {attr}")
except Exception as e:
    print(f"Error: {e}")

print("\nTrying to access EXECINSTR directly:")
try:
    # Check if we can access the EXECINSTR flag directly
    print("lief.ELF.Section.FLAGS.EXECINSTR:", hasattr(lief.ELF.Section.FLAGS, 'EXECINSTR'))
    if hasattr(lief.ELF.Section.FLAGS, 'EXECINSTR'):
        execinstr = lief.ELF.Section.FLAGS.EXECINSTR
        print("EXECINSTR:", execinstr)
        print("EXECINSTR value:", getattr(execinstr, 'value', 'No value attribute'))
except Exception as e:
    print(f"Error accessing EXECINSTR: {e}")