#!/usr/bin/env python3
"""
Compilation script for the complete unpacking stub.
Uses the C Preprocessor (gcc -E) to allow for conditional compilation
of debug messages.
"""

import subprocess
import sys
import os
import argparse

def main():
    parser = argparse.ArgumentParser(description="Compiler for the complete unpacking stub.")
    parser.add_argument("--release", action="store_true", help="Enable release mode (removes debug messages).")
    args = parser.parse_args()

    # Get the directory of this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Define paths
    stub_source = os.path.join(script_dir, "complete_unpacking_stub.s")
    preprocessed_stub_source = os.path.join(script_dir, "complete_unpacking_stub.preprocessed.s")
    stub_object = os.path.join(script_dir, "complete_unpacking_stub.o")
    stub_elf = os.path.join(script_dir, "complete_unpacking_stub.elf")
    stub_binary = os.path.join(script_dir, "complete_unpacking_stub_compiled.bin")
    linker_script = os.path.join(script_dir, "stub_linker.ld")
    
    # Check if source files exist
    if not os.path.exists(stub_source):
        print(f"Error: Source file {stub_source} not found.")
        return 1

    if not os.path.exists(linker_script):
        print(f"Error: Linker script {linker_script} not found.")
        return 1

    # C preprocessor command
    cpp_command = ["gcc", "-E", "-P", "-nostdinc"]
    if args.release:
        print("Compiling in RELEASE mode (debug messages disabled).")
        cpp_command.append("-DRELEASE=1")
    else:
        print("Compiling in DEBUG mode (debug messages enabled).")
        cpp_command.append("-DDEBUG=1")
    
    cpp_command.append(stub_source)

    # Preprocess the stub by capturing stdout and writing to file
    try:
        result = subprocess.run(cpp_command, capture_output=True, text=True, check=True)
        with open(preprocessed_stub_source, "w") as f:
            f.write(result.stdout)
    except (subprocess.CalledProcessError, IOError) as e:
        print("Error: Failed to preprocess stub.")
        if isinstance(e, subprocess.CalledProcessError):
            print(f"Command: {' '.join(e.cmd)}")
            print(f"Stderr: {e.stderr}")
        else:
            print(f"IOError: {e}")
        return 1
        
    # Compile the preprocessed stub
    print("Compiling complete unpacking stub...")
    try:
        # Use gcc to assemble, as it's more robust than calling 'as' directly.
        # -fPIC is crucial for generating position-independent code,
        # which is necessary for the final -pie linking.
        result = subprocess.run([
            "gcc", "-fPIC", "-c", "-o", stub_object, preprocessed_stub_source
        ], capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        print("Error: Failed to compile stub.")
        print(f"Command: {' '.join(e.cmd)}")
        print(f"Stderr: {e.stderr}")
        # Cleanup if preprocess succeeded but this failed
        if os.path.exists(preprocessed_stub_source):
            os.remove(preprocessed_stub_source)
        return 1
    
    # Link the objects to create an ELF executable
    print("Linking objects to create ELF executable...")
    try:
        # We use a custom linker script to ensure the sections are correctly
        # laid out and not discarded by the linker. Using gcc to drive the
        # linker is often more robust than calling ld directly, as it can
        # supply necessary default flags. We use -nostdlib to prevent linking
        # against any standard libraries, creating a minimal stub.
        # -pie creates a position-independent executable, essential for ASLR.
        result = subprocess.run([
            "gcc", "-nostdlib", "-pie", "-T", linker_script, "-o", stub_elf, stub_object
        ], capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        print("Error: Failed to link objects.")
        print(f"Command: {' '.join(e.cmd)}")
        print(f"Stderr: {e.stderr}")
        os.remove(preprocessed_stub_source)
        os.remove(stub_object)
        return 1
    
    # Extract the raw binary data by converting the entire ELF file into a flat binary.
    # This is the most reliable way to get a memory image of the executable segments.
    # It correctly handles layout, alignment, and padding between sections.
    print("Extracting raw binary data...")
    try:
        subprocess.run(
            ["objcopy", "-O", "binary", stub_elf, stub_binary],
            capture_output=True, text=True, check=True
        )
    except subprocess.CalledProcessError as e:
        print("Error: Failed to extract raw binary data.")
        print(f"Command: {' '.join(e.cmd)}")
        print(f"Stderr: {e.stderr}")
        # Cleanup
        if os.path.exists(preprocessed_stub_source): os.remove(preprocessed_stub_source)
        if os.path.exists(stub_object): os.remove(stub_object)
        return 1
    
    # Clean up intermediate files
    os.remove(preprocessed_stub_source)
    os.remove(stub_object)
    
    print(f"Successfully compiled complete unpacking stub: {stub_binary}")
    print(f"ELF executable (for debugging): {stub_elf}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
