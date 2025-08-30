#!/usr/bin/env python3
"""
Test script to create a minimal binary with our stub code
"""

import lief
import subprocess
import os

def test_minimal_binary():
    # Compile our simple exit stub
    current_dir = os.path.dirname(os.path.abspath(__file__))
    stub_source = os.path.join(current_dir, "ca_packer", "minimal_exit_stub_simple.c")
    stub_obj = os.path.join(current_dir, "ca_packer", "minimal_exit_stub_simple.o")
    stub_elf = os.path.join(current_dir, "ca_packer", "minimal_exit_stub_simple.elf")
    stub_blob = os.path.join(current_dir, "ca_packer", "minimal_exit_stub_simple_compiled.bin")
    
    # Compile to object file
    compile_cmd = [
        "gcc",
        "-c",
        "-ffreestanding",
        "-fno-stack-protector",
        "-fno-exceptions",
        "-fno-asynchronous-unwind-tables",
        "-Os",
        "-m64",
        stub_source,
        "-o", stub_obj
    ]
    subprocess.run(compile_cmd, check=True)
    
    # Link to create a full ELF binary
    link_cmd = [
        "ld",
        "-o", stub_elf,
        stub_obj
    ]
    subprocess.run(link_cmd, check=True)
    
    # Extract raw binary from .text section
    objcopy_cmd = [
        "objcopy",
        "-O", "binary",
        "--only-section=.text",
        stub_elf,
        stub_blob
    ]
    subprocess.run(objcopy_cmd, check=True)
    
    # Read the stub blob
    with open(stub_blob, 'rb') as f:
        stub_data = f.read()
    
    print(f"Stub data size: {len(stub_data)} bytes")
    print(f"Stub data: {stub_data.hex()}")
    
    # Create a minimal ELF binary
    # We'll create a new binary from scratch
    binary = lief.ELF.Binary("test_minimal_binary", lief.ELF.ARCH.X86_64)
    
    # Set as executable
    binary.header.file_type = lief.ELF.Header.FILE_TYPE.EXEC
    
    # Add a code section with our stub
    code_section = lief.ELF.Section(".text")
    code_section.content = list(stub_data)
    code_section.flags = (
        lief.ELF.Section.FLAGS.ALLOC |
        lief.ELF.Section.FLAGS.EXECINSTR
    )
    code_section = binary.add_section(code_section, loaded=True)
    
    # Set entry point
    binary.header.entrypoint = code_section.virtual_address
    
    # Save binary
    builder = lief.ELF.Builder(binary)
    builder.build()
    builder.write("test_minimal_binary")
    
    # Make it executable
    os.chmod("test_minimal_binary", 0o755)
    
    print("Created test_minimal_binary")

if __name__ == "__main__":
    test_minimal_binary()