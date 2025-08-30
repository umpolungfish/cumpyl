#!/usr/bin/env python3
"""
Test script to create a minimal static binary with our stub code
"""

import lief
import subprocess
import os

def test_minimal_static_binary():
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
    
    # Link to create a full static ELF binary without interpreter
    link_cmd = [
        "ld",
        "-o", stub_elf,
        "-static",  # Create a static binary
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
    # We'll start with a simple binary and modify it
    binary = lief.ELF.parse("test_binary.exe")
    
    # Remove the interpreter
    # Find and remove the interpreter segment
    segments_to_remove = []
    for segment in binary.segments:
        if segment.type == lief.ELF.SEGMENT_TYPES.INTERP:
            segments_to_remove.append(segment)
    
    for segment in segments_to_remove:
        binary.remove(segment)
    
    # Add stub section
    stub_section = lief.ELF.Section(".stub")
    stub_section.content = list(stub_data)
    stub_section.flags = (
        lief.ELF.Section.FLAGS.ALLOC |
        lief.ELF.Section.FLAGS.EXECINSTR
    )
    stub_section = binary.add(stub_section)
    
    # Update entry point
    new_ep_rva = stub_section.virtual_address
    binary.header.entrypoint = new_ep_rva
    print(f"New entry point: 0x{new_ep_rva:x}")
    
    # Change binary type to EXEC
    binary.header.file_type = lief.ELF.Header.FILE_TYPE.EXEC
    
    # Save binary
    builder = lief.ELF.Builder(binary)
    builder.build()
    builder.write("test_minimal_static_binary")
    
    # Make it executable
    os.chmod("test_minimal_static_binary", 0o755)
    
    print("Created test_minimal_static_binary")

if __name__ == "__main__":
    test_minimal_static_binary()