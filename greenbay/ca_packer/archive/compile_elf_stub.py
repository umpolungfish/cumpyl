#!/usr/bin/env python3
"""
Compilation script for the ELF stub
"""

import os
import subprocess
import logging
import sys

def compile_elf_stub():
    """Compile the ELF stub"""
    logging.basicConfig(level=logging.DEBUG)
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    stub_source = os.path.join(current_dir, "stub_elf.c")
    stub_obj = os.path.join(current_dir, "stub_elf.o")
    stub_blob = os.path.join(current_dir, "elf_stub_compiled.bin")
    
    try:
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
        logging.debug(f"Compile command: {' '.join(compile_cmd)}")
        result = subprocess.run(compile_cmd, check=True, capture_output=True, text=True)
        if result.stderr:
            logging.warning(f"Compiler stderr: {result.stderr}")
            
        # Extract raw binary from .text section
        objcopy_cmd = [
            "objcopy",
            "-O", "binary",
            "--only-section=.text",
            stub_obj,
            stub_blob
        ]
        logging.debug(f"Objcopy command: {' '.join(objcopy_cmd)}")
        result = subprocess.run(objcopy_cmd, check=True, capture_output=True, text=True)
        if result.stderr:
            logging.warning(f"Objcopy stderr: {result.stderr}")
            
        logging.info(f"ELF stub compiled successfully to blob: {stub_blob}")
        print(f"ELF stub blob created at: {stub_blob}")
        
    except subprocess.CalledProcessError as e:
        logging.error(f"Stub compilation failed: {e}")
        logging.error(f"Command: {e.cmd}")
        logging.error(f"Stdout: {e.stdout}")
        logging.error(f"Stderr: {e.stderr}")
        raise
    except Exception as e:
        logging.error(f"An error occurred during stub compilation: {e}")
        raise

if __name__ == "__main__":
    compile_elf_stub()