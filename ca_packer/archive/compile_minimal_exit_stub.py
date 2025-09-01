#!/usr/bin/env python3
"""
Compilation script for the minimal exit stub
"""

import os
import subprocess
import logging
import sys

def compile_minimal_exit_stub():
    """Compile the minimal exit stub"""
    logging.basicConfig(level=logging.DEBUG)
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    stub_source = os.path.join(current_dir, "minimal_exit_stub.c")
    stub_obj = os.path.join(current_dir, "minimal_exit_stub.o")
    stub_elf = os.path.join(current_dir, "minimal_exit_stub.elf")
    stub_blob = os.path.join(current_dir, "minimal_exit_stub_compiled.bin")
    
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
            
        # Link to create a full ELF binary
        link_cmd = [
            "ld",
            "-o", stub_elf,
            stub_obj
        ]
        logging.debug(f"Link command: {' '.join(link_cmd)}")
        result = subprocess.run(link_cmd, check=True, capture_output=True, text=True)
        if result.stderr:
            logging.warning(f"Linker stderr: {result.stderr}")
            
        # Extract raw binary from .text section
        objcopy_cmd = [
            "objcopy",
            "-O", "binary",
            "--only-section=.text",
            stub_elf,
            stub_blob
        ]
        logging.debug(f"Objcopy command: {' '.join(objcopy_cmd)}")
        result = subprocess.run(objcopy_cmd, check=True, capture_output=True, text=True)
        if result.stderr:
            logging.warning(f"Objcopy stderr: {result.stderr}")
            
        logging.info(f"Minimal exit stub compiled successfully to blob: {stub_blob}")
        print(f"Minimal exit stub blob created at: {stub_blob}")
        
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
    compile_minimal_exit_stub()