#!/usr/bin/env python3
"""
Module to compile the C stub and convert it to a binary blob for embedding.
This script handles the compilation and extraction process.
"""

import os
import subprocess
import logging

def compile_stub_to_blob(stub_c_path, output_blob_path, is_elf=False):
    """
    Compiles a C stub to an object file and then extracts the raw binary.

    Args:
        stub_c_path (str): Path to the stub C source file.
        output_blob_path (str): Path where the raw binary blob will be saved.
        is_elf (bool): Whether to compile for ELF (Linux) or PE (Windows).
    """
    logging.info(f"Compiling stub: {stub_c_path}")
    dir_name = os.path.dirname(stub_c_path)
    base_name = os.path.splitext(os.path.basename(stub_c_path))[0]
    stub_obj = os.path.join(dir_name, f"{base_name}.o")
    ca_engine_obj = os.path.join(dir_name, "ca_engine_stub.o")
    chacha20_obj = os.path.join(dir_name, "chacha20poly1305.o")
    linked_obj = os.path.join(dir_name, f"{base_name}_linked.o")
    #exe_file = os.path.join(dir_name, f"{base_name}.exe") # Not needed for blob

    # Determine which compiler and tools to use
    if is_elf:
        compiler = "gcc"
        linker = "ld"
        objcopy = "objcopy"
    else:
        compiler = "x86_64-w64-mingw32-gcc"
        linker = "x86_64-w64-mingw32-ld"
        objcopy = "x86_64-w64-mingw32-objcopy"

    try:
        # 1. Compile stub to object file (.o)
        compile_stub_cmd = [
            compiler,
            "-c", # Compile only, no linking
            "-ffreestanding", # Implies -fno-builtin and more, good for stubs
            "-fno-stack-protector", # Remove stack protection overhead
            "-fno-exceptions", # No C++ exceptions
            "-fno-asynchronous-unwind-tables", # Reduce size
            "-Os", # Optimize for size
            "-m64", # 64-bit
            stub_c_path,
            "-o", stub_obj
        ]
        logging.debug(f"Compile stub command: {' '.join(compile_stub_cmd)}")
        result = subprocess.run(compile_stub_cmd, check=True, capture_output=True, text=True)
        if result.stderr:
            logging.warning(f"Stub compiler stderr: {result.stderr}")

        # 2. Compile CA engine to object file (.o)
        compile_ca_cmd = [
            compiler,
            "-c", # Compile only, no linking
            "-ffreestanding", # Implies -fno-builtin and more, good for stubs
            "-fno-stack-protector", # Remove stack protection overhead
            "-fno-exceptions", # No C++ exceptions
            "-fno-asynchronous-unwind-tables", # Reduce size
            "-Os", # Optimize for size
            "-m64", # 64-bit
            os.path.join(dir_name, "ca_engine_stub.c"),
            "-o", ca_engine_obj
        ]
        logging.debug(f"Compile CA engine command: {' '.join(compile_ca_cmd)}")
        result = subprocess.run(compile_ca_cmd, check=True, capture_output=True, text=True)
        if result.stderr:
            logging.warning(f"CA engine compiler stderr: {result.stderr}")

        # 3. Compile ChaCha20-Poly1305 to object file (.o)
        compile_chacha_cmd = [
            compiler,
            "-c", # Compile only, no linking
            "-ffreestanding", # Implies -fno-builtin and more, good for stubs
            "-fno-stack-protector", # Remove stack protection overhead
            "-fno-exceptions", # No C++ exceptions
            "-fno-asynchronous-unwind-tables", # Reduce size
            "-Os", # Optimize for size
            "-m64", # 64-bit
            os.path.join(dir_name, "chacha20poly1305.c"),
            "-o", chacha20_obj
        ]
        logging.debug(f"Compile ChaCha20 command: {' '.join(compile_chacha_cmd)}")
        result = subprocess.run(compile_chacha_cmd, check=True, capture_output=True, text=True)
        if result.stderr:
            logging.warning(f"ChaCha20 compiler stderr: {result.stderr}")

        # 4. Link all object files
        link_cmd = [
            linker,
            "-r", # Relocatable object
            stub_obj,
            ca_engine_obj,
            chacha20_obj,
            "-o", linked_obj
        ]
        logging.debug(f"Link command: {' '.join(link_cmd)}")
        result = subprocess.run(link_cmd, check=True, capture_output=True, text=True)
        if result.stderr:
            logging.warning(f"Linker stderr: {result.stderr}")

        # 5. Extract raw binary (.bin) from linked object file
        objcopy_cmd = [
            objcopy,
            "-O", "binary", # Output format
            "--only-section=.text", # Only extract .text section
            linked_obj,
            output_blob_path
        ]
        logging.debug(f"Objcopy command: {' '.join(objcopy_cmd)}")
        result = subprocess.run(objcopy_cmd, check=True, capture_output=True, text=True)
        if result.stderr:
            logging.warning(f"Objcopy stderr: {result.stderr}")

        logging.info(f"Stub compiled successfully to blob: {output_blob_path}")

        # 6. (Optional) Clean up intermediate .o files
        # os.remove(stub_obj)
        # os.remove(ca_engine_obj)
        # os.remove(chacha20_obj)
        # os.remove(linked_obj)

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
    # Example usage
    logging.basicConfig(level=logging.DEBUG)
    
    # These paths would be relative to the script's location or absolute
    # For this example, we assume the script is in `greenbay/ca_packer/`
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Check if we're compiling for PE or ELF
    import sys
    is_elf = False
    if len(sys.argv) > 1 and sys.argv[1] == "elf":
        stub_source = os.path.join(current_dir, "stub_elf.c")
        stub_blob_output = os.path.join(current_dir, "elf_stub_compiled.bin")
        is_elf = True
    else:
        stub_source = os.path.join(current_dir, "stub_mvp.c")
        stub_blob_output = os.path.join(current_dir, "pe_stub_compiled.bin")

    if not os.path.exists(stub_source):
        logging.error(f"Stub source file not found: {stub_source}")
    else:
        try:
            compile_stub_to_blob(stub_source, stub_blob_output, is_elf)
            print(f"Stub blob created at: {stub_blob_output}")
        except Exception as e:
            print(f"Error: {e}")