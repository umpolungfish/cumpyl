#!/usr/bin/env python3
"""
Main Packer Module for the CA-Packer project.
This module orchestrates the packing process:
1. Loading the target binary.
2. Performing initial analysis (entropy, structure).
3. Preparing the payload (compression, encryption, segmentation).
4. Applying CA-based masking.
5. Generating the stub/loader.
6. Integrating the payload and stub into the final binary using LIEF.
"""

import logging
import os
import subprocess
import sys
import lief

# --- Dynamic Path Resolution ---
# This ensures that the script can be run from any directory and still find its modules.
try:
    # For relative imports when used as a module
    from . import ca_engine
    from . import crypto_engine
except (ImportError, ModuleNotFoundError):
    # For running as a script. This makes packer.py work standalone.
    _script_dir = os.path.dirname(os.path.abspath(__file__))
    if _script_dir not in sys.path:
        sys.path.insert(0, _script_dir)

    # Now that the path is set, we can import siblings directly
    import ca_engine
    import crypto_engine

# Make functions available for convenience, aliasing to match original code
generate_mask = ca_engine.generate_mask
encrypt_payload = crypto_engine.encrypt_payload
# TODO: Import other necessary modules (e.g., for compression, binary analysis, integration)

# --- Configuration (Could be moved to a config file later) ---
DEFAULT_BLOCK_SIZE = 32  # 256 bits, matching the CA mask size
# The offset of the parameter_area in the stub, determined by the size of the initial jump.
# We now use a RIP-relative LEA instruction to make the jump position-independent,
# and we initialize %r8 with the address of the parameter area.
STUB_PARAMETER_OFFSET = 0x12  # 7 bytes for `lea parameter_area(%rip), %r8` + 2 bytes for padding + 3 bytes for parameter_area label
# Parameter offsets within the parameter area
PAYLOAD_RVA_OFFSET_IN_PARAMS = 0x30  # Offset of payload RVA in parameter area
PAYLOAD_SIZE_OFFSET_IN_PARAMS = 0x38  # Offset of payload size in parameter area
STUB_RVA_OFFSET_IN_PARAMS = 0x40  # Offset of stub RVA in parameter area
# TODO: Add configuration for compression, CA steps, etc.
# -----------------------------

def load_target_binary(filepath):
    """
    Loads the target binary using LIEF for analysis and modification.
    """
    logging.info(f"Loading target binary: {filepath}")
    try:
        # Determine binary format and parse
        binary = lief.parse(filepath)
        if binary is None:
            raise ValueError(f"Could not parse {filepath} as a valid binary.")
        logging.debug(f"Binary loaded. Format: {binary.format}")
        return binary
    except Exception as e:
        logging.error(f"Failed to load binary {filepath}: {e}")
        raise

def analyze_binary(binary):
    """
    Performs initial analysis on the loaded binary.
    - Identifies key sections.
    - OEP is no longer needed as the stub uses fexecve to let the kernel handle loading.
    """
    logging.info("Performing initial binary analysis...")
    
    sections = [s.name for s in binary.sections]
    
    # OEP is no longer needed as we use memfd_create and fexecve in the stub.
    # The original OEP from the header will be used by the kernel's loader.
    
    # Placeholder for analysis results
    analysis_results = {
        "sections": sections,
        # Add more details as needed
    }
    logging.debug(f"Analysis results: {analysis_results}")
    return analysis_results

def prepare_payload(binary_path):
    """
    Prepares the raw binary data for packing.
    1. (Optional) Compresses the data.
    2. Encrypts the (compressed) data using the core cipher.
    3. Segments the encrypted data into fixed-size blocks.
    Returns the list of encrypted blocks, encryption metadata (key, nonce),
    and the original size of the payload before padding.
    """
    logging.info("Preparing payload...")
    
    # --- Extract Raw Payload Data ---
    # This is a more accurate way to get the raw bytes of the binary file.
    try:
        with open(binary_path, "rb") as f:
            binary_data = f.read()
        logging.debug(f"Read raw binary data. Size: {len(binary_data)} bytes")
    except Exception as e:
        logging.error(f"Failed to read raw binary data from {binary_path}: {e}")
        raise

    # TODO: Implement compression logic if enabled.
    data_to_encrypt = binary_data # Placeholder
    original_size = len(data_to_encrypt)

    # --- Encryption ---
    encrypted_data, key, nonce = encrypt_payload(data_to_encrypt)
    logging.debug(f"Payload encrypted. Key length: {len(key)}, Nonce length: {len(nonce)}")

    # --- Segmentation ---
    blocks = [
        encrypted_data[i:i + DEFAULT_BLOCK_SIZE]
        for i in range(0, len(encrypted_data), DEFAULT_BLOCK_SIZE)
    ]
    # Handle last block padding if necessary
    if blocks and len(blocks[-1]) < DEFAULT_BLOCK_SIZE:
         # Simple zero-padding for now. Consider PKCS7 or storing original length.
         blocks[-1] = blocks[-1].ljust(DEFAULT_BLOCK_SIZE, b'\x00')
         logging.debug("Last block padded.")

    logging.info(f"Payload prepared into {len(blocks)} blocks. Original size: {original_size} bytes.")
    return blocks, key, nonce, original_size

def apply_ca_masking(blocks, key, nonce):
    """
    Applies the CA-based masking to each encrypted block.
    1. For each block, generate a unique mask using the CA engine.
    2. XOR the block with its mask.
    3. Aggregate the masked blocks.
    Returns the final obfuscated payload P' and a list of block lengths (if needed for unpadded last block).
    """
    logging.info("Applying CA-based masking...")
    obfuscated_blocks = []
    # Store lengths to handle potential padding removal during unpacking if needed
    block_lengths = [len(block) for block in blocks]

    for i, block in enumerate(blocks):
        # Ensure block is the correct size
        if len(block) != DEFAULT_BLOCK_SIZE:
             logging.warning(f"Block {i} is not {DEFAULT_BLOCK_SIZE} bytes. Padding/Truncating.")
             block = block.ljust(DEFAULT_BLOCK_SIZE, b'\x00')[:DEFAULT_BLOCK_SIZE]

        # --- CA Mask Generation ---
        mask = generate_mask(key, i, DEFAULT_BLOCK_SIZE)
        # logging.debug(f"Generated mask for block {i}") # Very verbose

        # --- Apply Mask ---
        obfuscated_block = bytes(a ^ b for a, b in zip(block, mask))
        obfuscated_blocks.append(obfuscated_block)

    # Aggregate into final payload P'
    final_payload = b''.join(obfuscated_blocks)
    logging.info("CA masking applied.")
    return final_payload, block_lengths

def generate_stub_mvp(key, nonce, ca_params, block_lengths, payload_size, binary_format, debug_stub=False):
    """
    Generates the MVP stub by compiling the C code and patching parameters.
    """
    logging.info("Generating MVP stub from C source...")
    
    # 1. Compile the stub C code to a binary blob
    if binary_format == lief.Binary.FORMATS.PE:
        # Use the complete unpacking stub for PE binaries too
        stub_source_path = os.path.join(os.path.dirname(__file__), "complete_unpacking_stub.s")
        stub_type = "pe"
        compile_script = os.path.join(os.path.dirname(__file__), "compile_complete_unpacking_stub.py")
        compiled_stub_path = os.path.join(os.path.dirname(__file__), "complete_unpacking_stub_compiled.bin")
    else:  # ELF
        # Use the complete unpacking stub
        stub_source_path = os.path.join(os.path.dirname(__file__), "complete_unpacking_stub.s")
        stub_type = "elf"
        compile_script = os.path.join(os.path.dirname(__file__), "compile_complete_unpacking_stub.py")
        compiled_stub_path = os.path.join(os.path.dirname(__file__), "complete_unpacking_stub_compiled.bin")

    # Run the compilation script to ensure the stub is up-to-date
    compilation_command = [sys.executable, compile_script]
    if not debug_stub:
        compilation_command.append("--release")

    logging.info(f"Running stub compilation script: {' '.join(compilation_command)}")
    try:
        result = subprocess.run(
            compilation_command,
            capture_output=True, text=True, check=True
        )
        logging.debug(f"Stub compilation stdout: {result.stdout}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to compile stub using {compile_script}.")
        logging.error(f"Return code: {e.returncode}")
        logging.error(f"Stdout: {e.stdout}")
        logging.error(f"Stderr: {e.stderr}")
        raise RuntimeError("Stub compilation failed.")
    except FileNotFoundError:
        logging.error(f"Compilation script not found at {compile_script}")
        raise

    # Read the compiled binary blob
    try:
        with open(compiled_stub_path, 'rb') as f:
            stub_data = bytearray(f.read())
        logging.debug(f"Read compiled stub blob. Size: {len(stub_data)} bytes")
        if not stub_data:
            raise RuntimeError("Compiled stub is empty. Compilation likely failed to produce executable code.")
        # Log the first few bytes of the stub data
        if len(stub_data) >= 16:
            logging.debug(f"First 16 bytes of stub data: {stub_data[:16].hex()}")
            
        # Log some bytes from the parameter area to verify it's correctly embedded
        param_offset = STUB_PARAMETER_OFFSET
        if len(stub_data) >= param_offset + 16:
            logging.debug(f"Parameter area bytes (offset {param_offset}): {stub_data[param_offset:param_offset+16].hex()}")
            
    except Exception as e:
        logging.error(f"Failed to read compiled stub blob: {e}")
        raise

    # Embed parameters into the stub data.

    # We will embed parameters at a fixed offset to avoid corrupting the code.
    # The offset is determined by the size of the initial jump instruction in the stub.
    STUB_PARAMETER_SIZE = 0x48  # 72 bytes for parameters (key, nonce, etc. + stub_rva)

    # Ensure there's enough space for parameters
    required_size = STUB_PARAMETER_OFFSET + STUB_PARAMETER_SIZE
    if len(stub_data) < required_size:
        stub_data.extend(b'\x00' * (required_size - len(stub_data)))
        logging.debug(f"Extended stub data to {len(stub_data)} bytes for parameters")
        
    # Log the offset where parameters will be embedded
    logging.debug(f"Embedding parameters at offset 0x{STUB_PARAMETER_OFFSET:x}")

    # Log the stub data before embedding parameters
    logging.debug("Stub data before parameter embedding:")
    for i in range(0, min(len(stub_data), 128), 16):
        logging.debug(f"  {i:04x}: {stub_data[i:i+16].hex()}")

    # Embed parameters into the stub data at the fixed offset
    # OEP is no longer needed. The parameter block starts with the key.

    # Key (32 bytes) - Simple XOR obfuscation
    FIXED_OBFUS_KEY = 0xCABEFEBEEFBEADDE # 64-bit value
    obfuscated_key_p1 = int.from_bytes(key[0:8], 'little') ^ FIXED_OBFUS_KEY
    obfuscated_key_p2 = int.from_bytes(key[8:16], 'little') ^ FIXED_OBFUS_KEY
    obfuscated_key_p3 = int.from_bytes(key[16:24], 'little') ^ FIXED_OBFUS_KEY
    obfuscated_key_p4 = int.from_bytes(key[24:32], 'little') ^ FIXED_OBFUS_KEY

    stub_data[STUB_PARAMETER_OFFSET + 0x00:STUB_PARAMETER_OFFSET + 0x08] = obfuscated_key_p1.to_bytes(8, 'little')
    stub_data[STUB_PARAMETER_OFFSET + 0x08:STUB_PARAMETER_OFFSET + 0x10] = obfuscated_key_p2.to_bytes(8, 'little')
    stub_data[STUB_PARAMETER_OFFSET + 0x10:STUB_PARAMETER_OFFSET + 0x18] = obfuscated_key_p3.to_bytes(8, 'little')
    stub_data[STUB_PARAMETER_OFFSET + 0x18:STUB_PARAMETER_OFFSET + 0x20] = obfuscated_key_p4.to_bytes(8, 'little')

    # Nonce (12 bytes)
    stub_data[STUB_PARAMETER_OFFSET + 0x20:STUB_PARAMETER_OFFSET + 0x2C] = nonce

    # CA Steps (4 bytes, little-endian)
    # Use a fixed, reasonable number of CA steps to avoid performance issues
    ca_steps = 100  # Fixed to 100 steps
    stub_data[STUB_PARAMETER_OFFSET + 0x2C:STUB_PARAMETER_OFFSET + 0x30] = ca_steps.to_bytes(4, 'little')

    # Payload Section RVA (8 bytes, little-endian) - Placeholder
    payload_rva_placeholder = 0xDEADBEEFDEADBEEF
    stub_data[STUB_PARAMETER_OFFSET + PAYLOAD_RVA_OFFSET_IN_PARAMS:STUB_PARAMETER_OFFSET + PAYLOAD_RVA_OFFSET_IN_PARAMS + 8] = payload_rva_placeholder.to_bytes(8, 'little')
    logging.debug(f"Embedded payload RVA placeholder: 0x{payload_rva_placeholder:x}")

    # Payload Size (8 bytes, little-endian)
    payload_size_bytes = payload_size.to_bytes(8, 'little')
    stub_data[STUB_PARAMETER_OFFSET + PAYLOAD_SIZE_OFFSET_IN_PARAMS:STUB_PARAMETER_OFFSET + PAYLOAD_SIZE_OFFSET_IN_PARAMS + 8] = payload_size_bytes
    logging.debug(f"Embedded payload size: 0x{payload_size:x} as bytes: {payload_size_bytes.hex()}")

    # Stub RVA (8 bytes, little-endian) - Placeholder
    stub_rva_placeholder = 0xCAFEBABEDEADBEEF
    stub_data[STUB_PARAMETER_OFFSET + STUB_RVA_OFFSET_IN_PARAMS:STUB_PARAMETER_OFFSET + STUB_RVA_OFFSET_IN_PARAMS + 8] = stub_rva_placeholder.to_bytes(8, 'little')
    logging.debug(f"Embedded stub RVA placeholder: 0x{stub_rva_placeholder:x}")
    
    logging.info("MVP stub generated with embedded parameters.")
    
    # Log the parameter area after embedding to verify it's correctly embedded
    param_offset = STUB_PARAMETER_OFFSET
    if len(stub_data) >= param_offset + 16:
        logging.debug(f"Parameter area bytes after embedding: {stub_data[param_offset:param_offset+16].hex()}")
        
    # Log the stub RVA bytes specifically
    stub_rva_offset = param_offset + 0x40
    if len(stub_data) >= stub_rva_offset + 8:
        logging.debug(f"Stub RVA bytes after embedding: {stub_data[stub_rva_offset:stub_rva_offset+8].hex()}")
        
    # Log the stub data after embedding parameters
    logging.debug("Stub data after parameter embedding:")
    for i in range(0, min(len(stub_data), 128), 16):
        logging.debug(f"  {i:04x}: {stub_data[i:i+16].hex()}")
    
    logging.info("MVP stub generated with embedded parameters.")
    
    # Log the parameter area after embedding to verify it's correctly embedded
    param_offset = STUB_PARAMETER_OFFSET
    if len(stub_data) >= param_offset + 16:
        logging.debug(f"Parameter area bytes after embedding: {stub_data[param_offset:param_offset+16].hex()}")
        
    # Log the stub RVA bytes specifically
    stub_rva_offset = param_offset + 0x40
    if len(stub_data) >= stub_rva_offset + 8:
        logging.debug(f"Stub RVA bytes after embedding: {stub_data[stub_rva_offset:stub_rva_offset+8].hex()}")
        
    # Log the stub data after embedding parameters
    logging.debug("Stub data after parameter embedding:")
    for i in range(0, min(len(stub_data), 128), 16):
        logging.debug(f"  {i:04x}: {stub_data[i:i+16].hex()}")
        
    return bytes(stub_data)

def integrate_packed_binary(original_binary_path, original_binary, stub_data, obfuscated_payload, payload_size, output_path):
    """
    Integrates the stub and obfuscated payload into the original binary using LIEF.
    1. Creates new sections for stub and payload.
    2. Writes stub and payload data into sections.
    3. Updates the entry point to point to the stub.
    4. Saves the modified binary.
    """
    logging.info("Integrating packed elements into binary...")
    try:
        # Check binary format
        if original_binary.format == lief.Binary.FORMATS.PE:
            # --- Add Sections ---
            # Note: Section names might need to be <= 8 characters for PE
            
            # Add Stub Section
            # Note: Section names might need to be <= 8 characters for PE
            
            # Add Stub Section
            stub_section = lief.PE.Section(".stub")
            stub_section.content = list(stub_data) # LIEF expects a list of ints
            # Add common characteristics for executable code/data
            stub_section.characteristics = (
                lief.PE.Section.CHARACTERISTICS.MEM_READ |
                lief.PE.Section.CHARACTERISTICS.MEM_WRITE |
                lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE |
                lief.PE.Section.CHARACTERISTICS.CNT_CODE
            )
            stub_section = original_binary.add_section(stub_section)

            # Add Payload Section
            payload_section = lief.PE.Section(".cpload") # CA Packed Payload
            payload_section.content = list(obfuscated_payload)
            # Characteristics for data
            payload_section.characteristics = (
                lief.PE.Section.CHARACTERISTICS.MEM_READ |
                lief.PE.Section.CHARACTERISTICS.CNT_INITIALIZED_DATA
            )
            payload_section = original_binary.add_section(payload_section)

            # --- Patch Payload RVA into Stub ---
            payload_rva = payload_section.virtual_address
            logging.debug(f"Payload section virtual address: 0x{payload_rva:x} ({payload_rva} decimal)")
            logging.debug(f"Payload section virtual address type: {type(payload_rva)}")
            logging.debug(f"Payload section virtual address repr: {repr(payload_rva)}")
            
            # Check if the payload_rva is actually an integer
            if not isinstance(payload_rva, int):
                logging.error(f"Payload section virtual address is not an integer: {type(payload_rva)}")
                raise TypeError("Payload section virtual address is not an integer")
            
            # Check the value of payload_rva
            if payload_rva != 0x1005000:
                logging.warning(f"Payload section virtual address is not 0x1005000: 0x{payload_rva:x}")
                
            real_rva_bytes = payload_rva.to_bytes(8, 'little')
            logging.debug(f"Payload RVA bytes: {real_rva_bytes.hex()}")
            logging.debug(f"Payload RVA bytes length: {len(real_rva_bytes)}")
            # Convert back to verify
            converted_back = int.from_bytes(real_rva_bytes, 'little')
            logging.debug(f"Converted back: 0x{converted_back:x} ({converted_back} decimal)")
            logging.debug(f"Match: {payload_rva == converted_back}")
            
            expected_rva_bytes = (0x1005000).to_bytes(8, 'little')
            logging.debug(f"Expected payload RVA bytes: {expected_rva_bytes.hex()}")
            
            # Create a mutable copy of the stub content for patching
            stub_content_mutable = bytearray(stub_section.content)
            
            # Patch Payload RVA
            patch_offset = STUB_PARAMETER_OFFSET + PAYLOAD_RVA_OFFSET_IN_PARAMS
            logging.debug(f"Patch offset for payload RVA: 0x{patch_offset:x}")
            
            logging.debug(f"Original bytes at payload RVA patch offset: {bytes(stub_content_mutable[patch_offset:patch_offset + 8]).hex()}")
            stub_content_mutable[patch_offset:patch_offset + 8] = real_rva_bytes
            logging.debug(f"Patched bytes at payload RVA patch offset: {bytes(stub_content_mutable[patch_offset:patch_offset + 8]).hex()}")
            logging.debug(f"Patched payload RVA 0x{payload_rva:x} into stub at offset {patch_offset}")
            
            # --- Patch Payload Size into Stub ---
            payload_size_bytes = payload_size.to_bytes(8, 'little')
            patch_offset = STUB_PARAMETER_OFFSET + PAYLOAD_SIZE_OFFSET_IN_PARAMS
            logging.debug(f"Original bytes at payload size patch offset: {bytes(stub_content_mutable[patch_offset:patch_offset + 8]).hex()}")
            stub_content_mutable[patch_offset:patch_offset + 8] = payload_size_bytes
            logging.debug(f"Patched bytes at payload size patch offset: {bytes(stub_content_mutable[patch_offset:patch_offset + 8]).hex()}")
            logging.debug(f"Patched payload size 0x{payload_size:x} into stub at offset {patch_offset}")
            
            # --- Patch Stub RVA into Stub ---
            stub_rva = stub_section.virtual_address
            patch_offset = STUB_PARAMETER_OFFSET + STUB_RVA_OFFSET_IN_PARAMS
            logging.debug(f"Original bytes at stub RVA patch offset: {bytes(stub_content_mutable[patch_offset:patch_offset + 8]).hex()}")
            stub_content_mutable[patch_offset:patch_offset + 8] = stub_rva.to_bytes(8, 'little')
            logging.debug(f"Patched bytes at stub RVA patch offset: {bytes(stub_content_mutable[patch_offset:patch_offset + 8]).hex()}")
            logging.debug(f"Patched stub RVA 0x{stub_rva:x} into stub at offset {patch_offset}")

            # Re-assign the patched content
            stub_section.content = list(stub_content_mutable)

            # --- Update Entry Point ---
            # Get the relative virtual address (RVA) of the stub section's content
            new_ep_rva = stub_section.virtual_address # RVA relative to ImageBase
            original_binary.optional_header.addressof_entrypoint = new_ep_rva

            logging.debug(f"New entry point set to RVA: 0x{new_ep_rva:x}")
            logging.debug(f"Stub section RVA: 0x{stub_section.virtual_address:x}")
            logging.debug(f"Payload section RVA: 0x{payload_section.virtual_address:x}")

            # --- Save Binary ---
            # LIEF builder is recommended for final output to ensure headers are correct
            builder = lief.PE.Builder(original_binary)
            builder.build() # This finalizes the build process
            builder.write(output_path)
            
        elif original_binary.format == lief.Binary.FORMATS.ELF:
            # --- Add Sections ---
            
            # Add Stub Section
            stub_section = lief.ELF.Section(".stub")
            stub_section.content = list(stub_data)
            # Set section flags for executable and writable code
            stub_section.flags = (
                lief.ELF.Section.FLAGS.ALLOC |
                lief.ELF.Section.FLAGS.WRITE |
                lief.ELF.Section.FLAGS.EXECINSTR
            )
            stub_section.alignment = 0x1000  # Page alignment
            stub_section = original_binary.add(stub_section)

            # LIEF might place the stub in a read-only segment. We must find the segment
            # and explicitly make it writable to allow for in-place key deobfuscation.
            stub_segment = original_binary.segment_from_virtual_address(stub_section.virtual_address)
            if stub_segment:
                stub_segment.flags |= lief.ELF.Segment.FLAGS.W
                logging.debug(f"Ensured stub segment has WRITE flag. New flags: {stub_segment.flags}")
            else:
                # This should not happen, but we'll log a warning if it does.
                logging.warning("Could not find segment for stub section to make it writable.")

            # Add Payload Section
            payload_section = lief.ELF.Section(".cpload")
            payload_section.content = list(obfuscated_payload)
            # Set section flags and alignment for data
            payload_section.flags = (
                lief.ELF.Section.FLAGS.ALLOC |
                lief.ELF.Section.FLAGS.WRITE
            )
            payload_section.alignment = 0x1000  # Page alignment
            payload_section = original_binary.add(payload_section)

            # Ensure the segment containing the payload is also writable for in-place decryption.
            payload_segment = original_binary.segment_from_virtual_address(payload_section.virtual_address)
            if payload_segment:
                payload_segment.flags |= lief.ELF.Segment.FLAGS.W | lief.ELF.Segment.FLAGS.R
                logging.debug(f"Ensured payload segment has WRITE and READ flags. New flags: {payload_segment.flags}")
            else:
                logging.warning("Could not find segment for payload section to make it writable and readable.")
            
            logging.debug(f"Added payload section. Virtual address: 0x{payload_section.virtual_address:x}")
            logging.debug(f"Payload section virtual address type: {type(payload_section.virtual_address)}")
            logging.debug(f"Payload section virtual address repr: {repr(payload_section.virtual_address)}")
            
            # Check if the virtual address is actually an integer
            if not isinstance(payload_section.virtual_address, int):
                logging.error(f"Payload section virtual address is not an integer: {type(payload_section.virtual_address)}")
                raise TypeError("Payload section virtual address is not an integer")
            
            # Check the value of the virtual address
            payload_rva = payload_section.virtual_address
            logging.debug(f"Payload section virtual address: 0x{payload_rva:x} ({payload_rva} decimal)")
            
            # Check if the virtual address is reasonable
            if payload_rva < 0x1000 or payload_rva > 0x10000000:
                logging.warning(f"Payload section virtual address seems unreasonable: 0x{payload_rva:x}")
                
            # Convert to bytes and check
            payload_rva_bytes = payload_rva.to_bytes(8, 'little')
            logging.debug(f"Payload RVA bytes: {payload_rva_bytes.hex()}")
            
            # Convert back and check
            converted_back = int.from_bytes(payload_rva_bytes, 'little')
            logging.debug(f"Converted back: 0x{converted_back:x} ({converted_back} decimal)")
            logging.debug(f"Match: {payload_rva == converted_back}")
            
            # Check if the bytes are reasonable
            if converted_back != payload_rva:
                logging.error(f"Conversion mismatch: 0x{payload_rva:x} != 0x{converted_back:x}")
                raise ValueError("Conversion mismatch")
                
            # Check if the bytes represent a reasonable address
            if converted_back < 0x1000 or converted_back > 0x10000000:
                logging.warning(f"Converted payload RVA seems unreasonable: 0x{converted_back:x}")
            
            # --- Patch Parameters into Stub ---
            # Create a mutable copy of the stub content for patching
            stub_content_mutable = bytearray(stub_section.content)
            
            # Verify the size of the stub content
            logging.debug(f"Stub content size: {len(stub_content_mutable)}")
            
            # Verify that we have enough space for parameters
            required_size = STUB_PARAMETER_OFFSET + 0x48  # 0x48 is the size of the parameter area
            if len(stub_content_mutable) < required_size:
                logging.error(f"Stub content is too small. Required: {required_size}, Actual: {len(stub_content_mutable)}")
                raise ValueError("Stub content is too small for parameters")
            
            # Log the bytes at the parameter area before patching
            param_start = STUB_PARAMETER_OFFSET
            param_end = param_start + 0x48
            if len(stub_content_mutable) >= param_end:
                logging.debug(f"Parameter area before patching: {stub_content_mutable[param_start:param_end].hex()}")
            
            # Patch Payload RVA
            patch_offset = STUB_PARAMETER_OFFSET + PAYLOAD_RVA_OFFSET_IN_PARAMS
            logging.debug(f"Patch offset for payload RVA: 0x{patch_offset:x}")
            
            if patch_offset + 8 <= len(stub_content_mutable):
                logging.debug(f"Original bytes at payload RVA patch offset: {bytes(stub_content_mutable[patch_offset:patch_offset + 8]).hex()}")
                stub_content_mutable[patch_offset:patch_offset + 8] = payload_rva_bytes
                logging.debug(f"Patched bytes at payload RVA patch offset: {bytes(stub_content_mutable[patch_offset:patch_offset + 8]).hex()}")
                logging.debug(f"Patched payload RVA 0x{payload_rva:x} into stub at offset {patch_offset}")
            else:
                logging.error(f"Not enough space to patch payload RVA. Content size: {len(stub_content_mutable)}, Patch offset: {patch_offset}")
                raise ValueError("Not enough space to patch payload RVA")
            
            # Patch Payload Size
            payload_size_bytes = payload_size.to_bytes(8, 'little')
            patch_offset = STUB_PARAMETER_OFFSET + PAYLOAD_SIZE_OFFSET_IN_PARAMS
            logging.debug(f"Original bytes at payload size patch offset: {bytes(stub_content_mutable[patch_offset:patch_offset + 8]).hex()}")
            stub_content_mutable[patch_offset:patch_offset + 8] = payload_size_bytes
            logging.debug(f"Patched bytes at payload size patch offset: {bytes(stub_content_mutable[patch_offset:patch_offset + 8]).hex()}")
            logging.debug(f"Patched payload size 0x{payload_size:x} into stub at offset {patch_offset}")
            
            # Patch Stub RVA
            stub_rva = stub_section.virtual_address
            patch_offset = STUB_PARAMETER_OFFSET + STUB_RVA_OFFSET_IN_PARAMS
            logging.debug(f"Original bytes at stub RVA patch offset: {bytes(stub_content_mutable[patch_offset:patch_offset + 8]).hex()}")
            stub_content_mutable[patch_offset:patch_offset + 8] = stub_rva.to_bytes(8, 'little')
            logging.debug(f"Patched bytes at stub RVA patch offset: {bytes(stub_content_mutable[patch_offset:patch_offset + 8]).hex()}")
            logging.debug(f"Patched stub RVA 0x{stub_rva:x} into stub at offset {patch_offset}")

            # Re-assign the patched content
            stub_section.content = list(stub_content_mutable)
            
            # --- Update Entry Point ---
            # The stub's entry point (_start symbol) is at the beginning of the stub section
            new_ep_rva = stub_section.virtual_address
            original_binary.header.entrypoint = new_ep_rva
            
            logging.debug(f"New entry point set to RVA: 0x{new_ep_rva:x}")
            logging.debug(f"Stub section RVA: 0x{stub_section.virtual_address:x}")
            logging.debug(f"Payload section RVA: 0x{payload_section.virtual_address:x}")

            # --- Save Binary ---
            builder = lief.ELF.Builder(original_binary)
            builder.build()
            builder.write(output_path)

        else:
            raise ValueError(f"Unsupported binary format: {original_binary.format}")

        logging.info(f"Packed binary saved to: {output_path}")

    except Exception as e:
        logging.error(f"Failed to integrate packed binary: {e}")
        raise

def pack_binary(input_path, output_path, debug_stub=False):
    """
    Main function to pack a binary.
    Orchestrates the entire packing workflow.
    """
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

    logging.info("=== CA-BASED PACKER START ===")
    logging.info(f"Input: {input_path} -> Output: {output_path}")

    # 1. Load
    binary = load_target_binary(input_path)

    # 2. Analyze
    analysis_results = analyze_binary(binary)

    # 3. Prepare Payload (using the file path for accurate data extraction)
    blocks, key, nonce, original_payload_size = prepare_payload(input_path)

    # 4. CA Masking
    ca_params = {} # Placeholder for CA parameters (rule, steps, etc. if needed in stub)
    obfuscated_payload, block_lengths = apply_ca_masking(blocks, key, nonce)

    # 5. Generate Stub (MVP)
    # The stub is generated with a placeholder for the payload RVA.
    # The correct RVA will be patched in during the integration step.
    stub_data = generate_stub_mvp(key, nonce, ca_params, block_lengths, original_payload_size, binary.format, debug_stub=debug_stub)

    # 6. Integrate
    integrate_packed_binary(input_path, binary, stub_data, obfuscated_payload, original_payload_size, output_path)

    logging.info("=== CA-BASED PACKER END ===")


if __name__ == "__main__":
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description="CA-Packer: A binary packer using Cellular Automata for obfuscation")
    parser.add_argument("input_binary", help="Path to the input binary to pack")
    parser.add_argument("output_packed_binary", help="Path where the packed binary will be saved")
    parser.add_argument("--ca-steps", type=int, default=100, help="Number of CA steps to use for mask generation (default: 100)")
    parser.add_argument("--debug-stub", action="store_true", help="Compile the unpacking stub in debug mode (with verbose output).")
    
    args = parser.parse_args()
    
    input_file = args.input_binary
    output_file = args.output_packed_binary
    
    # Update the CA steps in the ca_engine module
    ca_engine.NUM_STEPS = args.ca_steps
    
    # Debug output to verify the value was updated
    print(f"INFO: CA Steps set to: {ca_engine.NUM_STEPS}")
    
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)

    try:
        pack_binary(input_file, output_file, debug_stub=args.debug_stub)
        print(f"Binary packed successfully: {output_file} (CA steps: {args.ca_steps}, Debug Stub: {args.debug_stub})")
    except Exception as e:
        print(f"Error during packing: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
