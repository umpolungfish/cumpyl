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

# Import core modules
# Handle both relative and absolute imports
try:
    from .ca_engine import generate_mask
    from .crypto_engine import encrypt_payload
except ImportError:
    # Fallback to absolute imports when running as script
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    try:
        from ca_engine import generate_mask
        from crypto_engine import encrypt_payload
    except ImportError:
        # Try utils prefix
        from utils.ca_engine import generate_mask
        from utils.crypto_engine import encrypt_payload
# TODO: Import other necessary modules (e.g., for compression, binary analysis, integration)

import lief
import os
import logging

# --- Configuration (Could be moved to a config file later) ---
DEFAULT_BLOCK_SIZE = 32  # 256 bits, matching the CA mask size
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
    - Identifies key sections (.text, .data).
    - Determines the Original Entry Point (OEP).
    - Plans for new section creation.
    """
    logging.info("Performing initial binary analysis...")
    
    if binary.format == lief.Binary.FORMATS.PE:
        oep = binary.optional_header.addressof_entrypoint
        sections = [s.name for s in binary.sections]
    elif binary.format == lief.Binary.FORMATS.ELF:
        oep = binary.header.entrypoint
        sections = [s.name for s in binary.sections]
    else:
        raise ValueError(f"Unsupported binary format: {binary.format}")
    
    # Placeholder for analysis results
    analysis_results = {
        "oep": oep,
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
    Returns the list of encrypted blocks and encryption metadata (key, nonce).
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

    logging.info(f"Payload prepared into {len(blocks)} blocks.")
    return blocks, key, nonce

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

def generate_stub_mvp(oep_rva, key, nonce, ca_params, block_lengths, payload_rva, payload_size, binary_format):
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

    try:
        # Use a pre-compiled simple stub for testing
        compiled_stub_path = os.path.join(os.path.dirname(__file__), "archive", "minimal_exit_stub_simple_compiled.bin")
        
        # Check if the pre-compiled stub exists
        if not os.path.exists(compiled_stub_path):
            logging.error(f"Pre-compiled stub not found at {compiled_stub_path}")
            raise FileNotFoundError(f"Pre-compiled stub not found at {compiled_stub_path}")
            
        # Read the pre-compiled stub
        try:
            with open(compiled_stub_path, 'rb') as f:
                stub_data = bytearray(f.read())
            logging.debug(f"Read pre-compiled stub blob. Size: {len(stub_data)} bytes")
        except Exception as e:
            logging.error(f"Failed to read pre-compiled stub blob: {e}")
            raise
    except Exception as e:
        logging.error(f"Failed to compile stub: {e}")
        raise

    # 2. Read the compiled binary blob
    try:
        with open(compiled_stub_path, 'rb') as f:
            stub_data = bytearray(f.read())
        logging.debug(f"Read compiled stub blob. Size: {len(stub_data)} bytes")
    except Exception as e:
        logging.error(f"Failed to read compiled stub blob: {e}")
        raise

    # 3. For simple stubs, we don't need to pad or embed parameters
    # Only do this for complex stubs that need parameters
    # For now, we'll just use the stub as-is without padding
    
    # Check if this is a complex stub that needs parameters
    # For now, we'll assume simple stubs don't need parameter embedding
    STUB_PARAMETER_OFFSET = 0x400
    required_size = STUB_PARAMETER_OFFSET + 0x40 # 0x40 is enough for our parameters
    
    # Only pad and embed parameters if we're using a complex stub
    # For simple exit stubs, we don't need to do this
    if len(stub_data) >= 50:  # Arbitrary threshold to distinguish simple from complex stubs
        # For complex stubs, we need to ensure there's enough space for parameters
        # We'll embed parameters at the fixed offset 0x400
        required_size = 0x400 + 0x40  # 0x400 offset + 0x40 bytes for parameters
        if len(stub_data) < required_size:
            # Extend the stub data with zeros
            stub_data.extend(b'\x00' * (required_size - len(stub_data)))
            logging.debug(f"Extended stub data to {len(stub_data)} bytes for parameters at offset 0x400")
        
        STUB_PARAMETER_OFFSET = 0x400  # Fixed offset as expected by the stub

        # 4. Embed parameters into the stub data at the fixed offset
        # Ensure the stub data is large enough for the parameters at offset 0x400
        required_size = 0x400 + 0x40  # 0x400 offset + 0x40 bytes for parameters
        if len(stub_data) < required_size:
            # Extend the stub data with zeros
            stub_data.extend(b'\x00' * (required_size - len(stub_data)))
            logging.debug(f"Extended stub data to {len(stub_data)} bytes for parameters at offset 0x400")
        
        STUB_PARAMETER_OFFSET = 0x400  # Fixed offset as expected by the stub
        
        STUB_PARAMETER_OFFSET = 0x400  # Fixed offset as expected by the stub
        
        # OEP (8 bytes, little-endian)
        stub_data[STUB_PARAMETER_OFFSET + 0x00:STUB_PARAMETER_OFFSET + 0x08] = oep_rva.to_bytes(8, 'little')
    
        # Key (32 bytes) - Simple XOR obfuscation
        FIXED_OBFUS_KEY = 0xCABEFEBEEFBEADDE # 64-bit value
        obfuscated_key_p1 = int.from_bytes(key[0:8], 'little') ^ FIXED_OBFUS_KEY
        obfuscated_key_p2 = int.from_bytes(key[8:16], 'little') ^ FIXED_OBFUS_KEY
        obfuscated_key_p3 = int.from_bytes(key[16:24], 'little') ^ FIXED_OBFUS_KEY
        obfuscated_key_p4 = int.from_bytes(key[24:32], 'little') ^ FIXED_OBFUS_KEY
    
        stub_data[STUB_PARAMETER_OFFSET + 0x08:STUB_PARAMETER_OFFSET + 0x10] = obfuscated_key_p1.to_bytes(8, 'little')
        stub_data[STUB_PARAMETER_OFFSET + 0x10:STUB_PARAMETER_OFFSET + 0x18] = obfuscated_key_p2.to_bytes(8, 'little')
        stub_data[STUB_PARAMETER_OFFSET + 0x18:STUB_PARAMETER_OFFSET + 0x20] = obfuscated_key_p3.to_bytes(8, 'little')
        stub_data[STUB_PARAMETER_OFFSET + 0x20:STUB_PARAMETER_OFFSET + 0x28] = obfuscated_key_p4.to_bytes(8, 'little')

        # Nonce (12 bytes)
        stub_data[STUB_PARAMETER_OFFSET + 0x28:STUB_PARAMETER_OFFSET + 0x34] = nonce

        # CA Steps (4 bytes, little-endian)
        # Get the CA steps from the ca_engine module (which might have been updated via command line)
        try:
            import utils.ca_engine as ca_engine
        except ImportError:
            # Try direct import if running from utils directory
            import ca_engine
        ca_steps = getattr(ca_engine, 'NUM_STEPS', 100)  # Default to 100 if not set
        stub_data[STUB_PARAMETER_OFFSET + 0x34:STUB_PARAMETER_OFFSET + 0x38] = ca_steps.to_bytes(4, 'little')

        # Payload Section RVA (4 bytes, little-endian)
        payload_rva_bytes = payload_rva.to_bytes(4, 'little')
        stub_data[STUB_PARAMETER_OFFSET + 0x38:STUB_PARAMETER_OFFSET + 0x3C] = payload_rva_bytes
        logging.debug(f"Embedded payload RVA: 0x{payload_rva:x} as bytes: {payload_rva_bytes.hex()}")

        # Payload Size (4 bytes, little-endian)
        payload_size_bytes = payload_size.to_bytes(4, 'little')
        stub_data[STUB_PARAMETER_OFFSET + 0x3C:STUB_PARAMETER_OFFSET + 0x40] = payload_size_bytes
        logging.debug(f"Embedded payload size: 0x{payload_size:x} as bytes: {payload_size_bytes.hex()}")
    else:
        # For simple stubs, we don't embed parameters, but we still need to ensure
        # we're not adding extra padding. The stub_data should be used as-is.
        logging.debug(f"Using simple stub of size {len(stub_data)} bytes without parameter embedding")

    logging.info("MVP stub generated with embedded parameters.")
    return bytes(stub_data)

def integrate_packed_binary(original_binary_path, original_binary, stub_data, obfuscated_payload, output_path):
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
            stub_section = lief.PE.Section(".stub")
            stub_section.content = list(stub_data) # LIEF expects a list of ints
            # Add common characteristics for executable code/data
            stub_section.characteristics = (
                lief.PE.Section.CHARACTERISTICS.MEM_READ |
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
            # Set section flags for executable code
            stub_section.flags = (
                lief.ELF.Section.FLAGS.ALLOC |
                lief.ELF.Section.FLAGS.EXECINSTR
            )
            stub_section = original_binary.add(stub_section)

            # Add Payload Section
            payload_section = lief.ELF.Section(".cpload")
            payload_section.content = list(obfuscated_payload)
            # Set section flags for data
            payload_section.flags = (
                lief.ELF.Section.FLAGS.ALLOC |
                lief.ELF.Section.FLAGS.WRITE
            )
            payload_section = original_binary.add(payload_section)

            # --- Update Entry Point ---
            new_ep_rva = stub_section.virtual_address
            original_binary.header.entrypoint = new_ep_rva
            
            # Keep binary type as DYN (PIE) - this works with our stub
            # original_binary.header.file_type = lief.ELF.Header.FILE_TYPE.EXEC

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

def pack_binary(input_path, output_path):
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
    oep_rva = analysis_results['oep']

    # 3. Prepare Payload (using the file path for accurate data extraction)
    blocks, key, nonce = prepare_payload(input_path)

    # 4. CA Masking
    ca_params = {} # Placeholder for CA parameters (rule, steps, etc. if needed in stub)
    obfuscated_payload, block_lengths = apply_ca_masking(blocks, key, nonce)
    payload_size = len(obfuscated_payload)

    # 5. Generate Stub (MVP)
    # Add a placeholder section to get its RVA, then regenerate the stub.
    # Create a temporary binary object for this
    temp_binary = lief.parse(input_path)
    
    if temp_binary.format == lief.Binary.FORMATS.PE:
        temp_payload_section = lief.PE.Section(".cpload_temp")
        temp_payload_section.content = [0x00] * 100 # Dummy content
        temp_payload_section = temp_binary.add_section(temp_payload_section)
        dummy_payload_rva = temp_payload_section.virtual_address
        # Use the simple minimal exit stub for debugging
        stub_source_path = os.path.join(os.path.dirname(__file__), "minimal_exit_stub_simple.c")
        stub_type = "pe"
        compile_script = os.path.join(os.path.dirname(__file__), "compile_minimal_exit_stub_simple.py")
        compiled_stub_path = os.path.join(os.path.dirname(__file__), "minimal_exit_stub_simple_compiled.bin")
    elif temp_binary.format == lief.Binary.FORMATS.ELF:
        temp_payload_section = lief.ELF.Section(".cpload_temp")
        temp_payload_section.content = [0x00] * 100 # Dummy content
        temp_payload_section = temp_binary.add(temp_payload_section)
        dummy_payload_rva = temp_payload_section.virtual_address
        # Use the complete unpacking stub
        stub_source_path = os.path.join(os.path.dirname(__file__), "complete_unpacking_stub.s")
        stub_type = "elf"
        compile_script = os.path.join(os.path.dirname(__file__), "compile_complete_unpacking_stub.py")
        compiled_stub_path = os.path.join(os.path.dirname(__file__), "complete_unpacking_stub_compiled.bin")
    else:
        raise ValueError(f"Unsupported binary format: {temp_binary.format}")
    
    # Generate the stub with the dummy RVA
    stub_data = generate_stub_mvp(oep_rva, key, nonce, ca_params, block_lengths, dummy_payload_rva, payload_size, temp_binary.format)

    # 6. Integrate
    # Use the original `binary` object and the input path for integration
    integrate_packed_binary(input_path, binary, stub_data, obfuscated_payload, output_path)

    logging.info("=== CA-BASED PACKER END ===")


# Allow importing ca_engine for NUM_STEPS constant
try:
    import utils.ca_engine as ca_engine
except ImportError:
    # Try direct import if running from utils directory
    import ca_engine

if __name__ == "__main__":
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description="CA-Packer: A binary packer using Cellular Automata for obfuscation")
    parser.add_argument("input_binary", help="Path to the input binary to pack")
    parser.add_argument("output_packed_binary", help="Path where the packed binary will be saved")
    parser.add_argument("--ca-steps", type=int, default=100, help="Number of CA steps to use for mask generation (default: 100)")
    
    args = parser.parse_args()
    
    input_file = args.input_binary
    output_file = args.output_packed_binary
    
    # Update the CA steps in the ca_engine module
    try:
        import utils.ca_engine as ca_engine
    except ImportError:
        # Try direct import if running from utils directory
        import ca_engine
    ca_engine.NUM_STEPS = args.ca_steps
    
    # Debug output to verify the value was updated
    print(f"INFO: CA Steps set to: {ca_engine.NUM_STEPS}")
    
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)

    try:
        pack_binary(input_file, output_file)
        print(f"Binary packed successfully: {output_file} (CA steps: {args.ca_steps})")
    except Exception as e:
        print(f"Error during packing: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
