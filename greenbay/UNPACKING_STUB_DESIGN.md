# Unpacking Stub Design for CA-Packer

This document outlines the design and requirements for the unpacking stub that will be embedded into the target binary by the CA-Packer.

## 1. Stub Responsibilities

The stub is the first code executed when the packed binary runs. Its primary responsibilities are:
1.  **Locate Packed Payload:** Find the `.cpload` section containing the obfuscated data (`P'`).
2.  **Retrieve Parameters:** Access the necessary decryption and CA parameters (OEP, key, nonce, CA steps, etc.) embedded within the binary or stub itself.
3.  **De-obfuscate Payload:** Reverse the CA masking process to retrieve the encrypted payload blocks (`B_i`).
4.  **Decrypt Payload:** Use the retrieved key and nonce to decrypt the payload (`P`).
5.  **Prepare for Execution:** Allocate memory for the decrypted payload (if needed) and prepare to transfer execution to the original entry point (OEP).
6.  **Jump to OEP:** Transfer control to the original, unpacked program.

## 2. Programming Language & Compilation

- **Language:** C is chosen for its balance of low-level control, performance, and relative ease of development compared to pure assembly. It also facilitates easier integration of the `crypto_engine` logic (ChaCha20-Poly1305) if a C implementation is available or can be adapted.
- **Compiler:** `x86_64-w64-mingw32-gcc` (MinGW-w64) for generating Windows PE-compatible object code/binary.
- **Compilation Flags:** `-Os` (optimize for size), `-fno-asynchronous-unwind-tables` (reduce size), `-nostdlib` (avoid linking standard library, making stub more self-contained).
- **Output:** Raw binary opcodes (`.bin`) or a PE section-compatible format.

## 3. Parameter Embedding Strategy

Parameters needed by the stub must be embedded within the final packed binary. Here's the proposed strategy:

1.  **Fixed Offsets (Simple MVP Approach):**
    *   Define specific offsets within the `.stub` section where parameters will be placed.
    *   The packer, after compiling the stub, will "patch" these offsets with the actual values.
    *   Example:
        *   Offset 0x100: OEP (8 bytes, little-endian)
        *   Offset 0x108: Key (32 bytes)
        *   Offset 0x128: Nonce (12 bytes)
        *   Offset 0x134: CA Steps (4 bytes, little-endian)
        *   Offset 0x138: Payload Section RVA (4 bytes, little-endian)
        *   Offset 0x13C: Payload Size (4 bytes, little-endian)
    *   This requires the stub to know its own base address in memory to calculate absolute addresses for these offsets.

2.  **Magic Byte Sequence (Alternative):**
    *   Embed unique, unlikely-to-occur byte sequences (e.g., `0xDEADBEEFCAFEBABE`) as placeholders in the stub's source or compiled binary.
    *   The packer searches for these sequences in the compiled stub binary and replaces them with the actual parameter values.
    *   This can be more robust if offsets are hard to predict but requires careful selection of magic bytes.

For the MVP, the **Fixed Offsets** approach is simpler and will be used.

## 4. Stub Workflow (Detailed Steps)

1.  **Initialization:**
    *   The stub starts execution. It needs to determine its own base address in memory. This can be done using a common technique like calling `GetModuleHandle(NULL)` (if linking to kernel32) or by using inline assembly to get the return address of a function call on the stack and walking backwards to find the MZ header.
    *   Calculate the absolute address of the parameter storage area using the base address and the fixed offset.

2.  **Parameter Retrieval:**
    *   Read the OEP, Key, Nonce, CA Steps, Payload Section RVA, and Payload Size from their designated offsets in the stub's memory/data section.

3.  **Key De-obfuscation (MVP):**
    *   The key is stored in an obfuscated form (e.g., XORed with a fixed value known to the stub). The stub performs the reverse operation to get the real key.
    *   `real_key = obfuscated_key XOR FIXED_VALUE`

4.  **Locate Payload:**
    *   Use the retrieved Payload Section RVA to calculate the absolute memory address of the `.cpload` section.
    *   Verify the section name if possible, or rely on the RVA being correct.
    *   Use the Payload Size to know how much data to process.

5.  **De-obfuscate Payload (`P'` -> `P`):**
    *   Segment the payload data at the Payload Address into blocks of `DEFAULT_BLOCK_SIZE` (32 bytes).
    *   For each block `i`:
        a.  **Regenerate CA Mask:** Call the internal CA logic (ported to the stub) with `real_key`, `i`, and `CA Steps` to generate `M_i`.
        b.  **Unmask Block:** `B_i = B'_i XOR M_i`
    *   Reassemble the `B_i` blocks into the full encrypted payload `P`.

6.  **Decrypt Payload (`P` -> Original Binary Data):**
    *   Call the internal ChaCha20-Poly1305 decryption logic with `P`, `real_key`, and `Nonce` to get the original, decrypted binary data.

7.  **Prepare for Execution (MVP Simplification):**
    *   For the MVP, we can assume the decrypted data can be executed in-place if it's just code, or that the original binary's structure is simple. A full implementation would involve allocating new memory, mapping sections, and rebuilding the PE headers properly.
    *   A simpler MVP approach might be to copy the decrypted code/data back over the original sections in memory (if permissions allow) and then jump to OEP. This is destructive but simpler for a first version.

8.  **Jump to OEP:**
    *   Perform a jump to the retrieved OEP address, effectively transferring control to the now-unpacked original program.

## 5. Integration with Packer

- The `packer.py` module will need a new function, e.g., `compile_stub()`, that:
    1.  Invokes the C compiler on the stub source code (`stub.c`) to produce a raw binary (`stub.bin`) or an object file.
    2.  Reads the `stub.bin` into a byte array.
    3.  Calculates the locations of the parameter placeholders/offsets within `stub.bin`.
    4.  Patches `stub.bin` with the actual parameter values (OEP, key, nonce, etc.).
    5.  Passes this patched byte array as `stub_data` to the `integrate_packed_binary` function.

## 6. Key Considerations

- **Size:** The stub should be as small as possible to minimize the footprint of the packed binary.
- **Dependencies:** Minimize external library dependencies. Crypto and CA logic should be self-contained.
- **Position Independence:** The stub code should ideally be position-independent, or at least easily adaptable to its loaded address.
- **Error Handling:** Basic error handling (e.g., checksums on payload, decryption failure) should lead to a clean exit or a defined failure state.
- **Stealth (Future):** Consider basic anti-debugging or anti-analysis techniques in later versions.
