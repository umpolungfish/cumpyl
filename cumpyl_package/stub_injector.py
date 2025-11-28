#!/usr/bin/env python3
"""
Stub Injection Framework for Cumpyl
Injects deobfuscation stubs into PE binaries to enable functional string obfuscation
"""

import lief
import struct
from typing import Dict, List, Tuple, Optional, Any
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class DeobfuscationType(Enum):
    """Supported deobfuscation methods"""
    XOR = "xor"
    BASE64 = "base64"
    ROT13 = "rot13"
    REVERSE = "reverse"
    VIGENERE = "vigenere"
    CAESAR = "caesar"
    AES_CBC = "aes_cbc"
    NONE = "none"


class StubInjector:
    """
    Injects deobfuscation stubs into PE binaries

    Architecture:
    1. Create new .stub section for deobfuscation code
    2. Create .xdata section for key/parameter storage
    3. Inject stub routines for each obfuscation method
    4. Track stub offsets for reference patching
    """

    def __init__(self, binary: lief.PE.Binary):
        """Initialize stub injector with a PE binary"""
        self.binary = binary
        self.stub_section = None
        self.xdata_section = None
        self.stub_offsets = {}  # Maps method -> RVA
        self.key_table_offset = None
        self.key_table_entries = []  # List of (string_rva, key_data, method)

    def inject_all_stubs(self) -> bool:
        """
        Inject all necessary deobfuscation stubs
        Returns True on success
        """
        try:
            logger.info("Starting stub injection...")

            # Create necessary sections
            if not self._create_stub_section():
                logger.error("Failed to create stub section")
                return False

            if not self._create_xdata_section():
                logger.error("Failed to create xdata section")
                return False

            # Inject stub code for each method
            self._inject_xor_stub()
            self._inject_base64_stub()
            self._inject_rot13_stub()
            self._inject_reverse_stub()
            self._inject_vigenere_stub()
            self._inject_caesar_stub()

            logger.info(f"Successfully injected {len(self.stub_offsets)} stubs")
            return True

        except Exception as e:
            logger.error(f"Stub injection failed: {e}")
            return False

    def _create_stub_section(self) -> bool:
        """Create .stub section for deobfuscation code"""
        try:
            # Create new section
            stub_section = lief.PE.Section(".stub")

            # Set properties
            stub_section.virtual_size = 0x2000  # 8KB should be enough for stubs
            stub_section.characteristics = (
                lief.PE.SECTION_CHARACTERISTICS.MEM_READ |
                lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE |
                lief.PE.SECTION_CHARACTERISTICS.CNT_CODE
            )

            # Initialize with zeros
            stub_section.content = [0] * 0x2000

            # Add to binary
            self.stub_section = self.binary.add_section(stub_section)

            logger.info(f"Created .stub section at RVA: 0x{self.stub_section.virtual_address:08x}")
            return True

        except Exception as e:
            logger.error(f"Failed to create stub section: {e}")
            return False

    def _create_xdata_section(self) -> bool:
        """Create .xdata section for key/parameter storage"""
        try:
            # Create new section
            xdata_section = lief.PE.Section(".xdata")

            # Set properties
            xdata_section.virtual_size = 0x1000  # 4KB for keys and parameters
            xdata_section.characteristics = (
                lief.PE.SECTION_CHARACTERISTICS.MEM_READ |
                lief.PE.SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA
            )

            # Initialize with zeros
            xdata_section.content = [0] * 0x1000

            # Add to binary
            self.xdata_section = self.binary.add_section(xdata_section)

            logger.info(f"Created .xdata section at RVA: 0x{self.xdata_section.virtual_address:08x}")
            return True

        except Exception as e:
            logger.error(f"Failed to create xdata section: {e}")
            return False

    def _inject_xor_stub(self) -> bool:
        """
        Inject XOR deobfuscation stub

        Stub signature:
        char* xor_deobfuscate(char* str, size_t len, uint8_t key)

        Assembly (x86):
        push ebx
        mov ebx, [esp+8]   ; str pointer
        mov ecx, [esp+12]  ; length
        mov al, [esp+16]   ; key
        .loop:
            xor byte [ebx], al
            inc ebx
            loop .loop
        pop ebx
        ret
        """
        try:
            # x86 XOR stub (32-bit)
            xor_stub_x86 = bytes([
                0x53,                    # push ebx
                0x8B, 0x5C, 0x24, 0x08,  # mov ebx, [esp+8]  (str)
                0x8B, 0x4C, 0x24, 0x0C,  # mov ecx, [esp+12] (len)
                0x8A, 0x44, 0x24, 0x10,  # mov al, [esp+16]  (key)
                0x30, 0x03,              # xor byte [ebx], al
                0x43,                    # inc ebx
                0xE2, 0xFB,              # loop -5
                0x5B,                    # pop ebx
                0xC3                     # ret
            ])

            # x64 XOR stub (64-bit) - Using Windows x64 calling convention (RCX, RDX, R8)
            xor_stub_x64 = bytes([
                0x48, 0x85, 0xD2,        # test rdx, rdx (check length)
                0x74, 0x0C,              # jz end
                0x44, 0x30, 0x01,        # xor byte [rcx], r8b
                0x48, 0xFF, 0xC1,        # inc rcx
                0x48, 0xFF, 0xCA,        # dec rdx
                0x75, 0xF5,              # jnz loop
                0x48, 0x8B, 0xC1,        # mov rax, rcx (return pointer)
                0xC3                     # ret
            ])

            # Determine architecture
            if self.binary.header.machine == lief.PE.MACHINE_TYPES.I386:
                stub_code = xor_stub_x86
            else:  # x64
                stub_code = xor_stub_x64

            # Write to stub section
            current_offset = 0
            section_content = list(self.stub_section.content)
            for i, byte in enumerate(stub_code):
                section_content[current_offset + i] = byte

            self.stub_section.content = section_content

            # Store stub RVA
            stub_rva = self.stub_section.virtual_address + current_offset
            self.stub_offsets[DeobfuscationType.XOR] = stub_rva

            logger.info(f"Injected XOR stub at RVA: 0x{stub_rva:08x}")
            return True

        except Exception as e:
            logger.error(f"Failed to inject XOR stub: {e}")
            return False

    def _inject_base64_stub(self) -> bool:
        """
        Inject Base64 deobfuscation stub

        Note: Base64 decoding is complex in assembly, so we use a simplified approach
        or rely on existing library functions if available
        """
        try:
            # For now, we'll create a placeholder that calls a hypothetical base64_decode function
            # In production, you'd either:
            # 1. Include a full base64 decoder in assembly
            # 2. Link against a library that provides base64 decoding
            # 3. Use inline decoding lookup tables

            # Simplified stub that marks it as needing runtime support
            base64_stub = bytes([
                0xCC,  # int3 (breakpoint - indicates not implemented yet)
                0xC3   # ret
            ])

            current_offset = 0x100  # Offset from XOR stub
            section_content = list(self.stub_section.content)
            for i, byte in enumerate(base64_stub):
                section_content[current_offset + i] = byte

            self.stub_section.content = section_content

            stub_rva = self.stub_section.virtual_address + current_offset
            self.stub_offsets[DeobfuscationType.BASE64] = stub_rva

            logger.warning(f"Base64 stub is a placeholder at RVA: 0x{stub_rva:08x}")
            return True

        except Exception as e:
            logger.error(f"Failed to inject Base64 stub: {e}")
            return False

    def _inject_rot13_stub(self) -> bool:
        """
        Inject ROT13 deobfuscation stub

        Stub signature:
        char* rot13_deobfuscate(char* str, size_t len)
        """
        try:
            # x86 ROT13 stub
            rot13_stub_x86 = bytes([
                0x53,                    # push ebx
                0x8B, 0x5C, 0x24, 0x08,  # mov ebx, [esp+8]  (str)
                0x8B, 0x4C, 0x24, 0x0C,  # mov ecx, [esp+12] (len)
                # loop start
                0x8A, 0x03,              # mov al, [ebx]
                0x3C, 0x41,              # cmp al, 'A'
                0x72, 0x15,              # jb skip
                0x3C, 0x5A,              # cmp al, 'Z'
                0x77, 0x07,              # ja check_lower
                0x04, 0x0D,              # add al, 13
                0x3C, 0x5A,              # cmp al, 'Z'
                0x76, 0x0C,              # jbe store
                0x2C, 0x1A,              # sub al, 26
                0xEB, 0x08,              # jmp store
                # check_lower
                0x3C, 0x61,              # cmp al, 'a'
                0x72, 0x06,              # jb skip
                0x3C, 0x7A,              # cmp al, 'z'
                0x77, 0x02,              # ja skip
                0x04, 0x0D,              # add al, 13
                # store
                0x88, 0x03,              # mov [ebx], al
                # skip
                0x43,                    # inc ebx
                0xE2, 0xE1,              # loop loop_start
                0x5B,                    # pop ebx
                0xC3                     # ret
            ])

            current_offset = 0x200
            section_content = list(self.stub_section.content)
            for i, byte in enumerate(rot13_stub_x86):
                section_content[current_offset + i] = byte

            self.stub_section.content = section_content

            stub_rva = self.stub_section.virtual_address + current_offset
            self.stub_offsets[DeobfuscationType.ROT13] = stub_rva

            logger.info(f"Injected ROT13 stub at RVA: 0x{stub_rva:08x}")
            return True

        except Exception as e:
            logger.error(f"Failed to inject ROT13 stub: {e}")
            return False

    def _inject_reverse_stub(self) -> bool:
        """
        Inject string reversal stub

        Stub signature:
        char* reverse_deobfuscate(char* str, size_t len)
        """
        try:
            # x86 reverse stub
            reverse_stub_x86 = bytes([
                0x53,                    # push ebx
                0x56,                    # push esi
                0x57,                    # push edi
                0x8B, 0x7C, 0x24, 0x10,  # mov edi, [esp+16] (str)
                0x8B, 0x74, 0x24, 0x14,  # mov esi, [esp+20] (len)
                0x8D, 0x1C, 0x37,        # lea ebx, [edi+esi] (end)
                0x4B,                    # dec ebx
                0x39, 0xDF,              # cmp edi, ebx
                0x73, 0x0A,              # jae done
                # swap_loop
                0x8A, 0x07,              # mov al, [edi]
                0x8A, 0x13,              # mov dl, [ebx]
                0x88, 0x17,              # mov [edi], dl
                0x88, 0x03,              # mov [ebx], al
                0x47,                    # inc edi
                0x4B,                    # dec ebx
                0xEB, 0xF0,              # jmp cmp
                # done
                0x5F,                    # pop edi
                0x5E,                    # pop esi
                0x5B,                    # pop ebx
                0xC3                     # ret
            ])

            current_offset = 0x300
            section_content = list(self.stub_section.content)
            for i, byte in enumerate(reverse_stub_x86):
                section_content[current_offset + i] = byte

            self.stub_section.content = section_content

            stub_rva = self.stub_section.virtual_address + current_offset
            self.stub_offsets[DeobfuscationType.REVERSE] = stub_rva

            logger.info(f"Injected REVERSE stub at RVA: 0x{stub_rva:08x}")
            return True

        except Exception as e:
            logger.error(f"Failed to inject REVERSE stub: {e}")
            return False

    def _inject_vigenere_stub(self) -> bool:
        """Inject Vigenère cipher stub (placeholder)"""
        try:
            # Complex cipher - using placeholder for now
            vigenere_stub = bytes([0xCC, 0xC3])  # int3, ret

            current_offset = 0x400
            section_content = list(self.stub_section.content)
            for i, byte in enumerate(vigenere_stub):
                section_content[current_offset + i] = byte

            self.stub_section.content = section_content

            stub_rva = self.stub_section.virtual_address + current_offset
            self.stub_offsets[DeobfuscationType.VIGENERE] = stub_rva

            logger.warning(f"Vigenère stub is a placeholder at RVA: 0x{stub_rva:08x}")
            return True

        except Exception as e:
            logger.error(f"Failed to inject Vigenère stub: {e}")
            return False

    def _inject_caesar_stub(self) -> bool:
        """Inject Caesar cipher stub (similar to XOR but with rotation)"""
        try:
            # Caesar cipher is essentially XOR with modulo arithmetic on alphabet
            # For simplicity, treating it similar to ROT-N
            caesar_stub = bytes([0xCC, 0xC3])  # Placeholder

            current_offset = 0x500
            section_content = list(self.stub_section.content)
            for i, byte in enumerate(caesar_stub):
                section_content[current_offset + i] = byte

            self.stub_section.content = section_content

            stub_rva = self.stub_section.virtual_address + current_offset
            self.stub_offsets[DeobfuscationType.CAESAR] = stub_rva

            logger.warning(f"Caesar stub is a placeholder at RVA: 0x{stub_rva:08x}")
            return True

        except Exception as e:
            logger.error(f"Failed to inject Caesar stub: {e}")
            return False

    def store_key(self, string_rva: int, key_data: bytes, method: DeobfuscationType) -> int:
        """
        Store decryption key/parameters in .xdata section

        Returns offset in .xdata section where key is stored
        """
        try:
            if not self.xdata_section:
                logger.error("xdata section not created")
                return -1

            # Key table entry format:
            # [4 bytes] String RVA
            # [1 byte]  Method type
            # [1 byte]  Key length
            # [N bytes] Key data (max 64 bytes)

            entry_data = struct.pack('<I', string_rva)  # String RVA
            entry_data += struct.pack('B', list(DeobfuscationType).index(method))  # Method
            entry_data += struct.pack('B', len(key_data))  # Key length
            entry_data += key_data[:64]  # Key data (truncated to 64 bytes)

            # Find next available offset in xdata
            current_offset = len(self.key_table_entries) * 70  # Max 70 bytes per entry

            if current_offset + len(entry_data) > len(self.xdata_section.content):
                logger.error("xdata section full")
                return -1

            # Write to xdata section
            section_content = list(self.xdata_section.content)
            for i, byte in enumerate(entry_data):
                section_content[current_offset + i] = byte

            self.xdata_section.content = section_content

            # Track entry
            self.key_table_entries.append({
                'string_rva': string_rva,
                'method': method,
                'key_data': key_data,
                'xdata_offset': current_offset
            })

            logger.debug(f"Stored key at xdata offset 0x{current_offset:04x} for string at RVA 0x{string_rva:08x}")
            return current_offset

        except Exception as e:
            logger.error(f"Failed to store key: {e}")
            return -1

    def get_stub_rva(self, method: DeobfuscationType) -> Optional[int]:
        """Get RVA of deobfuscation stub for given method"""
        return self.stub_offsets.get(method)

    def get_key_table_rva(self) -> Optional[int]:
        """Get RVA of key table in xdata section"""
        if self.xdata_section:
            return self.xdata_section.virtual_address
        return None

    def generate_stub_call(self, method: DeobfuscationType, string_rva: int,
                          key_data: bytes, is_x64: bool = False) -> bytes:
        """
        Generate assembly code to call deobfuscation stub

        Returns machine code that:
        1. Pushes parameters (string ptr, length, key)
        2. Calls deobfuscation stub
        3. Restores stack
        4. Returns deobfuscated string pointer in EAX/RAX
        """
        try:
            stub_rva = self.get_stub_rva(method)
            if stub_rva is None:
                logger.error(f"No stub found for method {method}")
                return bytes()

            if is_x64:
                # x64 Windows calling convention: RCX, RDX, R8, R9
                # mov rcx, string_ptr
                # mov rdx, length
                # mov r8b, key (for XOR)
                # call stub
                code = bytes([
                    0x48, 0xB9,  # mov rcx, imm64
                ]) + struct.pack('<Q', string_rva)
                code += bytes([
                    0x48, 0xBA,  # mov rdx, imm64 (length - would need actual length)
                ]) + struct.pack('<Q', 0)  # Placeholder length
                code += bytes([
                    0x41, 0xB0,  # mov r8b, imm8
                    key_data[0] if key_data else 0
                ])
                code += bytes([0xE8])  # call rel32
                code += struct.pack('<i', stub_rva - (string_rva + len(code) + 4))  # Relative offset

            else:
                # x86 cdecl: push params right-to-left, then call
                code = bytes([0x68]) + struct.pack('<I', key_data[0] if key_data else 0)  # push key
                code += bytes([0x68]) + struct.pack('<I', 0)  # push length (placeholder)
                code += bytes([0x68]) + struct.pack('<I', string_rva)  # push string_ptr
                code += bytes([0xE8])  # call rel32
                code += struct.pack('<i', stub_rva - (string_rva + len(code) + 4))
                code += bytes([0x83, 0xC4, 0x0C])  # add esp, 12 (clean up stack)

            return code

        except Exception as e:
            logger.error(f"Failed to generate stub call: {e}")
            return bytes()

    def finalize(self) -> bool:
        """
        Finalize stub injection
        - Update section headers
        - Recalculate checksums
        - Validate structure
        """
        try:
            # LIEF should handle most of this automatically when we save
            # But we can add additional validation here

            if not self.stub_section or not self.xdata_section:
                logger.error("Required sections not created")
                return False

            logger.info(f"Stub injection finalized:")
            logger.info(f"  - {len(self.stub_offsets)} stubs injected")
            logger.info(f"  - {len(self.key_table_entries)} keys stored")
            logger.info(f"  - .stub section at RVA 0x{self.stub_section.virtual_address:08x}")
            logger.info(f"  - .xdata section at RVA 0x{self.xdata_section.virtual_address:08x}")

            return True

        except Exception as e:
            logger.error(f"Failed to finalize stub injection: {e}")
            return False


# Helper function for use in plugins
def create_stub_injector(binary: lief.PE.Binary) -> Optional[StubInjector]:
    """
    Create and initialize a stub injector for a PE binary

    Args:
        binary: LIEF PE binary object

    Returns:
        Configured StubInjector instance or None on failure
    """
    try:
        injector = StubInjector(binary)
        if injector.inject_all_stubs():
            return injector
        return None
    except Exception as e:
        logger.error(f"Failed to create stub injector: {e}")
        return None
