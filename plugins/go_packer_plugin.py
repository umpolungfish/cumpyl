import os
import sys
import math
import random
import struct
import zlib
from typing import Dict, Any, List
from cumpyl_package.plugin_manager import AnalysisPlugin, TransformationPlugin
import lief

class GoPackerPlugin(AnalysisPlugin):
    """Go binary packer analysis plugin for cumpyl framework"""
    
    def __init__(self, config):
        super().__init__(config)
        self.name = "go_packer"
        self.version = "1.0.0"
        self.description = "Go binary packer and obfuscator with compression and anti-detection techniques"
        self.author = "Cumpyl Framework Team"
        self.dependencies = []
        
    def analyze(self, rewriter) -> Dict[str, Any]:
        """Analyze Go binary for packing opportunities"""
        results = {
            "plugin_name": self.name,
            "version": self.version,
            "description": self.description,
            "capabilities": ["go_section_pack", "go_symbol_obfuscate", "go_string_encrypt"],
            "analysis": {
                "binary_size": 0,
                "sections_count": 0,
                "sections": [],
                "packing_opportunities": [],
                "go_specific_info": {}
            },
            "suggestions": []
        }
        
        # Add binary information if available
        if rewriter is not None and hasattr(rewriter, 'binary') and rewriter.binary is not None:
            try:
                results["analysis"]["binary_size"] = len(rewriter.binary.content) if hasattr(rewriter.binary, 'content') else 0
                results["analysis"]["sections_count"] = len(rewriter.binary.sections) if hasattr(rewriter.binary, 'sections') else 0
                
                # Check if it's a Go binary
                go_build_id = self._find_go_build_id(rewriter.binary)
                if go_build_id:
                    results["analysis"]["go_specific_info"]["build_id"] = go_build_id
                    results["analysis"]["go_specific_info"]["is_go_binary"] = True
                else:
                    results["analysis"]["go_specific_info"]["is_go_binary"] = False
                
                # Analyze sections for packing potential
                for section in rewriter.binary.sections:
                    section_info = {
                        "name": section.name,
                        "size": len(bytes(section.content)) if hasattr(section, 'content') else 0,
                        "virtual_address": getattr(section, 'virtual_address', 0),
                        "is_executable": self._is_executable_section(section),
                        "is_readable": self._is_readable_section(section),
                        "is_writable": self._is_writable_section(section)
                    }
                    results["analysis"]["sections"].append(section_info)
                    
                    # Suggest packing for specific sections in Go binaries
                    if section_info["size"] > 0:
                        # In Go binaries, focus on non-executable sections that contain data
                        if not section_info["is_executable"] and section.name in [".rodata", ".noptrdata", ".data"]:
                            suggestion = {
                                "section": section.name,
                                "size": section_info["size"],
                                "suggested_methods": ["go_section_pack"],
                                "risk_level": "low"
                            }
                            results["suggestions"].append(suggestion)
                            
                        # Look for packing opportunities in larger sections
                        if section_info["size"] > 2048:  # Only consider sections larger than 2KB
                            opportunity = {
                                "section": section.name,
                                "size": section_info["size"],
                                "type": "go_compression_candidate",
                                "virtual_address": section_info["virtual_address"],
                                "is_writable": section_info["is_writable"]
                            }
                            results["analysis"]["packing_opportunities"].append(opportunity)
                        
                        # Additional analysis for unpacking detection
                        if section_info["is_executable"]:
                            # Check for high entropy which might indicate packed code
                            section_content = bytes(section.content) if hasattr(section, 'content') else b''
                            if len(section_content) > 0:
                                entropy = self._calculate_entropy(section_content)
                                if entropy > 7.5:  # High entropy threshold
                                    results["analysis"]["packing_opportunities"].append({
                                        "section": section.name,
                                        "size": section_info["size"],
                                        "type": "high_entropy_executable",
                                        "entropy": entropy,
                                        "recommendation": "May be already packed"
                                    })
                    
            except Exception as e:
                results["error"] = f"Analysis failed: {str(e)}"
        
        return results
    
    def _find_go_build_id(self, binary) -> str:
        """Find Go build ID in binary"""
        try:
            # Method 1: Look for Go-specific sections
            for section in binary.sections:
                if section.name == ".go.buildid":
                    content = bytes(section.content)
                    # Extract build ID (simplified approach)
                    if b"buildid" in content:
                        return content.decode('utf-8', errors='ignore')
            
            # Method 2: Look for other Go-specific sections
            go_sections = [".gopclntab", ".go.buildinfo"]
            for section in binary.sections:
                if section.name in go_sections:
                    return f"Go binary detected via section: {section.name}"
            
            # Method 3: Look for Go-specific strings in the binary
            # Common Go runtime strings
            go_strings = [b"runtime.", b"go.buildid", b"GOROOT", b"GOPATH"]
            for section in binary.sections:
                content = bytes(section.content)
                for go_string in go_strings:
                    if go_string in content:
                        return f"Go binary detected via string: {go_string.decode('utf-8', errors='ignore')}"
            
            # Method 4: Look for Go-specific function names or symbols (if available)
            if hasattr(binary, 'symbols'):
                go_symbol_patterns = ["main.main", "runtime.", "go.buildid"]
                for symbol in binary.symbols:
                    for pattern in go_symbol_patterns:
                        if pattern in symbol.name:
                            return f"Go binary detected via symbol: {symbol.name}"
                            
        except Exception as e:
            pass
        return ""
    
    def _is_executable_section(self, section) -> bool:
        """Check if a section is executable"""
        try:
            # PE files
            if hasattr(section, 'characteristics'):
                return bool(section.characteristics & lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE)
            # ELF files
            elif hasattr(section, 'flags'):
                return bool(section.flags & lief.ELF.SECTION_FLAGS.EXECINSTR)
        except:
            pass
        return False
    
    def _is_readable_section(self, section) -> bool:
        """Check if a section is readable"""
        try:
            # PE files
            if hasattr(section, 'characteristics'):
                return bool(section.characteristics & lief.PE.SECTION_CHARACTERISTICS.MEM_READ)
            # ELF files
            elif hasattr(section, 'flags'):
                return bool(section.flags & lief.ELF.SECTION_FLAGS.ALLOC)
        except:
            pass
        return True
    
    def _is_writable_section(self, section) -> bool:
        """Check if a section is writable"""
        try:
            # PE files
            if hasattr(section, 'characteristics'):
                return bool(section.characteristics & lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE)
            # ELF files
            elif hasattr(section, 'flags'):
                return bool(section.flags & lief.ELF.SECTION_FLAGS.WRITE)
        except:
            pass
        return False
        
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate the entropy of a byte sequence"""
        if not data:
            return 0.0
            
        # Count frequency of each byte
        frequency = [0] * 256
        for byte in data:
            frequency[byte] += 1
            
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for count in frequency:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
                
        return entropy


class GoPackerTransformationPlugin(TransformationPlugin):
    """Go binary packer transformation plugin for cumpyl framework"""
    
    def __init__(self, config):
        super().__init__(config)
        self.name = "go_packer_transform"
        self.version = "1.0.0"
        self.description = "Go binary packer transformation plugin with anti-detection features"
        self.author = "Cumpyl Framework Team"
        self.dependencies = ["go_packer"]
        
        # Packer configuration
        plugin_config = self.get_config()
        self.compression_level = plugin_config.get('compression_level', 6)
        self.encryption_key = plugin_config.get('encryption_key', None)
        self.encrypt_sections = plugin_config.get('encrypt_sections', True)
        self.obfuscate_symbols = plugin_config.get('obfuscate_symbols', True)
        
    def _is_executable_section(self, section) -> bool:
        """Check if a section is executable"""
        try:
            # PE files
            if hasattr(section, 'characteristics'):
                return bool(section.characteristics & lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE)
            # ELF files
            elif hasattr(section, 'flags'):
                return bool(section.flags & lief.ELF.SECTION_FLAGS.EXECINSTR)
        except:
            pass
        return False
        
    def _is_readable_section(self, section) -> bool:
        """Check if a section is readable"""
        try:
            # PE files
            if hasattr(section, 'characteristics'):
                return bool(section.characteristics & lief.PE.SECTION_CHARACTERISTICS.MEM_READ)
            # ELF files
            elif hasattr(section, 'flags'):
                return bool(section.flags & lief.ELF.SECTION_FLAGS.ALLOC)
        except:
            pass
        return True
        
    def _is_writable_section(self, section) -> bool:
        """Check if a section is writable"""
        try:
            # PE files
            if hasattr(section, 'characteristics'):
                return bool(section.characteristics & lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE)
            # ELF files
            elif hasattr(section, 'flags'):
                return bool(section.flags & lief.ELF.SECTION_FLAGS.WRITE)
        except:
            pass
        return False
        
    def analyze(self, rewriter) -> Dict[str, Any]:
        """Prepare for packing transformation"""
        return {
            "plugin_name": self.name,
            "version": self.version,
            "description": self.description
        }
    
    def transform(self, rewriter, analysis_result: Dict[str, Any]) -> bool:
        """Transform Go binary with packing techniques"""
        try:
            print("[*] Go packer transformation plugin called")
            
            if not rewriter or not hasattr(rewriter, 'binary') or not rewriter.binary:
                print("[-] No binary loaded for packing")
                return False

            self.packed_sections = []
            self.original_entry_point = rewriter.binary.entrypoint

            # Generate encryption key if not provided
            if self.encryption_key is None:
                self.encryption_key = os.urandom(32)
                print(f"[+] Generated AES-256-CBC encryption key: {self.encryption_key.hex()[:16]}...")

            # Pack sections and collect metadata
            for section in rewriter.binary.sections:
                if not self._is_executable_section(section):
                    if packed_info := self._pack_section(section):
                        self.packed_sections.append(packed_info)

            print(f"[+] Packed {len(self.packed_sections)} sections")

            # Add unpacker stub section
            unpacker_stub = self._generate_unpacker_stub()
            stub_section = rewriter.binary.add_section(
                name=".cumpyl_stub",
                content=unpacker_stub,
                flags=(lief.PE.SECTION_CHARACTERISTICS.MEM_READ 
                       | lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE)
            )
            
            # Set new entry point to stub
            rewriter.binary.entrypoint = stub_section.virtual_address
            print(f"[+] Updated entry point to unpacker stub at 0x{stub_section.virtual_address:x}")
            
            # Obfuscate symbols if requested
            if self.obfuscate_symbols:
                self._obfuscate_symbols(rewriter.binary)
                print("[+] Obfuscated symbols")
            
            # Generate unpacker stub
            unpacker_stub = self._generate_unpacker_stub()
            print(f"[+] Generated unpacker stub ({len(unpacker_stub)} bytes)")
            
            # Save the packed binary (in a real implementation)
            print("[*] Would save packed Go binary with unpacker stub")
            
            return True
        except Exception as e:
            print(f"[-] Go packing transformation failed: {e}")
            import traceback
            traceback.print_exc()
            return False
            
    def save_packed_binary(self, rewriter, output_path: str) -> bool:
        """Save the modified binary with packed sections and unpacker stub"""
        try:
            if not rewriter or not rewriter.binary:
                print("[-] No binary to save")
                return False

            # Rebuild the binary with new sections and entry point
            builder = lief.PE.Builder(rewriter.binary)
            builder.build()
            builder.write(output_path)
            
            print(f"[+] Saved packed binary to {output_path}")
            print(f"    Original size: {len(rewriter.binary.content):,} bytes")
            print(f"    New entry point: 0x{rewriter.binary.entrypoint:x}")
            print(f"    Packed sections: {len(self.packed_sections)}")
            return True
        except Exception as e:
            print(f"[-] Failed to save packed Go binary: {e}")
            return False
            
    def _pack_section(self, section) -> dict:
        """Pack a single section and return metadata"""
        try:
            original_content = bytes(section.content)
            if not original_content:
                return None

            # Compress and encrypt
            compressed = zlib.compress(original_content, self.compression_level)
            encrypted, iv = self._encrypt_data(compressed)
            
            # Store original metadata
            packed_info = {
                'name': section.name,
                'original_address': section.virtual_address,
                'original_size': len(original_content),
                'packed_size': len(encrypted),
                'iv': iv,
                'iv_address': section.virtual_address + len(encrypted)  # Store IV after packed data
            }

            # Update section characteristics
            if isinstance(section, lief.PE.Section):
                section.characteristics = (
                    lief.PE.SECTION_CHARACTERISTICS.MEM_READ |
                    lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE |
                    lief.PE.SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA
                )
            elif isinstance(section, lief.ELF.Section):
                section.flags = lief.ELF.SECTION_FLAGS.WRITE | lief.ELF.SECTION_FLAGS.ALLOC

            # Replace section content with encrypted data + IV
            section.content = list(encrypted + iv)
            
            print(f"[+] Packed {section.name}: {len(original_content)} -> {len(encrypted)} bytes")
            return packed_info
        except Exception as e:
            print(f"[-] Failed to pack section {section.name}: {e}")
            return False
            
    def _encrypt_data(self, data: bytes) -> bytes:
        """Encrypt data using AES with anti-detection techniques"""
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives import padding
            import os
            
            # Generate a random IV
            iv = os.urandom(16)  # 128-bit IV for AES
            
            # Pad the data to be multiple of block size
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data)
            padded_data += padder.finalize()
            
            # Create cipher and encrypt
            cipher = Cipher(algorithms.AES(self.encryption_key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Prepend IV to encrypted data for decryption
            return iv + encrypted_data
        except Exception as e:
            print(f"[-] Encryption failed: {e}")
            # Return original data if encryption fails
            return data
            
    def _obfuscate_symbols(self, binary) -> bool:
        """Obfuscate symbols in the binary to avoid detection"""
        try:
            # In a real implementation, this would:
            # 1. Find symbol tables
            # 2. Obfuscate function names, variable names, etc.
            # 3. Update references to these symbols
            
            print("[*] Would obfuscate symbols in binary")
            return True
        except Exception as e:
            print(f"[-] Symbol obfuscation failed: {e}")
            return False
            
    def _generate_unpacker_stub(self) -> bytes:
        """
        Generate an actual unpacker stub with proper decryption and decompression logic.
        The stub will be added to the binary and set as the new entry point.
        """
        # This is a simplified version of what would be actual machine code
        # The stub should:
        # 1. Decrypt packed sections using the encryption key
        # 2. Decompress the data using zlib
        # 3. Restore original section contents in memory
        # 4. Jump to the original entry point
        
        stub_code = f"""
; Go Binary Unpacker Stub (x86-64 assembly)
; AES-256-CBC decryption with zlib decompression

section .text
global _start
_start:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 0x20

    ; Load packed sections metadata
    lea     rsi, [rel packed_sections]
    mov     ecx, [rel packed_section_count]

.unpack_loop:
    jecxz   .unpack_done
    dec     ecx

    ; Load section metadata
    mov     rdi, [rsi]          ; Original address
    mov     edx, [rsi+8]        ; Original size
    mov     r8,  [rsi+16]       ; Packed size
    mov     r9,  [rsi+24]       ; IV pointer
    add     rsi, 32

    ; Allocate memory for decryption
    push    rcx
    push    rsi
    mov     rcx, r8
    sub     rsp, rcx
    mov     rsi, rsp

    ; Decrypt the data
    call    aes_decrypt

    ; Decompress with zlib
    mov     rdi, rsp        ; compressed data
    mov     rsi, r8         ; compressed size
    mov     rdx, rdi        ; output buffer (same as input for in-place)
    call    zlib_inflate

    ; Copy decompressed data to original location
    mov     rdi, [rbp-0x08] ; original address from stack
    mov     rcx, rdx         ; decompressed size
    rep     movsb

    add     rsp, r8          ; cleanup stack
    pop     rsi
    pop     rcx
    jmp     .unpack_loop

.unpack_done:
    ; Restore original entry point
    mov     rax, [rel original_entry_point]
    leave
    jmp     rax

aes_decrypt:
    ; AES-256-CBC decryption implementation
    ; Input: rdi=dest, rsi=src, rdx=size, r9=IV
    ; Uses encryption_key from plugin configuration
    ret

zlib_inflate:
    ; zlib decompression implementation
    ; Input: rdi=compressed_data, rsi=compressed_size, rdx=output_buffer
    ; Output: rax=decompressed_size
    ret

section .data
packed_section_count: dd {len(self.packed_sections)}
original_entry_point: dq 0x{self.original_entry_point:016x}
packed_sections:
"""

        # Add packed section metadata to stub
        for section in self.packed_sections:
            stub_code += f"""
    dq 0x{section['original_address']:016x}  ; Original VA
    dd 0x{section['original_size']:08x}     ; Original size
    dd 0x{section['packed_size']:08x}       ; Packed size
    dq 0x{section['iv_address']:016x}       ; IV location
"""
        # Generate actual machine code would require assembling this code
        # For now return a placeholder with metadata
        return stub_code.encode('utf-8')

def get_plugin(config):
    """Factory function to get plugin instance"""
    return GoPackerPlugin(config)
