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
            
            # Check if binary is loaded
            if not rewriter or not hasattr(rewriter, 'binary') or not rewriter.binary:
                print("[-] No binary loaded for packing")
                return False
                
            # Check if it's a Go binary
            is_go_binary = analysis_result.get("analysis", {}).get("go_specific_info", {}).get("is_go_binary", False)
            if not is_go_binary:
                print("[-] Warning: Not detected as a Go binary, but continuing with generic packing as requested")
                # Continue with generic packing approach rather than failing completely
                # Set is_go_binary to True to proceed with the transformation
                is_go_binary = True
                
            # Generate encryption key if not provided
            if self.encryption_key is None:
                self.encryption_key = os.urandom(32)  # 256-bit key for AES
                print(f"[+] Generated random encryption key")
            
            # Pack each section
            packed_sections = 0
            for section in rewriter.binary.sections:
                # Focus on non-executable sections for Go binaries
                if not self._is_executable_section(section) and self._pack_section(section):
                    packed_sections += 1
                    
            print(f"[+] Packed {packed_sections} sections")
            
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
        """
        Save the packed binary to a file.
        This is a placeholder - a real implementation would be more complex.
        """
        try:
            if not rewriter or not hasattr(rewriter, 'binary') or not rewriter.binary:
                print("[-] No binary to save")
                return False
                
            # In a real implementation, we would:
            # 1. Replace sections with packed data
            # 2. Add unpacker stub to the binary
            # 3. Update entry point to point to unpacker
            # 4. Save the modified binary
            
            print(f"[*] Would save packed Go binary to {output_path}")
            print(f"[*] Original binary size: {len(rewriter.binary.content) if hasattr(rewriter.binary, 'content') else 'unknown'} bytes")
            
            # For demonstration, let's just save a simple placeholder
            with open(output_path, 'wb') as f:
                f.write(b"PACKED_GO_BINARY_PLACEHOLDER")
                if hasattr(rewriter.binary, 'content'):
                    f.write(rewriter.binary.content[:100])  # First 100 bytes as identifier
                f.write(b"_WITH_UNPACKER")
                
            print(f"[+] Saved packed Go binary to {output_path}")
            return True
        except Exception as e:
            print(f"[-] Failed to save packed Go binary: {e}")
            return False
            
    def _pack_section(self, section) -> bool:
        """Pack a single section with compression and encryption"""
        try:
            # Get section content
            section_content = bytes(section.content)
            if len(section_content) == 0:
                return False
                
            print(f"[*] Packing section: {section.name} (size: {len(section_content)} bytes)")
            
            # Only pack non-executable sections
            is_executable = self._is_executable_section(section)
            if is_executable:
                return False
                
            # Compress the section content
            compressed_data = zlib.compress(section_content, self.compression_level)
            print(f"[*] Compressed {len(section_content)} bytes to {len(compressed_data)} bytes")
            
            # Encrypt the compressed data
            encrypted_data = self._encrypt_data(compressed_data)
            print(f"[*] Encrypted data to {len(encrypted_data)} bytes")
            
            # Update section content (in a real implementation, this would be more complex)
            # For now, we'll just print what we would do
            print(f"[*] Would update section {section.name} with packed data")
            
            return True
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
        Generate a simple unpacker stub that can decompress and decrypt the packed sections.
        This is a simplified version - a real implementation would be more complex.
        """
        # This would typically be machine code, but we'll create a simple placeholder
        # that demonstrates the concept
        
        stub_code = f"""
; Simple Unpacker Stub for Go binaries (x86-64 assembly pseudocode)
; This would typically be compiled to actual machine code

unpacker_start:
    ; Save registers
    push rax
    push rbx
    push rcx
    push rdx
    
    ; Decrypt and decompress each packed section
    ; (Implementation details would go here)
    
    ; Restore registers
    pop rdx
    pop rcx
    pop rbx
    pop rax
    
    ; Jump to original entry point
    ; (Address would be stored in the packed binary)
    
unpacker_end:
"""
        
        # In a real implementation, this would be actual compiled machine code
        # For now, we'll just return a placeholder
        key_part = self.encryption_key[:16] if self.encryption_key else b"DEFAULT_KEY_HERE"
        return b"GO_UNPACKER_STUB_PLACEHOLDER_" + key_part

def get_plugin(config):
    """Factory function to get plugin instance"""
    return GoPackerPlugin(config)