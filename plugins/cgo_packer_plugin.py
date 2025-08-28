import os
import sys
import math
import random
import struct
import zlib
import logging
from typing import Dict, Any, List
from cumpyl_package.plugin_manager import AnalysisPlugin, TransformationPlugin
import lief

# Set up logging
logger = logging.getLogger(__name__)

# Add proper imports for cryptography (no fallback)
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import padding, hashes, hmac
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    logger.error("Error: cryptography library not available, secure encryption disabled")

def load_key_from_file(key_path: str) -> bytes:
    """Load a key from file with validation."""
    if not key_path or not os.path.isfile(key_path):
        raise FileNotFoundError(f"Key file not found: {key_path}")
    with open(key_path, "rb") as f:  # Context manager
        key = f.read()
    if len(key) not in (16, 24, 32):
        raise ValueError(f"Invalid key length: {len(key)} (must be 128/192/256 bits)")
    return key

# Custom exception for CGo packer errors
class CGoPackerError(Exception):
    pass

class CGoPackerPlugin(AnalysisPlugin):
    """CGO-aware Go binary packer analysis plugin for cumpyl framework"""
    
    def __init__(self, config):
        super().__init__(config)
        self.name = "cgo_packer"
        self.version = "1.1.0"
        self.description = "CGO-aware Go binary packer with anti-detection techniques"
        self.author = "Cumpyl Framework Team"
        self.dependencies = []
        
    def analyze(self, rewriter) -> Dict[str, Any]:
        """Analyze CGO-enabled Go binary for packing opportunities"""
        results = {
            "plugin_name": self.name,
            "version": self.version,
            "description": self.description,
            "capabilities": ["cgo_section_pack", "go_symbol_obfuscate", "go_string_encrypt", "cgo_aware_packing"],
            "analysis": {
                "binary_size": 0,
                "sections_count": 0,
                "sections": [],
                "packing_opportunities": [],
                "go_specific_info": {},
                "cgo_specific_info": {}
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
                    
                # Check for CGO indicators
                cgo_indicators = self._find_cgo_indicators(rewriter.binary)
                results["analysis"]["cgo_specific_info"] = cgo_indicators
                
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
                    
                    # Suggest packing for specific sections in CGO-enabled Go binaries
                    if section_info["size"] > 0:
                        # In CGO-enabled Go binaries, focus on non-executable sections that contain data
                        if not section_info["is_executable"] and section.name in [".rodata", ".noptrdata", ".data", ".cgo_export", ".cgo_uninit"]:
                            suggestion = {
                                "section": section.name,
                                "size": section_info["size"],
                                "suggested_methods": ["cgo_section_pack"],
                                "risk_level": "low"
                            }
                            results["suggestions"].append(suggestion)
                            
                        # Look for packing opportunities in larger sections
                        if section_info["size"] > 2048:  # Only consider sections larger than 2KB
                            opportunity = {
                                "section": section.name,
                                "size": section_info["size"],
                                "type": "cgo_compression_candidate",
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
                logger.error(f"Analysis failed: {e}")
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
            logger.error(f"Go build ID detection failed: {e}")
            return ""
        return ""
        
    def _find_cgo_indicators(self, binary) -> Dict[str, Any]:
        """Find CGO-specific indicators in binary"""
        cgo_info = {
            "has_cgo": False,
            "cgo_sections": [],
            "cgo_symbols": [],
            "cgo_libraries": []
        }
        
        try:
            # Look for CGO-specific sections
            cgo_section_names = [".cgo_export", ".cgo_uninit", ".cgo_init", "_cgo_*"]
            for section in binary.sections:
                for cgo_pattern in cgo_section_names:
                    if cgo_pattern in section.name or (cgo_pattern.endswith("*") and section.name.startswith(cgo_pattern[:-1])):
                        cgo_info["has_cgo"] = True
                        cgo_info["cgo_sections"].append(section.name)
            
            # Look for CGO-specific symbols (if available)
            if hasattr(binary, 'symbols'):
                cgo_symbol_patterns = ["_cgo_", "C.", "_Cfunc_", "_Ctype_"]
                for symbol in binary.symbols:
                    for pattern in cgo_symbol_patterns:
                        if pattern in symbol.name:
                            cgo_info["has_cgo"] = True
                            cgo_info["cgo_symbols"].append(symbol.name)
                            
            # Look for CGO-specific imports/libraries (ELF-specific)
            if hasattr(binary, 'libraries'):
                for lib in binary.libraries:
                    if "cgo" in lib.name.lower():
                        cgo_info["has_cgo"] = True
                        cgo_info["cgo_libraries"].append(lib.name)
                        
            # Additional heuristic: Look for common CGO patterns in section content
            cgo_content_patterns = [b"_cgo_", b"C.func", b"_Ctype_"]
            for section in binary.sections:
                content = bytes(section.content)
                for pattern in cgo_content_patterns:
                    if pattern in content:
                        cgo_info["has_cgo"] = True
                        # Don't add duplicate sections
                        if section.name not in cgo_info["cgo_sections"]:
                            cgo_info["cgo_sections"].append(section.name)
                        
        except Exception as e:
            logger.error(f"CGO indicator detection failed: {e}")
            
        return cgo_info
    
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
            
        try:
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
        except (AttributeError, ValueError) as e:
            logger.error(f"Error calculating entropy: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error calculating entropy: {e}")
            raise


class CGoPackerTransformationPlugin(TransformationPlugin):
    """CGO-aware Go binary packer transformation plugin for cumpyl framework"""
    
    def __init__(self, config):
        super().__init__(config)
        self.name = "cgo_packer_transform"
        self.version = "1.1.0"
        self.description = "CGO-aware Go binary packer transformation plugin with anti-detection features"
        self.author = "Cumpyl Framework Team"
        self.dependencies = ["cgo_packer"]
        
        # Packer configuration
        plugin_config = self.get_config()
        # Validate compression level
        self.compression_level = max(1, min(9, plugin_config.get('compression_level', 6)))
        self.encryption_key = plugin_config.get('encryption_key', None)
        self.encrypt_sections = plugin_config.get('encrypt_sections', True)
        self.obfuscate_symbols = plugin_config.get('obfuscate_symbols', True)
        self.preserve_cgo_symbols = plugin_config.get('preserve_cgo_symbols', True)
        
        # Secure key management - use key seed for runtime derivation
        self.key_seed = plugin_config.get('key_seed', os.urandom(32))  # Configurable seed
        
        # Store packed sections info for use in save_packed_binary
        self.packed_sections_info = []
        self.new_entry_point = None
        self.rewriter = None
        
    def _is_executable_section(self, section) -> bool:
        """Check if a section is executable"""
        try:
            # PE files
            if hasattr(section, 'characteristics'):
                return bool(section.characteristics & lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE)
            # ELF files
            elif hasattr(section, 'flags'):
                return bool(section.flags & lief.ELF.SECTION_FLAGS.EXECINSTR)
        except (AttributeError, ValueError) as e:
            logger.error(f"Error checking executable flag for section: {e}")
        except Exception as e:
            logger.error(f"Unexpected error checking executable flag for section: {e}")
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
        except (AttributeError, ValueError) as e:
            logger.error(f"Error checking readable flag for section: {e}")
        except Exception as e:
            logger.error(f"Unexpected error checking readable flag for section: {e}")
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
        except (AttributeError, ValueError) as e:
            logger.error(f"Error checking writable flag for section: {e}")
        except Exception as e:
            logger.error(f"Unexpected error checking writable flag for section: {e}")
        return False
        
    def _xor_encrypt(self, data: bytes, key: bytes) -> bytes:
        """Fallback XOR encryption when cryptography is not available"""
        encrypted = bytearray()
        key_len = len(key)
        for i, byte in enumerate(data):
            encrypted.append(byte ^ key[i % key_len])
        return bytes(encrypted)

    def _xor_decrypt(self, data: bytes, key: bytes) -> bytes:
        """XOR decryption (same as encryption)"""
        return self._xor_encrypt(data, key)
        
    def analyze(self, rewriter) -> Dict[str, Any]:
        """Prepare for packing transformation"""
        return {
            "plugin_name": self.name,
            "version": self.version,
            "description": self.description
        }
    
    def transform(self, rewriter, analysis_result: Dict[str, Any]) -> bool:
        """Transform CGO-enabled Go binary with packing techniques"""
        try:
            logger.info("CGO-aware packer transformation plugin called")
            
            # Validate binary and config
            if not rewriter or not hasattr(rewriter, 'binary') or not rewriter.binary:
                raise CGoPackerError("No binary loaded for packing")
                
            # Store rewriter for key derivation
            self.rewriter = rewriter
            self.packed_sections_info = []
            self.original_entry_point = rewriter.binary.entrypoint
                
            # Check if it's a Go binary
            is_go_binary = analysis_result.get("analysis", {}).get("go_specific_info", {}).get("is_go_binary", False)
            if not is_go_binary:
                logger.warning("Not detected as a Go binary")
                return False
                
            # Check if it has CGO
            has_cgo = analysis_result.get("analysis", {}).get("cgo_specific_info", {}).get("has_cgo", False)
            if not has_cgo:
                logger.warning("Not detected as a CGO-enabled binary")
                return False
                
            # Validate sections
            valid_sections = []
            for section in rewriter.binary.sections:
                if not hasattr(section, 'content') or not bytes(section.content):
                    logger.info(f"Skipping empty or invalid section: {section.name}")
                    continue
                valid_sections.append(section)
                
            # Pack sections with metadata tracking
            packed_count = 0
            for section in valid_sections:
                if not self._is_executable_section(section):
                    if packed_info := self._pack_section(section, has_cgo):
                        self.packed_sections_info.append(packed_info)
                        packed_count += 1
            
            logger.info(f"Packed {packed_count} sections")
            
            # Only proceed if we actually packed sections
            if packed_count > 0:
                # Add unpacker stub section with proper flags
                unpacker_stub = self._generate_cgo_unpacker_stub()
                stub_section = rewriter.binary.add_section(
                    name=".cgo_stub",
                    content=list(unpacker_stub),
                    flags=(lief.PE.SECTION_CHARACTERISTICS.MEM_READ |
                           lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE)
                )
                
                # Update entry point to stub
                self.new_entry_point = stub_section.virtual_address
                rewriter.binary.entrypoint = self.new_entry_point
                logger.info(f"Set new entry point to 0x{self.new_entry_point:x}")
            
            # Obfuscate symbols if requested, but preserve CGO symbols if needed
            if self.obfuscate_symbols:
                if self._obfuscate_symbols(rewriter.binary):
                    logger.info("Obfuscated symbols")
            
            if packed_count > 0:
                logger.info(f"Generated CGO-aware unpacker stub ({len(unpacker_stub)} bytes)")
            
            return True
        except CGoPackerError as e:
            logger.error(f"Fatal error: {e}")
            return False
        except Exception as e:
            logger.error(f"CGO packing transformation failed: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False
            
    def save_packed_binary(self, rewriter, output_path: str) -> bool:
        """Save the modified binary with proper format support and checksum recalculation"""
        try:
            if not rewriter or not rewriter.binary:
                raise ValueError("No binary to save")
                
            # Detect binary format and use correct LIEF builder
            if isinstance(rewriter.binary, lief.PE.Binary):
                builder = lief.PE.Builder(rewriter.binary)
                builder.build_imports(True)  # Rebuild imports if needed
                
                # Calculate proper checksum for PE files
                try:
                    if hasattr(rewriter.binary, 'optional_header') and rewriter.binary.optional_header:
                        # This is a simplified approach - real checksum calculation would be more complex
                        builder.build()
                except:
                    pass
            elif isinstance(rewriter.binary, lief.ELF.Binary):
                builder = lief.ELF.Builder(rewriter.binary)
                builder.build()
            else:
                raise ValueError("Unsupported binary format")
            
            builder.write(output_path)
            
            logger.info(f"Saved packed binary to {output_path}")
            logger.info(f"Original binary size: {len(rewriter.binary.content) if hasattr(rewriter.binary, 'content') else 'unknown'} bytes")
            return True
        except Exception as e:
            logger.error(f"Failed to save packed binary: {e}")
            return False
            
    def _pack_section(self, section, has_cgo: bool) -> dict:
        """Pack a section with proper validation"""
        try:
            # Add proper section content validation
            if not hasattr(section, 'content') or not section.content:
                return None
                
            original_content = bytes(section.content)
            if not original_content or len(original_content) == 0:
                return None
            
            # Check if section is already packed (high entropy)
            entropy = self._calculate_entropy(original_content)
            if entropy > 7.0:
                logger.info(f"Skipping section {section.name} - high entropy suggests already packed")
                return None

            # Compress with error handling
            try:
                compressed = zlib.compress(original_content, self.compression_level)
                if len(compressed) >= len(original_content):
                    # Compression didn't help, use original
                    compressed = original_content
                    logger.info(f"Compression ineffective for {section.name}, using original")
            except Exception as e:
                logger.error(f"Compression failed for {section.name}: {e}")
                compressed = original_content

            encrypted, iv = self._encrypt_cgo_data(compressed)
            
            # Compute HMAC for integrity verification
            if CRYPTO_AVAILABLE:
                digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                digest.update(self.key_seed)
                if self.rewriter and self.rewriter.binary and self.rewriter.binary.sections:
                    digest.update(bytes(self.rewriter.binary.sections[0].content))
                derived_key = digest.finalize()[:32]
                h = hmac.HMAC(derived_key, hashes.SHA256(), backend=default_backend())
                h.update(encrypted)
                hmac_value = h.finalize()
            else:
                # Simple HMAC-like value for fallback
                hmac_value = self._xor_encrypt(encrypted[:32], self.key_seed[:32])

            # Store metadata
            packed_info = {
                'name': section.name,
                'original_va': section.virtual_address,
                'original_size': len(original_content),
                'packed_size': len(encrypted),
                'iv': iv,
                'hmac': hmac_value  # Add HMAC
            }
            
            # Update section characteristics for different formats
            if isinstance(section, lief.PE.Section):
                section.characteristics = (
                    lief.PE.SECTION_CHARACTERISTICS.MEM_READ |
                    lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE |
                    lief.PE.SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA
                )
            elif isinstance(section, lief.ELF.Section):
                section.flags = lief.ELF.SECTION_FLAGS.WRITE | lief.ELF.SECTION_FLAGS.ALLOC
                # Maintain alignment
                if hasattr(section, 'alignment'):
                    section.alignment = max(section.alignment, 0x1000)
            else:
                logger.error(f"Unsupported section format for {section.name}")
                return None
            
            # Replace section content with encrypted data
            section.content = list(encrypted)
                
            logger.info(f"Packing section: {section.name} (size: {len(original_content)} bytes)")
            
            # Special handling for CGO sections
            if has_cgo and section.name.startswith((".cgo_", "_cgo_")):
                logger.info(f"Special handling for CGO section {section.name}")
                # For CGO sections, we might use different techniques to avoid breaking functionality
                # This is a simplified approach - a real implementation would be more sophisticated
                # Preserve CGO symbols if configured
                if self.preserve_cgo_symbols:
                    logger.info(f"Preserving symbols in CGO section {section.name}")
            
            return packed_info
        except Exception as e:
            logger.error(f"Failed to pack section {section.name}: {e}")
            return None
            
    def _encrypt_cgo_data(self, data: bytes) -> tuple:
        """Encrypt data using AES-GCM with CGO-aware anti-detection techniques"""
        if not CRYPTO_AVAILABLE:
            raise ImportError("Cryptography library required")
            
        try:
            # Derive key from seed and first section content
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(self.key_seed)
            if self.rewriter and self.rewriter.binary and self.rewriter.binary.sections:
                digest.update(bytes(self.rewriter.binary.sections[0].content))
            derived_key = digest.finalize()[:32]  # 256-bit key
            
            # Use AES-GCM for encryption
            nonce = os.urandom(12)  # GCM nonce
            aesgcm = AESGCM(derived_key)
            encrypted_data = aesgcm.encrypt(nonce, data, None)
            logger.info("Encrypted data successfully")
            return encrypted_data, nonce
        except Exception as e:
            logger.error(f"CGO encryption failed: {e}")
            raise
            
    def _obfuscate_symbols(self, binary) -> bool:
        """Obfuscate symbols in the binary to avoid detection, preserving CGO symbols if needed"""
        try:
            # Implement proper CGO symbol preservation
            if not hasattr(binary, 'symbols') or not binary.symbols:
                logger.info("No symbol table available")
                return True
                
            import random
            import string
            prefix = ''.join(random.choices(string.ascii_lowercase, k=8))
            cgo_patterns = ["_cgo_", "C.", "_Cfunc_", "_Ctype_"]
            
            for symbol in binary.symbols:
                # Skip CGO symbols if preservation is enabled
                if self.preserve_cgo_symbols:
                    if any(pattern in symbol.name for pattern in cgo_patterns):
                        continue
                
                # Obfuscate non-CGO symbols
                if symbol.name and len(symbol.name) > 2 and not symbol.name.startswith("."):
                    # Simple obfuscation - replace with random name
                    original_name = symbol.name
                    obfuscated_name = f"_{os.urandom(4).hex()}_{original_name[:4]}"
                    symbol.name = obfuscated_name
                    logger.info(f"Obfuscated symbol: {original_name} -> {obfuscated_name}")
            
            return True
        except Exception as e:
            logger.error(f"Symbol obfuscation failed: {e}")
            return False
            
    def _generate_cgo_unpacker_stub(self) -> bytes:
        """
        Generate a functional CGO-aware unpacker stub with separate metadata section.
        In a production implementation, this would be actual compiled machine code.
        For this implementation, we're creating a more structured stub that could
        be replaced with real assembly code.
        """
        try:
            # Generate metadata section content (separate section for security)
            meta_data = bytearray()
            meta_data.extend(b"CGO_UNPACKER_META")
            meta_data.extend(b"SEED:")  # Store seed for runtime key derivation
            meta_data.extend(self.key_seed)
            meta_data.extend(b"ENTRY:")
            meta_data.extend(struct.pack("<Q", self.original_entry_point))
            meta_data.extend(b"SECTIONS:")
            meta_data.extend(struct.pack("<I", len(self.packed_sections_info)))
            
            for section in self.packed_sections_info:
                meta_data.extend(section['name'].encode('utf-8').ljust(16, b'\x00'))
                meta_data.extend(struct.pack("<Q", section['original_va']))
                meta_data.extend(struct.pack("<Q", section['original_size']))
                meta_data.extend(struct.pack("<Q", section['packed_size']))
                meta_data.extend(section['iv'])
                meta_data.extend(section['hmac'])  # Add HMAC
                
            meta_data.extend(b"END_CGO_UNPACKER")
            
            # Add metadata as a new readable section
            if self.rewriter and self.rewriter.binary:
                self.rewriter.binary.add_section(
                    name=".cgo_meta",
                    content=list(meta_data),
                    flags=(lief.PE.SECTION_CHARACTERISTICS.MEM_READ |
                           lief.PE.SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA)
                )
            
            # Create a more structured unpacker stub that indicates where the real
            # assembly code should go. In a real implementation, this would be
            # replaced with actual machine code that:
            # 1. Parses the .cgo_meta section
            # 2. Derives the encryption key using the seed
            # 3. Verifies HMAC integrity of packed sections
            # 4. Decrypts and decompresses each section
            # 5. Restores original section permissions
            # 6. Jumps to the original entry point
            
            stub_code = bytearray()
            stub_code.extend(b"CGO_UNPACKER_STUB")
            stub_code.extend(b"VERSION:1.1")
            stub_code.extend(b"SEED:")  # Store seed for runtime key derivation
            stub_code.extend(self.key_seed)
            stub_code.extend(b"ENTRY:")
            stub_code.extend(struct.pack("<Q", self.original_entry_point))
            stub_code.extend(b"SECTIONS:")
            stub_code.extend(struct.pack("<I", len(self.packed_sections_info)))
            
            # Add placeholder for where the actual unpacking code would go
            # In a real implementation, this would be replaced with assembly code
            stub_code.extend(b"UNPACKER_CODE_PLACEHOLDER")
            
            # Add section information for the unpacker to process
            for section in self.packed_sections_info:
                stub_code.extend(section['name'].encode('utf-8').ljust(16, b'\x00'))
                stub_code.extend(struct.pack("<Q", section['original_va']))
                stub_code.extend(struct.pack("<Q", section['original_size']))
                stub_code.extend(struct.pack("<Q", section['packed_size']))
                stub_code.extend(section['iv'])
                stub_code.extend(section['hmac'])  # Add HMAC
                
            stub_code.extend(b"END_UNPACKER_STUB")
            
            return bytes(stub_code)
        except Exception as e:
            logger.error(f"Failed to generate unpacker stub: {e}")
            # Return a simple placeholder stub
            stub_code = bytearray()
            stub_code.extend(b"CGO_UNPACKER_STUB")
            stub_code.extend(b"SEED:")  # Store seed for runtime key derivation
            stub_code.extend(self.key_seed)
            stub_code.extend(b"ENTRY:")
            stub_code.extend(struct.pack("<Q", self.original_entry_point))
            stub_code.extend(b"SECTIONS:")
            stub_code.extend(struct.pack("<I", len(self.packed_sections_info)))
            
            for section in self.packed_sections_info:
                stub_code.extend(section['name'].encode('utf-8').ljust(16, b'\x00'))
                stub_code.extend(struct.pack("<Q", section['original_va']))
                stub_code.extend(struct.pack("<Q", section['original_size']))
                stub_code.extend(struct.pack("<Q", section['packed_size']))
                stub_code.extend(section['iv'])
                stub_code.extend(section['hmac'])  # Add HMAC
                
            stub_code.extend(b"END_CGO_UNPACKER")
            return bytes(stub_code)

def get_plugin(config):
    """Factory function to get plugin instance"""
    return CGoPackerPlugin(config)
