import os
import sys
import logging
from typing import Dict, Any, List
from cumpyl_package.plugin_manager import AnalysisPlugin, TransformationPlugin
import lief
import zlib
import random
import struct

# Use consolidated utilities
from plugins.consolidated_utils import detect_format, is_executable_section, is_readable_section, is_writable_section, calculate_entropy_with_confidence
from plugins.base_plugin import BasePlugin

def calculate_entropy(data: bytes) -> float:
    """Simple entropy calculation wrapper for backward compatibility."""
    result = calculate_entropy_with_confidence(data)
    return result["value"]

# Set up logging
logger = logging.getLogger(__name__)

# Use the new key loading function from crypto_utils
from plugins.crypto_utils import load_and_derive_key, derive_secure_key

def sample_bytes(data: bytes, max_samples: int = 65536) -> bytes:
    """Return a deterministic sample up to max_samples for large blobs."""
    if len(data) <= max_samples:
        return data
    # simple sampling: take first, middle, last chunks
    chunk = max_samples // 3
    return data[:chunk] + data[len(data)//2:len(data)//2 + chunk] + data[-chunk:]


def create_integrity_hash(data: bytes) -> str:
    """Create an integrity hash for data verification."""
    from plugins.crypto_utils import safe_hash
    return safe_hash(data)

def encrypt_bytes_aesgcm(key: bytes, data: bytes) -> dict:
    """Return dict {ciphertext, nonce, tag} where AESGCM stores tag inside ciphertext in cryptography lib."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import secrets
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)  # recommended for GCM
        ct = aesgcm.encrypt(nonce, data, associated_data=None)
        return {"ciphertext": ct, "nonce": nonce}
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        raise

def decrypt_bytes_aesgcm(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        raise

def save_packed_binary(binary, output_path: str, fmt: str) -> bool:
    """Select builder by format and write file; validate post-write."""
    try:
        if fmt == "PE":
            builder = lief.PE.Builder(binary)
        elif fmt == "ELF":
            builder = lief.ELF.Builder(binary)
        elif fmt == "MACHO":
            builder = lief.MachO.Builder(binary)
        else:
            raise ValueError("Unsupported binary format for saving")
        builder.build()
        builder.write(output_path)
        # Post-write sanity: check file exists & non-zero
        if not os.path.isfile(output_path) or os.path.getsize(output_path) == 0:
            raise IOError("Builder wrote an invalid file")
        logger.info("Saved packed binary to %s", output_path)
        return True
    except (AttributeError, ValueError, IOError) as e:
        logger.error(f"Failed to save packed binary: {e}")
        raise
    except Exception as e:
        logger.exception("Unexpected error saving packed binary")
        raise


class PackerPlugin(AnalysisPlugin, BasePlugin):
    """Universal binary packer analysis plugin for cumpyl framework"""
    
    def __init__(self, config):
        # Initialize both parent classes
        BasePlugin.__init__(self, config)
        AnalysisPlugin.__init__(self, config)
        self.name = "packer"
        self.version = "1.1.0"
        self.description = "Universal binary packer and obfuscator with compression and encryption"
        self.author = "Cumpyl Framework Team"
        self.dependencies = []
        
    def analyze(self, rewriter) -> Dict[str, Any]:
        """Analyze binary for packing opportunities"""
        results = {
            "plugin_name": self.name,
            "version": self.version,
            "description": self.description,
            "capabilities": ["simple_pack", "section_encrypt", "payload_inject"],
            "analysis": {
                "binary_size": 0,
                "sections_count": 0,
                "sections": [],
                "packing_opportunities": []
            },
            "suggestions": []
        }
        
        # Add binary information if available
        if rewriter is not None and hasattr(rewriter, 'binary') and rewriter.binary is not None:
            try:
                binary = rewriter.binary
                fmt = detect_format(binary)
                results["analysis"]["binary_format"] = fmt
                results["analysis"]["binary_size"] = getattr(binary, 'original_size', 0) or (len(binary.content) if hasattr(binary, 'content') else 0)
                results["analysis"]["sections_count"] = len(getattr(binary, 'sections', []))
                
                # Analyze sections for packing potential
                for section in getattr(binary, 'sections', []):
                    section_info = {
                        "name": getattr(section, 'name', '<unnamed>'),
                        "size": len(bytes(getattr(section, 'content', b''))),
                        "virtual_address": getattr(section, 'virtual_address', 0),
                        "is_executable": is_executable_section(section, fmt),
                        "is_readable": is_readable_section(section, fmt),
                        "is_writable": is_writable_section(section, fmt)
                    }
                    results["analysis"]["sections"].append(section_info)
                    
                    # Suggest packing for executable sections
                    if section_info["is_executable"] and section_info["size"] > 0:
                        suggestion = {
                            "section": section_info["name"],
                            "size": section_info["size"],
                            "suggested_methods": ["section_encrypt"],
                            "risk_level": "high" if section_info["is_writable"] else "medium"
                        }
                        results["suggestions"].append(suggestion)
                        
                    # Look for packing opportunities
                    if section_info["size"] > 1024:  # Only consider sections larger than 1KB
                        opportunity = {
                            "section": section_info["name"],
                            "size": section_info["size"],
                            "type": "compression_candidate" if not section_info["is_executable"] else "encryption_candidate",
                            "virtual_address": section_info["virtual_address"],
                            "is_writable": section_info["is_writable"]
                        }
                        results["analysis"]["packing_opportunities"].append(opportunity)
                        
                    # Additional analysis for unpacking detection
                    if section_info["is_executable"]:
                        # Check for high entropy which might indicate packed code
                        section_content = bytes(getattr(section, 'content', b''))
                        if len(section_content) > 0:
                            # Sample large sections for entropy calculation
                            sample = sample_bytes(section_content)
                            entropy = calculate_entropy(sample)
                            if entropy > 7.5:  # High entropy threshold
                                results["analysis"]["packing_opportunities"].append({
                                    "section": section_info["name"],
                                    "size": section_info["size"],
                                    "type": "high_entropy_executable",
                                    "entropy": entropy,
                                    "recommendation": "May be already packed"
                                })
                        
            except Exception as e:
                logger.exception("Analysis failed")
                results["error"] = f"Analysis failed: {str(e)}"
        
        return results


class PackerTransformationPlugin(TransformationPlugin, BasePlugin):
    """Universal binary packer transformation plugin for cumpyl framework"""
    
    def __init__(self, config):
        # Initialize both parent classes
        BasePlugin.__init__(self, config)
        TransformationPlugin.__init__(self, config)
        self.name = "packer_transform"
        self.version = "1.1.0"
        self.description = "Universal binary packer transformation plugin"
        self.author = "Cumpyl Framework Team"
        self.dependencies = ["packer"]
        
        # Packer configuration
        self.compression_level = self.get_config_value('compression_level', 6)
        self.key_path = self.get_config_value('key_path', None)  # key must be provided; we will not generate/print keys
        self.encrypt_sections = self.get_config_value('encrypt_sections', True)
        self.safe_mode = self.get_config_value("safe_mode", True)
        self.dry_run = self.get_config_value("dry_run", True)
        self.skip_pointer_sections = self.get_config_value("skip_pointer_sections", True)
        self.encryption_enabled = bool(self.key_path)
        self.format = None
        # metadata sidecar
        self.packed_metadata = []
        
    def analyze(self, rewriter) -> Dict[str, Any]:
        """Prepare for packing transformation"""
        return {
            "plugin_name": self.name,
            "version": self.version,
            "description": self.description
        }
    
    def transform(self, rewriter, analysis_result: Dict[str, Any]) -> bool:
        """Transform binary with packing techniques"""
        try:
            # Validate inputs
            if not rewriter or not getattr(rewriter, "binary", None):
                logger.error("No binary provided for transformation")
                return False

            binary = rewriter.binary
            self.format = detect_format(binary)
            logger.info("Detected format: %s", self.format)

            # Dry-run: collect what *would* be changed and return without writing
            if self.dry_run:
                logger.info("Dry-run mode: reporting changes without modifying binary")
                # build report here...
                return True

            # If encryption requested, validate key with enhanced security
            if self.encryption_enabled:
                try:
                    # Add binary-specific context for key derivation
                    import hashlib
                    binary_context = hashlib.sha256(binary.path.encode()).digest() if hasattr(binary, 'path') else b""
                    encryption_key, hmac_key, salts = derive_secure_key(self.key_path, binary_context=binary_context)
                    key = encryption_key  # Use the derived encryption key
                except FileNotFoundError:
                    logger.error(f"Key file not found: {self.key_path}")
                    return False
                except ValueError as e:
                    logger.error(f"Invalid encryption key: {e}")
                    return False
                except Exception as e:
                    logger.exception("Unexpected error during key derivation")
                    return False

            # Iterate sections safely
            for section in getattr(binary, "sections", []):
                try:
                    name = getattr(section, "name", "<unnamed>")
                    size = len(bytes(getattr(section, "content", b"")))
                    logger.debug("Considering section %s size=%d", name, size)

                    # Skip pointer-heavy sections
                    if self.skip_pointer_sections and name in (".noptrdata", ".data", ".gopclntab", ".go.buildid"):
                        logger.info("Skipping pointer/GC-critical section %s", name)
                        continue

                    # Only pack non-exec, non-empty sections in this safe mode
                    if is_executable_section(section, self.format):
                        logger.debug("Skipping executable section %s", name)
                        continue

                    # Read content safely
                    content = bytes(getattr(section, "content", b""))
                    if not content:
                        continue

                    # Entropy sampling
                    sample = sample_bytes(content)
                    ent = calculate_entropy(sample)
                    logger.debug("Sample entropy for %s = %.3f", name, ent)
                    # Configurable threshold
                    ent_threshold = self.get_config_value("entropy_threshold", 7.8)
                    if ent > ent_threshold:
                        logger.info("High entropy in %s (%.3f) - skipping packing to avoid corruption", name, ent)
                        continue

                    # Do not actually encrypt/modify here without explicit opt-in
                    # Instead, record metadata in sidecar and optionally write to a non-exec section
                    self.packed_metadata.append({
                        "section": name,
                        "size": size,
                        "entropy": ent,
                        "action": "would_pack"  # actionable, not performed
                    })
                except AttributeError as e:
                    logger.error(f"Failed to process section {name}: {e}")
                    continue
                except Exception as e:
                    logger.exception(f"Unexpected error processing section {name}")
                    continue

            # If we made it here and not dry-run, optionally create a metadata-only non-exec section
            if not self.dry_run:
                try:
                    # create metadata payload (JSON) and add to a non-exec section
                    import json
                    payload = json.dumps({"packed_metadata": self.packed_metadata}).encode("utf-8")
                    
                    # Encrypt metadata section if encryption is enabled
                    if self.encryption_enabled:
                        try:
                            # Add binary-specific context for key derivation
                            import hashlib
                            binary_context = hashlib.sha256(binary.path.encode()).digest() if hasattr(binary, 'path') else b""
                            encryption_key, hmac_key, salts = derive_secure_key(self.key_path, binary_context=binary_context)
                            encrypted_payload = encrypt_bytes_aesgcm(encryption_key, payload)["ciphertext"]
                            payload = encrypted_payload
                            logger.info("Encrypted metadata section")
                        except Exception as e:
                            logger.error(f"Failed to encrypt metadata section: {e}")
                            return False
                    
                    # Add new section safely as readable non-exec
                    try:
                        # For PE, use add_section; for ELF, use appropriate builder calls
                        # Use duck-typing and LIEF API for your format
                        new_section_name = ".cgo_meta"
                        if self.format == "PE":
                            # Create a proper Section object
                            section_obj = lief.PE.Section(new_section_name)
                            section_obj.content = list(payload)
                            sec = binary.add_section(section_obj)
                            # ensure non-exec flags
                            sec.characteristics &= ~lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE.value
                        else:
                            # Create a proper Section object
                            section_obj = lief.PE.Section(new_section_name)
                            section_obj.content = list(payload)
                            sec = binary.add_section(section_obj)
                        logger.info("Added metadata section %s (len=%d)", new_section_name, len(payload))
                    except Exception as e:
                        logger.error(f"Failed to modify binary: {e}")
                        return False
                    except Exception as e:
                        logger.error(f"Failed to add metadata section: {e}")
                        return False

                    # Save using builder helper
                    out = self.get_config_value("output_path", "packed_output.bin")
                    return save_packed_binary(binary, out, self.format)
                except IOError as e:
                    logger.error(f"Failed to save binary: {e}")
                    return False
                except Exception as e:
                    logger.exception("Unexpected error during binary saving")
                    return False

            return True
        except Exception as e:
            logger.exception("Unexpected transformation error")
            return False
            
    def save_packed_binary(self, rewriter, output_path: str) -> bool:
        """
        Save the packed binary to a file.
        """
        try:
            if not rewriter or not hasattr(rewriter, 'binary') or not rewriter.binary:
                logger.error("No binary to save")
                return False
                
            binary = rewriter.binary
            fmt = detect_format(binary)
            
            # Use proper builder based on format
            result = save_packed_binary(binary, output_path, fmt)
            if result:
                logger.info("Successfully saved packed binary to %s", output_path)
            else:
                logger.error("Failed to save packed binary")
            return result
        except Exception as e:
            logger.exception("Failed to save packed binary: %s", e)
            return False

def get_plugin(config):
    """Factory function to get analysis plugin instance"""
    # Extract the config dictionary from ConfigManager
    if hasattr(config, 'config_data'):
        # Framework ConfigManager
        config_dict = config.config_data
    elif hasattr(config, 'config'):
        # Plugin ConfigManager or dict-like object
        config_dict = config.config
    else:
        # Assume it's already a dictionary
        config_dict = config
    return PackerPlugin(config_dict)

def get_transform_plugin(config):
    """Factory function to get transformation plugin instance"""
    # Extract the config dictionary from ConfigManager
    if hasattr(config, 'config_data'):
        # Framework ConfigManager
        config_dict = config.config_data
    elif hasattr(config, 'config'):
        # Plugin ConfigManager or dict-like object
        config_dict = config.config
    else:
        # Assume it's already a dictionary
        config_dict = config
    return PackerTransformationPlugin(config_dict)