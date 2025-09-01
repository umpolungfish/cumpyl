"""CA-based binary packer plugin for the cumpyl framework"""
import os
import sys
import logging
from typing import Dict, Any, List
from cumpyl_package.plugin_manager import AnalysisPlugin, TransformationPlugin
import lief

# Use consolidated utilities
from plugins.consolidated_utils import detect_format, is_executable_section, is_readable_section, is_writable_section, calculate_entropy_with_confidence
from plugins.base_plugin import BasePlugin

# Add the utils directory to the Python path
_utils_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'utils')
if _utils_path not in sys.path:
    sys.path.insert(0, _utils_path)

# Import the CA packer modules
try:
    import ca_packer
    import ca_engine
    import crypto_engine
    CA_PACKER_AVAILABLE = True
except ImportError as e:
    logging.error(f"Failed to import CA packer modules: {e}")
    CA_PACKER_AVAILABLE = False

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
    """CA-based binary packer analysis plugin for cumpyl framework"""
    
    def __init__(self, config):
        # Initialize both parent classes
        BasePlugin.__init__(self, config)
        AnalysisPlugin.__init__(self, config)
        self.name = "packer"
        self.version = "1.2.0"
        self.description = "CA-based binary packer and obfuscator with compression and encryption"
        self.author = "Cumpyl Framework Team"
        self.dependencies = []
        
    def analyze(self, rewriter) -> Dict[str, Any]:
        """Analyze binary for packing opportunities"""
        results = {
            "plugin_name": self.name,
            "version": self.version,
            "description": self.description,
            "capabilities": ["ca_pack", "section_encrypt", "payload_inject"],
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
    """CA-based binary packer transformation plugin for cumpyl framework"""
    
    def __init__(self, config):
        # Initialize both parent classes
        BasePlugin.__init__(self, config)
        TransformationPlugin.__init__(self, config)
        self.name = "packer_transform"
        self.version = "1.2.0"
        self.description = "CA-based binary packer transformation plugin"
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
        self.ca_steps = self.get_config_value("ca_steps", 100)
        self.debug_stub = self.get_config_value("debug_stub", False)
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
        """Transform binary with CA-based packing techniques"""
        try:
            # Validate inputs
            if not rewriter or not getattr(rewriter, "binary", None):
                logger.error("No binary provided for transformation")
                return False

            # Check if CA packer modules are available
            if not CA_PACKER_AVAILABLE:
                logger.error("CA packer modules not available")
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

            # Use the CA packer to pack the binary
            try:
                # Get the input binary path
                input_path = binary.path if hasattr(binary, 'path') else None
                if not input_path:
                    logger.error("Cannot determine input binary path")
                    return False

                # Set CA steps
                ca_engine.NUM_STEPS = self.ca_steps

                # Generate output path
                output_path = self.get_config_value("output_path", "packed_output.bin")

                # Pack the binary using the CA packer
                ca_packer.pack_binary(input_path, output_path)

                logger.info("Successfully packed binary using CA packer")
                return True
            except Exception as e:
                logger.exception("Failed to pack binary with CA packer")
                return False

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