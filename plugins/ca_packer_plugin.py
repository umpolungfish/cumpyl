"""CA-based binary packer plugin for the cumpyl framework"""
import os
import sys
import logging
from typing import Dict, Any
from plugins.base_plugin import BasePlugin
from cumpyl_package.plugin_manager import AnalysisPlugin, TransformationPlugin

# Add the ca_packer directory to the Python path
_ca_packer_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ca_packer')
if _ca_packer_path not in sys.path:
    sys.path.insert(0, _ca_packer_path)

# Import the CA packer modules
try:
    import ca_engine
    import crypto_engine
    import packer_fixed_final
    CA_PACKER_AVAILABLE = True
except ImportError as e:
    logging.error(f"Failed to import CA packer modules: {e}")
    CA_PACKER_AVAILABLE = False

# Set up logging
logger = logging.getLogger(__name__)

def calculate_entropy(data: bytes) -> float:
    """Simple entropy calculation wrapper for backward compatibility."""
    if not data:
        return 0.0
    
    # Simple entropy calculation
    import math
    from collections import Counter
    
    if len(data) == 0:
        return 0.0
        
    counts = Counter(data)
    probabilities = [count / len(data) for count in counts.values()]
    entropy = -sum(p * math.log2(p) for p in probabilities)
    return entropy

class CAPackerPlugin(AnalysisPlugin, BasePlugin):
    """CA-based binary packer analysis plugin for cumpyl framework"""
    
    def __init__(self, config):
        # Initialize both parent classes
        BasePlugin.__init__(self, config)
        AnalysisPlugin.__init__(self, config)
        self.name = "ca_packer"
        self.version = "1.0.0"
        self.description = "CA-based binary packer and obfuscator with compression and encryption"
        self.author = "Cumpyl Framework Team"
        self.dependencies = []
        
    def analyze(self, rewriter) -> Dict[str, Any]:
        """Analyze binary for CA packing opportunities"""
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
                # Detect format (simplified)
                fmt = "UNKNOWN"
                if hasattr(binary, 'header'):
                    # For PE files
                    if hasattr(binary.header, 'signature'):
                        if binary.header.signature == 0x5A4D:  # PE signature (MZ)
                            fmt = "PE"
                    # For ELF files
                    elif hasattr(binary.header, 'identity'):
                        if binary.header.identity == b"\x7fELF":
                            fmt = "ELF"
                    # Alternative way to detect PE files
                    elif hasattr(binary, 'format') and binary.format == lief.Binary.FORMATS.PE:
                        fmt = "PE"
                    # Alternative way to detect ELF files
                    elif hasattr(binary, 'format') and binary.format == lief.Binary.FORMATS.ELF:
                        fmt = "ELF"
                
                results["analysis"]["binary_format"] = fmt
                results["analysis"]["binary_size"] = getattr(binary, 'original_size', 0) or (len(binary.content) if hasattr(binary, 'content') else 0)
                results["analysis"]["sections_count"] = len(getattr(binary, 'sections', []))
                
                # Analyze sections for packing potential
                for section in getattr(binary, 'sections', []):
                    section_info = {
                        "name": getattr(section, 'name', '<unnamed>'),
                        "size": len(bytes(getattr(section, 'content', b''))),
                        "virtual_address": getattr(section, 'virtual_address', 0),
                        "is_executable": False,  # Simplified
                        "is_readable": True,
                        "is_writable": False
                    }
                    results["analysis"]["sections"].append(section_info)
                    
                    # Look for packing opportunities
                    if section_info["size"] > 1024:  # Only consider sections larger than 1KB
                        opportunity = {
                            "section": section_info["name"],
                            "size": section_info["size"],
                            "type": "compression_candidate",
                            "virtual_address": section_info["virtual_address"],
                            "is_writable": section_info["is_writable"]
                        }
                        results["analysis"]["packing_opportunities"].append(opportunity)
                        
                    # Additional analysis for unpacking detection
                    if section_info["size"] > 0:
                        # Check for high entropy which might indicate packed code
                        section_content = bytes(getattr(section, 'content', b''))
                        if len(section_content) > 0 and len(section_content) <= 65536:  # Limit for performance
                            entropy = calculate_entropy(section_content)
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

class CAPackerTransformationPlugin(TransformationPlugin, BasePlugin):
    """CA-based binary packer transformation plugin for cumpyl framework"""
    
    def __init__(self, config):
        # Initialize both parent classes
        BasePlugin.__init__(self, config)
        TransformationPlugin.__init__(self, config)
        self.name = "ca_packer_transform"
        self.version = "1.0.0"
        self.description = "CA-based binary packer transformation plugin"
        self.author = "Cumpyl Framework Team"
        self.dependencies = ["ca_packer"]
        
        # Packer configuration
        self.compression_level = self.get_config_value('compression_level', 6)
        self.key_path = self.get_config_value('key_path', None)
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
        """Prepare for CA packing transformation"""
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
            logger.info("Detected format: %s", self.format or "UNKNOWN")

            # Dry-run: collect what *would* be changed and return without writing
            if self.dry_run:
                logger.info("Dry-run mode: reporting changes without modifying binary")
                # build report here...
                return True

            # If encryption requested, validate key
            if self.encryption_enabled:
                try:
                    # For now, we'll just check if the key file exists
                    if not os.path.exists(self.key_path):
                        logger.error(f"Key file not found: {self.key_path}")
                        return False
                except Exception as e:
                    logger.error(f"Invalid encryption key: {e}")
                    return False

            # Use the CA packer to pack the binary
            try:
                # Get the input binary path
                input_path = getattr(binary, 'path', None)
                if not input_path:
                    logger.error("Cannot determine input binary path")
                    return False

                # Set CA steps
                ca_engine.NUM_STEPS = self.ca_steps

                # Generate output path
                output_path = self.get_config_value("output_path", "ca_packed_output.bin")

                # Pack the binary using the CA packer
                packer_fixed_final.pack_binary(input_path, output_path)

                logger.info("Successfully packed binary using CA packer")
                return True
            except Exception as e:
                logger.exception("Failed to pack binary with CA packer")
                return False

        except Exception as e:
            logger.exception("Unexpected transformation error")
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
    return CAPackerPlugin(config_dict)

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
    return CAPackerTransformationPlugin(config_dict)