#!/usr/bin/env python3
"""
Payload Transmutation Plugin for Cumpyl Framework
Integrates sc8r payload transmutation capabilities with cumpyl's plugin system
"""

import os
import sys
from typing import Dict, Any, List
from cumpyl_package.plugin_manager import AnalysisPlugin, TransformationPlugin
from cumpyl_package.transmuter import PayloadTransmuter, TransmuteConfig, TransmuteMethod, PayloadLibrary

class TransmuterPlugin(AnalysisPlugin):
    """Payload transmutation analysis plugin for cumpyl framework"""
    
    def __init__(self, config):
        super().__init__(config)
        self.name = "transmuter"
        self.version = "1.0.0"
        self.description = "Payload transmutation and obfuscation plugin with multiple encoding methods"
        self.author = "Cumpyl Framework Team"
        self.dependencies = []
        
        # Initialize transmuter
        self.transmuter_config = TransmuteConfig()
        self.transmuter = PayloadTransmuter(self.transmuter_config)
    
    def analyze(self, rewriter) -> Dict[str, Any]:
        """Analyze binary for potential payload injection points and obfuscation opportunities"""
        results = {
            "plugin_name": self.name,
            "version": self.version,
            "description": self.description,
            "capabilities": [method.value for method in TransmuteMethod],
            "templates": PayloadLibrary.list_categories(),
            "analysis": {
                "binary_size": 0,
                "sections_count": 0,
                "sections": []
            },
            "suggestions": []
        }
        
        # Add binary information if available
        if rewriter is not None and hasattr(rewriter, 'binary') and rewriter.binary is not None:
            try:
                results["analysis"]["binary_size"] = getattr(rewriter.binary, 'original_size', 0) or (len(rewriter.binary.content) if hasattr(rewriter.binary, 'content') else 0)
                results["analysis"]["sections_count"] = len(rewriter.binary.sections) if hasattr(rewriter.binary, 'sections') else 0
                
                # Analyze sections for obfuscation potential
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
                    
                    # Suggest obfuscation for non-executable sections
                    if not section_info["is_executable"] and section_info["size"] > 0:
                        suggestion = {
                            "section": section.name,
                            "size": section_info["size"],
                            "suggested_methods": ["hex", "base64", "unicode"],
                            "risk_level": "low" if section_info["is_writable"] else "medium"
                        }
                        results["suggestions"].append(suggestion)
            except Exception as e:
                results["error"] = f"Analysis failed: {str(e)}"
        
        return results
    
    def _is_executable_section(self, section) -> bool:
        """Check if a section is executable"""
        try:
            # PE files
            if hasattr(section, 'characteristics'):
                import lief
                return bool(section.characteristics & lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE)
            # ELF files
            elif hasattr(section, 'flags'):
                import lief
                return bool(section.flags & lief.ELF.SECTION_FLAGS.EXECINSTR)
        except:
            pass
        return False
    
    def _is_readable_section(self, section) -> bool:
        """Check if a section is readable"""
        try:
            # PE files
            if hasattr(section, 'characteristics'):
                import lief
                return bool(section.characteristics & lief.PE.SECTION_CHARACTERISTICS.MEM_READ)
            # ELF files
            elif hasattr(section, 'flags'):
                import lief
                return bool(section.flags & lief.ELF.SECTION_FLAGS.ALLOC)
        except:
            pass
        return True
    
    def _is_writable_section(self, section) -> bool:
        """Check if a section is writable"""
        try:
            # PE files
            if hasattr(section, 'characteristics'):
                import lief
                return bool(section.characteristics & lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE)
            # ELF files
            elif hasattr(section, 'flags'):
                import lief
                return bool(section.flags & lief.ELF.SECTION_FLAGS.WRITE)
        except:
            pass
        return False
    
    def _is_executable_section(self, section) -> bool:
        """Check if a section is executable"""
        try:
            # PE files
            if hasattr(section, 'characteristics'):
                import lief
                return bool(section.characteristics & lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE)
            # ELF files
            elif hasattr(section, 'flags'):
                import lief
                return bool(section.flags & lief.ELF.SECTION_FLAGS.EXECINSTR)
        except:
            pass
        return False
    
    def _is_readable_section(self, section) -> bool:
        """Check if a section is readable"""
        try:
            # PE files
            if hasattr(section, 'characteristics'):
                import lief
                return bool(section.characteristics & lief.PE.SECTION_CHARACTERISTICS.MEM_READ)
            # ELF files
            elif hasattr(section, 'flags'):
                import lief
                return bool(section.flags & lief.ELF.SECTION_FLAGS.ALLOC)
        except:
            pass
        return True
    
    def _is_writable_section(self, section) -> bool:
        """Check if a section is writable"""
        try:
            # PE files
            if hasattr(section, 'characteristics'):
                import lief
                return bool(section.characteristics & lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE)
            # ELF files
            elif hasattr(section, 'flags'):
                import lief
                return bool(section.flags & lief.ELF.SECTION_FLAGS.WRITE)
        except:
            pass
        return False

class TransmuterTransformationPlugin(TransformationPlugin):
    """Payload transmutation transformation plugin for cumpyl framework"""
    
    def __init__(self, config):
        super().__init__(config)
        self.name = "transmuter_transform"
        self.version = "1.0.0"
        self.description = "Payload transmutation transformation plugin"
        self.author = "Cumpyl Framework Team"
        self.dependencies = ["transmuter"]
        
        # Initialize transmuter
        self.transmuter_config = TransmuteConfig()
        self.transmuter = PayloadTransmuter(self.transmuter_config)
    
    def analyze(self, rewriter) -> Dict[str, Any]:
        """Prepare for transformation - this is a placeholder"""
        return {
            "plugin_name": self.name,
            "version": self.version,
            "description": self.description
        }
    
    def transform(self, rewriter, analysis_result: Dict[str, Any]) -> bool:
        """Transform binary with payload transmutation techniques"""
        # This is where we would implement actual payload injection
        # For now, we'll just return True to indicate the plugin is working
        return True

# Utility functions for direct use in cumpyl
def transmute_payload(payload: str, method: str = "null_padding", **kwargs) -> str:
    """Transmute a payload using specified method"""
    config = TransmuteConfig()
    transmuter = PayloadTransmuter(config)
    
    try:
        method_enum = TransmuteMethod(method)
        result = transmuter.transmute(payload, method_enum, **kwargs)
        if isinstance(result, dict):
            # For mixed encoding, return the first result
            return list(result.values())[0] if result else ""
        return result
    except Exception as e:
        print(f"Error transmuting payload: {e}")
        return payload

def get_transmuter_methods() -> List[str]:
    """Get list of available transmutation methods"""
    return [method.value for method in TransmuteMethod]

def get_payload_templates() -> List[str]:
    """Get list of available payload templates"""
    return PayloadLibrary.list_categories()

def get_template_payloads(template: str) -> List[str]:
    """Get payloads for a specific template"""
    return PayloadLibrary.get_payloads(template)

def get_plugin(config):
    """Factory function to get plugin instance"""
    return TransmuterPlugin(config)