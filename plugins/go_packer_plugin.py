"""
Go Binary Analysis Plugin for Cumpyl Framework

This plugin performs analysis-only detection of Go binaries and identifies
potential packing opportunities. It does not perform any binary transformations.

Ethical Use Notice:
- This plugin is for research and educational purposes only
- Only analyze binaries you own or have explicit authorization to examine
- Do not use for malicious purposes

Technical Documentation:
For detailed technical information about the implementation, see plugins/TECHNICAL_DOCS.md
"""
import logging
import os
from typing import Dict, Any, List, Optional
from cumpyl_package.plugin_manager import AnalysisPlugin
import lief
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import our new modules
from plugins.analysis import find_go_build_id
from plugins.analysis_utils import analyze_binary_sections
from plugins.consolidated_utils import detect_format, is_executable_section, is_readable_section, is_writable_section, calculate_entropy_with_confidence
from plugins.crypto_utils import safe_hash
from plugins.config_manager import ConfigManager
from plugins.transform import create_transformation_plan, apply_transformation_plan
from plugins.logging_config import setup_logging

# Set up structured logging
setup_logging()
logger = logging.getLogger(__name__)

class GoBinaryAnalysisPlugin(AnalysisPlugin):
    """
    Analysis-only plugin for detecting Go binaries and packing opportunities.
    
    This plugin follows a strict analysis-only approach:
    1. Detects Go binaries using multiple heuristics with confidence scoring
    2. Analyzes sections for potential packing opportunities
    3. Calculates entropy with contextual awareness
    4. Creates transformation plans without executing them
    
    Safety features:
    - No operational packer behavior in mainline code
    - Transformation converted to skeletons that perform metadata-only modifications
    - Clear runtime flag (--allow-transform) required for any modification features
    - Pre-flight validation and dry-run mode
    """
    
    def __init__(self, config):
        """
        Initialize the Go Binary Analysis Plugin.
        
        Args:
            config (ConfigManager): Framework configuration manager
        """
        super().__init__(config)
        self.name = "go_binary_analyzer"
        self.version = "1.0.0"
        self.description = "Analysis-only detection of Go binaries and packing opportunities"
        self.author = "Cumpyl Framework Team"
        self.dependencies = []
        
        # Check for allow-transform flag in config
        # Extract config dict from ConfigManager
        config_dict = {}
        if hasattr(config, 'config_data'):
            config_dict = config.config_data
        elif hasattr(config, 'config'):
            config_dict = config.config
            
        self.allow_transform = config_dict.get('allow_transform', False)
        if self.allow_transform:
            logger.warning("Transformation mode enabled - only use in controlled environments")
            
    def analyze_section(self, section, binary, format_type):
        """Analyze a single section for Go characteristics and packing opportunities."""
        # Early validation
        if section is None:
            logger.warning("Received None section, returning default values")
            return {"name": "unknown", "size": 0, "virtual_address": 0, "is_executable": False, "is_readable": False, "is_writable": False, "entropy": 0.0, "confidence": 0.0}, None
            
        try:
            # Safely extract section name with error handling for Unicode issues
            try:
                section_name = section.name
                # Handle potential Unicode issues in section names
                if isinstance(section_name, bytes):
                    section_name = section_name.decode('utf-8', errors='replace')
                elif not isinstance(section_name, str):
                    section_name = str(section_name)
            except (UnicodeError, AttributeError):
                section_name = "unknown_section"
            
            # Safely extract section content with error handling
            try:
                content = bytes(section.content) if hasattr(section, 'content') else b''
            except (ValueError, TypeError, UnicodeError) as content_error:
                logger.debug(f"Failed to extract content from section {section_name}: {content_error}")
                content = b''
            size = len(content)
            entropy_result = calculate_entropy_with_confidence(content)
            
            section_info = {
                "name": section_name,
                "size": size,
                "virtual_address": getattr(section, 'virtual_address', 0),
                "is_executable": is_executable_section(section, format_type),
                "is_readable": is_readable_section(section, format_type),
                "is_writable": is_writable_section(section, format_type),
                "entropy": entropy_result["value"],
                "confidence": entropy_result["confidence"]
            }
            
            packing_opportunity = None
            if section_info["is_executable"] and entropy_result["value"] > 7.5 and entropy_result["confidence"] > 0.7:
                packing_opportunity = {
                    "section": section_info["name"],
                    "size": size,
                    "type": "high_entropy_executable",
                    "entropy": entropy_result["value"],
                    "confidence": entropy_result["confidence"],
                    "recommendation": "May be already packed"
                }
            elif not section_info["is_executable"] and entropy_result["value"] < 6.0 and entropy_result["confidence"] > 0.7:
                packing_opportunity = {
                    "section": section_info["name"],
                    "size": size,
                    "type": "low_entropy_data",
                    "entropy": entropy_result["value"],
                    "confidence": entropy_result["confidence"],
                    "recommendation": "Good candidate for compression"
                }
            
            return section_info, packing_opportunity
        except Exception as e:
            # Safely handle exception with potential invalid Unicode characters
            try:
                error_msg = str(e)
            except UnicodeError:
                error_msg = repr(e)
            
            # Safely get section name for logging
            try:
                section_name = section.name if section else 'unknown'
                # Handle potential Unicode issues in section names
                if isinstance(section_name, bytes):
                    section_name = section_name.decode('utf-8', errors='replace')
                elif not isinstance(section_name, str):
                    section_name = str(section_name)
            except (UnicodeError, AttributeError):
                section_name = "unknown_section"
                
            logger.error(f"Failed to analyze section {section_name}: {error_msg}")
            
            # Return safe default values
            return {"name": section_name, "size": 0, "virtual_address": 0, "is_executable": False, "is_readable": False, "is_writable": False, "entropy": 0.0, "confidence": 0.0}, None
            
    def analyze(self, rewriter) -> Dict[str, Any]:
        """
        Analyze binary for Go characteristics and packing opportunities.
        
        This method performs comprehensive analysis including:
        1. Format detection (PE/ELF/Mach-O)
        2. Go binary detection with confidence scoring
        3. Section analysis with entropy calculation
        4. Packing opportunity identification
        5. Transformation planning (skeleton only)
        
        Args:
            rewriter: Binary rewriter object containing the binary to analyze
            
        Returns:
            dict: Structured analysis results containing:
                - plugin_name (str): Name of the plugin
                - version (str): Plugin version
                - binary_format (str): Detected binary format
                - analysis (dict): Detailed analysis results
                - transformation_plan (dict): Planned transformations (skeleton only)
                - suggestions (list): Analysis-based suggestions
        """
        results = {
            "plugin_name": self.name,
            "version": self.version,
            "description": self.description,
            "binary_format": "UNKNOWN",
            "analysis": {
                "binary_size": 0,
                "sections_count": 0,
                "sections": [],
                "packing_opportunities": [],
                "go_detection": {
                    "detected": False,
                    "confidence": 0.0,
                    "method": None,
                    "evidence": {}
                }
            },
            "transformation_plan": None,
            "suggestions": []
        }
        
        # Add binary information if available
        if rewriter is not None and hasattr(rewriter, 'binary') and rewriter.binary is not None:
            try:
                binary = rewriter.binary
                format_type = detect_format(binary)
                results["binary_format"] = format_type
                
                if format_type == "UNKNOWN":
                    results["error"] = "Unsupported binary format"
                    return results
                
                # Basic binary info
                results["analysis"]["binary_size"] = getattr(binary, 'original_size', 0) or (len(binary.content) if hasattr(binary, 'content') else 0)
                results["analysis"]["sections_count"] = len(binary.sections) if hasattr(binary, 'sections') else 0
                
                # Check if it's a Go binary using improved detection
                go_detection = find_go_build_id(binary)
                results["analysis"]["go_detection"] = go_detection
                
                # Use shared section analysis
                sections_info, packing_opportunities = analyze_binary_sections(binary, format_type)
                results["analysis"]["sections"] = sections_info
                results["analysis"]["packing_opportunities"] = packing_opportunities
                
                # Create transformation plan (skeleton only)
                plan = create_transformation_plan(binary, results)
                results["transformation_plan"] = {
                    "actions_count": len(plan.actions),
                    "actions": plan.actions,
                    "metadata": plan.metadata
                }
                
                # Apply transformation skeleton if allowed
                if self.allow_transform:
                    success, report = apply_transformation_plan(binary, plan, allow_transform=True)
                    if report:
                        results["transformation_report"] = report
                
                # Add suggestions based on analysis
                if go_detection["detected"]:
                    results["suggestions"].append({
                        "type": "go_binary_detected",
                        "confidence": go_detection["confidence"],
                        "description": f"Go binary detected via {go_detection['method']}",
                        "recommendation": "For research purposes, examine sections for data protection techniques"
                    })
                    
                # Suggest analysis of large sections
                large_sections = [s for s in results["analysis"]["sections"] if s["size"] > 2048]
                if large_sections:
                    results["suggestions"].append({
                        "type": "large_sections",
                        "count": len(large_sections),
                        "description": f"Found {len(large_sections)} large sections",
                        "recommendation": "Analyze for data compression opportunities"
                    })
                    
            except Exception as e:
                # Safely handle exception with potential invalid Unicode characters
                try:
                    error_msg = str(e)
                except UnicodeError:
                    error_msg = repr(e)
                
                # Safely log the error message to avoid Unicode issues
                try:
                    logger.error(f"Analysis failed: {error_msg}", exc_info=True)
                    results["error"] = f"Analysis failed: {error_msg}"
                except UnicodeError:
                    logger.error("Analysis failed: Unicode error in error message", exc_info=True)
                    results["error"] = "Analysis failed: Unicode error in error message"
        
        return results

def get_analysis_plugin(config):
    """
    Factory function to get analysis plugin instance.
    
    Args:
        config (dict): Configuration dictionary
        
    Returns:
        GoBinaryAnalysisPlugin: Analysis plugin instance
    """
    # Extract the config dictionary from ConfigManager
    config_dict = config.config if hasattr(config, 'config') else config
    return GoBinaryAnalysisPlugin(config_dict)

def get_transformation_plugin(config):
    """
    Factory function to get transformation plugin instance.
    
    Args:
        config (dict): Configuration dictionary
        
    Returns:
        GoBinaryAnalysisPlugin: Transformation plugin instance
    """
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
    return GoBinaryAnalysisPlugin(config_dict)

def get_plugins(config):
    """
    Factory function to get all available plugin instances.
    
    Args:
        config (dict): Configuration dictionary
        
    Returns:
        dict: Dictionary containing analysis and transformation plugin instances
    """
    # Extract the config dictionary from ConfigManager
    config_dict = config.config if hasattr(config, 'config') else config
    return {
        "analysis": get_analysis_plugin(config_dict),
        "transformation": get_transformation_plugin(config_dict)
    }
