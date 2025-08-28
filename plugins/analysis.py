"""Analysis functions for Go binary detection and entropy analysis"""
import lief
import logging
from typing import Dict, Any, List, Tuple
from .consolidated_utils import detect_format, is_executable_section
from .utils import calculate_entropy, fast_entropy

logger = logging.getLogger(__name__)

def find_go_build_id(binary) -> Dict[str, Any]:
    """Find Go build ID in binary with detailed evidence"""
    result = {
        "detected": False,
        "method": None,
        "evidence": {},
        "confidence": 0.0
    }
    
    try:
        format_type = detect_format(binary)
        if format_type == "UNKNOWN":
            return result
            
        # Method 1: Look for Go-specific sections
        for section in binary.sections:
            if section.name == ".go.buildid":
                content = bytes(section.content)
                result["detected"] = True
                result["method"] = "go_buildid_section"
                result["evidence"] = {
                    "section": section.name,
                    "size": len(content)
                }
                result["confidence"] = 0.95
                return result
        
        # Method 2: Look for other Go-specific sections
        go_sections = [".gopclntab", ".go.buildinfo"]
        for section in binary.sections:
            if section.name in go_sections:
                result["detected"] = True
                result["method"] = "go_section"
                result["evidence"] = {
                    "section": section.name,
                    "size": section.size
                }
                result["confidence"] = 0.9
                return result
        
        # Method 3: Look for Go-specific strings in the binary
        go_strings = [b"runtime.", b"go.buildid", b"GOROOT", b"GOPATH"]
        found_strings = []
        for section in binary.sections:
            try:
                content = bytes(section.content)
                for go_string in go_strings:
                    if go_string in content:
                        found_strings.append(go_string.decode('utf-8', errors='ignore'))
            except Exception:
                continue
                
        if found_strings:
            result["detected"] = True
            result["method"] = "go_strings"
            result["evidence"] = {
                "strings": found_strings
            }
            result["confidence"] = 0.7
            return result
            
        # Method 4: Look for Go-specific function names or symbols (if available)
        if hasattr(binary, 'symbols'):
            go_symbol_patterns = ["main.main", "runtime.", "go.buildid"]
            found_symbols = []
            for symbol in binary.symbols:
                for pattern in go_symbol_patterns:
                    if pattern in symbol.name:
                        found_symbols.append(symbol.name)
                        
            if found_symbols:
                result["detected"] = True
                result["method"] = "go_symbols"
                result["evidence"] = {
                    "symbols": found_symbols
                }
                result["confidence"] = 0.8
                return result
                
    except (AttributeError, ValueError) as e:
        logger.error(f"Error in find_go_build_id: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error in find_go_build_id: {e}")
        raise
        
    return result

def calculate_entropy_with_confidence(data: bytes, section_size: int = 0) -> Dict[str, Any]:
    """Calculate the entropy of a byte sequence with confidence metrics"""
    result = {
        "value": 0.0,
        "confidence": 0.0,
        "interpretation": ""
    }
    
    if not data or len(data) == 0:
        return result
        
    # For very small sections, entropy is unreliable
    if 0 < section_size < 256 or len(data) < 256:
        result["confidence"] = 0.1
        result["interpretation"] = "too_small_for_reliable_entropy"
        return result
    
    try:
        # Use the centralized entropy calculation function
        entropy_value = fast_entropy(data)  # Use fast entropy calculation
        result["value"] = entropy_value
        
        # Set confidence based on data size
        data_len = len(data)
        if data_len > 1024:
            result["confidence"] = 0.9
        elif data_len > 512:
            result["confidence"] = 0.7
        else:
            result["confidence"] = 0.5
            
        # Interpretation
        if entropy_value > 7.5:
            result["interpretation"] = "high_entropy_packed"
        elif entropy_value > 6.0:
            result["interpretation"] = "medium_entropy"
        else:
            result["interpretation"] = "low_entropy"
            
    except (AttributeError, ValueError) as e:
        logger.error(f"Error calculating entropy: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error calculating entropy: {e}")
        raise
        
    return result

def analyze_sections_for_packing(binary) -> List[Dict[str, Any]]:
    """Analyze sections for packing opportunities with optimized performance"""
    opportunities = []
    format_type = detect_format(binary)
    
    try:
        section_cache = []  # Cache for reuse
        for section in binary.sections:
            content = bytes(section.content) if hasattr(section, 'content') else b''
            size = len(content)
            info = {
                "name": section.name,
                "size": size,
                "virtual_address": getattr(section, 'virtual_address', 0),
                "is_executable": is_executable_section(section, format_type),
                "entropy": fast_entropy(content) if size > 0 else None  # Use fast entropy
            }
            section_cache.append(info)
            
            # Add opportunities based on entropy...
            # Calculate entropy for executable sections
            if info["is_executable"] and content:
                try:
                    entropy_result = calculate_entropy_with_confidence(content, info["size"])
                    
                    # Add as opportunity if high entropy
                    if entropy_result["value"] > 7.5 and entropy_result["confidence"] > 0.7:
                        opportunities.append({
                            "section": section.name,
                            "size": info["size"],
                            "type": "high_entropy_executable",
                            "entropy": entropy_result["value"],
                            "confidence": entropy_result["confidence"],
                            "recommendation": "May be already packed"
                        })
                except Exception as e:
                    logger.error(f"Error analyzing section {section.name}: {e}")
                    
            # Extend to check for low entropy data sections that might benefit from compression
            if not info["is_executable"] and content:
                entropy_result = calculate_entropy_with_confidence(content, info["size"])
                
                # Add as opportunity if low entropy (good compression candidate)
                if entropy_result["value"] < 6.0 and entropy_result["confidence"] > 0.7:
                    opportunities.append({
                        "section": section.name,
                        "size": info["size"],
                        "type": "low_entropy_data",
                        "entropy": entropy_result["value"],
                        "confidence": entropy_result["confidence"],
                        "recommendation": "Good candidate for compression"
                    })
                    
    except (AttributeError, ValueError) as e:
        logger.error(f"Error in analyze_sections_for_packing: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error in analyze_sections_for_packing: {e}", exc_info=True)
        raise
        
    return opportunities