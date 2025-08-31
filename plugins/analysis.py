"""Analysis functions for Go binary detection and entropy analysis"""
import lief
import logging
import math
from collections import Counter
from typing import Dict, Any, List, Tuple
from plugins.consolidated_utils import detect_format, is_executable_section, calculate_entropy_with_confidence

logger = logging.getLogger(__name__)

logger = logging.getLogger(__name__)

def find_go_build_id(binary) -> Dict[str, Any]:
    """Enhanced Go detection with weighted confidence and version checking."""
    result = {"detected": False, "methods": [], "evidence": {}, "confidence": 0.0, "go_version": None}
    score = 0.0
    
    # Method 1: Go-specific sections (high weight)
    go_sections = [".go.buildid", ".gopclntab", ".go.buildinfo"]
    found_sections = [s.name for s in binary.sections if s.name in go_sections]
    if found_sections:
        result["methods"].append("go_sections")
        result["evidence"]["sections"] = found_sections
        score += 0.4 * len(found_sections) / len(go_sections)
    
    # Method 2: PCLNTAB magic (0xFFFFFFFB or 0xFFFFFFFA)
    for section in binary.sections:
        if section.name == ".gopclntab":
            content = bytes(section.content)
            if content.startswith(b'\xfb\xff\xff\xff') or content.startswith(b'\xfa\xff\xff\xff'):
                result["methods"].append("pclntab_magic")
                score += 0.3
                break
    
    # Method 3: Go build info section for version detection
    for section in binary.sections:
        if section.name == ".go.buildinfo":
            content = bytes(section.content)
            try:
                # Use a more robust approach to handle invalid UTF-8 sequences
                version_info = content.decode('utf-8', errors='replace').split('\n')
                for line in version_info:
                    if line.startswith("go\t"):
                        result["go_version"] = line.split('\t')[1]
                        result["methods"].append("go_buildinfo")
                        score += 0.2
                        break
            except Exception as e:
                logger.debug(f"Failed to parse go.buildinfo: {e}")
    
    # Method 4: Strings (medium weight)
    go_strings = [b"runtime.", b"go.buildid", b"GOROOT", b"GOPATH"]
    found_strings = []
    for section in binary.sections:
        content = bytes(section.content)
        # Use a more robust approach to handle invalid UTF-8 sequences
        try:
            content_str = content.decode('utf-8', errors='replace')
            found_strings.extend([s.decode('utf-8', errors='replace') for s in go_strings if s in content])
        except Exception as e:
            logger.debug(f"Failed to decode section content for string search: {e}")
    if found_strings:
        result["methods"].append("go_strings")
        result["evidence"]["strings"] = list(set(found_strings))
        score += 0.2
    
    # Method 5: Symbols (low weight)
    if hasattr(binary, 'symbols'):
        go_symbols = ["main.main", "runtime.", "go.buildid"]
        found_symbols = [sym.name for sym in binary.symbols for pat in go_symbols if pat in sym.name]
        if found_symbols:
            result["methods"].append("go_symbols")
            result["evidence"]["symbols"] = list(set(found_symbols))
            score += 0.1
    
    result["confidence"] = min(1.0, score)
    result["detected"] = result["confidence"] > 0.5
    return result

def analyze_sections_for_packing(binary) -> List[Dict[str, Any]]:
    """Single-pass section analysis for packing opportunities."""
    opportunities = []
    format_type = detect_format(binary)
    
    for section in binary.sections:
        content = bytes(section.content) if hasattr(section, 'content') else b''
        size = len(content)
        entropy_result = calculate_entropy_with_confidence(content)  # From consolidated_utils
        
        info = {
            "name": section.name,
            "size": size,
            "virtual_address": getattr(section, 'virtual_address', 0),
            "is_executable": is_executable_section(section, format_type),
            "entropy": entropy_result["value"],
            "confidence": entropy_result["confidence"]
        }
        
        # Opportunities in one go
        if info["is_executable"] and entropy_result["value"] > 7.5 and entropy_result["confidence"] > 0.7:
            opportunities.append({
                "section": info["name"], "size": size, "type": "high_entropy_executable",
                "entropy": entropy_result["value"], "confidence": entropy_result["confidence"],
                "recommendation": "May be already packed"
            })
        elif not info["is_executable"] and entropy_result["value"] < 6.0 and entropy_result["confidence"] > 0.7:
            opportunities.append({
                "section": info["name"], "size": size, "type": "low_entropy_data",
                "entropy": entropy_result["value"], "confidence": entropy_result["confidence"],
                "recommendation": "Good candidate for compression"
            })
    
    return opportunities