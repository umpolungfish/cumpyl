"""Shared analysis functions for binary analysis plugins."""

from typing import Dict, Any, List, Tuple
from plugins.consolidated_utils import detect_format, is_executable_section, is_readable_section, is_writable_section, calculate_entropy_with_confidence

def analyze_binary_sections(binary, format_type: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Analyze binary sections for characteristics and packing opportunities."""
    sections_info = []
    packing_opportunities = []
    
    for section in getattr(binary, 'sections', []):
        try:
            content = bytes(section.content) if hasattr(section, 'content') else b''
        except (ValueError, TypeError, UnicodeError):
            continue
        size = len(content)
        entropy_result = calculate_entropy_with_confidence(content)
        
        section_info = {
            "name": section.name,
            "size": size,
            "virtual_address": getattr(section, 'virtual_address', 0),
            "is_executable": is_executable_section(section, format_type),
            "is_readable": is_readable_section(section, format_type),
            "is_writable": is_writable_section(section, format_type),
            "entropy": entropy_result["value"],
            "confidence": entropy_result["confidence"]
        }
        sections_info.append(section_info)
        
        # Identify packing opportunities
        if section_info["is_executable"] and entropy_result["value"] > 7.5 and entropy_result["confidence"] > 0.7:
            packing_opportunities.append({
                "section": section_info["name"],
                "size": size,
                "type": "high_entropy_executable",
                "entropy": entropy_result["value"],
                "confidence": entropy_result["confidence"],
                "recommendation": "May be already packed"
            })
        elif not section_info["is_executable"] and entropy_result["value"] < 6.0 and entropy_result["confidence"] > 0.7:
            packing_opportunities.append({
                "section": section_info["name"],
                "size": size,
                "type": "low_entropy_data",
                "entropy": entropy_result["value"],
                "confidence": entropy_result["confidence"],
                "recommendation": "Good candidate for compression"
            })
    
    return sections_info, packing_opportunities