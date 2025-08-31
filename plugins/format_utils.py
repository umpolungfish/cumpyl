"""Format utilities for PE/ELF/Mach-O binary analysis"""
import lief
import logging
from typing import Dict, Any, Tuple
from plugins.consolidated_utils import detect_format, is_executable_section, is_readable_section, is_writable_section

logger = logging.getLogger(__name__)

def section_permissions_from_program_headers(binary, section) -> Dict[str, bool]:
    """Get section permissions from program headers (ELF) with improved error handling."""
    permissions = {"r": False, "w": False, "x": False}
    
    try:
        format_type = detect_format(binary)
        if format_type != "ELF":
            return permissions
        
        # For ELF, check program headers for actual permissions
        for segment in binary.segments:
            if segment.type == lief.ELF.SEGMENT_TYPES.LOAD:
                # Check if section falls within this segment
                section_start = section.virtual_address
                section_end = section.virtual_address + section.size
                
                if (segment.virtual_address <= section_start and 
                    section_end <= segment.virtual_address + segment.physical_size):
                    # Found the segment containing this section
                    if segment.flags & lief.ELF.SEGMENT_FLAGS.R:
                        permissions["r"] = True
                    if segment.flags & lief.ELF.SEGMENT_FLAGS.W:
                        permissions["w"] = True
                    if segment.flags & lief.ELF.SEGMENT_FLAGS.X:
                        permissions["x"] = True
                    break
    except (AttributeError, ValueError) as e:
        logger.error(f"Error getting section permissions from program headers: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error getting section permissions: {e}")
        raise
    
    return permissions

def create_section_for_format(format_type: str, name: str, content: bytes = None) -> Any:
    """Create a section object appropriate for the binary format."""
    try:
        if format_type == "PE":
            section = lief.PE.Section(name)
            if content:
                section.content = list(content)
        elif format_type == "ELF":
            section = lief.ELF.Section(name)
            if content:
                section.content = list(content)
            # Set default flags for ELF sections
            section.flags = lief.ELF.SECTION_FLAGS.ALLOC
        elif format_type == "MACHO":
            # For Mach-O, we might need to handle this differently depending on the specific use case
            section = lief.PE.Section(name)  # Fallback to PE section for now
            if content:
                section.content = list(content)
        else:
            # Unknown format, fallback to PE section
            section = lief.PE.Section(name)
            if content:
                section.content = list(content)
        
        return section
    except Exception as e:
        logger.error(f"Error creating section for format {format_type}: {e}")
        raise