"""Centralized utility functions for binary analysis."""
import lief
import logging
import math
from collections import Counter
from typing import Dict, Any

logger = logging.getLogger(__name__)

def detect_format(binary: Any) -> str:
    """Detect binary format (PE, ELF, MACHO, or UNKNOWN)."""
    if not binary:
        raise ValueError("Binary object is None")
    try:
        fmt = binary.format
        if fmt == lief.Binary.FORMATS.PE:
            return "PE"
        elif fmt == lief.Binary.FORMATS.ELF:
            return "ELF"
        elif fmt == lief.Binary.FORMATS.MACHO:
            return "MACHO"
    except AttributeError:
        logger.warning("Binary lacks 'format' attribute; falling back to header check")
        if hasattr(binary, "header") and hasattr(binary.header, "machine"):
            return "ELF/PE"  # Crude fallback
    except Exception as e:
        logger.error(f"Format detection failed: {e}")
    return "UNKNOWN"

def is_executable_section(section: Any, binary_format: str) -> bool:
    """Check if a section is executable, handling LIEF and mock objects."""
    if not section:
        return False
    try:
        if binary_format == "PE":
            chars = section.characteristics if hasattr(section, 'characteristics') else section.characteristics_value
            return bool(chars & lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE)
        elif binary_format == "ELF":
            flags = section.flags if hasattr(section, 'flags') else section.flags_value
            return bool(flags & lief.ELF.SECTION_FLAGS.EXECINSTR)
        elif binary_format == "MACHO":
            if hasattr(section, 'segment') and hasattr(section.segment, 'flags'):
                return bool(section.segment.flags & lief.MachO.SEGMENT_FLAGS.VM_PROT_EXECUTE)
    except Exception as e:
        logger.error(f"Executable check failed for section: {e}")
    return False

def is_readable_section(section: Any, binary_format: str) -> bool:
    """Check if a section is readable, handling LIEF and mock objects."""
    if not section:
        return False
    try:
        if binary_format == "PE":
            chars = section.characteristics if hasattr(section, 'characteristics') else section.characteristics_value
            return bool(chars & lief.PE.SECTION_CHARACTERISTICS.MEM_READ)
        elif binary_format == "ELF":
            flags = section.flags if hasattr(section, 'flags') else section.flags_value
            return bool(flags & lief.ELF.SECTION_FLAGS.ALLOC)
        elif binary_format == "MACHO":
            if hasattr(section, 'segment') and hasattr(section.segment, 'flags'):
                return bool(section.segment.flags & lief.MachO.SEGMENT_FLAGS.VM_PROT_READ)
            return True  # Simplified for Mach-O
    except Exception as e:
        logger.error(f"Readable check failed for section: {e}")
    return True

def is_writable_section(section: Any, binary_format: str) -> bool:
    """Check if a section is writable, handling LIEF and mock objects."""
    if not section:
        return False
    try:
        if binary_format == "PE":
            chars = section.characteristics if hasattr(section, 'characteristics') else section.characteristics_value
            return bool(chars & lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE)
        elif binary_format == "ELF":
            flags = section.flags if hasattr(section, 'flags') else section.flags_value
            return bool(flags & lief.ELF.SECTION_FLAGS.WRITE)
        elif binary_format == "MACHO":
            if hasattr(section, 'segment') and hasattr(section.segment, 'flags'):
                return bool(section.segment.flags & lief.MachO.SEGMENT_FLAGS.VM_PROT_WRITE)
            return False  # Simplified for Mach-O
    except Exception as e:
        logger.error(f"Writable check failed for section: {e}")
    return False

def calculate_entropy(data: bytes, max_samples: int = 65536) -> float:
    """Calculate entropy with efficient sampling for large data."""
    if not data:
        return 0.0
    sample = data if len(data) <= max_samples else (
        data[:max_samples//3] + data[len(data)//2:len(data)//2 + max_samples//3] + data[-max_samples//3:]
    )
    counts = Counter(sample)
    data_len = len(sample)
    entropy = sum(- (count / data_len) * math.log2(count / data_len) for count in counts.values())
    return entropy