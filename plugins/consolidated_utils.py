"""Centralized utility functions for binary analysis."""
import lief
import logging
import math
import secrets
import hashlib
from collections import Counter
from typing import Dict, Any
from functools import lru_cache

# Optional numpy import for fast path
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    np = None
    HAS_NUMPY = False

logger = logging.getLogger(__name__)

def detect_format_enhanced(binary: Any) -> Dict[str, Any]:
    """Enhanced binary format detection with confidence scoring."""
    result = {
        "format": "UNKNOWN",
        "confidence": 0.0,
        "details": {}
    }
    
    # Method 1: LIEF format detection
    try:
        if hasattr(binary, 'format'):
            fmt = binary.format
            if fmt == lief.Binary.FORMATS.PE:
                result["format"] = "PE"
                result["confidence"] += 0.4
            elif fmt == lief.Binary.FORMATS.ELF:
                result["format"] = "ELF"
                result["confidence"] += 0.4
            elif fmt == lief.Binary.FORMATS.MACHO:
                result["format"] = "MACHO"
                result["confidence"] += 0.4
    except:
        pass
    
    # Method 2: Magic number detection
    try:
        if hasattr(binary, 'content') and binary.content:
            content = bytes(binary.content[:4])
            
            # PE magic
            if content.startswith(b'MZ'):
                result["format"] = "PE"
                result["confidence"] += 0.3
                result["details"]["magic"] = "MZ"
            
            # ELF magic
            elif content.startswith(b'\x7fELF'):
                result["format"] = "ELF"
                result["confidence"] += 0.3
                result["details"]["magic"] = "ELF"
            
            # Mach-O magic
            elif content.startswith((b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', 
                                   b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe')):
                result["format"] = "MACHO"
                result["confidence"] += 0.3
                result["details"]["magic"] = "Mach-O"
    except:
        pass
    
    # Method 3: Section-based detection
    try:
        if hasattr(binary, 'sections'):
            sections = [s.name for s in binary.sections]
            
            # PE sections
            pe_sections = [".text", ".data", ".rdata", ".rsrc"]
            if any(s in sections for s in pe_sections):
                result["format"] = "PE"
                result["confidence"] += 0.2
            
            # ELF sections
            elf_sections = [".text", ".data", ".bss", ".rodata"]
            if any(s in sections for s in elf_sections):
                result["format"] = "ELF"
                result["confidence"] += 0.2
    except:
        pass
    
    return result

@lru_cache(maxsize=32)
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
        logger.warning("Binary lacks 'format' attribute; attempting header-based detection")
        try:
            if hasattr(binary, 'content') and binary.content:
                magic = binary.content[:4]
                if magic == b"\x7fELF":
                    return "ELF"
                elif magic[:2] == b"MZ":
                    return "PE"
                elif magic in (b"\xFE\xED\xFA\xCE", b"\xCE\xFA\xED\xFE", b"\xFE\xED\xFA\xCF", b"\xCF\xFA\xED\xFE"):
                    return "MACHO"
        except Exception as e:
            logger.error(f"Header-based detection failed: {e}")
    return "UNKNOWN"

def is_executable_section(section: Any, binary_format: str) -> bool:
    """Check if a section is executable, handling LIEF and mock objects."""
    if not section:
        return False
    try:
        if binary_format == "PE":
            chars = section.characteristics if hasattr(section, 'characteristics') else section.characteristics_value
            # Get the actual integer value from the enum
            mem_execute = lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE
            if hasattr(mem_execute, 'value'):
                mem_execute = mem_execute.value
            return bool(chars & mem_execute)
        elif binary_format == "ELF":
            flags = section.flags if hasattr(section, 'flags') else section.flags_value
            # For ELF, check if the section has execute permissions using the correct flag
            execinstr_flag = lief.ELF.Section.FLAGS.EXECINSTR.value if hasattr(lief.ELF.Section.FLAGS.EXECINSTR, 'value') else 0x4
            return bool(flags & execinstr_flag)
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
            # Get the actual integer value from the enum
            mem_read = lief.PE.Section.CHARACTERISTICS.MEM_READ
            if hasattr(mem_read, 'value'):
                mem_read = mem_read.value
            return bool(chars & mem_read)
        elif binary_format == "ELF":
            flags = section.flags if hasattr(section, 'flags') else section.flags_value
            # For ELF, check if the section is allocated (readable) using the correct flag
            alloc_flag = lief.ELF.Section.FLAGS.ALLOC.value if hasattr(lief.ELF.Section.FLAGS.ALLOC, 'value') else 0x2
            return bool(flags & alloc_flag)
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
            # Get the actual integer value from the enum
            mem_write = lief.PE.Section.CHARACTERISTICS.MEM_WRITE
            if hasattr(mem_write, 'value'):
                mem_write = mem_write.value
            return bool(chars & mem_write)
        elif binary_format == "ELF":
            flags = section.flags if hasattr(section, 'flags') else section.flags_value
            # For ELF, check if the section is writable using the correct flag
            write_flag = lief.ELF.Section.FLAGS.WRITE.value if hasattr(lief.ELF.Section.FLAGS.WRITE, 'value') else 0x1
            return bool(flags & write_flag)
        elif binary_format == "MACHO":
            if hasattr(section, 'segment') and hasattr(section.segment, 'flags'):
                return bool(section.segment.flags & lief.MachO.SEGMENT_FLAGS.VM_PROT_WRITE)
            return False  # Simplified for Mach-O
    except Exception as e:
        logger.error(f"Writable check failed for section: {e}")
    return False

@lru_cache(maxsize=128)
def calculate_entropy_with_confidence(data: bytes, max_samples: int = 65536) -> Dict[str, Any]:
    """Calculate entropy with stratified sampling, confidence, and interpretation."""
    # Generate a hash of the data for caching
    data_hash = hashlib.sha256(data).hexdigest()
    logger.debug(f"Computing entropy for data hash {data_hash[:16]}...")
    
    if not data:
        return {"value": 0.0, "confidence": 0.0, "interpretation": "empty_data"}
    
    data_len = len(data)
    if data_len <= 256:
        return {"value": 0.0, "confidence": 0.1, "interpretation": "too_small_for_reliable_entropy"}
    
    # Early exit for uniform data
    if len(set(data)) <= 1:
        return {"value": 0.0, "confidence": 0.9, "interpretation": "uniform_data"}
    
    # Stratified sampling
    if data_len > max_samples:
        chunk_size = data_len // (max_samples // 256)
        sample = bytearray()
        for i in range(0, data_len, chunk_size):
            chunk = data[i:i + chunk_size]
            sample.extend(chunk[:256] if len(chunk) > 256 else chunk)
        sample = bytes(sample[:max_samples])
    else:
        sample = data
    
    # Use NumPy fast path if available
    if HAS_NUMPY:
        try:
            # Fast path with NumPy
            counts = np.bincount(np.frombuffer(sample, dtype=np.uint8), minlength=256)
            counts = counts[counts > 0]
            if counts.size == 0:
                return {"value": 0.0, "confidence": 0.1, "interpretation": "no_variety"}
            p = counts / counts.sum()
            entropy = -np.sum(p * np.log2(p))
        except Exception as e:
            logger.warning(f"NumPy entropy calculation failed, falling back to pure Python: {e}")
            # Simplified fallback for small data
            counts = {}
            for b in sample:
                counts[b] = counts.get(b, 0) + 1
            entropy = sum(- (count / len(sample)) * math.log2(count / len(sample)) for count in counts.values() if count > 0)
    else:
        # Simplified fallback for small data
        counts = {}
        for b in sample:
            counts[b] = counts.get(b, 0) + 1
        entropy = sum(- (count / len(sample)) * math.log2(count / len(sample)) for count in counts.values() if count > 0)
    
    confidence = min(1.0, len(sample) / 1024 * 0.9)
    interpretation = "high_entropy_packed" if entropy > 7.5 else "medium_entropy" if entropy > 6.0 else "low_entropy"
    
    return {"value": entropy, "confidence": confidence, "interpretation": interpretation}