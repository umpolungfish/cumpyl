"""Strategy pattern for format-specific operations."""
from abc import ABC, abstractmethod
from typing import Dict, Any
import lief

class FormatStrategy(ABC):
    """Abstract base class for format-specific operations."""
    
    @abstractmethod
    def is_executable_section(self, section) -> bool:
        pass
    
    @abstractmethod
    def is_readable_section(self, section) -> bool:
        pass
    
    @abstractmethod
    def is_writable_section(self, section) -> bool:
        pass
    
    @abstractmethod
    def add_section(self, binary, name: str, content: bytes, permissions: Dict[str, bool]) -> Any:
        pass

class PEFormatStrategy(FormatStrategy):
    """PE format-specific operations."""
    
    def is_executable_section(self, section) -> bool:
        return bool(section.characteristics & lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE)
    
    def is_readable_section(self, section) -> bool:
        return bool(section.characteristics & lief.PE.SECTION_CHARACTERISTICS.MEM_READ)
    
    def is_writable_section(self, section) -> bool:
        return bool(section.characteristics & lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE)
    
    def add_section(self, binary, name: str, content: bytes, permissions: Dict[str, bool]) -> Any:
        section = binary.add_section(name, list(content))
        characteristics = 0
        if permissions.get('r', True):
            characteristics |= lief.PE.SECTION_CHARACTERISTICS.MEM_READ
        if permissions.get('w', False):
            characteristics |= lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE
        if permissions.get('x', False):
            characteristics |= lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE
        section.characteristics = characteristics
        return section

class ELFFormatStrategy(FormatStrategy):
    """ELF format-specific operations."""
    
    def is_executable_section(self, section) -> bool:
        return bool(section.flags & lief.ELF.SECTION_FLAGS.EXECINSTR)
    
    def is_readable_section(self, section) -> bool:
        return bool(section.flags & lief.ELF.SECTION_FLAGS.ALLOC)
    
    def is_writable_section(self, section) -> bool:
        return bool(section.flags & lief.ELF.SECTION_FLAGS.WRITE)
    
    def add_section(self, binary, name: str, content: bytes, permissions: Dict[str, bool]) -> Any:
        section = binary.add_section(name, list(content))
        flags = 0
        if permissions.get('r', True):
            flags |= lief.ELF.SECTION_FLAGS.ALLOC
        if permissions.get('w', False):
            flags |= lief.ELF.SECTION_FLAGS.WRITE
        if permissions.get('x', False):
            flags |= lief.ELF.SECTION_FLAGS.EXECINSTR
        section.flags = flags
        return section

class FormatStrategyFactory:
    """Factory for format strategy objects."""
    
    @staticmethod
    def get_strategy(format_type: str) -> FormatStrategy:
        strategies = {
            "PE": PEFormatStrategy,
            "ELF": ELFFormatStrategy,
            "MACHO": PEFormatStrategy  # Placeholder, implement MachO strategy
        }
        strategy_class = strategies.get(format_type)
        if not strategy_class:
            raise ValueError(f"Unsupported format: {format_type}")
        return strategy_class()