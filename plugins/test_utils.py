"""Utilities for testing binary analysis plugins."""
import tempfile
import os
from typing import Dict, Any
import lief
from unittest.mock import Mock, MagicMock

class TestBinaryFactory:
    """Factory for creating test binaries."""
    
    @staticmethod
    def create_pe_test_binary() -> lief.Binary:
        """Create a minimal PE binary for testing."""
        binary = lief.PE.Binary("test.exe", lief.PE.PE_TYPE.PE32)
        
        # Add basic sections
        text_section = binary.add_section(".text", [0x90] * 100)  # NOP instructions
        text_section.characteristics = (
            lief.PE.SECTION_CHARACTERISTICS.MEM_READ |
            lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE
        )
        
        data_section = binary.add_section(".data", [0x00] * 50)
        data_section.characteristics = (
            lief.PE.SECTION_CHARACTERISTICS.MEM_READ |
            lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE
        )
        
        return binary
    
    @staticmethod
    def create_elf_test_binary() -> lief.Binary:
        """Create a minimal ELF binary for testing."""
        binary = lief.ELF.Binary("test.elf", lief.ELF.ELF_CLASS.CLASS64)
        
        # Add basic sections
        text_section = binary.add_section(".text", [0x90] * 100)
        text_section.flags = (
            lief.ELF.SECTION_FLAGS.ALLOC |
            lief.ELF.SECTION_FLAGS.EXECINSTR
        )
        
        data_section = binary.add_section(".data", [0x00] * 50)
        data_section.flags = (
            lief.ELF.SECTION_FLAGS.ALLOC |
            lief.ELF.SECTION_FLAGS.WRITE
        )
        
        return binary

class PluginTestCase:
    """Base test case for plugin testing."""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.config = {
            'dry_run': True,
            'safe_mode': True,
            'compression_level': 6
        }
    
    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def create_test_rewriter(self, binary_format: str = "PE") -> Mock:
        """Create a mock rewriter for testing."""
        rewriter = Mock()
        if binary_format == "PE":
            rewriter.binary = TestBinaryFactory.create_pe_test_binary()
        elif binary_format == "ELF":
            rewriter.binary = TestBinaryFactory.create_elf_test_binary()
        return rewriter