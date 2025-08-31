#!/usr/bin/env python3
"""
Comprehensive test script to verify ELF binary support in the Cumpyl framework
"""

import sys
import os
import tempfile
import logging

# Add the current directory to the path so we can import cumpyl_package
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cumpyl_package.cumpyl import BinaryRewriter
from cumpyl_package.config import ConfigManager
from plugins.packer_plugin import get_plugin as get_packer_plugin
from plugins.packer_plugin import get_transform_plugin as get_packer_transform_plugin

def test_elf_comprehensive():
    """Comprehensive test of ELF binary support"""
    print("Running comprehensive ELF test...")
    
    # Use the existing ELF test file
    elf_file = "/home/developer/cumpyl/greenbay/ca_packer/archive/minimal_exit_stub.elf"
    
    if not os.path.exists(elf_file):
        print(f"ELF test file not found: {elf_file}")
        return False
    
    try:
        # Initialize config
        config = ConfigManager()
        
        # Create BinaryRewriter
        rewriter = BinaryRewriter(elf_file, config)
        
        # Test 1: Load the binary
        print("Test 1: Loading ELF binary...")
        if not rewriter.load_binary():
            print("Failed to load ELF binary")
            return False
        print("✓ ELF binary loaded successfully")
        
        # Test 2: Basic analysis
        print("\nTest 2: Basic binary analysis...")
        analysis = rewriter.analyze_binary()
        if not analysis:
            print("Failed to perform basic analysis")
            return False
        print("✓ Basic analysis completed")
        print(f"  Architecture: {analysis.get('architecture', 'Unknown')}")
        print(f"  Entry point: 0x{analysis.get('entry_point', 0):x}")
        print(f"  Sections: {len(analysis.get('sections', []))}")
        
        # Test 3: Section analysis
        print("\nTest 3: Section analysis...")
        # This should work without errors now
        rewriter.analyze_sections()
        print("✓ Section analysis completed")
        
        # Test 4: Plugin system
        print("\nTest 4: Plugin system...")
        loaded_plugins = rewriter.load_plugins()
        print(f"✓ Loaded {loaded_plugins} plugins")
        
        # Test 5: Plugin analysis
        print("\nTest 5: Plugin analysis...")
        analysis_results = rewriter.run_plugin_analysis()
        if not analysis_results:
            print("Failed to run plugin analysis")
            return False
        print("✓ Plugin analysis completed")
        print(f"  Plugins that ran: {list(analysis_results.keys())}")
        
        # Test 6: Packer plugin specifically
        print("\nTest 6: Packer plugin...")
        packer_plugin = get_packer_plugin(config.config_data)
        packer_analysis = packer_plugin.analyze(rewriter)
        if not packer_analysis:
            print("Failed to run packer analysis")
            return False
        print("✓ Packer analysis completed")
        print(f"  Detected format: {packer_analysis.get('analysis', {}).get('binary_format', 'Unknown')}")
        print(f"  Sections analyzed: {len(packer_analysis.get('analysis', {}).get('sections', []))}")
        
        # Test 7: Packer transformation (dry run)
        print("\nTest 7: Packer transformation (dry run)...")
        transform_plugin = get_packer_transform_plugin(config.config_data)
        transform_plugin.dry_run = True
        success = transform_plugin.transform(rewriter, packer_analysis)
        if not success:
            print("Failed to run packer transformation")
            return False
        print("✓ Packer transformation completed")
        
        # Test 8: Section permission checks
        print("\nTest 8: Section permission checks...")
        binary = rewriter.binary
        if binary and hasattr(binary, 'sections'):
            from plugins.consolidated_utils import is_executable_section, is_readable_section, is_writable_section
            format_type = "ELF"  # We know it's ELF
            
            for section in binary.sections[:3]:  # Test first 3 sections
                name = getattr(section, 'name', 'Unknown')
                is_exec = is_executable_section(section, format_type)
                is_read = is_readable_section(section, format_type)
                is_write = is_writable_section(section, format_type)
                print(f"  Section '{name}': Exec={is_exec}, Read={is_read}, Write={is_write}")
        print("✓ Section permission checks completed")
        
        # Test 9: Format detection
        print("\nTest 9: Format detection...")
        from plugins.consolidated_utils import detect_format
        detected_format = detect_format(binary)
        if detected_format != "ELF":
            print(f"Format detection failed: expected 'ELF', got '{detected_format}'")
            return False
        print("✓ Format detection confirmed as ELF")
        
        return True
    except Exception as e:
        print(f"Error in comprehensive ELF test: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Main test function"""
    print("Comprehensive ELF Support Test for Cumpyl Framework")
    print("=" * 60)
    
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    # Run comprehensive test
    success = test_elf_comprehensive()
    
    print("\n" + "=" * 60)
    print("Comprehensive ELF Test Results:")
    if success:
        print("✓ ALL TESTS PASSED - ELF support is working correctly!")
        return 0
    else:
        print("✗ SOME TESTS FAILED - ELF support needs attention")
        return 1

if __name__ == "__main__":
    sys.exit(main())