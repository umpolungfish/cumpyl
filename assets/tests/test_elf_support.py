#!/usr/bin/env python3
"""
Test script to verify ELF binary support in the Cumpyl framework
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

def test_elf_loading():
    """Test that ELF binaries can be loaded and analyzed"""
    print("Testing ELF binary loading...")
    
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
        
        # Load the binary
        if not rewriter.load_binary():
            print("Failed to load ELF binary")
            return False
            
        print("Successfully loaded ELF binary")
        
        # Test basic analysis
        analysis = rewriter.analyze_binary()
        print(f"Binary analysis: {analysis}")
        
        # Test section analysis
        print("\nAnalyzing sections...")
        rewriter.analyze_sections()
        
        # Test plugin system with ELF
        print("\nTesting plugin analysis with ELF...")
        loaded_plugins = rewriter.load_plugins()
        print(f"Loaded {loaded_plugins} plugins")
        
        # Run plugin analysis
        analysis_results = rewriter.run_plugin_analysis()
        print(f"Plugin analysis results: {list(analysis_results.keys())}")
        
        return True
    except Exception as e:
        print(f"Error testing ELF support: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_elf_packing():
    """Test that ELF binaries can be processed by the packer plugin"""
    print("\nTesting ELF binary packing...")
    
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
        
        # Load the binary
        if not rewriter.load_binary():
            print("Failed to load ELF binary for packing test")
            return False
            
        print("Successfully loaded ELF binary for packing test")
        
        # Get the packer plugin
        packer_plugin = get_packer_plugin(config.config_data)
        
        # Run analysis
        analysis_result = packer_plugin.analyze(rewriter)
        print(f"Packer analysis completed: {analysis_result.get('analysis', {}).get('binary_format', 'Unknown')}")
        
        # Get the transformation plugin
        transform_plugin = get_packer_transform_plugin(config.config_data)
        
        # Run transformation (dry run)
        transform_plugin.dry_run = True
        success = transform_plugin.transform(rewriter, analysis_result)
        print(f"Packer transformation (dry run) success: {success}")
        
        return True
    except Exception as e:
        print(f"Error testing ELF packing: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Main test function"""
    print("Testing ELF support in Cumpyl framework")
    print("=" * 50)
    
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    # Test ELF loading and analysis
    loading_success = test_elf_loading()
    
    # Test ELF packing
    packing_success = test_elf_packing()
    
    print("\n" + "=" * 50)
    print("Test Results:")
    print(f"ELF Loading & Analysis: {'PASS' if loading_success else 'FAIL'}")
    print(f"ELF Packing: {'PASS' if packing_success else 'FAIL'}")
    
    if loading_success and packing_success:
        print("\nAll ELF tests passed!")
        return 0
    else:
        print("\nSome ELF tests failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main())