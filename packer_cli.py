#!/usr/bin/env python3
"""Command-line interface for the PE Packer plugin"""

import sys
import os
import argparse
import json

# Add the cumpyl_package to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'cumpyl_package'))

from cumpyl_package.cumpyl import BinaryRewriter
from cumpyl_package.config import ConfigManager
from plugins.packer_plugin import PackerPlugin, PackerTransformationPlugin

def analyze_binary(input_file, output_format='json'):
    """Analyze a binary for packing opportunities"""
    try:
        # Create config and rewriter
        config = {}  # Start with an empty dictionary
        config_manager = ConfigManager(config)  # Pass the dictionary to ConfigManager
        rewriter = BinaryRewriter(input_file, config_manager)
        
        # Load the binary
        if not rewriter.load_binary():
            print("[-] Failed to load binary")
            return False
            
        # Analyze with packer plugin
        analysis_plugin = PackerPlugin(config)
        analysis_result = analysis_plugin.analyze(rewriter)
        
        # Output results
        if output_format == 'json':
            print(json.dumps(analysis_result, indent=2))
        else:
            print("Plugin:", analysis_result.get('plugin_name', 'unknown'))
            print("Version:", analysis_result.get('version', 'unknown'))
            print("Capabilities:", analysis_result.get('capabilities', []))
            
            # Show analysis details
            analysis = analysis_result.get('analysis', {})
            print("Binary size:", analysis.get('binary_size', 0), "bytes")
            print("Sections count:", analysis.get('sections_count', 0))
            
            sections = analysis.get('sections', [])
            print("\nSections:")
            for section in sections:
                perms = ""
                if section.get('is_executable'):
                    perms += "X"
                if section.get('is_readable'):
                    perms += "R"
                if section.get('is_writable'):
                    perms += "W"
                print(f"  {section['name']:<12} {section['size']:>8} bytes  {perms}")
            
            opportunities = analysis.get('packing_opportunities', [])
            if opportunities:
                print("\nPacking opportunities:")
                for opp in opportunities:
                    print(f"  {opp['section']:<12} {opp['size']:>8} bytes  {opp['type']}")
            
            suggestions = analysis_result.get('suggestions', [])
            if suggestions:
                print("\nSuggestions:")
                for suggestion in suggestions:
                    methods = ' '.join(suggestion.get('suggested_methods', []))
                    print(f"  {suggestion['section']:<12} {suggestion['size']:>8} bytes  {methods}")
        
        return True
    except Exception as e:
        print(f"[-] Analysis failed: {e}")
        return False

def pack_binary(input_file, output_file=None):
    """Pack a binary with the packer plugin"""
    try:
        # Create config and rewriter
        config = {}  # Start with an empty dictionary
        config_manager = ConfigManager(config)  # Pass the dictionary to ConfigManager
        rewriter = BinaryRewriter(input_file, config_manager)
        
        # Load the binary
        if not rewriter.load_binary():
            print("[-] Failed to load binary")
            return False
            
        # Analyze with packer plugin
        analysis_plugin = PackerPlugin(config)
        analysis_result = analysis_plugin.analyze(rewriter)
        
        # Transform with packer plugin
        transform_plugin = PackerTransformationPlugin(config)
        transform_result = transform_plugin.transform(rewriter, analysis_result)
        
        if transform_result:
            # Save packed binary
            if not output_file:
                output_file = f"packed_{os.path.basename(input_file)}"
            save_result = transform_plugin.save_packed_binary(rewriter, output_file)
            if save_result:
                print(f"[+] Saved packed binary to: {output_file}")
                return True
            else:
                print("[-] Failed to save packed binary")
                return False
        else:
            print("[-] Packing transformation failed")
            return False
    except Exception as e:
        print(f"[-] Packing failed: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="PE Packer Plugin CLI")
    parser.add_argument("input", help="Input binary file")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("--analyze", action="store_true", help="Analyze binary for packing opportunities")
    parser.add_argument("--pack", action="store_true", help="Pack binary with compression and encryption")
    parser.add_argument("--format", choices=["json", "text"], default="text", help="Output format for analysis")
    
    args = parser.parse_args()
    
    if not args.analyze and not args.pack:
        parser.error("Either --analyze or --pack must be specified")
    
    if args.analyze:
        if not analyze_binary(args.input, args.format):
            sys.exit(1)
    
    if args.pack:
        if not pack_binary(args.input, args.output):
            sys.exit(1)

if __name__ == "__main__":
    main()