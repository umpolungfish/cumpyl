#!/usr/bin/env python3
"""
Plugin Packer Menu System
Provides a user-friendly menu interface for selecting and using different plugins.
"""

import sys
import os
import importlib
import json
from typing import Dict, Any, List

# Add the plugins directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'plugins'))

def list_available_plugins() -> Dict[str, List[str]]:
    """List all available plugins in the plugins directory."""
    plugins_dir = os.path.join(os.path.dirname(__file__), 'plugins')
    packing_plugins = []
    
    # Look for plugin files
    for filename in os.listdir(plugins_dir):
        if filename.endswith('_plugin.py') and filename not in ['base_plugin.py']:
            plugin_name = filename.replace('_plugin.py', '')
            # Exclude test plugins and transmuter plugin (has its own menu)
            if plugin_name.startswith('test_') or plugin_name == 'transmuter':
                continue
            # Add all packing plugins - they should all be transformative
            packing_plugins.append(plugin_name)
    
    # Ensure packer_transform is included
    if 'packer_transform' not in packing_plugins:
        packing_plugins.append('packer_transform')
    
    return {
        'analysis': packing_plugins,  # All plugins can do analysis
        'transformation': packing_plugins  # All plugins can do transformation
    }

def load_plugin(plugin_name: str, plugin_type: str):
    """Dynamically load a plugin module."""
    try:
        if plugin_name == 'packer' and plugin_type == 'analysis':
            from plugins.packer_plugin import get_plugin
            return get_plugin
        elif plugin_name == 'packer_transform' and plugin_type == 'transformation':
            from plugins.packer_plugin import get_transform_plugin
            return get_transform_plugin
        else:
            # Try to load other plugins dynamically
            # Use direct import instead of importlib for better path handling
            if plugin_name == 'cgo_packer':
                import plugins.cgo_packer_plugin
                module = plugins.cgo_packer_plugin
            elif plugin_name == 'go_packer':
                import plugins.go_packer_plugin
                module = plugins.go_packer_plugin
            elif plugin_name == 'transmuter':
                import plugins.transmuter_plugin
                module = plugins.transmuter_plugin
            else:
                # Fallback to importlib
                module_name = f"plugins.{plugin_name}_plugin"
                module = importlib.import_module(module_name)
            
            if plugin_type == 'analysis':
                if hasattr(module, 'get_analysis_plugin'):
                    return getattr(module, 'get_analysis_plugin')
                elif hasattr(module, 'get_plugin'):
                    return getattr(module, 'get_plugin')
            elif plugin_type == 'transformation':
                if hasattr(module, 'get_transformation_plugin'):
                    return getattr(module, 'get_transformation_plugin')
                elif hasattr(module, 'get_transform_plugin'):
                    return getattr(module, 'get_transform_plugin')
            
            # Fallback to get_plugins if it exists
            if hasattr(module, 'get_plugins'):
                plugins = getattr(module, 'get_plugins')({})
                return plugins.get(plugin_type)
                
    except Exception as e:
        print(f"Error loading {plugin_type} plugin '{plugin_name}': {e}")
        return None

def display_menu(options: List[str], title: str) -> int:
    """Display a menu and get user selection."""
    print(f"\n{title}")
    print("=" * len(title))
    for i, option in enumerate(options, 1):
        print(f"{i}. {option}")
    print("0. Exit")
    
    while True:
        try:
            choice = int(input("\nEnter your choice: "))
            if 0 <= choice <= len(options):
                return choice
            else:
                print("Invalid choice. Please try again.")
        except ValueError:
            print("Please enter a valid number.")

def configure_plugin(plugin_name: str) -> Dict[str, Any]:
    """Get configuration for a plugin from user input."""
    config = {}
    print(f"\nConfiguring {plugin_name} plugin:")
    
    # Common configuration options
    if plugin_name in ['packer', 'packer_transform']:
        compression = input("Compression level (1-9, default 6): ").strip()
        if compression:
            try:
                config['compression_level'] = int(compression)
            except ValueError:
                config['compression_level'] = 6
        
        key_path = input("Encryption key path (leave empty to disable encryption): ").strip()
        if key_path:
            config['key_path'] = key_path
            config['encrypt_sections'] = True
        else:
            config['encrypt_sections'] = False
            
        safe_mode = input("Enable safe mode? (y/n, default y): ").strip().lower()
        config['safe_mode'] = safe_mode != 'n'
        
        dry_run = input("Enable dry run mode? (y/n, default n): ").strip().lower()
        config['dry_run'] = dry_run == 'y'
        
        skip_pointer = input("Skip pointer sections? (y/n, default y): ").strip().lower()
        config['skip_pointer_sections'] = skip_pointer != 'n'
    elif plugin_name == 'cgo_packer':
        # CGO packer specific configuration
        compression = input("Compression level (1-9, default 6): ").strip()
        if compression:
            try:
                config['compression_level'] = int(compression)
            except ValueError:
                config['compression_level'] = 6
        
        # For CGO packer, disable dry run by default to actually save files
        dry_run = input("Enable dry run mode? (y/n, default n): ").strip().lower()
        config['dry_run'] = dry_run == 'y'
        
        encrypt_sections = input("Encrypt sections? (y/n, default y): ").strip().lower()
        config['encrypt_sections'] = encrypt_sections != 'n'
        
        obfuscate_symbols = input("Obfuscate symbols? (y/n, default y): ").strip().lower()
        config['obfuscate_symbols'] = obfuscate_symbols != 'n'
        
        preserve_cgo_symbols = input("Preserve CGO symbols? (y/n, default y): ").strip().lower()
        config['preserve_cgo_symbols'] = preserve_cgo_symbols != 'n'
    elif plugin_name == 'go_packer':
        # Go packer specific configuration
        compression = input("Compression level (1-9, default 6): ").strip()
        if compression:
            try:
                config['compression_level'] = int(compression)
            except ValueError:
                config['compression_level'] = 6
        
        # For Go packer, disable dry run by default to actually save files
        dry_run = input("Enable dry run mode? (y/n, default n): ").strip().lower()
        config['dry_run'] = dry_run == 'y'
        
        encrypt_sections = input("Encrypt sections? (y/n, default y): ").strip().lower()
        config['encrypt_sections'] = encrypt_sections != 'n'
        
        obfuscate_symbols = input("Obfuscate symbols? (y/n, default y): ").strip().lower()
        config['obfuscate_symbols'] = obfuscate_symbols != 'n'
        
        preserve_cgo_symbols = input("Preserve CGO symbols? (y/n, default y): ").strip().lower()
        config['preserve_cgo_symbols'] = preserve_cgo_symbols != 'n'
    
    return config

def analyze_binary_with_plugin(plugin_factory, config: Dict[str, Any], binary_path: str):
    """Analyze a binary using the selected plugin."""
    try:
        # Import required modules
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'cumpyl_package'))
        from cumpyl_package.cumpyl import BinaryRewriter
        from cumpyl_package.config import ConfigManager
        
        # Create config and rewriter
        config_manager = ConfigManager()  # Create with default config
        # Update with our custom config
        if hasattr(config_manager, 'config_data'):
            config_manager.config_data.update(config)
        rewriter = BinaryRewriter(binary_path, config_manager)
        
        # Load the binary
        if not rewriter.load_binary():
            print("[-] Failed to load binary")
            return None
            
        # Create plugin instance
        plugin = plugin_factory(config_manager)
        
        # Analyze with plugin
        print(f"[+] Analyzing binary with {plugin.name if hasattr(plugin, 'name') else 'selected'} plugin...")
        analysis_result = plugin.analyze(rewriter)
        
        return analysis_result
    except Exception as e:
        print(f"[-] Analysis failed: {e}")
        return None

def transform_binary_with_plugin(plugin_factory, config: Dict[str, Any], binary_path: str, analysis_result: Dict[str, Any]):
    """Transform a binary using the selected plugin."""
    try:
        # Import required modules
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'cumpyl_package'))
        from cumpyl_package.cumpyl import BinaryRewriter
        from cumpyl_package.config import ConfigManager
        
        # Create config and rewriter
        config_manager = ConfigManager()  # Create with default config
        # Update with our custom config
        if hasattr(config_manager, 'config_data'):
            config_manager.config_data.update(config)
        rewriter = BinaryRewriter(binary_path, config_manager)
        
        # Load the binary
        if not rewriter.load_binary():
            print("[-] Failed to load binary")
            return False
            
        # Create plugin instance
        plugin = plugin_factory(config_manager)
        
        # Transform with plugin
        print(f"[+] Transforming binary with {plugin.name if hasattr(plugin, 'name') else 'selected'} plugin...")
        transform_result = plugin.transform(rewriter, analysis_result)
        
        if transform_result:
            # Save transformed binary
            output_file = config.get('output_path', f"transformed_{os.path.basename(binary_path)}")
            
            # Check if plugin has save_packed_binary method
            if hasattr(plugin, 'save_packed_binary'):
                # Only save if not in dry run mode
                if not config.get('dry_run', True):
                    save_result = plugin.save_packed_binary(rewriter, output_file)
                    if save_result:
                        print(f"[+] Saved transformed binary to: {output_file}")
                    else:
                        print("[-] Failed to save transformed binary")
                else:
                    print("[+] Dry run mode: Transformation completed but binary not saved")
            else:
                # Try to save using rewriter's save_binary method
                # Only save if not in dry run mode
                if not config.get('dry_run', True):
                    save_result = rewriter.save_binary(output_file)
                    if save_result:
                        print(f"[+] Saved transformed binary to: {output_file}")
                    else:
                        print("[-] Failed to save transformed binary")
                else:
                    print("[+] Dry run mode: Transformation completed but binary not saved")
            return True
        else:
            print("[-] Transformation failed")
            return False
    except Exception as e:
        print(f"[-] Transformation failed: {e}")
        return False

def display_analysis_results(results: Dict[str, Any]):
    """Display analysis results in a user-friendly format."""
    if not results:
        print("No analysis results to display")
        return
    
    print("\n" + "="*50)
    print("ANALYSIS RESULTS")
    print("="*50)
    
    # Basic plugin info
    print(f"Plugin: {results.get('plugin_name', 'Unknown')}")
    print(f"Version: {results.get('version', 'Unknown')}")
    print(f"Description: {results.get('description', 'No description')}")
    
    # Binary format if available
    if 'binary_format' in results:
        print(f"Binary Format: {results['binary_format']}")
    
    # Analysis details
    if 'analysis' in results:
        analysis = results['analysis']
        print(f"\nBinary Size: {analysis.get('binary_size', 0)} bytes")
        print(f"Sections Count: {analysis.get('sections_count', 0)}")
        
        # Sections
        sections = analysis.get('sections', [])
        if sections:
            print("\nSections:")
            print("-" * 60)
            for section in sections:
                perms = ""
                if section.get('is_executable'):
                    perms += "X"
                if section.get('is_readable'):
                    perms += "R"
                if section.get('is_writable'):
                    perms += "W"
                print(f"  {section['name']:<15} {section['size']:>10} bytes  {perms}")
        
        # Packing opportunities
        opportunities = analysis.get('packing_opportunities', [])
        if opportunities:
            print("\nPacking Opportunities:")
            print("-" * 60)
            for opp in opportunities:
                opp_type = opp.get('type', 'Unknown')
                print(f"  {opp.get('section', 'Unknown'):<15} {opp.get('size', 0):>10} bytes  {opp_type}")
        
        # Go detection (if present)
        if 'go_detection' in analysis:
            go_detection = analysis['go_detection']
            if go_detection.get('detected'):
                print(f"\nGo Binary Detected:")
                print(f"  Confidence: {go_detection.get('confidence', 0.0):.2f}")
                print(f"  Method: {go_detection.get('method', 'Unknown')}")
    
    # Suggestions
    suggestions = results.get('suggestions', [])
    if suggestions:
        print("\nSuggestions:")
        print("-" * 60)
        for suggestion in suggestions:
            print(f"  {suggestion.get('description', 'No description')}")
            if 'recommendation' in suggestion:
                print(f"    Recommendation: {suggestion['recommendation']}")
    
    # Transformation plan (if present)
    if 'transformation_plan' in results:
        plan = results['transformation_plan']
        if plan and plan.get('actions'):
            print("\nTransformation Plan:")
            print("-" * 60)
            for action in plan['actions']:
                print(f"  {action.get('type', 'Unknown action')}: {action.get('description', 'No description')}")

def main():
    """Main menu loop."""
    print("Cumpyl Plugin Packer Menu")
    print("=" * 30)
    
    # Check if a binary file was provided as command line argument
    binary_path = None
    if len(sys.argv) > 1:
        binary_path = sys.argv[1]
        if not os.path.exists(binary_path):
            print(f"Warning: Specified binary file '{binary_path}' not found")
            binary_path = None
    
    # Main menu loop
    while True:
        # Get binary file if not already provided
        while not binary_path:
            binary_path = input("Enter path to binary file (or 'q' to quit): ").strip()
            if binary_path.lower() == 'q':
                print("Goodbye!")
                return
            if not os.path.exists(binary_path):
                print("File not found. Please try again.")
                binary_path = None
        
        # Main options
        main_options = [
            "Analyze binary",
            "Transform binary",
            "Change binary file",
            "List available plugins"
        ]
        
        choice = display_menu(main_options, "MAIN MENU")
        
        if choice == 0:
            print("Goodbye!")
            break
        elif choice == 1:
            # Analyze binary
            plugins = list_available_plugins()
            analysis_plugins = plugins['analysis']
            
            if not analysis_plugins:
                print("No analysis plugins available")
                continue
            
            plugin_names = [f"{name} plugin" for name in analysis_plugins]
            plugin_choice = display_menu(plugin_names, "SELECT ANALYSIS PLUGIN")
            
            if plugin_choice == 0:
                continue
            
            selected_plugin = analysis_plugins[plugin_choice - 1]
            print(f"Selected plugin: {selected_plugin}")
            
            # Configure plugin
            config = configure_plugin(selected_plugin)
            
            # Load plugin
            plugin_factory = load_plugin(selected_plugin, 'analysis')
            if not plugin_factory:
                print("Failed to load plugin")
                continue
            
            # Analyze binary
            results = analyze_binary_with_plugin(plugin_factory, config, binary_path)
            if results:
                display_analysis_results(results)
                
                # Ask if user wants to save results
                save_choice = input("\nSave analysis results to file? (y/n): ").strip().lower()
                if save_choice == 'y':
                    output_file = input("Enter output filename (default: analysis_results.json): ").strip()
                    if not output_file:
                        output_file = "analysis_results.json"
                    try:
                        with open(output_file, 'w') as f:
                            json.dump(results, f, indent=2)
                        print(f"[+] Results saved to {output_file}")
                    except Exception as e:
                        print(f"[-] Failed to save results: {e}")
            else:
                print("Analysis failed")
                
        elif choice == 2:
            # Transform binary
            plugins = list_available_plugins()
            transform_plugins = plugins['transformation']
            
            if not transform_plugins:
                print("No transformation plugins available")
                continue
            
            plugin_names = [f"{name} plugin" for name in transform_plugins]
            plugin_choice = display_menu(plugin_names, "SELECT TRANSFORMATION PLUGIN")
            
            if plugin_choice == 0:
                continue
            
            selected_plugin = transform_plugins[plugin_choice - 1]
            print(f"Selected plugin: {selected_plugin}")
            
            # Configure plugin
            config = configure_plugin(selected_plugin)
            
            # Get output path
            output_path = input("Output file path (leave empty for default): ").strip()
            if output_path:
                config['output_path'] = output_path
            
            # Load plugin
            plugin_factory = load_plugin(selected_plugin, 'transformation')
            if not plugin_factory:
                print("Failed to load plugin")
                continue
            
            # First run analysis (required for most transformation plugins)
            print("[+] Running preliminary analysis...")
            analysis_plugin_factory = load_plugin('packer', 'analysis')  # Use packer as default analysis
            if analysis_plugin_factory:
                analysis_results = analyze_binary_with_plugin(analysis_plugin_factory, config, binary_path)
                if analysis_results:
                    # Transform binary
                    success = transform_binary_with_plugin(plugin_factory, config, binary_path, analysis_results)
                    if success:
                        print("[+] Transformation completed successfully")
                    else:
                        print("[-] Transformation failed")
                else:
                    print("[-] Preliminary analysis failed")
            else:
                print("[-] Failed to load analysis plugin")
                
        elif choice == 3:
            # Change binary file
            binary_path = None
            continue
            
        elif choice == 4:
            # List available plugins
            plugins = list_available_plugins()
            print("\nAvailable Plugins:")
            print("-" * 30)
            print("Analysis Plugins:")
            for plugin in plugins['analysis']:
                print(f"  - {plugin}")
            print("\nTransformation Plugins:")
            for plugin in plugins['transformation']:
                print(f"  - {plugin}")

if __name__ == "__main__":
    main()