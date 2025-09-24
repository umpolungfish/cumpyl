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
import importlib.resources

def list_available_plugins() -> Dict[str, List[str]]:
    """List all available plugins in the plugins directory."""
    packing_plugins = []
    
    # Look for plugin files
    for filename in importlib.resources.contents('plugins'):
        if filename.endswith('_plugin.py') and filename not in ['base_plugin.py', '__init__.py']:
            plugin_name = filename.replace('_plugin.py', '')
            # Exclude test plugins and transmuter plugin (has its own menu)
            if plugin_name.startswith('test_') or plugin_name == 'transmuter':
                continue
            packing_plugins.append(plugin_name)
    
    transformation_plugins = list(packing_plugins)
    # Ensure packer_transform is included for transformation
    if 'packer_transform' not in transformation_plugins:
        transformation_plugins.append('packer_transform')
    
    return {
        'analysis': packing_plugins,
        'transformation': transformation_plugins
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
            module_name = f"plugins.{plugin_name}_plugin"
            module = importlib.import_module(module_name)
            
            # Try to get the appropriate factory function
            if plugin_type == 'analysis':
                factory_func_name = 'get_analysis_plugin'
            elif plugin_type == 'transformation':
                factory_func_name = 'get_transformation_plugin'
            else:
                factory_func_name = 'get_plugin'
            
            if hasattr(module, factory_func_name):
                return getattr(module, factory_func_name)
            elif hasattr(module, 'get_plugin'):
                return getattr(module, 'get_plugin')
            else:
                # Try to instantiate the plugin class directly
                class_name = f"{plugin_name.capitalize()}Plugin"
                if hasattr(module, class_name):
                    return getattr(module, class_name)
                else:
                    raise ImportError(f"No factory function or class found in {module_name}")
                    
    except Exception as e:
        print(f"Error loading plugin {plugin_name}: {e}")
        return None

def display_menu(options: List[str], title: str) -> int:
    """Display a menu and return the selected option index."""
    print(f"\n{title}")
    print("-" * len(title))
    
    for i, option in enumerate(options, 1):
        print(f"{i}. {option}")
    print("0. Back/Exit")
    
    while True:
        try:
            choice = input(f"\nSelect an option (0-{len(options)}): ")
            choice = int(choice)
            if 0 <= choice <= len(options):
                return choice
            else:
                print(f"Please enter a number between 0 and {len(options)}")
        except ValueError:
            print("Please enter a valid number")

def configure_plugin(plugin_name: str) -> Dict[str, Any]:
    """Configure plugin settings."""
    config = {}
    
    # Plugin-specific configurations
    if plugin_name == 'packer':
        print("\nPackager Configuration:")
        compression = input("Compression level (1-9, default 6): ").strip()
        if compression:
            try:
                config['compression_level'] = int(compression)
            except ValueError:
                print("Invalid compression level, using default")
                config['compression_level'] = 6
        else:
            config['compression_level'] = 6
            
        key_path = input("Encryption key file path (optional): ").strip()
        if key_path:
            config['key_path'] = key_path
            
    elif plugin_name == 'go_packer':
        print("\nGo Packager Configuration:")
        allow_transform = input("Allow transformation mode? (y/N): ").strip().lower()
        config['allow_transform'] = allow_transform == 'y'
        
    return config

def analyze_binary_with_plugin(plugin_factory, config: Dict[str, Any], binary_path: str):
    """Analyze a binary using the specified plugin."""
    try:
        # Create plugin instance
        plugin = plugin_factory(config)
        
        # Load binary
        sys.path.append(os.path.dirname(os.path.abspath(__file__)))
        from cumpyl_package.cumpyl import BinaryRewriter
        
        rewriter = BinaryRewriter(binary_path)
        if not rewriter.load_binary():
            print("Failed to load binary")
            return None
            
        # Run analysis
        print(f"Analyzing {binary_path} with {plugin.name} plugin...")
        results = plugin.analyze(rewriter)
        
        # Display results
        display_analysis_results(results)
        return results
        
    except Exception as e:
        print(f"Error during analysis: {e}")
        import traceback
        traceback.print_exc()
        return None

def transform_binary_with_plugin(plugin_factory, config: Dict[str, Any], binary_path: str, analysis_result: Dict[str, Any]):
    """Transform a binary using the specified plugin."""
    try:
        # Create plugin instance
        plugin = plugin_factory(config)
        
        # Check if plugin has transform method
        if not hasattr(plugin, 'transform'):
            print(f"Plugin {plugin.name} does not support transformation")
            return False
            
        # Load binary
        sys.path.append(os.path.dirname(os.path.abspath(__file__)))
        from cumpyl_package.cumpyl import BinaryRewriter
        
        rewriter = BinaryRewriter(binary_path)
        if not rewriter.load_binary():
            print("Failed to load binary")
            return False
            
        # Run transformation
        print(f"Transforming {binary_path} with {plugin.name} plugin...")
        success = plugin.transform(rewriter, analysis_result)
        
        if success:
            # Save transformed binary
            output_path = f"transformed_{os.path.basename(binary_path)}"
            if rewriter.save_binary(output_path):
                print(f"Successfully saved transformed binary to {output_path}")
                return True
            else:
                print("Failed to save transformed binary")
                return False
        else:
            print("Transformation failed")
            return False
            
    except Exception as e:
        print(f"Error during transformation: {e}")
        import traceback
        traceback.print_exc()
        return False

def display_analysis_results(results: Dict[str, Any]):
    """Display analysis results in a formatted way."""
    print("\n" + "="*50)
    print("ANALYSIS RESULTS")
    print("="*50)
    
    if not results:
        print("No results to display")
        return
        
    # Display basic plugin info
    if 'plugin_name' in results:
        print(f"Plugin: {results['plugin_name']}")
    if 'version' in results:
        print(f"Version: {results['version']}")
    if 'description' in results:
        print(f"Description: {results['description']}")
        
    print("-"*50)
    
    # Display analysis data
    analysis = results.get('analysis', {})
    if isinstance(analysis, dict):
        for key, value in analysis.items():
            if isinstance(value, (str, int, float, bool)):
                print(f"{key}: {value}")
            elif isinstance(value, list):
                print(f"{key}:")
                for item in value:
                    if isinstance(item, dict):
                        print(f"  - {item}")
                    else:
                        print(f"  - {item}")
            elif isinstance(value, dict):
                print(f"{key}:")
                for subkey, subvalue in value.items():
                    print(f"  {subkey}: {subvalue}")
    elif isinstance(analysis, list):
        for item in analysis:
            print(f"- {item}")
    else:
        print(f"Analysis: {analysis}")
        
    print("="*50)

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
                print(f"Failed to load plugin {selected_plugin}")
                continue
                
            # Analyze binary
            results = analyze_binary_with_plugin(plugin_factory, config, binary_path)
            if results:
                print("\nAnalysis completed successfully!")
                # Store results for potential transformation
                last_analysis_results = results
                last_analysis_plugin = selected_plugin
            else:
                print("\nAnalysis failed!")
                
        elif choice == 2:
            # Transform binary
            if 'last_analysis_results' not in locals():
                print("Please run an analysis first!")
                continue
                
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
            
            # Load plugin
            plugin_factory = load_plugin(selected_plugin, 'transformation')
            if not plugin_factory:
                print(f"Failed to load plugin {selected_plugin}")
                continue
                
            # Transform binary
            success = transform_binary_with_plugin(
                plugin_factory, config, binary_path, last_analysis_results
            )
            
            if success:
                print("\nTransformation completed successfully!")
            else:
                print("\nTransformation failed!")
                
        elif choice == 3:
            # Change binary file
            binary_path = None
            continue
            
        elif choice == 4:
            # List available plugins
            plugins = list_available_plugins()
            print("\nAvailable Analysis Plugins:")
            for plugin in plugins['analysis']:
                print(f"  - {plugin}")
            print("\nAvailable Transformation Plugins:")
            for plugin in plugins['transformation']:
                print(f"  - {plugin}")

def launch_plugin_packer_menu(config, target_file):
    """Launch the plugin packer menu with the specified configuration and target file."""
    import sys
    # Set the target file as a command line argument
    sys.argv = ['plugin_packer_menu.py', target_file]
    # Call the main function
    main()

if __name__ == "__main__":
    main()