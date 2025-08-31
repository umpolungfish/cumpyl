#!/usr/bin/env python3
"""
Fix for the "no save method available" issue in plugin_packer_menu.py
This script modifies the plugin_packer_menu.py to properly handle saving transformed binaries
"""

import os
import sys

def fix_plugin_packer_menu():
    """Fix the plugin_packer_menu.py file to properly handle saving transformed binaries"""
    menu_file = "/home/mrnob0dy666/cumpyl/plugin_packer_menu.py"
    
    # Read the current content
    with open(menu_file, 'r') as f:
        content = f.read()
    
    # Define the old and new transform_binary_with_plugin functions
    old_function = '''def transform_binary_with_plugin(plugin_factory, config: Dict[str, Any], binary_path: str, analysis_result: Dict[str, Any]):
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
            # Save transformed binary if the plugin has a save method
            output_file = config.get('output_path', f"transformed_{os.path.basename(binary_path)}")
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
                print("[+] Transformation completed (no save method available)")
            return True
        else:
            print("[-] Transformation failed")
            return False
    except Exception as e:
        print(f"[-] Transformation failed: {e}")
        return False'''

    new_function = '''def transform_binary_with_plugin(plugin_factory, config: Dict[str, Any], binary_path: str, analysis_result: Dict[str, Any]):
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
        return False'''
    
    # Replace the old function with the new one
    if old_function in content:
        content = content.replace(old_function, new_function)
        # Write the fixed content back to the file
        with open(menu_file, 'w') as f:
            f.write(content)
        print("[+] Successfully fixed plugin_packer_menu.py")
        return True
    else:
        print("[-] Could not find the function to replace in plugin_packer_menu.py")
        return False

if __name__ == "__main__":
    fix_plugin_packer_menu()