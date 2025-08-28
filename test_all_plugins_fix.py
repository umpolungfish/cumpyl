#!/usr/bin/env python3
"""
Enhanced test script to verify the fix for the "no save method available" issue
This script tests multiple plugins to ensure the fix works across different packers
"""

import sys
import os

# Add the cumpyl directory to the path
sys.path.insert(0, '/home/mrnob0dy666/cumpyl')

def test_plugin(plugin_name, binary_path, output_path):
    """Test a specific plugin"""
    try:
        # Import required modules
        from cumpyl_package.cumpyl import BinaryRewriter
        from cumpyl_package.config import ConfigManager
        
        # Import the appropriate plugin
        if plugin_name == "go_packer":
            from plugins.go_packer_plugin import get_analysis_plugin, get_transformation_plugin
        elif plugin_name == "cgo_packer":
            from plugins.cgo_packer_plugin import get_plugin, get_transformation_plugin
        elif plugin_name == "packer":
            from plugins.packer_plugin import get_plugin, get_transform_plugin
        else:
            print(f"[-] Unknown plugin: {plugin_name}")
            return False
        
        # Create config and rewriter
        config_manager = ConfigManager()
        config = config_manager.config_data if hasattr(config_manager, 'config_data') else {}
        
        # Set output path and disable dry run for actual saving
        config['output_path'] = output_path
        config['dry_run'] = False
        
        rewriter = BinaryRewriter(binary_path, config_manager)
        
        # Load the binary
        print(f"[+] Loading binary for {plugin_name} plugin...")
        if not rewriter.load_binary():
            print("[-] Failed to load binary")
            return False
            
        # Create analysis plugin instance
        print(f"[+] Creating analysis plugin instance for {plugin_name}...")
        if plugin_name == "go_packer":
            analysis_plugin = get_analysis_plugin(config)
        else:
            analysis_plugin = get_plugin(config)
        
        # Analyze with plugin
        print(f"[+] Running preliminary analysis with {plugin_name} plugin...")
        analysis_result = analysis_plugin.analyze(rewriter)
        
        if not analysis_result:
            print("[-] Analysis failed")
            return False
            
        print(f"[+] Analysis completed successfully for {plugin_name}")
        
        # Create transformation plugin instance
        print(f"[+] Creating transformation plugin instance for {plugin_name}...")
        if plugin_name == "go_packer":
            transform_plugin = get_transformation_plugin(config)
        elif plugin_name == "packer":
            transform_plugin = get_transform_plugin(config)
        else:
            transform_plugin = get_transformation_plugin(config)
        
        # Transform with plugin
        print(f"[+] Transforming binary with {plugin_name} plugin...")
        transform_result = transform_plugin.transform(rewriter, analysis_result)
        
        if transform_result:
            print(f"[+] Transformation completed successfully for {plugin_name}")
            
            # Try to save using rewriter's save_binary method
            print(f"[+] Saving transformed binary to: {output_path}")
            
            save_result = rewriter.save_binary(output_path)
            if save_result:
                print(f"[+] Successfully saved transformed binary to: {output_path}")
                return True
            else:
                print("[-] Failed to save transformed binary")
                return False
        else:
            print("[-] Transformation failed")
            return False
            
    except Exception as e:
        print(f"[-] Error with {plugin_name} plugin: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Test all plugins"""
    binary_path = '/home/mrnob0dy666/cumpyl/gogogo.exe'
    
    if not os.path.exists(binary_path):
        print(f"[-] Binary file not found: {binary_path}")
        return
    
    plugins_to_test = [
        ("go_packer", "go_packer_output.exe"),
        ("packer", "packer_output.exe")
    ]
    
    results = {}
    
    for plugin_name, output_file in plugins_to_test:
        print(f"\n{'='*60}")
        print(f"Testing {plugin_name} plugin")
        print(f"{'='*60}")
        
        success = test_plugin(plugin_name, binary_path, output_file)
        results[plugin_name] = success
        
        if success:
            print(f"[+] {plugin_name} plugin test completed successfully")
        else:
            print(f"[-] {plugin_name} plugin test failed")
    
    # Print summary
    print(f"\n{'='*60}")
    print("TEST SUMMARY")
    print(f"{'='*60}")
    
    for plugin_name, success in results.items():
        status = "PASSED" if success else "FAILED"
        print(f"{plugin_name}: {status}")
    
    all_passed = all(results.values())
    if all_passed:
        print("[+] All tests passed!")
    else:
        print("[-] Some tests failed.")
    
    return all_passed

if __name__ == "__main__":
    print("Testing plugin packer fixes...")
    success = main()
    sys.exit(0 if success else 1)