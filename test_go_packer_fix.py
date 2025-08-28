#!/usr/bin/env python3
"""
Test script to verify the fix for the "no save method available" issue
"""

import sys
import os

# Add the cumpyl directory to the path
sys.path.insert(0, '/home/mrnob0dy666/cumpyl')

def test_go_packer_plugin():
    """Test the go_packer plugin with the fix"""
    try:
        # Import required modules
        from cumpyl_package.cumpyl import BinaryRewriter
        from cumpyl_package.config import ConfigManager
        from plugins.go_packer_plugin import get_analysis_plugin, get_transformation_plugin
        
        # Create config and rewriter
        config_manager = ConfigManager()
        config = config_manager.config_data if hasattr(config_manager, 'config_data') else {}
        
        # Set output path and disable dry run for actual saving
        config['output_path'] = 'asdsdasd.exe'
        config['dry_run'] = False
        
        rewriter = BinaryRewriter('/home/mrnob0dy666/cumpyl/gogogo.exe', config_manager)
        
        # Load the binary
        print("[+] Loading binary...")
        if not rewriter.load_binary():
            print("[-] Failed to load binary")
            return False
            
        # Create analysis plugin instance
        print("[+] Creating analysis plugin instance...")
        analysis_plugin = get_analysis_plugin(config)
        
        # Analyze with plugin
        print("[+] Running preliminary analysis...")
        analysis_result = analysis_plugin.analyze(rewriter)
        
        if not analysis_result:
            print("[-] Analysis failed")
            return False
            
        print("[+] Analysis completed successfully")
        
        # Create transformation plugin instance
        print("[+] Creating transformation plugin instance...")
        transform_plugin = get_transformation_plugin(config)
        
        # Transform with plugin
        print("[+] Transforming binary with go_binary_analyzer plugin...")
        transform_result = transform_plugin.transform(rewriter, analysis_result)
        
        if transform_result:
            print("[+] Transformation completed successfully")
            
            # Try to save using rewriter's save_binary method
            output_file = config.get('output_path', f"transformed_gogogo.exe")
            print(f"[+] Saving transformed binary to: {output_file}")
            
            save_result = rewriter.save_binary(output_file)
            if save_result:
                print(f"[+] Successfully saved transformed binary to: {output_file}")
                return True
            else:
                print("[-] Failed to save transformed binary")
                return False
        else:
            print("[-] Transformation failed")
            return False
            
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("Testing go_packer plugin fix...")
    success = test_go_packer_plugin()
    if success:
        print("[+] Test completed successfully")
    else:
        print("[-] Test failed")