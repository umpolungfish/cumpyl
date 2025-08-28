#!/usr/bin/env python3
"""
Final test script to verify all fixes work correctly
"""

import sys
import os

# Add the cumpyl directory to the path
sys.path.insert(0, '/home/mrnob0dy666/cumpyl')

def test_packer_plugins():
    """Test that the packer plugins work correctly"""
    try:
        # Import required modules
        from cumpyl_package.cumpyl import BinaryRewriter
        from cumpyl_package.config import ConfigManager
        from plugins.go_packer_plugin import get_analysis_plugin, get_transformation_plugin
        
        print("[+] Testing Go packer plugin...")
        
        # Create config and rewriter
        config_manager = ConfigManager()
        config = config_manager.config_data if hasattr(config_manager, 'config_data') else {}
        
        # Set configuration for actual transformation (not dry run)
        config['dry_run'] = False
        config['output_path'] = 'final_test_output.exe'
        config['allow_transform'] = True
        
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
        print("[+] Running analysis...")
        analysis_result = analysis_plugin.analyze(rewriter)
        
        if not analysis_result:
            print("[-] Analysis failed")
            return False
            
        print("[+] Analysis completed successfully")
        
        # Create transformation plugin instance
        print("[+] Creating transformation plugin instance...")
        transform_plugin = get_transformation_plugin(config)
        
        # Transform with plugin
        print("[+] Running transformation...")
        transform_result = transform_plugin.transform(rewriter, analysis_result)
        
        if transform_result:
            print("[+] Transformation completed successfully")
            
            # Save the transformed binary
            output_file = config.get('output_path', 'transformed_output.exe')
            print(f"[+] Saving to {output_file}...")
            
            save_result = rewriter.save_binary(output_file)
            if save_result:
                print(f"[+] Successfully saved to {output_file}")
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
    print("Testing packer plugins with all fixes applied...")
    success = test_packer_plugins()
    if success:
        print("[+] All fixes are working correctly!")
    else:
        print("[-] There are still issues with the fixes.")