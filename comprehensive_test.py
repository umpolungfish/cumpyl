#!/usr/bin/env python3
"""
Comprehensive test to verify all packer plugins work correctly
"""

import sys
import os

# Add the cumpyl directory to the path
sys.path.insert(0, '/home/mrnob0dy666/cumpyl')

def test_all_packer_plugins():
    """Test that all packer plugins work correctly"""
    results = {}
    
    # Test Go packer plugin
    try:
        from cumpyl_package.cumpyl import BinaryRewriter
        from cumpyl_package.config import ConfigManager
        from plugins.go_packer_plugin import get_analysis_plugin, get_transformation_plugin
        
        print("[+] Testing Go packer plugin...")
        
        # Create config and rewriter
        config_manager = ConfigManager()
        config = config_manager.config_data if hasattr(config_manager, 'config_data') else {}
        
        # Set configuration for actual transformation (not dry run)
        config['dry_run'] = False
        config['output_path'] = 'comprehensive_go_test.exe'
        config['allow_transform'] = True
        
        rewriter = BinaryRewriter('/home/mrnob0dy666/cumpyl/gogogo.exe', config_manager)
        
        # Load the binary
        print("[+] Loading binary...")
        if not rewriter.load_binary():
            print("[-] Failed to load binary")
            results['go_packer'] = False
        else:
            # Create analysis plugin instance
            print("[+] Creating analysis plugin instance...")
            analysis_plugin = get_analysis_plugin(config)
            
            # Analyze with plugin
            print("[+] Running analysis...")
            analysis_result = analysis_plugin.analyze(rewriter)
            
            if not analysis_result:
                print("[-] Analysis failed")
                results['go_packer'] = False
            else:
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
                    output_file = config.get('output_path', 'go_transformed_output.exe')
                    print(f"[+] Saving to {output_file}...")
                    
                    save_result = rewriter.save_binary(output_file)
                    if save_result:
                        print(f"[+] Successfully saved to {output_file}")
                        results['go_packer'] = True
                    else:
                        print("[-] Failed to save transformed binary")
                        results['go_packer'] = False
                else:
                    print("[-] Transformation failed")
                    results['go_packer'] = False
                    
    except Exception as e:
        print(f"[-] Error with Go packer plugin: {e}")
        results['go_packer'] = False
    
    # Test CGo packer plugin
    try:
        from plugins.cgo_packer_plugin import get_plugin, get_transformation_plugin
        
        print("\n[+] Testing CGo packer plugin...")
        
        # Create config and rewriter
        config_manager = ConfigManager()
        config = config_manager.config_data if hasattr(config_manager, 'config_data') else {}
        
        # Set configuration for actual transformation (not dry run)
        config['dry_run'] = False
        config['output_path'] = 'comprehensive_cgo_test.exe'
        config['compression_level'] = 6
        config['encrypt_sections'] = True
        config['obfuscate_symbols'] = True
        config['preserve_cgo_symbols'] = True
        
        rewriter = BinaryRewriter('/home/mrnob0dy666/cumpyl/gogogo.exe', config_manager)
        
        # Load the binary
        print("[+] Loading binary...")
        if not rewriter.load_binary():
            print("[-] Failed to load binary")
            results['cgo_packer'] = False
        else:
            # Create analysis plugin instance
            print("[+] Creating analysis plugin instance...")
            analysis_plugin = get_plugin(config)
            
            # Analyze with plugin
            print("[+] Running analysis...")
            analysis_result = analysis_plugin.analyze(rewriter)
            
            if not analysis_result:
                print("[-] Analysis failed")
                results['cgo_packer'] = False
            else:
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
                    output_file = config.get('output_path', 'cgo_transformed_output.exe')
                    print(f"[+] Saving to {output_file}...")
                    
                    save_result = rewriter.save_binary(output_file)
                    if save_result:
                        print(f"[+] Successfully saved to {output_file}")
                        results['cgo_packer'] = True
                    else:
                        print("[-] Failed to save transformed binary")
                        results['cgo_packer'] = False
                else:
                    print("[-] Transformation failed")
                    results['cgo_packer'] = False
                    
    except Exception as e:
        print(f"[-] Error with CGo packer plugin: {e}")
        results['cgo_packer'] = False
    
    # Print summary
    print("\n" + "="*50)
    print("COMPREHENSIVE TEST SUMMARY")
    print("="*50)
    
    for plugin, success in results.items():
        status = "PASSED" if success else "FAILED"
        print(f"{plugin}: {status}")
    
    overall_success = all(results.values())
    print(f"\nOverall: {'PASSED' if overall_success else 'FAILED'}")
    
    return overall_success

if __name__ == "__main__":
    print("Running comprehensive test of all packer plugins...")
    success = test_all_packer_plugins()
    if success:
        print("\n[+] All packer plugins are working correctly!")
    else:
        print("\n[-] Some packer plugins are still having issues.")
    
    sys.exit(0 if success else 1)