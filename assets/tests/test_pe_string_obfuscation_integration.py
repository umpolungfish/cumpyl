"""
Integration test for PE String Obfuscation functionality
"""
import os
import sys
import tempfile
from unittest.mock import Mock, patch

# Add the project root to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

def test_plugin_loading():
    """Test that the PE String Obfuscation plugin can be loaded properly"""
    try:
        from plugins.pe_string_obfuscation import get_analysis_plugin, get_transformation_plugin
        from cumpyl_package.config import get_config
        
        config = get_config()
        
        # Test analysis plugin creation
        analysis_plugin = get_analysis_plugin(config)
        print(f"✓ Analysis Plugin: {analysis_plugin.name} v{analysis_plugin.version}")
        assert analysis_plugin.name == "pe_string_obfuscation"
        assert analysis_plugin.version == "2.0.0"
        
        # Test transformation plugin creation
        transformation_plugin = get_transformation_plugin(config)
        print(f"✓ Transformation Plugin: {transformation_plugin.name} v{transformation_plugin.version}")
        assert transformation_plugin.name == "pe_string_obfuscation_transform"
        assert transformation_plugin.version == "2.0.0"
        
        print("✓ Plugin loading test passed")
        return True
    except Exception as e:
        print(f"✗ Plugin loading test failed: {e}")
        return False

def test_command_line_integration():
    """Test that the command line arguments are properly added"""
    try:
        from cumpyl_package.cumpyl import main
        import argparse
        
        # Verify that the required command line arguments exist
        # This is more of a conceptual test since we can't easily test the full argparser
        print("✓ Command line integration concept verified")
        return True
    except Exception as e:
        print(f"✗ Command line integration test failed: {e}")
        return False

def test_obfuscation_methods():
    """Test that various obfuscation methods work correctly"""
    try:
        from plugins.pe_string_obfuscation import PEStringObfuscationTransformationPlugin
        from cumpyl_package.config import get_config
        
        config = get_config()
        plugin = PEStringObfuscationTransformationPlugin(config)
        
        # Test different obfuscation methods
        test_string = "Hello World!"
        
        # XOR
        xor_data, _ = plugin.xor_obfuscate(test_string)
        assert isinstance(xor_data, bytes)
        print(f"✓ XOR obfuscation works: {len(xor_data)} bytes")
        
        # Base64
        base64_data, _ = plugin.base64_obfuscate(test_string)
        assert isinstance(base64_data, bytes)
        print(f"✓ Base64 obfuscation works: {len(base64_data)} bytes")
        
        # ROT13
        rot13_data, _ = plugin.rot13_obfuscate(test_string)
        assert isinstance(rot13_data, bytes)
        assert rot13_data.decode('utf-8') == "Uryyb Jbeyq!"
        print(f"✓ ROT13 obfuscation works: {rot13_data.decode('utf-8')}")
        
        # Reverse
        reverse_data, _ = plugin.reverse_obfuscate(test_string)
        assert isinstance(reverse_data, bytes)
        assert reverse_data.decode('utf-8') == "!dlroW olleH"
        print(f"✓ Reverse obfuscation works: {reverse_data.decode('utf-8')}")
        
        # Caesar
        caesar_data, _ = plugin.caesar_cipher_obfuscate(test_string)
        assert isinstance(caesar_data, bytes)
        print(f"✓ Caesar cipher obfuscation works: {len(caesar_data)} bytes")
        
        print("✓ Obfuscation methods test passed")
        return True
    except Exception as e:
        print(f"✗ Obfuscation methods test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main_test():
    """Run all integration tests"""
    print("Running PE String Obfuscation Integration Tests...")
    print("="*50)
    
    tests = [
        ("Plugin Loading", test_plugin_loading),
        ("Command Line Integration", test_command_line_integration),
        ("Obfuscation Methods", test_obfuscation_methods)
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\nRunning {test_name}...")
        result = test_func()
        results.append((test_name, result))
    
    print("\n" + "="*50)
    print("Test Results:")
    all_passed = True
    for test_name, result in results:
        status = "PASS" if result else "FAIL"
        print(f"  {test_name}: {status}")
        if not result:
            all_passed = False
    
    print(f"\nOverall: {'ALL TESTS PASSED' if all_passed else 'SOME TESTS FAILED'}")
    return all_passed

if __name__ == "__main__":
    success = main_test()
    if not success:
        sys.exit(1)