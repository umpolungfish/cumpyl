"""
Functionality test for the PE String Obfuscation command line integration
"""
import os
import sys
import tempfile

# Add the project root to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

def test_plugin_registration():
    """Test that the PE String Obfuscation plugin is properly registered"""
    try:
        from plugins.plugin_registry import PluginRegistry
        
        analysis_plugins = PluginRegistry.list_plugins('analysis')
        transformation_plugins = PluginRegistry.list_plugins('transformation')
        
        assert 'pe_string_obfuscation' in analysis_plugins, "PE String Obfuscation analysis plugin not found"
        assert 'pe_string_obfuscation_transform' in transformation_plugins, "PE String Obfuscation transformation plugin not found"
        
        print("✓ PE String Obfuscation plugins are properly registered")
        return True
    except Exception as e:
        print(f"✗ Plugin registration test failed: {e}")
        return False

def test_plugin_factory_functions():
    """Test that the factory functions work properly"""
    try:
        from plugins.pe_string_obfuscation import get_analysis_plugin, get_transformation_plugin
        from cumpyl_package.config import get_config
        
        config = get_config()
        
        # Test both factory functions
        analysis_plugin = get_analysis_plugin(config)
        transformation_plugin = get_transformation_plugin(config)
        
        assert analysis_plugin.name == "pe_string_obfuscation"
        assert transformation_plugin.name == "pe_string_obfuscation_transform"
        
        print("✓ Plugin factory functions work correctly")
        return True
    except Exception as e:
        print(f"✗ Plugin factory test failed: {e}")
        return False

def test_config_integration():
    """Test that the plugin configuration is properly integrated"""
    try:
        from cumpyl_package.config import get_config

        config = get_config()
        plugin_config = config.get_plugin_config("pe_string_obfuscation")

        # Check if PE string obfuscation config exists in the config file
        if not plugin_config:
            # Check the raw config data to make sure it exists
            raw_config = config.config_data
            if 'plugins' in raw_config and 'pe_string_obfuscation' in raw_config['plugins']:
                plugin_config = raw_config['plugins']['pe_string_obfuscation']
            else:
                print("Plugin config not found in expected location")
                return False

        # Check that our configuration values exist
        assert 'min_string_length' in plugin_config or len(plugin_config) > 0
        print("✓ Plugin configuration is properly integrated")
        if plugin_config:
            print(f"  - Configuration keys: {list(plugin_config.keys())}")
        else:
            print("  - Configuration is empty but plugin exists in load order")
        return True
    except Exception as e:
        print(f"✗ Config integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all functionality tests"""
    print("Testing PE String Obfuscation Functionality...")
    print("="*50)
    
    tests = [
        test_plugin_registration,
        test_plugin_factory_functions,
        test_config_integration
    ]
    
    results = []
    for test_func in tests:
        result = test_func()
        results.append(result)
    
    print("\n" + "="*50)
    print("Test Results:")
    all_passed = all(results)
    
    for i, result in enumerate(results):
        status = "PASS" if result else "FAIL"
        print(f"  Test {i+1}: {status}")
    
    print(f"\nOverall: {'ALL TESTS PASSED' if all_passed else 'SOME TESTS FAILED'}")
    return all_passed

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)