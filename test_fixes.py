#!/usr/bin/env python3
"""
Test script to verify the fixes to the plugin packer menu
"""

import sys
import os

# Add the plugins directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'plugins'))

def test_consolidated_utils_fix():
    """Test that the LIEF SECTION_CHARACTERISTICS fix works"""
    try:
        import lief
        # This should work now
        has_execute = hasattr(lief.PE.Section.CHARACTERISTICS, 'MEM_EXECUTE')
        has_read = hasattr(lief.PE.Section.CHARACTERISTICS, 'MEM_READ')
        has_write = hasattr(lief.PE.Section.CHARACTERISTICS, 'MEM_WRITE')
        
        if has_execute and has_read and has_write:
            print("✓ LIEF SECTION_CHARACTERISTICS fix verified")
            return True
        else:
            print("✗ LIEF SECTION_CHARACTERISTICS fix failed")
            return False
    except Exception as e:
        print(f"✗ LIEF SECTION_CHARACTERISTICS test failed: {e}")
        return False

def test_config_fix():
    """Test that the config fix works"""
    try:
        # Test the imports work
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'cumpyl_package'))
        from cumpyl_package.config import ConfigManager
        
        # Test creating a config manager with default config (no dict parameter)
        config_manager = ConfigManager()
        
        # Test that we can update the config
        test_config = {"test": "value"}
        if hasattr(config_manager, 'config_data'):
            config_manager.config_data.update(test_config)
            if config_manager.config_data.get("test") == "value":
                print("✓ ConfigManager fix verified")
                return True
        
        print("✗ ConfigManager fix failed")
        return False
    except Exception as e:
        print(f"✗ ConfigManager test failed: {e}")
        return False

def test_syntax():
    """Test that the plugin packer menu has no syntax errors"""
    try:
        # Try to compile the plugin packer menu
        with open("/home/mrnob0dy666/cumpyl/plugin_packer_menu.py", "r") as f:
            compile(f.read(), "/home/mrnob0dy666/cumpyl/plugin_packer_menu.py", "exec")
        print("✓ Plugin packer menu syntax verified")
        return True
    except Exception as e:
        print(f"✗ Plugin packer menu syntax test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("Testing fixes to plugin packer menu...\n")
    
    tests = [
        test_syntax,
        test_consolidated_utils_fix,
        test_config_fix
    ]
    
    passed = 0
    for test in tests:
        if test():
            passed += 1
    
    print(f"\n{passed}/{len(tests)} tests passed")
    return passed == len(tests)

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)