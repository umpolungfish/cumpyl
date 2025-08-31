#!/usr/bin/env python3
"""
Test script for Cumpyl Framework menu system
"""

import sys
import os

# Add the current directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_menu_system():
    """Test that we can import the menu system without errors"""
    try:
        from cumpyl_package.start_menu import CumpylStartMenu
        from cumpyl_package.config import ConfigManager
        
        # Create a config manager
        config = ConfigManager()
        
        # Create the start menu
        menu = CumpylStartMenu(config)
        
        print("SUCCESS: Successfully imported and initialized menu system")
        print("SUCCESS: Menu system is ready for use")
        
        return True
    except Exception as e:
        print(f"ERROR: Error importing menu system: {e}")
        return False

if __name__ == "__main__":
    success = test_menu_system()
    sys.exit(0 if success else 1)