#!/usr/bin/env python3
"""
Entry point for the Cumpyl Framework
"""

import argparse
import sys
import os

# Add the current directory to the path so we can import cumpyl_package
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from cumpyl_package import launch_menu, launch_start_menu
    from cumpyl_package.config import ConfigManager
except ImportError as e:
    print(f"Error importing cumpyl_package: {e}")
    print("Make sure you're running this script from the correct directory.")
    sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Cumpyl Framework - Advanced Binary Analysis & Rewriting Platform")
    parser.add_argument("file", nargs="?", help="Binary file to analyze")
    parser.add_argument("--menu", action="store_true", help="Launch the legacy menu system")
    parser.add_argument("--start-menu", action="store_true", help="Launch the new start menu system")
    parser.add_argument("--analyze-sections", action="store_true", help="Analyze binary sections")
    parser.add_argument("--suggest-obfuscation", action="store_true", help="Suggest obfuscation techniques")
    parser.add_argument("--hex-view", action="store_true", help="Show hex view of binary")
    parser.add_argument("--run-analysis", action="store_true", help="Run comprehensive analysis")
    parser.add_argument("--profile", help="Analysis profile to use")
    parser.add_argument("--report-format", help="Report format (html, json, yaml, xml)")
    parser.add_argument("--report-output", help="Report output file")
    
    args = parser.parse_args()
    
    # Initialize config
    config = ConfigManager()
    
    # Launch appropriate menu system
    if args.start_menu:
        # Launch the new modular start menu
        launch_start_menu(config)
    elif args.menu:
        # Launch the legacy menu
        launch_menu(config, args.file)
    else:
        # Default to new start menu
        launch_start_menu(config)

if __name__ == "__main__":
    main()