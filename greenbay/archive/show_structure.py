#!/usr/bin/env python3
"""
Script to display the CA-Packer project structure.
"""

import os
import sys

def print_tree(dir_path, prefix="", is_last=True):
    """Print directory tree structure."""
    if not os.path.exists(dir_path):
        print(f"Error: Directory {dir_path} does not exist.")
        return
    
    # Get the directory name
    dir_name = os.path.basename(dir_path)
    if prefix == "":
        print(f"{dir_name}/")
    else:
        connector = "└── " if is_last else "├── "
        print(f"{prefix}{connector}{dir_name}/")
    
    # Update prefix for children
    if prefix == "":
        new_prefix = ""
    else:
        extension = "    " if is_last else "│   "
        new_prefix = prefix + extension
    
    # List all items in the directory
    try:
        items = sorted(os.listdir(dir_path))
    except PermissionError:
        print(f"{new_prefix}└── [Permission Denied]")
        return
    
    # Separate directories and files
    dirs = []
    files = []
    for item in items:
        item_path = os.path.join(dir_path, item)
        if os.path.isdir(item_path):
            dirs.append(item)
        else:
            files.append(item)
    
    # Print directories first
    all_items = dirs + files
    for i, item in enumerate(all_items):
        item_path = os.path.join(dir_path, item)
        is_last_item = (i == len(all_items) - 1)
        
        if os.path.isdir(item_path):
            print_tree(item_path, new_prefix, is_last_item)
        else:
            connector = "└── " if is_last_item else "├── "
            print(f"{new_prefix}{connector}{item}")

def main():
    # Get the project root directory (current directory)
    project_root = os.getcwd()
    
    print("CA-Packer Project Structure")
    print("=" * 30)
    print_tree(project_root)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())