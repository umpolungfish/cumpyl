#!/usr/bin/env python3
"""
Test script to check binary content attributes
"""

import lief
import sys
import os

def test_binary_content(binary_path):
    """Test what attributes are available on a LIEF binary object"""
    if not os.path.exists(binary_path):
        print(f"File not found: {binary_path}")
        return
    
    try:
        binary = lief.parse(binary_path)
        if binary is None:
            print("Failed to parse binary")
            return
            
        print(f"Binary format: {binary.format}")
        print(f"Has content attribute: {hasattr(binary, 'content')}")
        
        if hasattr(binary, 'content'):
            content = binary.content
            print(f"Content type: {type(content)}")
            try:
                content_len = len(content)
                print(f"Content length: {content_len}")
            except Exception as e:
                print(f"Error getting content length: {e}")
        else:
            print("Binary object attributes:")
            for attr in dir(binary):
                if not attr.startswith('_'):
                    print(f"  {attr}")
                    
        # Check if we can get size another way
        if hasattr(binary, 'header') and hasattr(binary.header, 'sizeof_image'):
            print(f"Image size from header: {binary.header.sizeof_image}")
            
        # Try to get file size
        file_size = os.path.getsize(binary_path)
        print(f"Actual file size: {file_size} bytes")
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        test_binary_content(sys.argv[1])
    else:
        print("Usage: python3 test_binary_content.py <binary_file>")