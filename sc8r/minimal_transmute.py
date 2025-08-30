#!/usr/bin/env python3
"""
Minimal transmutation tool for testing basic functionality 🔧
"""

import argparse
import sys

def null_padding(payload):
    """Simple null padding: a -> a\\0b\\0c"""
    return "\\0".join(payload)

def hex_encode(payload):
    """Simple hex encoding: a -> \\x61"""
    return "".join(f"\\x{ord(c):02x}" for c in payload)

def unicode_encode(payload):
    """Simple unicode encoding: a -> \\u0061"""
    return "".join(f"\\u{ord(c):04x}" for c in payload)

def url_encode(payload):
    """Simple URL encoding"""
    import urllib.parse
    return urllib.parse.quote(payload, safe='')

def base64_encode(payload):
    """Simple base64 encoding"""
    import base64
    return base64.b64encode(payload.encode()).decode()

def main():
    parser = argparse.ArgumentParser(description="Minimal Transmutation Tool 🔧")
    parser.add_argument("--payload", "-p", required=True, help="Payload to encode")
    parser.add_argument("--method", "-m", 
                       choices=["null", "hex", "unicode", "url", "base64"],
                       default="null", help="Encoding method")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if args.verbose:
        print(f"🔄 Encoding '{args.payload}' with method: {args.method}")
    
    # Simple method dispatch
    methods = {
        "null": null_padding,
        "hex": hex_encode,
        "unicode": unicode_encode,
        "url": url_encode,
        "base64": base64_encode
    }
    
    try:
        result = methods[args.method](args.payload)
        
        if args.verbose:
            print(f"✅ Encoding successful!")
            print(f"📝 Original: {args.payload}")
            print(f"🧬 Encoded:  {result}")
            print(f"📏 Length: {len(result)} chars")
        else:
            print(result)
            
    except Exception as e:
        print(f"❌ Encoding failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
