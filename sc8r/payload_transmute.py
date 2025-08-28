#!/usr/bin/env python3
"""
Payload Transmutation Tool 🔓
Advanced encoding/obfuscation utility for red team operations
"""

import argparse
import sys
import json
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Union
from dataclasses import dataclass
from enum import Enum
import re

class TransmuteMethod(Enum):
    """Available transmutation methods 💉"""
    NULL_PADDING = "null_padding"
    UNICODE = "unicode" 
    HEX = "hex"
    OCTAL = "octal"
    MIXED = "mixed"
    ENV_VAR = "env_var"
    BASE64 = "base64"
    URL_ENCODE = "url_encode"

@dataclass
class TransmuteConfig:
    """Configuration for transmutation operations ⚠"""
    default_method: str = "null_padding"
    output_format: str = "raw"
    preserve_spacing: bool = True
    custom_separators: Dict[str, str] = None
    encoding_charset: str = "utf-8"
    
    def __post_init__(self):
        if self.custom_separators is None:
            self.custom_separators = {
                "null": "\\0",
                "space": " ",
                "tab": "\\t",
                "custom": "|"
            }

class PayloadTransmuter:
    """Core transmutation engine 🧬"""
    
    def __init__(self, config: TransmuteConfig, verbose: bool = False):
        self.config = config
        self.verbose = verbose
        self.methods = {
            TransmuteMethod.NULL_PADDING: self._null_padding,
            TransmuteMethod.UNICODE: self._unicode_encode,
            TransmuteMethod.HEX: self._hex_encode,
            TransmuteMethod.OCTAL: self._octal_encode,
            TransmuteMethod.MIXED: self._mixed_encode,
            TransmuteMethod.ENV_VAR: self._env_var_encode,
            TransmuteMethod.BASE64: self._base64_encode,
            TransmuteMethod.URL_ENCODE: self._url_encode
        }
    
    def transmute(self, payload: str, method: TransmuteMethod, **kwargs) -> Union[str, Dict[str, str]]:
        """Main transmutation dispatcher 💥"""
        if self.verbose:
            print(f"🔄 Transmuting with method: {method.value}")
            print(f"📝 Original payload length: {len(payload)}")
        
        if method not in self.methods:
            raise ValueError(f"❌ Unknown method: {method}")
        
        result = self.methods[method](payload, **kwargs)
        
        if self.verbose:
            if isinstance(result, dict):
                print(f"✅ Mixed encoding generated {len(result)} variants")
                for method_name, encoded in result.items():
                    preview = encoded[:100] + "..." if len(encoded) > 100 else encoded
                    print(f"🔍 {method_name}: {preview}")
            else:
                print(f"✅ Transmuted payload length: {len(result)}")
                preview = result[:100] + "..." if len(result) > 100 else result
                print(f"🔍 First 100 chars: {preview}")
        
        return result
    
    def _null_padding(self, payload: str, separator: str = "\\0") -> str:
        """Null byte padding transmutation 🌩"""
        return separator.join(payload)
    
    def _unicode_encode(self, payload: str, prefix: str = "\\u") -> str:
        """Unicode escape sequence encoding ⛈"""
        return "".join(f"{prefix}{ord(c):04x}" for c in payload)
    
    def _hex_encode(self, payload: str, prefix: str = "\\x") -> str:
        """Hexadecimal encoding 🔥"""
        return "".join(f"{prefix}{ord(c):02x}" for c in payload)
    
    def _octal_encode(self, payload: str, prefix: str = "\\") -> str:
        """Octal encoding 💢"""
        return "".join(f"{prefix}{ord(c):03o}" for c in payload)
    
    def _mixed_encode(self, payload: str, methods: List[str] = None) -> Dict[str, str]:
        """Mixed encoding using multiple methods 🧨"""
        if methods is None:
            methods = ["unicode", "hex", "octal"]
        
        results = {}
        for method_name in methods:
            try:
                # Call the specific method directly to avoid recursion
                if method_name == "unicode":
                    results[method_name] = self._unicode_encode(payload)
                elif method_name == "hex":
                    results[method_name] = self._hex_encode(payload)
                elif method_name == "octal":
                    results[method_name] = self._octal_encode(payload)
                elif method_name == "null_padding":
                    results[method_name] = self._null_padding(payload)
                elif method_name == "base64":
                    results[method_name] = self._base64_encode(payload)
                elif method_name == "url_encode":
                    results[method_name] = self._url_encode(payload)
                else:
                    if self.verbose:
                        print(f"⚠ Unknown method in mixed encoding: {method_name}")
            except Exception as e:
                if self.verbose:
                    print(f"⚠ Error with method {method_name}: {e}")
        
        return results
    
    def _env_var_encode(self, payload: str, var_name: str = "IFS") -> str:
        """Environment variable substitution 🔌"""
        # Replace spaces with ${IFS} and other common substitutions
        substitutions = {
            " ": f"${{{var_name}}}",
            "/": "${PWD:0:1}",
            "cat": "${PATH:5:3}",
        }
        
        result = payload
        for original, replacement in substitutions.items():
            result = result.replace(original, replacement)
        
        return result
    
    def _base64_encode(self, payload: str) -> str:
        """Base64 encoding 💊"""
        import base64
        return base64.b64encode(payload.encode()).decode()
    
    def _url_encode(self, payload: str) -> str:
        """URL encoding 🛸"""
        import urllib.parse
        return urllib.parse.quote(payload, safe='')

class PayloadLibrary:
    """Common payload templates and examples 💀"""
    
    TEMPLATES = {
        "sql_injection": [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT NULL,NULL,NULL --"
        ],
        "command_injection": [
            "; cat /etc/passwd",
            "| whoami",
            "&& ls -la"
        ],
        "xss": [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "onmouseover=alert('XSS')"
        ],
        "path_traversal": [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam"
        ]
    }
    
    @classmethod
    def get_payloads(cls, category: str) -> List[str]:
        """Get payloads by category 👁"""
        return cls.TEMPLATES.get(category, [])
    
    @classmethod
    def list_categories(cls) -> List[str]:
        """List available payload categories 👀"""
        return list(cls.TEMPLATES.keys())

def load_config(config_path: Optional[Path] = None) -> TransmuteConfig:
    """Load configuration from YAML file 🔑"""
    if config_path and config_path.exists():
        with open(config_path, 'r') as f:
            config_data = yaml.safe_load(f)
        return TransmuteConfig(**config_data)
    return TransmuteConfig()

def save_results(results: Union[str, Dict], output_path: Path, format_type: str = "txt"):
    """Save transmutation results 💾"""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    if format_type == "json" and isinstance(results, dict):
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
    else:
        with open(output_path, 'w') as f:
            if isinstance(results, dict):
                for method, result in results.items():
                    f.write(f"=== {method.upper()} ===\n")
                    f.write(f"{result}\n\n")
            else:
                f.write(str(results))

def create_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser following guidelines 🤘"""
    parser = argparse.ArgumentParser(
        description="Payload Transmutation Tool 🔓",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -p "cat /etc/passwd" -m null_padding
  %(prog)s -f payloads.txt -m mixed -o results.json
  %(prog)s --template sql_injection -m unicode --verbose
        """
    )
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--payload", "-p",
        help="Single payload to transmute"
    )
    input_group.add_argument(
        "--file", "-f",
        type=Path,
        help="File containing payloads (one per line)"
    )
    input_group.add_argument(
        "--template", "-t",
        choices=PayloadLibrary.list_categories(),
        help="Use built-in payload template"
    )
    
    # Method selection
    parser.add_argument(
        "--method", "-m",
        type=str,
        choices=[method.value for method in TransmuteMethod],
        default="null_padding",
        help="Transmutation method to use"
    )
    
    # Output options
    parser.add_argument(
        "--output", "-o",
        type=Path,
        help="Output file path"
    )
    parser.add_argument(
        "--format", "-fmt",
        choices=["txt", "json"],
        default="txt",
        help="Output format"
    )
    
    # Configuration
    parser.add_argument(
        "--config", "-c",
        type=Path,
        help="Configuration file path"
    )
    
    # Control flags
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--list-methods", "-lm",
        action="store_true",
        help="List available transmutation methods"
    )
    parser.add_argument(
        "--list-templates", "-lt",
        action="store_true",
        help="List available payload templates"
    )
    
    return parser

def main():
    """Main execution function 💸"""
    parser = create_parser()
    args = parser.parse_args()
    
    # Handle list operations
    if args.list_methods:
        print("🔓 Available Transmutation Methods:")
        for method in TransmuteMethod:
            print(f"  • {method.value}")
        return
    
    if args.list_templates:
        print("💀 Available Payload Templates:")
        for category in PayloadLibrary.list_categories():
            payloads = PayloadLibrary.get_payloads(category)
            print(f"  • {category} ({len(payloads)} payloads)")
        return
    
    # Load configuration
    config = load_config(args.config)
    transmuter = PayloadTransmuter(config, args.verbose)
    
    # Determine input payloads
    payloads = []
    if args.payload:
        payloads = [args.payload]
    elif args.file:
        if not args.file.exists():
            print(f"❌ File not found: {args.file}")
            sys.exit(1)
        with open(args.file, 'r') as f:
            payloads = [line.strip() for line in f if line.strip()]
    elif args.template:
        payloads = PayloadLibrary.get_payloads(args.template)
    
    if not payloads:
        print("❌ No payloads to process")
        sys.exit(1)
    
    # Process payloads
    method = TransmuteMethod(args.method)
    all_results = {}
    
    for i, payload in enumerate(payloads):
        if args.verbose:
            print(f"\n🔄 Processing payload {i+1}/{len(payloads)}")
            print(f"📝 Original: {payload}")
        
        try:
            result = transmuter.transmute(payload, method)
            
            if method == TransmuteMethod.MIXED:
                for sub_method, sub_result in result.items():
                    key = f"payload_{i+1}_{sub_method}"
                    all_results[key] = {
                        "original": payload,
                        "method": sub_method,
                        "transmuted": sub_result
                    }
            else:
                key = f"payload_{i+1}"
                all_results[key] = {
                    "original": payload,
                    "method": method.value,
                    "transmuted": result
                }
            
            # Print to console - handle both dict and string results
            if isinstance(result, dict):
                for sub_method, sub_result in result.items():
                    print(f"🧬 {sub_method.upper()}: {sub_result}")
            else:
                print(f"🧬 {method.value.upper()}: {result}")
                
        except Exception as e:
            print(f"❌ Error processing payload: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()
    
    # Save results if output specified
    if args.output:
        save_results(all_results, args.output, args.format)
        print(f"\n💾 Results saved to: {args.output}")

if __name__ == "__main__":
    main()
