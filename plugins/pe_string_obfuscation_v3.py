#!/usr/bin/env python3
"""
PE String Obfuscation Plugin V3 - Functional Obfuscation
Includes stub injection and code reference patching for functional obfuscated binaries
"""

import lief
import random
import sys
import os
from typing import Dict, Any, List, Tuple, Optional

# Add parent directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

try:
    from cumpyl_package.plugin_manager import TransformationPlugin
    from cumpyl_package.cumpyl import BinaryRewriter
    from cumpyl_package.stub_injector import StubInjector, DeobfuscationType
    from cumpyl_package.code_analyzer import CodeAnalyzer, ReferencePatcher
except ImportError:
    from plugin_manager import TransformationPlugin
    from cumpyl import BinaryRewriter
    from stub_injector import StubInjector, DeobfuscationType
    from code_analyzer import CodeAnalyzer, ReferencePatcher


class PEStringObfuscationV3Plugin(TransformationPlugin):
    """
    Enhanced PE String Obfuscation with Functional Binary Support

    V3 Features:
    - Stub injection for runtime deobfuscation
    - Code reference analysis and patching
    - Key storage in dedicated section
    - Produces functional obfuscated binaries
    """

    def __init__(self, config):
        super().__init__(config)
        self.name = "pe_string_obfuscation_v3"
        self.version = "3.0.0"
        self.description = "Functional PE string obfuscation with stub injection"
        self.author = "Cumpyl Framework"
        self.dependencies = ["pe_string_obfuscation"]  # Uses analysis from v2

        # Components
        self.stub_injector = None
        self.code_analyzer = None
        self.reference_patcher = None

        # Configuration
        plugin_config = self.get_config()
        self.enabled_methods = plugin_config.get('enabled_methods', [
            'xor', 'rot13', 'reverse'  # Start with simpler methods
        ])
        self.patch_references = plugin_config.get('patch_references', True)
        self.validate_after_transform = plugin_config.get('validate_after_transform', True)

    def analyze(self, rewriter: BinaryRewriter) -> Dict[str, Any]:
        """Pre-transformation analysis"""
        return {
            'plugin_name': self.name,
            'version': self.version,
            'description': self.description,
            'enabled_methods': self.enabled_methods
        }

    def transform(self, rewriter: BinaryRewriter, analysis_result: Dict[str, Any]) -> bool:
        """
        Transform binary with functional string obfuscation

        Process:
        1. Get strings from analysis
        2. Inject deobfuscation stubs
        3. Analyze code for string references
        4. Obfuscate strings
        5. Store keys in .xdata
        6. Patch code references to call stubs
        7. Validate binary
        """
        try:
            if not rewriter.binary or not isinstance(rewriter.binary, lief.PE.Binary):
                print("[-] Binary is not a PE file or not loaded")
                return False

            print(f"\n[+] Starting Functional String Obfuscation V3...")
            print(f"[*] Enabled methods: {', '.join(self.enabled_methods)}")

            # Step 1: Get strings to obfuscate from analysis
            strings_to_obfuscate = self._select_strings_for_obfuscation(analysis_result)

            if not strings_to_obfuscate:
                print("[*] No strings selected for obfuscation")
                return True

            print(f"[+] Selected {len(strings_to_obfuscate)} strings for obfuscation")

            # Step 2: Inject deobfuscation stubs
            print(f"\n[*] Step 1/5: Injecting deobfuscation stubs...")
            self.stub_injector = StubInjector(rewriter.binary)
            if not self.stub_injector.inject_all_stubs():
                print("[-] Failed to inject stubs")
                return False
            print(f"[+] Successfully injected stubs")

            # Step 3: Analyze code for string references
            print(f"\n[*] Step 2/5: Analyzing code for string references...")
            self.code_analyzer = CodeAnalyzer(rewriter.binary)

            # Register all string RVAs
            string_rvas = []
            for s in strings_to_obfuscate:
                # Calculate RVA (virtual address)
                section = self._find_section(rewriter.binary, s['section'])
                if section:
                    string_rva = section.virtual_address + s['offset']
                    string_rvas.append(string_rva)
                    self.code_analyzer.register_string(string_rva)
                    s['rva'] = string_rva  # Store for later use

            # Analyze code sections
            refs_found = self.code_analyzer.analyze_code_sections()
            print(f"[+] Found {refs_found} code references to strings")

            # Generate reference report
            if refs_found > 0:
                report = self.code_analyzer.generate_reference_report()
                print(f"    - Patchable: {report['patchable_count']}")
                print(f"    - Unpatchable: {report['unpatchable_count']}")

            # Step 4: Obfuscate strings and store keys
            print(f"\n[*] Step 3/5: Obfuscating strings and storing keys...")
            obfuscation_map = {}  # Maps string_rva -> (method, stub_rva, key_data)

            for string_info in strings_to_obfuscate:
                result = self._obfuscate_string_v3(rewriter, string_info)
                if result:
                    string_rva = string_info['rva']
                    obfuscation_map[string_rva] = result
                    print(f"    [+] Obfuscated: {string_info['value'][:40]}")

            print(f"[+] Obfuscated {len(obfuscation_map)} strings")

            # Step 5: Patch code references
            if self.patch_references and refs_found > 0:
                print(f"\n[*] Step 4/5: Patching code references...")
                self.reference_patcher = ReferencePatcher(rewriter.binary, self.code_analyzer)

                # Create stub RVA map for patcher
                stub_rva_map = {}
                for string_rva, (method, stub_rva, key_data) in obfuscation_map.items():
                    stub_rva_map[string_rva] = stub_rva

                patched_count = self.reference_patcher.patch_all_references(stub_rva_map)
                print(f"[+] Patched {patched_count} code references")

                if patched_count < report['patchable_count']:
                    print(f"[!] Warning: Not all patchable references were patched")

            # Step 6: Finalize and validate
            print(f"\n[*] Step 5/5: Finalizing stub injection...")
            if not self.stub_injector.finalize():
                print("[-] Failed to finalize stubs")
                return False

            if self.validate_after_transform:
                print(f"\n[*] Validating transformed binary...")
                if self._validate_binary(rewriter.binary):
                    print(f"[+] Binary validation passed")
                else:
                    print(f"[!] Warning: Binary validation detected issues")

            print(f"\n[+] ✓ Functional string obfuscation complete!")
            print(f"[+] Binary should now execute correctly with obfuscated strings")
            return True

        except Exception as e:
            print(f"[-] Transformation failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _select_strings_for_obfuscation(self, analysis_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Select strings to obfuscate based on analysis and configuration"""
        strings_to_obfuscate = []

        # Get analysis from pe_string_obfuscation plugin
        if 'pe_string_obfuscation' in analysis_result:
            pe_analysis = analysis_result['pe_string_obfuscation']
            analysis = pe_analysis.get('analysis', {})

            # Get recommended methods
            recommended = analysis.get('recommended_methods', {})

            # Select strings based on enabled methods
            for method, string_list in recommended.items():
                if method in self.enabled_methods:
                    strings_to_obfuscate.extend(string_list[:10])  # Limit to 10 per method for safety

        # Remove duplicates
        seen = set()
        unique = []
        for s in strings_to_obfuscate:
            if s['value'] not in seen:
                seen.add(s['value'])
                unique.append(s)

        return unique[:50]  # Limit total to 50 strings for initial implementation

    def _obfuscate_string_v3(self, rewriter: BinaryRewriter,
                            string_info: Dict[str, Any]) -> Optional[Tuple[str, int, bytes]]:
        """
        Obfuscate a string using V3 architecture

        Returns: (method, stub_rva, key_data) or None on failure
        """
        try:
            # Select method
            method = self._select_method_for_string(string_info)
            if not method:
                return None

            # Get obfuscation method enum
            method_enum = self._method_name_to_enum(method)
            if method_enum is None:
                return None

            # Get stub RVA for this method
            stub_rva = self.stub_injector.get_stub_rva(method_enum)
            if stub_rva is None:
                print(f"[-] No stub available for method {method}")
                return None

            # Obfuscate the string
            if method == 'xor':
                obfuscated_bytes, key_data = self._xor_obfuscate_v3(string_info['value'])
            elif method == 'rot13':
                obfuscated_bytes, key_data = self._rot13_obfuscate_v3(string_info['value'])
            elif method == 'reverse':
                obfuscated_bytes, key_data = self._reverse_obfuscate_v3(string_info['value'])
            else:
                print(f"[-] Unsupported method: {method}")
                return None

            # Store obfuscated data in binary
            section = self._find_section(rewriter.binary, string_info['section'])
            if not section:
                return None

            # Modify section with obfuscated data
            section_content = list(section.content)
            offset = string_info['offset']

            for i, byte in enumerate(obfuscated_bytes[:string_info['length']]):
                if offset + i < len(section_content):
                    section_content[offset + i] = byte

            section.content = section_content

            # Store key in .xdata section
            string_rva = string_info['rva']
            key_offset = self.stub_injector.store_key(string_rva, key_data, method_enum)

            if key_offset < 0:
                print(f"[-] Failed to store key for string at RVA 0x{string_rva:08x}")
                return None

            return (method, stub_rva, key_data)

        except Exception as e:
            print(f"[-] Failed to obfuscate string: {e}")
            return None

    def _select_method_for_string(self, string_info: Dict[str, Any]) -> Optional[str]:
        """Select appropriate obfuscation method for a string"""
        value = string_info['value']
        length = len(value)

        # Prefer simpler methods for robustness
        if length < 8:
            return 'reverse' if 'reverse' in self.enabled_methods else None
        elif length < 20:
            return 'xor' if 'xor' in self.enabled_methods else 'rot13'
        else:
            return 'xor' if 'xor' in self.enabled_methods else None

    def _method_name_to_enum(self, method: str) -> Optional[DeobfuscationType]:
        """Convert method name to enum"""
        mapping = {
            'xor': DeobfuscationType.XOR,
            'base64': DeobfuscationType.BASE64,
            'rot13': DeobfuscationType.ROT13,
            'reverse': DeobfuscationType.REVERSE,
            'vigenere': DeobfuscationType.VIGENERE,
            'caesar': DeobfuscationType.CAESAR,
            'aes_cbc': DeobfuscationType.AES_CBC
        }
        return mapping.get(method)

    def _xor_obfuscate_v3(self, string: str) -> Tuple[bytes, bytes]:
        """XOR obfuscation - returns (obfuscated_bytes, key_data)"""
        key = random.randint(1, 255)
        string_bytes = string.encode('utf-8')
        obfuscated = bytes([b ^ key for b in string_bytes])
        key_data = bytes([key])
        return obfuscated, key_data

    def _rot13_obfuscate_v3(self, string: str) -> Tuple[bytes, bytes]:
        """ROT13 obfuscation - returns (obfuscated_bytes, key_data)"""
        import codecs
        encoded = codecs.encode(string, 'rot13')
        return encoded.encode('utf-8'), bytes()  # No key needed for ROT13

    def _reverse_obfuscate_v3(self, string: str) -> Tuple[bytes, bytes]:
        """Reverse obfuscation - returns (obfuscated_bytes, key_data)"""
        reversed_string = string[::-1]
        return reversed_string.encode('utf-8'), bytes()  # No key needed

    def _find_section(self, binary: lief.PE.Binary, section_name: str) -> Optional[lief.PE.Section]:
        """Find section by name"""
        for section in binary.sections:
            if section.name == section_name:
                return section
        return None

    def _validate_binary(self, binary: lief.PE.Binary) -> bool:
        """Validate binary structure after transformation"""
        try:
            # Check that sections exist
            if not binary.sections:
                return False

            # Check that .stub and .xdata sections were added
            has_stub = any(s.name == '.stub' for s in binary.sections)
            has_xdata = any(s.name == '.xdata' for s in binary.sections)

            if not has_stub or not has_xdata:
                print(f"[!] Missing required sections (stub={has_stub}, xdata={has_xdata})")
                return False

            # Check entrypoint is still valid
            if binary.optional_header.addressof_entrypoint == 0:
                print(f"[!] Invalid entry point")
                return False

            # Additional checks could include:
            # - Import table integrity
            # - Section alignment
            # - Checksum recalculation

            return True

        except Exception as e:
            print(f"[!] Validation error: {e}")
            return False


def get_plugin(config):
    """Factory function for plugin instantiation"""
    return PEStringObfuscationV3Plugin(config)
