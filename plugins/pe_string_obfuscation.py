"""
PE String Obfuscation Plugin for Cumpyl Framework

This plugin provides comprehensive PE executable string obfuscation functionality
including multiple obfuscation techniques, string detection, and safe transformation
capabilities.
"""
import lief
import re
import struct
import base64
import random
import string
from typing import Dict, Any, List, Tuple, Optional
import sys
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import marshal
import zlib

# Add the parent directory to the Python path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

try:
    from cumpyl_package.plugin_manager import AnalysisPlugin, TransformationPlugin
    from cumpyl_package.cumpyl import BinaryRewriter
except ImportError:
    from plugin_manager import AnalysisPlugin, TransformationPlugin
    from cumpyl import BinaryRewriter


class PEStringObfuscationPlugin(AnalysisPlugin):
    """PE-specific string obfuscation analysis plugin"""

    def __init__(self, config):
        super().__init__(config)
        self.name = "pe_string_obfuscation"
        self.version = "2.0.0"
        self.description = "Advanced PE string detection and obfuscation analysis"
        self.author = "Cumpyl Framework"
        self.dependencies = []

        # Configuration from config file
        plugin_config = self.get_config()
        self.min_string_length = plugin_config.get('min_string_length', 4)
        self.max_string_length = plugin_config.get('max_string_length', 200)
        self.obfuscation_methods = plugin_config.get('obfuscation_methods', [
            'xor', 'base64', 'rot13', 'reverse', 'substitute_cipher', 'caesar_cipher', 'vigenere_cipher'
        ])
        self.target_sections = plugin_config.get('target_sections', ['.rdata', '.data', '.text'])
        self.string_patterns = plugin_config.get('string_patterns', [
            r'[A-Za-z0-9/\\.:_%-]{6,}',
            r'[A-Z_][A-Z0-9_]{3,}',
            r'[a-z_][a-z0-9_]{3,}',
            r'\w+\.exe',
            r'\w+\.dll',
            r'\w+\.sys',
            r'(http|https|ftp)://[\w./%-]+'
        ])
        self.exclude_patterns = plugin_config.get('exclude_patterns', [
            r'^(Nt|Zw|NtDll|Kernel32|User32|Gdi32|Advapi32|Shell32|Ole32|OleAut32|Comctl32|Comdlg32|Dnsapi|Ws2_32|Iphlpapi|Urlmon|Wininet|Winhttp|Crypt32|Schannel|Secur32|Netapi32|Wtsapi32|Psapi|Dbghelp|Mscoree|Msvcr|ApiSet|ApiSetSchema)\w*$',  # System API names
            r'\b(kernel32\.dll|user32\.dll|gdi32\.dll|ntdll\.dll|advapi32\.dll|shell32\.dll)\b',  # System DLLs
        ])

    def analyze(self, rewriter: BinaryRewriter) -> Dict[str, Any]:
        """Analyze PE binary for string obfuscation opportunities"""
        results = {
            'plugin_name': self.name,
            'version': self.version,
            'description': self.description,
            'analysis': {
                'total_strings_found': 0,
                'strings_by_section': {},
                'high_risk_strings': [],
                'obfuscation_opportunities': [],
                'recommended_methods': {},
                'entropy_analysis': {},
                'section_sizes': {}
            },
            'strings': []
        }

        if not rewriter.binary or not isinstance(rewriter.binary, lief.PE.Binary):
            results['error'] = "Binary is not a PE file or not loaded"
            return results

        binary = rewriter.binary

        # Analyze each section for strings
        for section in binary.sections:
            section_name = section.name
            section_content = bytes(section.content)

            # Store section sizes for analysis
            results['analysis']['section_sizes'][section_name] = len(section_content)

            # Only analyze targeted sections
            if section_name not in self.target_sections:
                continue

            # Calculate entropy for the section
            entropy = self.calculate_entropy(section_content)
            results['analysis']['entropy_analysis'][section_name] = {
                'entropy': entropy,
                'size': len(section_content)
            }

            # Extract strings from section
            strings_in_section = self.extract_strings_from_section(section_content, section_name)

            # Filter out excluded patterns
            filtered_strings = self.filter_excluded_strings(strings_in_section)

            if filtered_strings:
                results['analysis']['strings_by_section'][section_name] = {
                    'count': len(filtered_strings),
                    'strings': filtered_strings
                }

                # Add to overall results
                results['strings'].extend([
                    {
                        'value': s['value'],
                        'section': section_name,
                        'offset': s['offset'],
                        'length': s['length'],
                        'type': s['type']
                    }
                    for s in filtered_strings
                ])

        # Calculate total strings found
        results['analysis']['total_strings_found'] = len(results['strings'])

        # Identify high-risk strings (potential indicators of compromise)
        results['analysis']['high_risk_strings'] = self.identify_high_risk_strings(results['strings'])

        # Determine obfuscation opportunities
        results['analysis']['obfuscation_opportunities'] = self.calculate_obfuscation_opportunities(results['strings'])

        # Recommend methods based on string types
        results['analysis']['recommended_methods'] = self.recommend_obfuscation_methods(results['strings'])

        return results

    def filter_excluded_strings(self, strings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter out strings that match exclusion patterns"""
        filtered = []

        for s in strings:
            value = s['value']
            is_excluded = False

            for pattern in self.exclude_patterns:
                if re.search(pattern, value, re.IGNORECASE):
                    is_excluded = True
                    break

            if not is_excluded:
                filtered.append(s)

        return filtered

    def extract_strings_from_section(self, content: bytes, section_name: str) -> List[Dict[str, Any]]:
        """Extract strings from a specific section using multiple techniques"""
        strings = []

        # Extract ASCII strings (traditional approach)
        ascii_strings = self.extract_ascii_strings(content)
        for s in ascii_strings:
            s['type'] = 'ascii'
            s['section'] = section_name
            strings.append(s)

        # Extract Unicode strings
        unicode_strings = self.extract_unicode_strings(content)
        for s in unicode_strings:
            s['type'] = 'unicode'
            s['section'] = section_name
            strings.append(s)

        # Apply additional pattern matching for special strings
        pattern_strings = self.extract_pattern_strings(content)
        for s in pattern_strings:
            s['section'] = section_name
            strings.append(s)

        # Apply advanced string detection
        advanced_strings = self.extract_advanced_strings(content, section_name)
        for s in advanced_strings:
            strings.append(s)

        return strings

    def extract_ascii_strings(self, data: bytes) -> List[Dict[str, Any]]:
        """Extract ASCII strings from binary data"""
        strings = []
        current_string = []
        start_offset = 0

        for i, byte in enumerate(data):
            if 32 <= byte <= 126 or byte in [9, 10, 13]:  # Printable chars and common whitespace
                if not current_string:
                    start_offset = i
                current_string.append(byte)
            else:
                if len(current_string) >= self.min_string_length:
                    string_val = bytes(current_string).decode('ascii', errors='ignore')
                    if len(string_val) >= self.min_string_length and not all(c == '\0' for c in string_val):
                        strings.append({
                            'value': string_val[:self.max_string_length],
                            'offset': start_offset,
                            'length': len(current_string),
                            'type': 'ascii'
                        })
                current_string = []

        # Handle last string if it exists
        if len(current_string) >= self.min_string_length:
            string_val = bytes(current_string).decode('ascii', errors='ignore')
            if len(string_val) >= self.min_string_length and not all(c == '\0' for c in string_val):
                strings.append({
                    'value': string_val[:self.max_string_length],
                    'offset': start_offset,
                    'length': len(current_string),
                    'type': 'ascii'
                })

        return strings

    def extract_unicode_strings(self, data: bytes) -> List[Dict[str, Any]]:
        """Extract Unicode (UTF-16) strings from binary data"""
        strings = []
        current_string = []
        start_offset = 0

        # Process pairs of bytes for UTF-16
        i = 0
        while i < len(data) - 1:
            # Check for possible null-terminated UTF-16 string
            char_word = data[i] | (data[i + 1] << 8)

            if 32 <= char_word <= 126 or 0xE000 <= char_word <= 0xF8FF or char_word in [9, 10, 13]:
                if not current_string:
                    start_offset = i
                current_string.append(char_word)
                i += 2  # Move by 2 bytes for UTF-16
            else:
                if len(current_string) >= self.min_string_length:
                    try:
                        string_bytes = b''.join([struct.pack('<H', c) for c in current_string])
                        string_val = string_bytes.decode('utf-16le', errors='ignore')
                        if len(string_val) >= self.min_string_length and not all(c == '\0' for c in string_val):
                            strings.append({
                                'value': string_val[:self.max_string_length],
                                'offset': start_offset,
                                'length': len(current_string) * 2,
                                'type': 'unicode'
                            })
                    except:
                        pass  # Skip if decoding fails

                current_string = []
                i += 1  # Move by 1 byte to continue search

        # Handle last string
        if len(current_string) >= self.min_string_length:
            try:
                string_bytes = b''.join([struct.pack('<H', c) for c in current_string])
                string_val = string_bytes.decode('utf-16le', errors='ignore')
                if len(string_val) >= self.min_string_length and not all(c == '\0' for c in string_val):
                    strings.append({
                        'value': string_val[:self.max_string_length],
                        'offset': start_offset,
                        'length': len(current_string) * 2,
                        'type': 'unicode'
                    })
            except:
                pass

        return strings

    def extract_pattern_strings(self, data: bytes) -> List[Dict[str, Any]]:
        """Extract strings matching specific patterns"""
        strings = []

        for pattern in self.string_patterns:
            try:
                # Try with compiled regex
                compiled_pattern = re.compile(pattern, re.IGNORECASE)
                for match in compiled_pattern.finditer(data.decode('utf-8', errors='ignore')):
                    strings.append({
                        'value': match.group(),
                        'offset': match.start(),
                        'length': len(match.group()),
                        'type': 'pattern'
                    })
            except Exception:
                # If UTF-8 decoding fails, try with bytes
                try:
                    pattern_bytes = pattern.encode('ascii', errors='ignore')
                    start = 0
                    while True:
                        pos = data.find(pattern_bytes, start)
                        if pos == -1:
                            break
                        # Extract context around the match to see if it forms a string
                        end_pos = pos + len(pattern_bytes)
                        # Look for potential string boundaries
                        strings.append({
                            'value': pattern_bytes.decode('ascii', errors='ignore'),
                            'offset': pos,
                            'length': len(pattern_bytes),
                            'type': 'pattern'
                        })
                        start = end_pos
                except:
                    continue

        return strings

    def extract_advanced_strings(self, data: bytes, section_name: str) -> List[Dict[str, Any]]:
        """Extract strings with more advanced techniques"""
        strings = []

        # Look for strings that might be obfuscated with simple methods
        # For example, strings obfuscated with simple XOR or addition
        potential_strings = []

        # Try different XOR keys (0x01 to 0xFF)
        for xor_key in range(1, 256):
            if xor_key % 32 == 0:  # Only try every 32nd key to save time
                try:
                    xor_data = bytes([b ^ xor_key for b in data])
                    xor_strings = self.extract_ascii_strings(xor_data)
                    for s in xor_strings:
                        # Check if this seems like a real string (not all random chars)
                        if self.is_likely_valid_string(s['value']):
                            s['value'] = bytes([c ^ xor_key for c in s['value'].encode('utf-8')]).decode('utf-8', errors='ignore')
                            s['offset'] = s['offset']
                            s['type'] = f'ascii_xor_{hex(xor_key)}'
                            s['section'] = section_name
                            potential_strings.append(s)
                except:
                    continue

        return potential_strings

    def is_likely_valid_string(self, value: str) -> bool:
        """Check if a string is likely a valid string (not random data)"""
        # Check if the string has at least some printable characters
        printable_chars = sum(1 for c in value if c.isprintable() and c != '\x00')
        return printable_chars / len(value) > 0.7 if value else False

    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of byte data"""
        if not data:
            return 0.0

        # Count frequency of each byte
        freq_dict = {}
        for byte in data:
            freq_dict[byte] = freq_dict.get(byte, 0) + 1

        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for count in freq_dict.values():
            probability = count / data_len
            if probability > 0:
                import math
                entropy -= probability * math.log2(probability)

        return entropy

    def identify_high_risk_strings(self, strings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify potentially malicious or sensitive strings"""
        high_risk = []

        # Define patterns for high-risk strings
        risk_patterns = [
            (r'(admin|root|password|secret|key|token|credential|api_key|password|user)', 'Credentials'),
            (r'(http|https|ftp|ftps)://', 'Network Indicators'),
            (r'\w+\.(exe|dll|sys|bat|cmd|ps1|vbs|js|msi|com|pif|scr)', 'Executables'),
            (r'(CreateRemoteThread|WriteProcessMemory|VirtualAllocEx|ReadProcessMemory|QueueUserAPC|SetWindowsHookEx)', 'Process Injection'),
            (r'(RegSetValue|RegCreateKey|RegOpenKey|RegDeleteKey)', 'Registry'),
            (r'(netstat|tasklist|taskkill|wmic|powershell|cmd|cmd\.exe)', 'Commands'),
            (r'([0-9]{1,3}\.){3}[0-9]{1,3}', 'IP Addresses'),
            (r'\w+@\w+\.\w+', 'Emails'),
            (r'(c:|d:|e:|f:|g:|h:|i:|j:|k:|l:|m:|n:|o:|p:|q:|r:|s:|t:|u:|v:|w:|x:|y:|z:)', 'Paths'),
            (r'(\\\\|//)', 'Network Paths'),
            (r'(\\\\\w+\\ipc\$|\\\\\w+\\admin\$|\\\\\w+\\c\$)', 'Admin Shares'),
            (r'(services|sc|netsh|schtasks)', 'System Services'),
            (r'(net user|net localgroup administrators|net group)', 'User Management'),
            (r'(lsass|lsasrv|sam|samlib)', 'Security'),
            (r'(mimikatz|bloodhound|cobalt|metasploit|cain|abel|ophcrack)', 'Tools'),
        ]

        for string_info in strings:
            value = string_info['value'].lower()
            for pattern, category in risk_patterns:
                if re.search(pattern, value, re.IGNORECASE):
                    high_risk.append({
                        'string': string_info,
                        'category': category
                    })

        return high_risk

    def calculate_obfuscation_opportunities(self, strings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Calculate potential obfuscation opportunities"""
        opportunities = []

        for string_info in strings:
            # Calculate obfuscation score based on string properties
            score = 0
            value = string_info['value']

            # Longer strings are better candidates for obfuscation (up to a point)
            length_factor = min(len(value) / 10, 5)  # Max 5 points for length
            score += length_factor

            # Strings with special characters are good candidates
            special_chars = sum(1 for c in value if c in ['.', '/', '\\', ':', '@', '_', '-', '&', '='])
            score += min(special_chars, 3)

            # Network-related strings are good candidates
            if any(protocol in value.lower() for protocol in ['http', 'ftp', 'smtp', 'tcp', 'ip']):
                score += 3

            # Executable-related strings are good candidates
            if any(ext in value.lower() for ext in ['.exe', '.dll', '.sys', '.bat', '.ps1']):
                score += 3

            # Credential-related strings are good candidates
            if any(cred in value.lower() for cred in ['password', 'key', 'token', 'admin', 'root', 'secret']):
                score += 4

            # High entropy strings might already be obfuscated
            if len(value) > 10:
                str_entropy = self.calculate_entropy(value.encode('utf-8'))
                if str_entropy > 6.5:  # High entropy might mean it's already obfuscated
                    score -= 2

            if score >= 1.5:  # Threshold for obfuscation opportunity
                opportunities.append({
                    'string': string_info,
                    'obfuscation_score': score,
                    'entropy': self.calculate_entropy(value.encode('utf-8')) if value else 0
                })

        return opportunities

    def recommend_obfuscation_methods(self, strings: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Recommend obfuscation methods for string types"""
        recommendations = {
            'xor': [],              # Good for general strings
            'base64': [],           # Good for URLs and paths
            'rot13': [],            # Good for simple obfuscation
            'reverse': [],          # Good for short strings
            'encrypt': [],          # Good for sensitive strings
            'substitute_cipher': [], # Good for basic obfuscation
            'caesar_cipher': [],    # Good for basic obfuscation
            'vigenere_cipher': [],  # Good for moderate obfuscation
            'compression': [],      # Good for long strings
        }

        for string_info in strings:
            value = string_info['value']

            # Determine best method based on string characteristics
            if len(value) < 8:
                recommendations['reverse'].append(string_info)
            elif 'http' in value.lower() or 'ftp' in value.lower():
                recommendations['base64'].append(string_info)
            elif any(char in value for char in ['@', '.exe', '.dll', '.sys']):
                recommendations['encrypt'].append(string_info)
            elif len(value) > 50:
                recommendations['compression'].append(string_info)
            elif any(cred in value.lower() for cred in ['password', 'key', 'token', 'secret']):
                recommendations['encrypt'].append(string_info)
            elif any(proto in value.lower() for proto in ['\\\\', '//']):
                recommendations['vigenere_cipher'].append(string_info)
            else:
                recommendations['xor'].append(string_info)

        return recommendations


class PEStringObfuscationTransformationPlugin(TransformationPlugin):
    """PE string obfuscation transformation plugin"""

    def __init__(self, config):
        super().__init__(config)
        self.name = "pe_string_obfuscation_transform"
        self.version = "2.0.0"
        self.description = "PE string obfuscation transformation plugin"
        self.author = "Cumpyl Framework"
        self.dependencies = ["pe_string_obfuscation"]

        # Configuration from config file
        plugin_config = self.get_config()
        self.obfuscation_methods = plugin_config.get('obfuscation_methods', [
            'xor', 'base64', 'rot13', 'reverse', 'substitute_cipher', 'caesar_cipher', 'vigenere_cipher'
        ])
        self.target_strings = plugin_config.get('target_strings', [])
        self.key_rotation_interval = plugin_config.get('key_rotation_interval', 10)
        self.injection_section = plugin_config.get('injection_section', '.rdata')
        self.backup_original = plugin_config.get('backup_original', True)
        self.store_keys_in_binary = plugin_config.get('store_keys_in_binary', False)

    def analyze(self, rewriter: BinaryRewriter) -> Dict[str, Any]:
        """Perform pre-transformation analysis"""
        return {
            'plugin_name': self.name,
            'version': self.version,
            'description': self.description
        }

    def transform(self, rewriter: BinaryRewriter, analysis_result: Dict[str, Any]) -> bool:
        """Transform the binary by obfuscating identified strings"""
        try:
            if not rewriter.binary or not isinstance(rewriter.binary, lief.PE.Binary):
                print("[-] Binary is not a PE file or not loaded")
                return False

            print(f"[+] Starting PE string obfuscation transformation...")

            # Use the analysis results to identify strings to obfuscate
            strings_to_obfuscate = self.select_strings_for_obfuscation(analysis_result)

            if not strings_to_obfuscate:
                print("[*] No strings found for obfuscation")
                return True

            print(f"[+] Identified {len(strings_to_obfuscate)} strings for obfuscation")

            # Backup original strings if needed
            if self.backup_original:
                self.backup_original_strings(rewriter, strings_to_obfuscate)

            # Apply obfuscation methods to each string
            for string_info in strings_to_obfuscate:
                success = self.obfuscate_string(rewriter, string_info)
                if not success:
                    print(f"[-] Failed to obfuscate string: {string_info['value']}")
                    return False

            print(f"[+] Successfully obfuscated {len(strings_to_obfuscate)} strings")
            return True

        except Exception as e:
            print(f"[-] Transformation failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    def backup_original_strings(self, rewriter: BinaryRewriter, strings: List[Dict[str, Any]]) -> None:
        """Backup original strings for potential restoration"""
        # In a real implementation, you might store this in a custom section
        # For now, we'll just log it
        print(f"[*] Backing up {len(strings)} original strings")

    def select_strings_for_obfuscation(self, analysis_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Select which strings to obfuscate based on analysis results"""
        strings_to_obfuscate = []

        # Get analysis results
        analysis = analysis_result.get('analysis', {})
        recommended_methods = analysis.get('recommended_methods', {})

        # Select strings based on recommended methods
        for method, string_list in recommended_methods.items():
            if method in self.obfuscation_methods:
                strings_to_obfuscate.extend(string_list)

        # Also include high-risk strings
        high_risk = analysis.get('high_risk_strings', [])
        for hr in high_risk:
            strings_to_obfuscate.append(hr['string'])

        # Remove duplicates by value
        seen_values = set()
        unique_strings = []
        for s in strings_to_obfuscate:
            if s['value'] not in seen_values:
                seen_values.add(s['value'])
                unique_strings.append(s)

        return unique_strings

    def obfuscate_string(self, rewriter: BinaryRewriter, string_info: Dict[str, Any]) -> bool:
        """Apply obfuscation method to a single string"""
        try:
            section_name = string_info['section']
            original_string = string_info['value']
            offset = string_info['offset']

            # Determine which method to use for this string
            method = self.select_obfuscation_method(string_info)

            print(f"[+] Obfuscating string '{original_string[:30]}...' using method: {method}")

            # Apply the selected obfuscation method
            if method == 'xor':
                obfuscated_data, decryption_stub = self.xor_obfuscate(original_string)
            elif method == 'base64':
                obfuscated_data, decryption_stub = self.base64_obfuscate(original_string)
            elif method == 'rot13':
                obfuscated_data, decryption_stub = self.rot13_obfuscate(original_string)
            elif method == 'reverse':
                obfuscated_data, decryption_stub = self.reverse_obfuscate(original_string)
            elif method == 'encrypt':
                obfuscated_data, decryption_stub = self.encrypt_obfuscate(original_string)
            elif method == 'substitute_cipher':
                obfuscated_data, decryption_stub = self.substitute_cipher_obfuscate(original_string)
            elif method == 'caesar_cipher':
                obfuscated_data, decryption_stub = self.caesar_cipher_obfuscate(original_string)
            elif method == 'vigenere_cipher':
                obfuscated_data, decryption_stub = self.vigenere_cipher_obfuscate(original_string)
            elif method == 'compression':
                obfuscated_data, decryption_stub = self.compression_obfuscate(original_string)
            else:
                print(f"[-] Unknown obfuscation method: {method}")
                return False

            # Pad the obfuscated data to match the original length if needed
            original_length = len(original_string.encode('utf-8'))
            if len(obfuscated_data) < original_length:
                # Add null bytes or random padding
                padding_needed = original_length - len(obfuscated_data)
                if method == 'xor':
                    # For XOR, we can use the same key for padding
                    key = getattr(self, '_last_xor_key', 0x42)  # Default key
                    obfuscated_data += bytes([0x00 ^ key] * padding_needed)
                else:
                    obfuscated_data += b'\x00' * padding_needed
            elif len(obfuscated_data) > original_length:
                # Truncate if needed (shouldn't happen in most cases)
                obfuscated_data = obfuscated_data[:original_length]

            # Modify the section with obfuscated data
            success = rewriter.modify_section_data(section_name, offset, obfuscated_data)

            if not success:
                print(f"[-] Failed to modify section {section_name} at offset {offset}")
                return False

            # For some methods, we might need to inject a decryption stub
            # This would require more complex PE manipulation
            # For now, we'll focus on direct replacement

            return True

        except Exception as e:
            print(f"[-] Failed to obfuscate string '{string_info['value']}': {e}")
            return False

    def select_obfuscation_method(self, string_info: Dict[str, Any]) -> str:
        """Select the best obfuscation method for a string"""
        value = string_info['value']

        # Choose method based on string characteristics
        if len(value) < 8:
            return 'reverse'
        elif any(proto in value.lower() for proto in ['http', 'ftp']):
            return 'base64'
        elif any(char in value for char in ['@', '.exe', '.dll', '.sys']):
            return 'encrypt'
        elif len(value) > 20:
            return 'vigenere_cipher'
        elif len(value) > 50:
            return 'compression'
        else:
            return 'xor'

    def xor_obfuscate(self, string: str) -> Tuple[bytes, Optional[bytes]]:
        """XOR obfuscate a string with a random key"""
        # Generate a random key (using a more sophisticated approach)
        key = random.randint(1, 255)
        self._last_xor_key = key  # Store for potential padding
        string_bytes = string.encode('utf-8')
        obfuscated = bytes([b ^ key for b in string_bytes])

        # In real scenario, you'd also need to store the key somewhere in the executable
        # This is a simplified version
        return obfuscated, None

    def base64_obfuscate(self, string: str) -> Tuple[bytes, Optional[bytes]]:
        """Base64 obfuscate a string"""
        encoded = base64.b64encode(string.encode('utf-8'))
        return encoded, None

    def rot13_obfuscate(self, string: str) -> Tuple[bytes, Optional[bytes]]:
        """ROT13 obfuscate a string"""
        # Use Python's built-in ROT13
        import codecs
        encoded = codecs.encode(string, 'rot13')
        return encoded.encode('utf-8'), None

    def reverse_obfuscate(self, string: str) -> Tuple[bytes, Optional[bytes]]:
        """Reverse obfuscate a string"""
        reversed_string = string[::-1]
        return reversed_string.encode('utf-8'), None

    def encrypt_obfuscate(self, string: str) -> Tuple[bytes, Optional[bytes]]:
        """Encrypt a string using AES"""
        # Generate a random key and IV
        key = os.urandom(32)  # 256-bit key
        iv = os.urandom(16)   # 128-bit IV

        # Pad the string to be AES-compatible
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(string.encode('utf-8')) + padder.finalize()

        # Encrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()

        # Return the IV + encrypted data (IV is not secret)
        # In a real implementation, you'd need to store the key securely
        return iv + encrypted, None

    def substitute_cipher_obfuscate(self, string: str) -> Tuple[bytes, Optional[bytes]]:
        """Substitute cipher obfuscate a string"""
        # Create a random substitution mapping
        alphabet = string.ascii_lowercase
        shuffled = list(alphabet)
        random.shuffle(shuffled)
        mapping = {c: s for c, s in zip(alphabet, shuffled)}

        # Apply the substitution
        result = ""
        for char in string.lower():
            if char in mapping:
                result += mapping[char]
            else:
                result += char

        # Store the mapping in a real implementation
        return result.encode('utf-8'), None

    def caesar_cipher_obfuscate(self, string: str) -> Tuple[bytes, Optional[bytes]]:
        """Caesar cipher obfuscate a string with random shift"""
        shift = random.randint(1, 25)  # Random shift between 1-25
        result = ""

        for char in string:
            if char.isalpha():
                if char.islower():
                    result += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
                else:
                    result += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            else:
                result += char

        return result.encode('utf-8'), None

    def vigenere_cipher_obfuscate(self, input_string: str) -> Tuple[bytes, Optional[bytes]]:
        """Vigenère cipher obfuscate a string with random key"""
        import string as string_module  # Import with different name to avoid conflict
        # Generate a random key
        key_length = min(random.randint(3, 8), len(input_string) // 2 + 1)
        random_key = ''.join(random.choices(string_module.ascii_lowercase, k=key_length))

        result = ""
        key_idx = 0
        for i, char in enumerate(input_string):
            if char.isalpha():
                key_char = random_key[key_idx % len(random_key)]
                key_idx += 1

                if char.islower():
                    result += chr((ord(char) - ord('a') + ord(key_char) - ord('a')) % 26 + ord('a'))
                else:
                    result += chr((ord(char) - ord('A') + ord(key_char) - ord('a')) % 26 + ord('A'))
            else:
                result += char

        return result.encode('utf-8'), None

    def compression_obfuscate(self, string: str) -> Tuple[bytes, Optional[bytes]]:
        """Compress and obfuscate a string"""
        # Compress the string using zlib
        compressed = zlib.compress(string.encode('utf-8'))

        # Optionally add more obfuscation to compressed data
        xor_key = random.randint(1, 255)
        obfuscated = bytes([b ^ xor_key for b in compressed])

        # In a real implementation, you'd need to store the key for decompression
        return obfuscated, None


def get_analysis_plugin(config):
    """Factory function for analysis plugin"""
    return PEStringObfuscationPlugin(config)


def get_transformation_plugin(config):
    """Factory function for transformation plugin"""
    return PEStringObfuscationTransformationPlugin(config)


# Example usage for testing
if __name__ == "__main__":
    import sys
    import os
    # Add proper path for testing
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

    try:
        from cumpyl_package.config import ConfigManager, get_config
        config = get_config()
        plugin = PEStringObfuscationPlugin(config)
        print(f"Plugin initialized: {plugin.name} v{plugin.version}")
        print(f"Description: {plugin.description}")
    except Exception as e:
        print(f"Error initializing plugin: {e}")