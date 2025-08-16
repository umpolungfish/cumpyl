import re
import string
from typing import Dict, Any, List, Tuple, Set
import sys
import os

# 𐑨𐑛 𐑞 𐑐𐑸𐑧𐑯𐑑 𐑛𐑲𐑮𐑧𐑒𐑑𐑼𐑦 𐑑 𐑞 𐑐𐑭𐑔 𐑓𐑹 𐑦𐑥𐑐𐑹𐑑𐑦𐑙
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from cumpyl_package.plugin_manager import AnalysisPlugin


class StringExtractionPlugin(AnalysisPlugin):
    """𐑦𐑒𐑕𐑑𐑮𐑨𐑒𐑑 𐑯 𐑩𐑯𐑨𐑤𐑲𐑟 𐑕𐑑𐑮𐑦𐑙𐑟 𐑦𐑯 𐑚𐑲𐑯𐑩𐑮𐑦 𐑓𐑲𐑤𐑟"""
    
    def __init__(self, config):
        super().__init__(config)
        self.name = "string_extraction"
        self.version = "1.0.0"
        self.description = "Extracts and analyzes strings from binary sections with context analysis"
        self.author = "Cumpyl Framework"
        self.dependencies = []
        
        # 𐑜𐑧𐑑 𐑒𐑪𐑯𐑓𐑦𐑜 𐑝𐑨𐑤𐑿𐑟
        plugin_config = self.get_config()
        self.min_string_length = plugin_config.get('min_string_length', 4)
        self.max_string_length = plugin_config.get('max_string_length', 200)
        self.include_unicode = plugin_config.get('include_unicode', True)
        self.extract_patterns = plugin_config.get('extract_patterns', True)
        
        # 𐑦𐑯𐑦𐑖𐑩𐑤𐑲𐑟 𐑮𐑧𐑒𐑟 𐑐𐑨𐑑𐑼𐑯𐑟
        self._init_patterns()
    
    def _init_patterns(self):
        """𐑦𐑯𐑦𐑖𐑩𐑤𐑲𐑟 𐑮𐑧𐑜𐑿𐑤𐑼 𐑦𐑒𐑕𐑐𐑮𐑧𐑖𐑩𐑯 𐑐𐑨𐑑𐑼𐑯𐑟 𐑓𐑹 𐑦𐑯𐑑𐑼𐑧𐑕𐑑𐑦𐑙 𐑕𐑑𐑮𐑦𐑙𐑟"""
        self.patterns = {
            # 𐑯𐑧𐑑𐑢𐑻𐑒 𐑮𐑦𐑤𐑱𐑑𐑦𐑛
            'ip_addresses': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            'urls': re.compile(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+'),
            'domains': re.compile(r'\b[a-zA-Z0-9-]+\.(?:com|org|net|edu|gov|mil|int|co|io|me|tv|info|biz|name|pro|aero|coop|museum|[a-z]{2})\b'),
            'email_addresses': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            
            # 𐑓𐑲𐑤 𐑐𐑭𐑔𐑕
            'file_paths_windows': re.compile(r'[A-Za-z]:\\[^<>:"|?*\x00-\x1f]+'),
            'file_paths_unix': re.compile(r'\/[^<>:"|?*\x00-\x1f\s]+'),
            'registry_keys': re.compile(r'HKEY_[A-Z_]+\\[^<>:"|?*\x00-\x1f]+'),
            
            # 𐑓𐑦𐑤 𐑧𐑒𐑕𐑑𐑧𐑯𐑖𐑩𐑯𐑟
            'executables': re.compile(r'\b\w+\.(?:exe|dll|sys|bat|cmd|ps1|vbs|js|jar|msi)\b', re.IGNORECASE),
            'documents': re.compile(r'\b\w+\.(?:doc|docx|pdf|txt|rtf|xls|xlsx|ppt|pptx)\b', re.IGNORECASE),
            'archives': re.compile(r'\b\w+\.(?:zip|rar|7z|tar|gz|bz2)\b', re.IGNORECASE),
            
            # 𐑦𐑯𐑒𐑮𐑦𐑐𐑖𐑩𐑯/𐑒𐑮𐑦𐑐𐑑𐑴
            'base64_strings': re.compile(r'[A-Za-z0-9+/]{20,}={0,2}'),
            'hex_strings': re.compile(r'\b[0-9A-Fa-f]{16,}\b'),
            'crypto_indicators': re.compile(r'\b(?:AES|RSA|SHA|MD5|DES|RC4|PGP|SSL|TLS)\b', re.IGNORECASE),
            
            # 𐑓𐑳𐑙𐑒𐑖𐑩𐑯 𐑯𐑱𐑥𐑟
            'api_functions': re.compile(r'\b(?:CreateProcess|WriteProcessMemory|VirtualAlloc|LoadLibrary|GetProcAddress|RegSetValue|ShellExecute|WinExec|CreateFile|CreateThread|SetWindowsHook|keybd_event|mouse_event)\w*\b', re.IGNORECASE),
            'socket_functions': re.compile(r'\b(?:WSAStartup|socket|connect|send|recv|bind|listen|accept|gethostbyname|inet_addr)\w*\b', re.IGNORECASE),
            
            # 𐑚𐑱𐑕 𐑦𐑯𐑓𐑼𐑥𐑱𐑖𐑩𐑯
            'error_messages': re.compile(r'(?:error|fail|exception|invalid|access denied|not found|permission|denied)', re.IGNORECASE),
            'debug_strings': re.compile(r'(?:debug|trace|log|printf|fprintf|sprintf|assert)', re.IGNORECASE),
            
            # 𐑕𐑦𐑒𐑢𐑮𐑦𐑑𐑦 𐑮𐑦𐑤𐑱𐑑𐑦𐑛
            'passwords': re.compile(r'(?:password|passwd|pwd|pass|secret|key)[\s=:]*[\'"]?[A-Za-z0-9!@#$%^&*()_+-=]{4,}[\'"]?', re.IGNORECASE),
            'credit_cards': re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'),
        }
        
        # 𐑦𐑯𐑑𐑼𐑧𐑕𐑑𐑦𐑙 𐑓𐑳𐑙𐑒𐑖𐑩𐑯 𐑯𐑱𐑥𐑟 (𐑩𐑒𐑕𐑐𐑨𐑯𐑛𐑦𐑛 𐑤𐑦𐑕𐑑)
        self.interesting_apis = {
            'process_manipulation': ['CreateProcess', 'OpenProcess', 'TerminateProcess', 'WriteProcessMemory', 'ReadProcessMemory', 'VirtualAllocEx'],
            'file_operations': ['CreateFile', 'WriteFile', 'ReadFile', 'DeleteFile', 'CopyFile', 'MoveFile'],
            'registry_operations': ['RegOpenKey', 'RegSetValue', 'RegGetValue', 'RegDeleteKey', 'RegCreateKey'],
            'network_operations': ['WSAStartup', 'socket', 'connect', 'send', 'recv', 'InternetOpen', 'HttpOpenRequest'],
            'crypto_operations': ['CryptAcquireContext', 'CryptCreateHash', 'CryptEncrypt', 'CryptDecrypt'],
            'hook_operations': ['SetWindowsHook', 'SetWinEventHook', 'CallNextHookEx'],
            'service_operations': ['CreateService', 'OpenService', 'StartService', 'ControlService'],
            'memory_operations': ['VirtualAlloc', 'VirtualProtect', 'HeapAlloc', 'GlobalAlloc']
        }
    
    def extract_ascii_strings(self, data: bytes) -> List[Dict[str, Any]]:
        """𐑦𐑒𐑕𐑑𐑮𐑨𐑒𐑑 ASCII 𐑕𐑑𐑮𐑦𐑙𐑟 𐑓𐑮𐑪𐑥 𐑚𐑲𐑯𐑩𐑮𐑦 𐑛𐑱𐑑𐑩"""
        strings = []
        current_string = ""
        start_offset = 0
        
        for i, byte in enumerate(data):
            if 32 <= byte <= 126:  # 𐑐𐑮𐑦𐑯𐑑𐑩𐑚𐑩𐑤 ASCII 𐑮𐑱𐑯𐑡
                if not current_string:
                    start_offset = i
                current_string += chr(byte)
            else:
                if len(current_string) >= self.min_string_length:
                    strings.append({
                        'value': current_string[:self.max_string_length],
                        'offset': start_offset,
                        'length': len(current_string),
                        'type': 'ascii'
                    })
                current_string = ""
        
        # 𐑗𐑧𐑒 𐑓𐑹 𐑞 𐑤𐑭𐑕𐑑 𐑕𐑑𐑮𐑦𐑙
        if len(current_string) >= self.min_string_length:
            strings.append({
                'value': current_string[:self.max_string_length],
                'offset': start_offset,
                'length': len(current_string),
                'type': 'ascii'
            })
        
        return strings
    
    def extract_unicode_strings(self, data: bytes) -> List[Dict[str, Any]]:
        """𐑦𐑒𐑕𐑑𐑮𐑨𐑒𐑑 Unicode (UTF-16) 𐑕𐑑𐑮𐑦𐑙𐑟 𐑓𐑮𐑪𐑥 𐑚𐑲𐑯𐑩𐑮𐑦 𐑛𐑱𐑑𐑩"""
        strings = []
        current_string = ""
        start_offset = 0
        
        # 𐑤𐑫𐑒 𐑓𐑹 UTF-16 𐑕𐑑𐑮𐑦𐑙𐑟 (𐑤𐑦𐑑𐑩𐑤 𐑧𐑯𐑛𐑦𐑩𐑯)
        for i in range(0, len(data) - 1, 2):
            if i + 1 < len(data):
                char_code = data[i] | (data[i + 1] << 8)
                
                # 𐑗𐑧𐑒 𐑦𐑓 𐑦𐑑'𐑕 𐑩 𐑐𐑮𐑦𐑯𐑑𐑩𐑚𐑩𐑤 Unicode 𐑒𐑸𐑦𐑒𐑑𐑼
                if 32 <= char_code <= 126 or 160 <= char_code <= 255:
                    if not current_string:
                        start_offset = i
                    try:
                        current_string += chr(char_code)
                    except ValueError:
                        # 𐑦𐑯𐑝𐑨𐑤𐑦𐑛 Unicode 𐑒𐑸𐑦𐑒𐑑𐑼
                        if len(current_string) >= self.min_string_length:
                            strings.append({
                                'value': current_string[:self.max_string_length],
                                'offset': start_offset,
                                'length': len(current_string) * 2,
                                'type': 'unicode'
                            })
                        current_string = ""
                else:
                    if len(current_string) >= self.min_string_length:
                        strings.append({
                            'value': current_string[:self.max_string_length],
                            'offset': start_offset,
                            'length': len(current_string) * 2,
                            'type': 'unicode'
                        })
                    current_string = ""
        
        # 𐑗𐑧𐑒 𐑓𐑹 𐑞 𐑤𐑭𐑕𐑑 𐑕𐑑𐑮𐑦𐑙
        if len(current_string) >= self.min_string_length:
            strings.append({
                'value': current_string[:self.max_string_length],
                'offset': start_offset,
                'length': len(current_string) * 2,
                'type': 'unicode'
            })
        
        return strings
    
    def categorize_strings(self, strings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """𐑒𐑨𐑑𐑩𐑜𐑼𐑲𐑟 𐑕𐑑𐑮𐑦𐑙𐑟 𐑚𐑱𐑕𐑑 𐑪𐑯 𐑞𐑺 𐑒𐑩𐑯𐑑𐑧𐑯𐑑"""
        categorized = {
            'network_indicators': [],
            'file_paths': [],
            'api_functions': [],
            'crypto_indicators': [],
            'error_messages': [],
            'debug_strings': [],
            'security_related': [],
            'interesting_patterns': [],
            'other': []
        }
        
        if not self.extract_patterns:
            categorized['other'] = strings
            return categorized
        
        for string_obj in strings:
            string_value = string_obj['value']
            matched_category = None
            
            # 𐑗𐑧𐑒 𐑩𐑜𐑱𐑯𐑕𐑑 𐑞 𐑐𐑨𐑑𐑼𐑯𐑟
            for pattern_name, pattern in self.patterns.items():
                if pattern.search(string_value):
                    string_obj['pattern_match'] = pattern_name
                    
                    # 𐑥𐑨𐑐 𐑐𐑨𐑑𐑼𐑯 𐑯𐑱𐑥𐑟 𐑑 𐑒𐑨𐑑𐑩𐑜𐑼𐑦𐑟
                    if pattern_name in ['ip_addresses', 'urls', 'domains', 'email_addresses']:
                        matched_category = 'network_indicators'
                    elif pattern_name in ['file_paths_windows', 'file_paths_unix', 'registry_keys']:
                        matched_category = 'file_paths'
                    elif pattern_name in ['api_functions', 'socket_functions']:
                        matched_category = 'api_functions'
                    elif pattern_name in ['base64_strings', 'hex_strings', 'crypto_indicators']:
                        matched_category = 'crypto_indicators'
                    elif pattern_name in ['error_messages']:
                        matched_category = 'error_messages'
                    elif pattern_name in ['debug_strings']:
                        matched_category = 'debug_strings'
                    elif pattern_name in ['passwords', 'credit_cards']:
                        matched_category = 'security_related'
                    else:
                        matched_category = 'interesting_patterns'
                    break
            
            # 𐑗𐑧𐑒 𐑩𐑜𐑱𐑯𐑕𐑑 API 𐑓𐑳𐑙𐑒𐑖𐑩𐑯 𐑤𐑦𐑕𐑑𐑕
            if matched_category is None:
                for category, apis in self.interesting_apis.items():
                    for api in apis:
                        if api.lower() in string_value.lower():
                            string_obj['api_category'] = category
                            matched_category = 'api_functions'
                            break
                    if matched_category:
                        break
            
            # 𐑨𐑛 𐑑 𐑞 𐑩𐑐𐑮𐑴𐑐𐑮𐑦𐑦𐑑 𐑒𐑨𐑑𐑩𐑜𐑼𐑦
            if matched_category:
                categorized[matched_category].append(string_obj)
            else:
                categorized['other'].append(string_obj)
        
        return categorized
    
    def analyze_string_context(self, strings: List[Dict[str, Any]], section_data: bytes) -> List[Dict[str, Any]]:
        """𐑩𐑯𐑨𐑤𐑲𐑟 𐑞 𐑒𐑩𐑯𐑑𐑧𐑒𐑕𐑑 𐑩𐑮𐑬𐑯𐑛 𐑦𐑯𐑑𐑼𐑧𐑕𐑑𐑦𐑙 𐑕𐑑𐑮𐑦𐑙𐑟"""
        enriched_strings = []
        
        for string_obj in strings:
            offset = string_obj['offset']
            context_size = 32
            
            # 𐑜𐑧𐑑 𐑚𐑲𐑑𐑕 𐑚𐑦𐑓𐑹 𐑯 𐑭𐑓𐑑𐑼 𐑞 𐑕𐑑𐑮𐑦𐑙
            start = max(0, offset - context_size)
            end = min(len(section_data), offset + string_obj['length'] + context_size)
            
            context_bytes = section_data[start:end]
            string_obj['context'] = {
                'hex': context_bytes.hex(),
                'offset_start': start,
                'offset_end': end
            }
            
            # 𐑒𐑨𐑤𐑒𐑿𐑤𐑱𐑑 𐑦𐑯𐑑𐑼𐑧𐑕𐑑 𐑕𐑒𐑹
            interest_score = self._calculate_interest_score(string_obj)
            string_obj['interest_score'] = interest_score
            
            enriched_strings.append(string_obj)
        
        # 𐑕𐑹𐑑 𐑚𐑲 𐑦𐑯𐑑𐑼𐑧𐑕𐑑 𐑕𐑒𐑹 (𐑣𐑦𐑜𐑼 𐑦𐑟 𐑥𐑹 𐑦𐑯𐑑𐑼𐑧𐑕𐑑𐑦𐑙)
        enriched_strings.sort(key=lambda x: x['interest_score'], reverse=True)
        
        return enriched_strings
    
    def _calculate_interest_score(self, string_obj: Dict[str, Any]) -> float:
        """𐑒𐑨𐑤𐑒𐑿𐑤𐑱𐑑 𐑩 𐑯𐑿𐑥𐑧𐑮𐑦𐑒 𐑦𐑯𐑑𐑼𐑧𐑕𐑑 𐑕𐑒𐑹 𐑓𐑹 𐑩 𐑕𐑑𐑮𐑦𐑙"""
        score = 0.0
        string_value = string_obj['value'].lower()
        
        # 𐑤𐑧𐑙𐑔 𐑚𐑴𐑯𐑩𐑕
        if string_obj['length'] > 10:
            score += 1.0
        
        # 𐑐𐑨𐑑𐑼𐑯 𐑥𐑨𐑗 𐑚𐑴𐑯𐑩𐑕
        if 'pattern_match' in string_obj:
            pattern_name = string_obj['pattern_match']
            if pattern_name in ['ip_addresses', 'urls', 'domains']:
                score += 5.0
            elif pattern_name in ['api_functions', 'socket_functions']:
                score += 4.0
            elif pattern_name in ['passwords', 'credit_cards']:
                score += 6.0
            elif pattern_name in ['crypto_indicators', 'base64_strings']:
                score += 3.0
            else:
                score += 2.0
        
        # API 𐑒𐑨𐑑𐑩𐑜𐑼𐑦 𐑚𐑴𐑯𐑩𐑕
        if 'api_category' in string_obj:
            category = string_obj['api_category']
            if category in ['process_manipulation', 'hook_operations']:
                score += 4.0
            elif category in ['network_operations', 'crypto_operations']:
                score += 3.5
            else:
                score += 2.0
        
        # 𐑦𐑯𐑑𐑼𐑧𐑕𐑑𐑦𐑙 𐑒𐑰𐑢𐑻𐑛 𐑚𐑴𐑯𐑩𐑕
        interesting_keywords = [
            'malware', 'virus', 'trojan', 'backdoor', 'keylog', 'rootkit',
            'exploit', 'payload', 'shellcode', 'inject', 'hook', 'stealth',
            'bypass', 'evasion', 'persistence', 'privilege', 'escalation'
        ]
        
        for keyword in interesting_keywords:
            if keyword in string_value:
                score += 3.0
        
        # 𐑦𐑯𐑒𐑮𐑦𐑐𐑖𐑩𐑯/𐑧𐑯𐑒𐑴𐑛𐑦𐑙 𐑦𐑯𐑛𐑦𐑒𐑱𐑑𐑼𐑟
        if len(string_value) > 20 and all(c in 'abcdefghijklmnopqrstuvwxyz0123456789+/=' for c in string_value):
            score += 2.0  # 𐑐𐑪𐑕𐑦𐑚𐑩𐑤 base64
        
        return score
    
    def analyze(self, rewriter) -> Dict[str, Any]:
        """𐑩𐑯𐑨𐑤𐑲𐑟 𐑷𐑤 𐑕𐑧𐑒𐑖𐑩𐑯𐑟 𐑯 𐑦𐑒𐑕𐑑𐑮𐑨𐑒𐑑 𐑕𐑑𐑮𐑦𐑙𐑟"""
        results = {
            'sections': {},
            'summary': {
                'total_strings': 0,
                'interesting_strings': [],
                'api_functions_found': set(),
                'network_indicators': [],
                'security_related': []
            }
        }
        
        try:
            # 𐑩𐑯𐑨𐑤𐑲𐑟 𐑰𐑗 𐑕𐑧𐑒𐑖𐑩𐑯
            for section in rewriter.binary.sections:
                section_name = section.name
                section_data = bytes(section.content)
                
                if len(section_data) == 0:
                    continue
                
                # 𐑦𐑒𐑕𐑑𐑮𐑨𐑒𐑑 ASCII 𐑕𐑑𐑮𐑦𐑙𐑟
                ascii_strings = self.extract_ascii_strings(section_data)
                
                # 𐑦𐑒𐑕𐑑𐑮𐑨𐑒𐑑 Unicode 𐑕𐑑𐑮𐑦𐑙𐑟 𐑦𐑓 𐑦𐑯𐑱𐑚𐑩𐑤𐑛
                unicode_strings = []
                if self.include_unicode:
                    unicode_strings = self.extract_unicode_strings(section_data)
                
                # 𐑒𐑩𐑥𐑚𐑲𐑯 𐑷𐑤 𐑕𐑑𐑮𐑦𐑙𐑟
                all_strings = ascii_strings + unicode_strings
                
                # 𐑒𐑨𐑑𐑩𐑜𐑼𐑲𐑟 𐑞 𐑕𐑑𐑮𐑦𐑙𐑟
                categorized = self.categorize_strings(all_strings)
                
                # 𐑩𐑯𐑨𐑤𐑲𐑟 𐑒𐑩𐑯𐑑𐑧𐑒𐑕𐑑 𐑓𐑹 𐑦𐑯𐑑𐑼𐑧𐑕𐑑𐑦𐑙 𐑕𐑑𐑮𐑦𐑙𐑟
                high_interest_strings = []
                for category_strings in categorized.values():
                    high_interest_strings.extend(category_strings)
                
                enriched_strings = self.analyze_string_context(high_interest_strings, section_data)
                
                # 𐑦𐑞𐑧𐑯𐑑𐑦𐑓𐑲 𐑑𐑩𐑐 𐑦𐑯𐑑𐑼𐑧𐑕𐑑𐑦𐑙 𐑕𐑑𐑮𐑦𐑙𐑟 (𐑑𐑩𐑐 10)
                top_interesting = enriched_strings[:10]
                
                section_result = {
                    'string_count': {
                        'ascii': len(ascii_strings),
                        'unicode': len(unicode_strings),
                        'total': len(all_strings)
                    },
                    'categorized_strings': categorized,
                    'top_interesting': top_interesting,
                    'statistics': {
                        'avg_length': sum(s['length'] for s in all_strings) / len(all_strings) if all_strings else 0,
                        'max_length': max(s['length'] for s in all_strings) if all_strings else 0,
                        'min_length': min(s['length'] for s in all_strings) if all_strings else 0
                    }
                }
                
                results['sections'][section_name] = section_result
                results['summary']['total_strings'] += len(all_strings)
                
                # 𐑨𐑛 𐑑 𐑜𐑤𐑴𐑚𐑩𐑤 𐑕𐑧𐑑𐑕
                for api_string in categorized['api_functions']:
                    results['summary']['api_functions_found'].add(api_string['value'])
                
                for net_string in categorized['network_indicators']:
                    results['summary']['network_indicators'].append({
                        'section': section_name,
                        'value': net_string['value'],
                        'type': net_string.get('pattern_match', 'unknown')
                    })
                
                for sec_string in categorized['security_related']:
                    results['summary']['security_related'].append({
                        'section': section_name,
                        'value': sec_string['value'],
                        'type': sec_string.get('pattern_match', 'unknown')
                    })
                
                # 𐑨𐑛 𐑣𐑲 𐑦𐑯𐑑𐑼𐑧𐑕𐑑 𐑕𐑑𐑮𐑦𐑙𐑟 𐑑 𐑜𐑤𐑴𐑚𐑩𐑤 𐑤𐑦𐑕𐑑
                for interesting_string in top_interesting:
                    if interesting_string['interest_score'] > 3.0:
                        results['summary']['interesting_strings'].append({
                            'section': section_name,
                            'value': interesting_string['value'],
                            'score': interesting_string['interest_score'],
                            'offset': interesting_string['offset']
                        })
        
        except Exception as e:
            results['error'] = str(e)
        
        # 𐑒𐑩𐑯𐑝𐑻𐑑 𐑕𐑧𐑑 𐑑 𐑤𐑦𐑕𐑑 𐑓𐑹 JSON 𐑕𐑦𐑮𐑦𐑩𐑤𐑲𐑟𐑱𐑖𐑩𐑯
        results['summary']['api_functions_found'] = list(results['summary']['api_functions_found'])
        
        return results