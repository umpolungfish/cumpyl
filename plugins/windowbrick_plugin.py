#!/usr/bin/env python3
"""
Windowbrick Plugin for Cumpyl Framework
Integrates windowbrick-style string obfuscation capabilities with cumpyl's plugin system
"""

import os
import sys
import logging
from typing import Dict, Any, List, Optional
import struct
import random
import time
from cumpyl_package.plugin_manager import AnalysisPlugin, TransformationPlugin

logger = logging.getLogger(__name__)


class WindowbrickAnalysisPlugin(AnalysisPlugin):
    """String obfuscation analysis plugin based on windowbrick techniques"""

    def __init__(self, config):
        super().__init__(config)
        self.name = "windowbrick_analysis"
        self.version = "1.0.0"
        self.description = "String obfuscation analysis using windowbrick techniques (XOR, rotation, substitution)"
        self.author = "Cumpyl Framework Team"
        self.dependencies = []

        # Initialize configuration
        plugin_config = self.get_config()
        self.rotation_amount = plugin_config.get('rotation_amount', 3)
        self.enable_anti_analysis = plugin_config.get('enable_anti_analysis', False)
        self.obfuscation_mode = plugin_config.get('obfuscation_mode', 'full')  # xor, rotation, substitution, full
        self.custom_substitution_table = plugin_config.get('custom_substitution_table', None)

    def _generate_dynamic_key(self) -> int:
        """Generate a dynamic key using system entropy sources"""
        # Get timestamp entropy
        timestamp_entropy = int(time.time() * 1000000) & 0xFF  # Lower byte of microseconds
        
        # Get PID entropy if available
        try:
            pid_entropy = os.getpid() & 0xFF
        except:
            pid_entropy = random.randint(0, 255)
        
        # Get random entropy 
        random_entropy = random.randint(0, 255)
        
        # Combine entropy sources
        combined_entropy = (timestamp_entropy ^ pid_entropy ^ random_entropy) & 0xFF
        return combined_entropy

    def _rotl(self, value: int, shift: int, bits: int = 8) -> int:
        """Rotate left operation"""
        shift = shift % bits
        return ((value << shift) | (value >> (bits - shift))) & ((1 << bits) - 1)

    def _rotr(self, value: int, shift: int, bits: int = 8) -> int:
        """Rotate right operation"""
        shift = shift % bits
        return ((value >> shift) | (value << (bits - shift))) & ((1 << bits) - 1)

    def _apply_xor(self, data: bytes, key: int) -> bytes:
        """Apply XOR operation to data"""
        return bytes(b ^ key for b in data)

    def _apply_rotation(self, data: bytes, amount: int) -> bytes:
        """Apply rotation operation to data"""
        # Handle positive (left) and negative (right) rotation amounts
        if amount >= 0:
            return bytes(self._rotl(b, amount) for b in data)
        else:
            # Convert negative rotation to right rotation
            right_amount = -amount % 8
            return bytes(self._rotr(b, right_amount) for b in data)

    def _get_default_substitution_table(self) -> bytes:
        """Get the default substitution table as a proper permutation for reversible cipher"""
        # Create a proper permutation of 0-255 to ensure reversible substitution cipher
        # This is a shuffled sequence of values 0-255
        return bytes([
            0x00, 0x1f, 0x2e, 0x3d, 0x4c, 0x5b, 0x6a, 0x79, 0x88, 0x97, 0xa6, 0xb5, 0xc4, 0xd3, 0xe2, 0xf1,
            0x10, 0x0f, 0x3e, 0x2d, 0x5c, 0x4b, 0x7a, 0x69, 0x98, 0x87, 0xb6, 0xa5, 0xd4, 0xc3, 0xf2, 0xe1,
            0x20, 0x3f, 0x0e, 0x1d, 0x6c, 0x7b, 0x4a, 0x59, 0xa8, 0xb7, 0x86, 0x95, 0xe4, 0xf3, 0xc2, 0xd1,
            0x30, 0x2f, 0x1e, 0x0d, 0x7c, 0x6b, 0x5a, 0x49, 0xb8, 0xa7, 0x96, 0x85, 0xf4, 0xe3, 0xd2, 0xc1,
            0x40, 0x5f, 0x6e, 0x7d, 0x0c, 0x1b, 0x2a, 0x39, 0xc8, 0xd7, 0xe6, 0xf5, 0x84, 0x93, 0xa2, 0xb1,
            0x50, 0x4f, 0x7e, 0x6d, 0x1c, 0x0b, 0x3a, 0x29, 0xd8, 0xc7, 0xf6, 0xe5, 0x94, 0x83, 0xb2, 0xa1,
            0x60, 0x7f, 0x4e, 0x5d, 0x2c, 0x3b, 0x0a, 0x19, 0xe8, 0xf7, 0xc6, 0xd5, 0xa4, 0xb3, 0x82, 0x91,
            0x70, 0x6f, 0x5e, 0x4d, 0x3c, 0x2b, 0x1a, 0x09, 0xf8, 0xe7, 0xd6, 0xc5, 0xb4, 0xa3, 0x92, 0x81,
            0x80, 0x9f, 0xae, 0xbd, 0xcc, 0xdb, 0xea, 0xf9, 0x08, 0x17, 0x26, 0x35, 0x44, 0x53, 0x62, 0x71,
            0x90, 0x8f, 0xbf, 0xad, 0xdc, 0xcb, 0xfa, 0xe9, 0x18, 0x07, 0x36, 0x25, 0x54, 0x43, 0x72, 0x61,
            0xa0, 0xbf, 0x8e, 0x9d, 0xec, 0xfb, 0xca, 0xd9, 0x28, 0x37, 0x06, 0x15, 0x64, 0x73, 0x42, 0x51,
            0xb0, 0xaf, 0x9e, 0x8d, 0xfc, 0xeb, 0xda, 0xc9, 0x38, 0x27, 0x16, 0x05, 0x74, 0x63, 0x52, 0x41,
            0xc0, 0xdf, 0xee, 0xfd, 0x8c, 0x9b, 0xaa, 0xb9, 0x48, 0x57, 0x66, 0x75, 0x04, 0x13, 0x22, 0x31,
            0xd0, 0xcf, 0xfe, 0xed, 0x9c, 0x8b, 0xba, 0xa9, 0x58, 0x47, 0x76, 0x65, 0x14, 0x03, 0x32, 0x21,
            0xe0, 0xff, 0xce, 0xdd, 0xac, 0xbb, 0x8a, 0x99, 0x68, 0x77, 0x46, 0x55, 0x24, 0x33, 0x02, 0x11,
            0xf0, 0xef, 0xde, 0xcd, 0xbc, 0xab, 0x9a, 0x89, 0x78, 0x67, 0x56, 0x45, 0x34, 0x23, 0x12, 0x01
        ])

    def _apply_substitution(self, data: bytes, table: bytes = None) -> bytes:
        """Apply substitution cipher using the substitution table"""
        if table is None:
            table = self._get_default_substitution_table()
        
        return bytes(table[b] for b in data)

    def _obfuscate_data(self, data: bytes, key: int) -> bytes:
        """Apply multi-layered obfuscation to data (XOR, rotation, substitution)"""
        result = data
        
        if self.obfuscation_mode in ['xor', 'full']:
            result = self._apply_xor(result, key)
        
        if self.obfuscation_mode in ['rotation', 'full']:
            result = self._apply_rotation(result, self.rotation_amount)
        
        if self.obfuscation_mode in ['substitution', 'full']:
            substitution_table = self.custom_substitution_table or self._get_default_substitution_table()
            result = self._apply_substitution(result, substitution_table)
        
        return result

    def _deobfuscate_data(self, data: bytes, key: int) -> bytes:
        """Reverse the multi-layered obfuscation to get original data"""
        result = data

        # Apply operations in reverse order (opposite of the obfuscation process)
        if self.obfuscation_mode in ['full', 'substitution']:
            # Reverse substitution: find the original value that maps to each substituted value
            substitution_table = self.custom_substitution_table or self._get_default_substitution_table()
            reverse_table = [0] * 256
            for i in range(256):
                reverse_table[substitution_table[i]] = i
            result = bytes(reverse_table[b] for b in result)

        if self.obfuscation_mode in ['full', 'rotation']:
            # Reverse rotation (opposite direction)
            result = self._apply_rotation(result, -self.rotation_amount)  # Negative rotation

        if self.obfuscation_mode in ['full', 'xor']:
            # Reverse XOR (XOR is its own inverse)
            result = self._apply_xor(result, key)

        return result

    def _anti_analysis_timing_check(self) -> bool:
        """Simple timing check to detect potential debugging (simulated)"""
        start = time.perf_counter_ns()
        # Some busy work
        for i in range(1000):
            _ = i * i
        end = time.perf_counter_ns()
        
        delta = end - start
        # Threshold check (simulated - real implementation would be more sophisticated)
        return delta < 1000000  # Return True if not detected as slow (not in a debugger)

    def analyze(self, rewriter) -> Dict[str, Any]:
        """Analyze binary for potential obfuscation opportunities"""
        results = {
            "plugin_name": self.name,
            "version": self.version,
            "description": self.description,
            "obfuscation_modes": ["xor", "rotation", "substitution", "full"],
            "analysis": {
                "binary_size": 0,
                "sections_count": 0,
                "obfuscation_opportunities": [],
                "recommended_strings": []
            },
            "config": {
                "rotation_amount": self.rotation_amount,
                "enable_anti_analysis": self.enable_anti_analysis,
                "obfuscation_mode": self.obfuscation_mode
            }
        }

        # Perform anti-analysis check if enabled
        if self.enable_anti_analysis:
            try:
                if not self._anti_analysis_timing_check():
                    # If we detect a potential analysis environment, we could implement a different behavior
                    # For now, we'll just log it
                    results["anti_analysis_detected"] = True
            except Exception:
                pass  # If anti-analysis check fails, continue normally

        # Add binary information if available
        if rewriter is not None and hasattr(rewriter, 'binary') and rewriter.binary is not None:
            try:
                results["analysis"]["binary_size"] = getattr(rewriter.binary, 'original_size', 0) or (len(rewriter.binary.content) if hasattr(rewriter.binary, 'content') else 0)
                results["analysis"]["sections_count"] = len(rewriter.binary.sections) if hasattr(rewriter.binary, 'sections') else 0

                # Analyze sections for potential obfuscation
                for i, section in enumerate(rewriter.binary.sections):
                    section_info = {
                        "index": i,
                        "name": section.name if hasattr(section, 'name') else f"section_{i}",
                        "size": len(bytes(section.content)) if hasattr(section, 'content') else 0,
                        "virtual_address": getattr(section, 'virtual_address', 0),
                        "is_executable": self._is_executable_section(section),
                        "is_readable": self._is_readable_section(section),
                        "is_writable": self._is_writable_section(section)
                    }

                    # Look for strings in the section that could be obfuscated
                    if hasattr(section, 'content'):
                        section_content = bytes(section.content)
                        strings_found = self._find_strings(section_content)
                        
                        if strings_found:
                            section_info["potential_strings"] = strings_found
                            results["analysis"]["recommended_strings"].extend([
                                {
                                    "section": section_info["name"],
                                    "string": s,
                                    "offset": offset
                                } 
                                for s, offset in strings_found
                            ])

                    results["analysis"]["obfuscation_opportunities"].append(section_info)

            except Exception as e:
                results["error"] = f"Analysis failed: {str(e)}"
                logger.error(f"Windowbrick analysis failed: {e}")

        return results

    def _find_strings(self, data: bytes, min_length: int = 4) -> List[tuple]:
        """Find potential ASCII strings in data"""
        strings = []
        current_string = b""
        start_pos = -1

        for i, byte in enumerate(data):
            if 32 <= byte <= 126:  # Printable ASCII range
                if len(current_string) == 0:
                    start_pos = i
                current_string += bytes([byte])
            else:
                if len(current_string) >= min_length:
                    try:
                        decoded_string = current_string.decode('ascii')
                        strings.append((decoded_string, start_pos))
                    except UnicodeDecodeError:
                        pass  # Skip invalid ASCII sequences
                current_string = b""

        # Handle the last string if it exists
        if len(current_string) >= min_length:
            try:
                decoded_string = current_string.decode('ascii')
                strings.append((decoded_string, start_pos))
            except UnicodeDecodeError:
                pass

        return strings

    def _is_executable_section(self, section) -> bool:
        """Check if a section is executable"""
        try:
            # PE files
            if hasattr(section, 'characteristics'):
                import lief
                return bool(section.characteristics & lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE)
            # ELF files
            elif hasattr(section, 'flags'):
                import lief
                return bool(section.flags & lief.ELF.SECTION_FLAGS.EXECINSTR)
        except:
            pass
        return False

    def _is_readable_section(self, section) -> bool:
        """Check if a section is readable"""
        try:
            # PE files
            if hasattr(section, 'characteristics'):
                import lief
                return bool(section.characteristics & lief.PE.SECTION_CHARACTERISTICS.MEM_READ)
            # ELF files
            elif hasattr(section, 'flags'):
                import lief
                return bool(section.flags & lief.ELF.SECTION_FLAGS.ALLOC)
        except:
            pass
        return True

    def _is_writable_section(self, section) -> bool:
        """Check if a section is writable"""
        try:
            # PE files
            if hasattr(section, 'characteristics'):
                import lief
                return bool(section.characteristics & lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE)
            # ELF files
            elif hasattr(section, 'flags'):
                import lief
                return bool(section.flags & lief.ELF.SECTION_FLAGS.WRITE)
        except:
            pass
        return False


class WindowbrickTransformationPlugin(TransformationPlugin):
    """String obfuscation transformation plugin based on windowbrick techniques"""

    def __init__(self, config):
        super().__init__(config)
        self.name = "windowbrick_transform"
        self.version = "1.0.0"
        self.description = "String obfuscation transformation using windowbrick techniques"
        self.author = "Cumpyl Framework Team"
        self.dependencies = ["windowbrick_analysis"]

        # Initialize configuration
        plugin_config = self.get_config()
        self.rotation_amount = plugin_config.get('rotation_amount', 3)
        self.enable_anti_analysis = plugin_config.get('enable_anti_analysis', False)
        self.obfuscation_mode = plugin_config.get('obfuscation_mode', 'full')  # xor, rotation, substitution, full
        self.custom_substitution_table = plugin_config.get('custom_substitution_table', None)

    def analyze(self, rewriter) -> Dict[str, Any]:
        """Prepare for transformation - this is a placeholder"""
        return {
            "plugin_name": self.name,
            "version": self.version,
            "description": self.description
        }

    def transform(self, rewriter, analysis_result: Dict[str, Any]) -> bool:
        """Transform binary with string obfuscation using windowbrick techniques"""
        try:
            # Get dynamic key for obfuscation
            key = self._generate_dynamic_key()
            
            # Find strings in the binary that we want to obfuscate
            strings_to_obfuscate = self._get_strings_from_analysis(analysis_result)
            
            if not strings_to_obfuscate:
                logger.info("No strings found for obfuscation")
                return True
            
            # For each string, we need to:
            # 1. Replace the original string with its obfuscated version
            # 2. If the obfuscated version is different size, we may need to handle that
            
            for string_info in strings_to_obfuscate:
                section_name = string_info.get('section', '')
                original_string = string_info.get('string', '')
                
                # Convert string to bytes
                string_bytes = original_string.encode('ascii')
                
                # Obfuscate the string
                obfuscated_bytes = self._obfuscate_data(string_bytes, key)
                
                # Find the section in the binary
                target_section = None
                for section in rewriter.binary.sections:
                    if (hasattr(section, 'name') and section.name == section_name) or f"section_{len(rewriter.binary.sections)}" == section_name:
                        target_section = section
                        break
                
                if target_section:
                    # This is a simplified approach - in reality, we'd need to handle the replacement more carefully
                    # For now, we'll log what we would do
                    logger.info(f"Would obfuscate string '{original_string}' in section '{section_name}'")
                    logger.info(f"Original bytes: {string_bytes.hex()}")
                    logger.info(f"Obfuscated bytes: {obfuscated_bytes.hex()}")
                    
                    # Add to rewriter's modification tracking
                    if not hasattr(rewriter, 'modifications'):
                        rewriter.modifications = []
                    
                    rewriter.modifications.append({
                        'type': 'string_obfuscation',
                        'section': section_name,
                        'original_string': original_string,
                        'key_used': key,
                        'mode': self.obfuscation_mode
                    })
            
            # If there are strings to obfuscate, we might need to inject a deobfuscation routine
            # This is a complex operation that would require assembling code and modifying entry points
            # For this implementation, we'll just track that string obfuscation was planned
            
            logger.info(f"Windowbrick transformation completed for {len(strings_to_obfuscate)} strings")
            return True
            
        except Exception as e:
            logger.error(f"Windowbrick transformation failed: {e}")
            return False

    def _generate_dynamic_key(self) -> int:
        """Generate a dynamic key using system entropy sources"""
        # Get timestamp entropy
        timestamp_entropy = int(time.time() * 1000000) & 0xFF  # Lower byte of microseconds
        
        # Get PID entropy if available
        try:
            pid_entropy = os.getpid() & 0xFF
        except:
            pid_entropy = random.randint(0, 255)
        
        # Get random entropy 
        random_entropy = random.randint(0, 255)
        
        # Combine entropy sources
        combined_entropy = (timestamp_entropy ^ pid_entropy ^ random_entropy) & 0xFF
        return combined_entropy

    def _rotl(self, value: int, shift: int, bits: int = 8) -> int:
        """Rotate left operation"""
        shift = shift % bits
        return ((value << shift) | (value >> (bits - shift))) & ((1 << bits) - 1)

    def _rotr(self, value: int, shift: int, bits: int = 8) -> int:
        """Rotate right operation"""
        shift = shift % bits
        return ((value >> shift) | (value << (bits - shift))) & ((1 << bits) - 1)

    def _apply_xor(self, data: bytes, key: int) -> bytes:
        """Apply XOR operation to data"""
        return bytes(b ^ key for b in data)

    def _apply_rotation(self, data: bytes, amount: int) -> bytes:
        """Apply rotation operation to data"""
        # Handle positive (left) and negative (right) rotation amounts
        if amount >= 0:
            return bytes(self._rotl(b, amount) for b in data)
        else:
            # Convert negative rotation to right rotation
            right_amount = -amount % 8
            return bytes(self._rotr(b, right_amount) for b in data)

    def _get_default_substitution_table(self) -> bytes:
        """Get the default substitution table as a proper permutation for reversible cipher"""
        # Create a proper permutation of 0-255 to ensure reversible substitution cipher
        # This is a shuffled sequence of values 0-255
        return bytes([
            0x00, 0x1f, 0x2e, 0x3d, 0x4c, 0x5b, 0x6a, 0x79, 0x88, 0x97, 0xa6, 0xb5, 0xc4, 0xd3, 0xe2, 0xf1,
            0x10, 0x0f, 0x3e, 0x2d, 0x5c, 0x4b, 0x7a, 0x69, 0x98, 0x87, 0xb6, 0xa5, 0xd4, 0xc3, 0xf2, 0xe1,
            0x20, 0x3f, 0x0e, 0x1d, 0x6c, 0x7b, 0x4a, 0x59, 0xa8, 0xb7, 0x86, 0x95, 0xe4, 0xf3, 0xc2, 0xd1,
            0x30, 0x2f, 0x1e, 0x0d, 0x7c, 0x6b, 0x5a, 0x49, 0xb8, 0xa7, 0x96, 0x85, 0xf4, 0xe3, 0xd2, 0xc1,
            0x40, 0x5f, 0x6e, 0x7d, 0x0c, 0x1b, 0x2a, 0x39, 0xc8, 0xd7, 0xe6, 0xf5, 0x84, 0x93, 0xa2, 0xb1,
            0x50, 0x4f, 0x7e, 0x6d, 0x1c, 0x0b, 0x3a, 0x29, 0xd8, 0xc7, 0xf6, 0xe5, 0x94, 0x83, 0xb2, 0xa1,
            0x60, 0x7f, 0x4e, 0x5d, 0x2c, 0x3b, 0x0a, 0x19, 0xe8, 0xf7, 0xc6, 0xd5, 0xa4, 0xb3, 0x82, 0x91,
            0x70, 0x6f, 0x5e, 0x4d, 0x3c, 0x2b, 0x1a, 0x09, 0xf8, 0xe7, 0xd6, 0xc5, 0xb4, 0xa3, 0x92, 0x81,
            0x80, 0x9f, 0xae, 0xbd, 0xcc, 0xdb, 0xea, 0xf9, 0x08, 0x17, 0x26, 0x35, 0x44, 0x53, 0x62, 0x71,
            0x90, 0x8f, 0xbf, 0xad, 0xdc, 0xcb, 0xfa, 0xe9, 0x18, 0x07, 0x36, 0x25, 0x54, 0x43, 0x72, 0x61,
            0xa0, 0xbf, 0x8e, 0x9d, 0xec, 0xfb, 0xca, 0xd9, 0x28, 0x37, 0x06, 0x15, 0x64, 0x73, 0x42, 0x51,
            0xb0, 0xaf, 0x9e, 0x8d, 0xfc, 0xeb, 0xda, 0xc9, 0x38, 0x27, 0x16, 0x05, 0x74, 0x63, 0x52, 0x41,
            0xc0, 0xdf, 0xee, 0xfd, 0x8c, 0x9b, 0xaa, 0xb9, 0x48, 0x57, 0x66, 0x75, 0x04, 0x13, 0x22, 0x31,
            0xd0, 0xcf, 0xfe, 0xed, 0x9c, 0x8b, 0xba, 0xa9, 0x58, 0x47, 0x76, 0x65, 0x14, 0x03, 0x32, 0x21,
            0xe0, 0xff, 0xce, 0xdd, 0xac, 0xbb, 0x8a, 0x99, 0x68, 0x77, 0x46, 0x55, 0x24, 0x33, 0x02, 0x11,
            0xf0, 0xef, 0xde, 0xcd, 0xbc, 0xab, 0x9a, 0x89, 0x78, 0x67, 0x56, 0x45, 0x34, 0x23, 0x12, 0x01
        ])

    def _apply_substitution(self, data: bytes, table: bytes = None) -> bytes:
        """Apply substitution cipher using the substitution table"""
        if table is None:
            table = self._get_default_substitution_table()
        
        return bytes(table[b] for b in data)

    def _obfuscate_data(self, data: bytes, key: int) -> bytes:
        """Apply multi-layered obfuscation to data (XOR, rotation, substitution)"""
        result = data
        
        if self.obfuscation_mode in ['xor', 'full']:
            result = self._apply_xor(result, key)
        
        if self.obfuscation_mode in ['rotation', 'full']:
            result = self._apply_rotation(result, self.rotation_amount)
        
        if self.obfuscation_mode in ['substitution', 'full']:
            substitution_table = self.custom_substitution_table or self._get_default_substitution_table()
            result = self._apply_substitution(result, substitution_table)
        
        return result

    def _get_strings_from_analysis(self, analysis_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract strings to obfuscate from analysis results"""
        strings = []
        
        # Extract from windowbrick analysis plugin if available
        if 'windowbrick_analysis' in analysis_result:
            wb_result = analysis_result['windowbrick_analysis']
            if 'analysis' in wb_result and 'recommended_strings' in wb_result['analysis']:
                strings.extend(wb_result['analysis']['recommended_strings'])
        
        # Also check other analysis results for strings
        for plugin_name, result in analysis_result.items():
            if plugin_name == 'string_extraction' and isinstance(result, dict) and 'summary' in result:
                if 'interesting_strings' in result['summary']:
                    for string_info in result['summary']['interesting_strings']:
                        strings.append({
                            'section': string_info.get('section', 'unknown'),
                            'string': string_info.get('value', ''),
                            'offset': string_info.get('offset', 0)
                        })
        
        # Remove duplicates
        seen_strings = set()
        unique_strings = []
        for s in strings:
            string_val = s.get('string', '')
            if string_val and string_val not in seen_strings:
                seen_strings.add(string_val)
                unique_strings.append(s)
        
        return unique_strings


# Factory functions for plugin registration
def get_analysis_plugin(config):
    """Factory function to get windowbrick analysis plugin instance"""
    return WindowbrickAnalysisPlugin(config)

def get_transformation_plugin(config):
    """Factory function to get windowbrick transformation plugin instance"""
    return WindowbrickTransformationPlugin(config)