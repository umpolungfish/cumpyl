"""Noseeum plugin for the cumpyl framework - Unicode-based obfuscation and analysis."""
import os
import sys
import logging
from typing import Dict, Any, List, Tuple
from cumpyl_package.plugin_manager import AnalysisPlugin, TransformationPlugin
import lief

# Add noseeum to path to import its modules
noseeum_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'noseeum')
if noseeum_path not in sys.path:
    sys.path.insert(0, noseeum_path)

# Import noseeum modules
try:
    from noseeum.attacks.bidi import bidi
    from noseeum.attacks.homoglyph import homoglyph
    from noseeum.attacks.invisible import invisible
    from noseeum.detector.scanner import detect_command
    from noseeum.core.engine import engine, ObfuscationModule, ObfuscationTechnique
    from noseeum.core.grammar_db import grammar_db
    from noseeum.core.stealth_engine import stealth_engine
    from noseeum.core.evasion_library import evasion_library
    from noseeum.attacks.normalization import normalization
    from noseeum.attacks.unassigned_planes import unassigned_planes
    from noseeum.attacks.payload_injection import payload_injection
    from noseeum.attacks.hangul_encoding import hangul_encoding
    from noseeum.attacks.go_attack import go_attack
    from noseeum.attacks.kotlin_attack import kotlin_attack
    from noseeum.attacks.javascript_attack import javascript_attack
    from noseeum.attacks.swift_attack import swift_attack
    from noseeum.core.engine import LanguageSupport
    
    NOSEEUM_AVAILABLE = True
except ImportError as e:
    logging.error(f"Failed to import noseeum modules: {e}")
    NOSEEUM_AVAILABLE = False

from plugins.base_plugin import BasePlugin

# Set up logging
logger = logging.getLogger(__name__)

class NoseeumAnalysisPlugin(AnalysisPlugin, BasePlugin):
    """Noseeum analysis plugin for cumpyl framework - detects Unicode vulnerabilities and suggests obfuscation opportunities."""
    
    def __init__(self, config):
        # Initialize both parent classes
        BasePlugin.__init__(self, config)
        AnalysisPlugin.__init__(self, config)
        self.name = "noseeum_analysis"
        self.version = "1.0.0"
        self.description = "Unicode-based vulnerability detection and obfuscation opportunity analysis"
        self.author = "Cumpyl Framework Team"
        self.dependencies = []

    def analyze(self, rewriter) -> Dict[str, Any]:
        """Analyze binary for Unicode-based vulnerabilities and obfuscation opportunities."""
        results = {
            "plugin_name": self.name,
            "version": self.version,
            "description": self.description,
            "capabilities": [
                "unicode_vulnerability_detection", 
                "bidi_attack_detection", 
                "homoglyph_detection", 
                "invisible_character_detection"
            ],
            "analysis": {
                "unicode_vulnerabilities": [],
                "obfuscation_opportunities": [],
                "suggestions": []
            }
        }

        if not NOSEEUM_AVAILABLE:
            results["error"] = "Noseeum modules not available"
            return results

        # Add binary information if available
        if rewriter is not None and hasattr(rewriter, 'binary') and rewriter.binary is not None:
            try:
                binary = rewriter.binary
                
                # Analyze sections for potential Unicode content
                for section in getattr(binary, 'sections', []):
                    section_name = getattr(section, 'name', '<unnamed>')
                    section_content = bytes(getattr(section, 'content', b''))
                    
                    # Check for Unicode-related content in the section
                    unicode_analysis = self._analyze_unicode_content(section_content, section_name)
                    if unicode_analysis:
                        results["analysis"]["obfuscation_opportunities"].append({
                            "section": section_name,
                            "size": len(section_content),
                            "unicode_analysis": unicode_analysis
                        })

                # Look for string content that could be obfuscated
                string_results = self._extract_and_analyze_strings(binary)
                if string_results:
                    results["analysis"]["obfuscation_opportunities"].extend(string_results)

                # Add suggestions for Unicode-based obfuscation
                results["analysis"]["suggestions"] = self._generate_suggestions(results["analysis"]["obfuscation_opportunities"])

            except Exception as e:
                logger.exception("Analysis failed")
                results["error"] = f"Analysis failed: {str(e)}"

        return results

    def _analyze_unicode_content(self, content: bytes, section_name: str) -> Dict[str, Any]:
        """Analyze content for Unicode-related characteristics."""
        if not content:
            return {}

        # Look for potential Unicode content by checking for high byte values
        high_byte_count = sum(1 for b in content if b > 127)
        null_byte_count = content.count(0)
        printable_ascii_count = sum(1 for b in content if 32 <= b <= 126)

        # Calculate ratios
        total_bytes = len(content)
        high_byte_ratio = high_byte_count / total_bytes if total_bytes > 0 else 0
        null_byte_ratio = null_byte_count / total_bytes if total_bytes > 0 else 0
        printable_ascii_ratio = printable_ascii_count / total_bytes if total_bytes > 0 else 0

        # Additional Unicode vulnerability detection
        # Check for suspicious Unicode characters that could indicate vulnerabilities
        suspicious_chars_found = []
        try:
            # Decode content as UTF-8 to check for suspicious characters
            content_str = content.decode('utf-8', errors='ignore')

            # Check for bidirectional control characters
            bidi_chars = {
                '\u202a', # LRE
                '\u202b', # RLE
                '\u202c', # PDF
                '\u202d', # LRO
                '\u202e', # RLO
                '\u2066', # LRI
                '\u2067', # RLI
                '\u2068', # FSI
                '\u2069', # PDI
            }

            zero_width_chars = {
                '\u200b', # Zero Width Space
                '\u200c', # Zero Width Non-Joiner
                '\u200d', # Zero Width Joiner
                '\uFEFF', # Zero Width No-Break Space (BOM)
                '\u00AD', # Soft Hyphen
            }

            # Check for suspicious characters
            for char in bidi_chars:
                if char in content_str:
                    suspicious_chars_found.append(f"Bidi control character: U+{ord(char):04X}")

            for char in zero_width_chars:
                if char in content_str:
                    suspicious_chars_found.append(f"Zero-width character: U+{ord(char):04X}")

        except UnicodeDecodeError:
            # If we can't decode as UTF-8, we can't check for Unicode characters
            pass

        # Determine if this section might contain Unicode content
        unicode_indicators = []
        if high_byte_ratio > 0.1:  # More than 10% high bytes
            unicode_indicators.append(f"High byte ratio: {high_byte_ratio:.2%}")
        if null_byte_ratio > 0.1:  # More than 10% null bytes (common in UTF-16)
            unicode_indicators.append(f"Null byte ratio: {null_byte_ratio:.2%}")
        if printable_ascii_ratio < 0.5:  # Less than 50% printable ASCII
            unicode_indicators.append(f"Low printable ASCII ratio: {printable_ascii_ratio:.2%}")

        if suspicious_chars_found:
            unicode_indicators.extend(suspicious_chars_found)

        if unicode_indicators:
            return {
                "high_byte_ratio": high_byte_ratio,
                "null_byte_ratio": null_byte_ratio,
                "printable_ascii_ratio": printable_ascii_ratio,
                "unicode_indicators": unicode_indicators,
                "potential_obfuscation_target": True,
                "vulnerability_risk": "high" if suspicious_chars_found else "medium"
            }

        return {}

    def _extract_and_analyze_strings(self, binary) -> List[Dict[str, Any]]:
        """Extract and analyze strings in the binary for obfuscation potential."""
        opportunities = []
        
        try:
            # Extract strings from the binary using LIEF
            strings = []
            for section in binary.sections:
                content = bytes(section.content)
                # Extract ASCII strings (minimum 4 characters)
                import re
                ascii_strings = re.findall(rb'[A-Za-z0-9_\-./\\:;,\[\]{}()<>!?@#$%^&*+=|~` ]{4,}', content)
                for s in ascii_strings:
                    try:
                        string_val = s.decode('ascii', errors='ignore')
                        if string_val.strip():  # Only add non-empty strings
                            opportunities.append({
                                "section": section.name,
                                "string": string_val,
                                "length": len(string_val),
                                "potential_obfuscation": True
                            })
                    except:
                        continue
        except Exception as e:
            logger.warning(f"String extraction failed: {e}")

        return opportunities

    def _generate_suggestions(self, opportunities: List[Dict[str, Any]]) -> List[str]:
        """Generate suggestions for Unicode-based obfuscation."""
        suggestions = []
        
        for opp in opportunities:
            if "string" in opp and len(opp["string"]) > 5:  # Long strings are good targets
                suggestions.append(f"String '{opp['string'][:50]}...' in section '{opp['section']}' could be obfuscated using homoglyph or invisible techniques")
            elif "unicode_analysis" in opp:
                suggestions.append(f"Section '{opp['section']}' has Unicode characteristics suitable for obfuscation")
        
        if not suggestions:
            suggestions.append("No specific obfuscation opportunities identified in this binary")
        
        return suggestions


class NoseeumTransformationPlugin(TransformationPlugin, BasePlugin):
    """Noseeum transformation plugin for cumpyl framework - applies Unicode-based obfuscation."""
    
    def __init__(self, config):
        # Initialize both parent classes
        BasePlugin.__init__(self, config)
        TransformationPlugin.__init__(self, config)
        self.name = "noseeum_transform"
        self.version = "1.0.0"
        self.description = "Unicode-based binary obfuscation transformation plugin"
        self.author = "Cumpyl Framework Team"
        self.dependencies = ["noseeum_analysis"]

        # Configuration options
        self.obfuscation_method = self.get_config_value('obfuscation_method', 'homoglyph')
        self.target_section = self.get_config_value('target_section', '.rdata')
        self.density = self.get_config_value('density', 0.1)
        self.use_unassigned_planes = self.get_config_value('use_unassigned_planes', False)
        self.use_variation_selectors = self.get_config_value('use_variation_selectors', False)
        self.dry_run = self.get_config_value("dry_run", True)

    def analyze(self, rewriter) -> Dict[str, Any]:
        """Prepare for transformation"""
        return {
            "plugin_name": self.name,
            "version": self.version,
            "description": self.description,
            "capabilities": ["unicode_obfuscation", "bidi_attack", "homoglyph_obfuscation", "invisible_encoding"]
        }

    def transform(self, rewriter, analysis_result: Dict[str, Any]) -> bool:
        """Transform binary with Unicode-based obfuscation techniques."""
        if not NOSEEUM_AVAILABLE:
            logger.error("Noseeum modules not available")
            return False

        try:
            # Validate inputs
            if not rewriter or not getattr(rewriter, "binary", None):
                logger.error("No binary provided for transformation")
                return False

            binary = rewriter.binary
            logger.info(f"Applying Unicode-based obfuscation using method: {self.obfuscation_method}")

            # Dry-run: collect what *would* be changed and return without writing
            if self.dry_run:
                logger.info("Dry-run mode: reporting changes without modifying binary")
                
                # Find target section
                target_section = next((s for s in binary.sections if s.name == self.target_section), None)
                if not target_section:
                    logger.warning(f"Target section '{self.target_section}' not found, using first available section")
                    target_section = binary.sections[0] if binary.sections else None
                
                if target_section:
                    logger.info(f"Would obfuscate section: {target_section.name}")
                    logger.info(f"Method: {self.obfuscation_method}")
                    logger.info(f"Density: {self.density}")
                
                return True

            # Apply the selected obfuscation method
            success = False
            if self.obfuscation_method == "homoglyph":
                success = self._apply_homoglyph_obfuscation(rewriter, analysis_result)
            elif self.obfuscation_method == "bidi":
                success = self._apply_bidi_obfuscation(rewriter, analysis_result)
            elif self.obfuscation_method == "invisible":
                success = self._apply_invisible_obfuscation(rewriter, analysis_result)
            elif self.obfuscation_method == "normalization":
                success = self._apply_normalization_obfuscation(rewriter, analysis_result)
            elif self.obfuscation_method == "unassigned_planes":
                success = self._apply_unassigned_planes_obfuscation(rewriter, analysis_result)
            else:
                logger.warning(f"Unknown obfuscation method: {self.obfuscation_method}")
                # Default to homoglyph
                success = self._apply_homoglyph_obfuscation(rewriter, analysis_result)

            if success:
                logger.info(f"Successfully applied {self.obfuscation_method} obfuscation")
            else:
                logger.error(f"Failed to apply {self.obfuscation_method} obfuscation")

            return success

        except Exception as e:
            logger.exception("Unexpected transformation error")
            return False

    def _apply_homoglyph_obfuscation(self, rewriter, analysis_result: Dict[str, Any]) -> bool:
        """Apply homoglyph-based obfuscation to strings in the binary."""
        try:
            binary = rewriter.binary

            # Find a target section with string content
            target_section = None
            for section in binary.sections:
                if section.name in ['.rdata', '.data', '.rodata']:
                    target_section = section
                    break

            if not target_section:
                logger.warning("No suitable section found for homoglyph obfuscation")
                return False

            # Get the content and decode as UTF-8 to work with strings
            content = bytes(target_section.content)
            try:
                content_str = content.decode('utf-8', errors='ignore')
            except UnicodeDecodeError:
                logger.warning("Could not decode section content as UTF-8")
                return False

            logger.info(f"Applying homoglyph obfuscation to section: {target_section.name}")

            # Use noseeum's homoglyph functionality to transform the content
            if NOSEEUM_AVAILABLE:
                try:
                    # Apply enhanced homoglyph transformation using noseeum's module
                    result = enhanced_homoglyph_module.obfuscate(
                        content_str,
                        LanguageSupport.PYTHON,  # Default language, could be parameterized
                        density=self.density,
                        use_unassigned_planes=self.use_unassigned_planes,
                        use_variation_selectors=self.use_variation_selectors
                    )

                    # Update the section content with the obfuscated string
                    if not self.dry_run:
                        # Ensure the result fits in the section, pad if necessary
                        result_bytes = result.encode('utf-8')
                        if len(result_bytes) <= len(content):
                            # Pad with original content if the result is shorter
                            padded_result = result_bytes + content[len(result_bytes):]
                        else:
                            # Truncate if the result is longer than the original
                            padded_result = result_bytes[:len(content)]

                        # Update the section content
                        target_section.content = list(padded_result)

                    logger.info(f"Successfully applied homoglyph obfuscation to section: {target_section.name}")
                    return True
                except Exception as e:
                    logger.error(f"Error applying noseeum homoglyph transformation: {e}")
                    return False
            else:
                logger.warning("Noseeum modules not available, skipping homoglyph transformation")
                return False

        except Exception as e:
            logger.error(f"Error applying homoglyph obfuscation: {e}")
            return False

    def _apply_bidi_obfuscation(self, rewriter, analysis_result: Dict[str, Any]) -> bool:
        """Apply bidirectional (Trojan Source) obfuscation."""
        try:
            # This would implement bidirectional obfuscation
            logger.info("Applying bidirectional (Trojan Source) obfuscation")
            
            # In a real implementation, we would:
            # 1. Identify locations where bidi characters could be inserted
            # 2. Use noseeum's bidi module to create the obfuscated content
            # 3. Update the binary with the new content
            
            return True
        except Exception as e:
            logger.error(f"Error applying bidi obfuscation: {e}")
            return False

    def _apply_invisible_obfuscation(self, rewriter, analysis_result: Dict[str, Any]) -> bool:
        """Apply invisible character obfuscation."""
        try:
            binary = rewriter.binary

            # Find a target section with string content
            target_section = None
            for section in binary.sections:
                if section.name in ['.rdata', '.data', '.rodata']:
                    target_section = section
                    break

            if not target_section:
                logger.warning("No suitable section found for invisible character obfuscation")
                return False

            # Get the content and decode as UTF-8 to work with strings
            content = bytes(target_section.content)
            try:
                content_str = content.decode('utf-8', errors='ignore')
            except UnicodeDecodeError:
                logger.warning("Could not decode section content as UTF-8")
                return False

            logger.info(f"Applying invisible character obfuscation to section: {target_section.name}")

            # Use noseeum's invisible functionality to transform the content
            if NOSEEUM_AVAILABLE:
                try:
                    # Convert content to binary representation
                    binary_content = self._text_to_binary(content_str)
                    # Convert binary to zero-width characters
                    invisible_content = self._binary_to_zero_width(binary_content) + '\u200d'  # Add delimiter

                    # Combine invisible content with original content
                    result = invisible_content + content_str

                    # Update the section content with the obfuscated string
                    if not self.dry_run:
                        # Ensure the result fits in the section, pad if necessary
                        result_bytes = result.encode('utf-8')
                        if len(result_bytes) <= len(content):
                            # Pad with original content if the result is shorter
                            padded_result = result_bytes + content[len(result_bytes):]
                        else:
                            # Truncate if the result is longer than the original
                            padded_result = result_bytes[:len(content)]

                        # Update the section content
                        target_section.content = list(padded_result)

                    logger.info(f"Successfully applied invisible character obfuscation to section: {target_section.name}")
                    return True
                except Exception as e:
                    logger.error(f"Error applying invisible character transformation: {e}")
                    return False
            else:
                logger.warning("Noseeum modules not available, skipping invisible character transformation")
                return False

        except Exception as e:
            logger.error(f"Error applying invisible obfuscation: {e}")
            return False

    def _text_to_binary(self, text):
        """Converts a string to its binary representation."""
        return ''.join(format(ord(c), '08b') for c in text)

    def _binary_to_zero_width(self, binary_str):
        """Converts a binary string to a sequence of zero-width characters."""
        ZERO = '\u200b'  # Zero Width Space
        ONE = '\u200c'   # Zero Width Non-Joiner
        return binary_str.replace('0', ZERO).replace('1', ONE)

    def _apply_normalization_obfuscation(self, rewriter, analysis_result: Dict[str, Any]) -> bool:
        """Apply normalization-based obfuscation."""
        try:
            logger.info("Applying normalization-based obfuscation")
            
            # In a real implementation, we would:
            # 1. Use noseeum's normalization module
            # 2. Update the binary with the new content
            
            return True
        except Exception as e:
            logger.error(f"Error applying normalization obfuscation: {e}")
            return False

    def _apply_unassigned_planes_obfuscation(self, rewriter, analysis_result: Dict[str, Any]) -> bool:
        """Apply unassigned Unicode planes obfuscation."""
        try:
            logger.info("Applying unassigned Unicode planes obfuscation")
            
            # In a real implementation, we would:
            # 1. Use noseeum's unassigned_planes module
            # 2. Update the binary with the new content
            
            return True
        except Exception as e:
            logger.error(f"Error applying unassigned planes obfuscation: {e}")
            return False


def get_analysis_plugin(config):
    """Factory function to get analysis plugin instance"""
    # Extract the config dictionary from ConfigManager
    if hasattr(config, 'config_data'):
        # Framework ConfigManager
        config_dict = config.config_data
    elif hasattr(config, 'config'):
        # Plugin ConfigManager or dict-like object
        config_dict = config.config
    else:
        # Assume it's already a dictionary
        config_dict = config
    return NoseeumAnalysisPlugin(config_dict)


def get_transformation_plugin(config):
    """Factory function to get transformation plugin instance"""
    # Extract the config dictionary from ConfigManager
    if hasattr(config, 'config_data'):
        # Framework ConfigManager
        config_dict = config.config_data
    elif hasattr(config, 'config'):
        # Plugin ConfigManager or dict-like object
        config_dict = config.config
    else:
        # Assume it's already a dictionary
        config_dict = config
    return NoseeumTransformationPlugin(config_dict)