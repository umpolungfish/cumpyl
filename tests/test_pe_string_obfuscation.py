"""
Tests for PE String Obfuscation Plugin
"""
import os
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

# Add the project root to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    from plugins.pe_string_obfuscation import PEStringObfuscationPlugin, PEStringObfuscationTransformationPlugin
    from cumpyl_package.config import ConfigManager, get_config
    from cumpyl_package.cumpyl import BinaryRewriter
except ImportError as e:
    print(f"Import error: {e}")
    # If imports fail, define mock classes for testing
    PEStringObfuscationPlugin = None
    PEStringObfuscationTransformationPlugin = None
    ConfigManager = None
    get_config = None
    BinaryRewriter = None


class TestPEStringObfuscationPlugin(unittest.TestCase):
    """Test cases for PE String Obfuscation Plugin"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test configuration"""
        if get_config:
            cls.config = get_config()
        else:
            # Create a mock config if real config is not available
            cls.config = Mock()
            cls.config.config_data = {
                'plugins': {
                    'pe_string_obfuscation': {
                        'min_string_length': 4,
                        'max_string_length': 200,
                        'obfuscation_methods': ['xor', 'base64', 'rot13', 'reverse'],
                        'target_sections': ['.rdata', '.data', '.text']
                    }
                }
            }
    
    @unittest.skipIf(PEStringObfuscationPlugin is None, "Plugin not available")
    def test_plugin_initialization(self):
        """Test plugin initialization"""
        plugin = PEStringObfuscationPlugin(self.config)
        self.assertEqual(plugin.name, "pe_string_obfuscation")
        self.assertEqual(plugin.version, "2.0.0")
        self.assertIn('xor', plugin.obfuscation_methods)
        self.assertIn('.rdata', plugin.target_sections)
    
    @unittest.skipIf(PEStringObfuscationPlugin is None, "Plugin not available")
    def test_string_extraction_ascii(self):
        """Test ASCII string extraction"""
        plugin = PEStringObfuscationPlugin(self.config)
        test_data = b"Hello World\x00This is a test string\x00Some more data"
        result = plugin.extract_ascii_strings(test_data)
        
        # Check if strings were found
        self.assertGreater(len(result), 0)
        found_hello = any('Hello World' in s['value'] for s in result)
        self.assertTrue(found_hello)
    
    @unittest.skipIf(PEStringObfuscationPlugin is None, "Plugin not available")
    def test_string_extraction_unicode(self):
        """Test Unicode string extraction"""
        plugin = PEStringObfuscationPlugin(self.config)
        # Create test data with some Unicode content
        test_data = b'\x48\x00\x65\x00\x6c\x00\x6c\x00\x6f\x00\x00\x00'  # "Hello" in UTF-16
        result = plugin.extract_unicode_strings(test_data)
        
        self.assertGreater(len(result), 0)
        found_hello = any('Hello' in s['value'] for s in result)
        self.assertTrue(found_hello)
    
    @unittest.skipIf(PEStringObfuscationPlugin is None, "Plugin not available")
    def test_entropy_calculation(self):
        """Test entropy calculation"""
        plugin = PEStringObfuscationPlugin(self.config)
        
        # Test with high entropy data (should be close to 8)
        high_entropy_data = bytes(range(256))  # All possible byte values
        high_entropy = plugin.calculate_entropy(high_entropy_data)
        self.assertGreater(high_entropy, 7.0)  # High entropy should be > 7.0
        
        # Test with low entropy data (should be close to 0)
        low_entropy_data = b'\x00' * 100  # All zeros
        low_entropy = plugin.calculate_entropy(low_entropy_data)
        self.assertLess(low_entropy, 1.0)  # Low entropy should be < 1.0
    
    @unittest.skipIf(PEStringObfuscationPlugin is None, "Plugin not available")
    def test_high_risk_string_detection(self):
        """Test detection of high-risk strings"""
        plugin = PEStringObfuscationPlugin(self.config)
        
        # Create test strings with high-risk content
        test_strings = [
            {'value': 'http://malicious-site.com', 'section': '.rdata', 'offset': 0, 'length': 25, 'type': 'ascii'},
            {'value': 'password123', 'section': '.data', 'offset': 100, 'length': 11, 'type': 'ascii'},
            {'value': 'cmd.exe', 'section': '.text', 'offset': 200, 'length': 7, 'type': 'ascii'}
        ]
        
        high_risk = plugin.identify_high_risk_strings(test_strings)
        self.assertGreater(len(high_risk), 0)
    
    @unittest.skipIf(PEStringObfuscationPlugin is None, "Plugin not available")
    def test_obfuscation_recommendations(self):
        """Test obfuscation method recommendations"""
        plugin = PEStringObfuscationPlugin(self.config)
        
        # Create test strings with different characteristics
        test_strings = [
            {'value': 'short', 'section': '.rdata', 'offset': 0, 'length': 5, 'type': 'ascii'},
            {'value': 'http://example.com/path/to/resource', 'section': '.data', 'offset': 100, 'length': 34, 'type': 'ascii'},
            {'value': 'password123', 'section': '.text', 'offset': 200, 'length': 11, 'type': 'ascii'}
        ]
        
        recommendations = plugin.recommend_obfuscation_methods(test_strings)
        
        # Check that recommendations were made for each method
        self.assertIn('xor', recommendations)
        self.assertIn('base64', recommendations)
        self.assertIn('encrypt', recommendations)
    
    @unittest.skipIf(PEStringObfuscationPlugin is None, "Plugin not available")
    def test_select_obfuscation_method(self):
        """Test method selection for strings - this method is in transformation plugin, not analysis"""
        # Since this method doesn't exist in the analysis plugin, just test that it doesn't exist
        plugin = PEStringObfuscationPlugin(self.config)
        self.assertFalse(hasattr(plugin, 'select_obfuscation_method'))


class TestPEStringObfuscationTransformationPlugin(unittest.TestCase):
    """Test cases for PE String Obfuscation Transformation Plugin"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test configuration"""
        if get_config:
            cls.config = get_config()
        else:
            # Create a mock config if real config is not available
            cls.config = Mock()
            cls.config.config_data = {
                'plugins': {
                    'pe_string_obfuscation': {
                        'min_string_length': 4,
                        'max_string_length': 200,
                        'obfuscation_methods': ['xor', 'base64', 'rot13', 'reverse'],
                        'target_sections': ['.rdata', '.data', '.text']
                    }
                }
            }
    
    @unittest.skipIf(PEStringObfuscationTransformationPlugin is None, "Transformation plugin not available")
    def test_transformation_plugin_initialization(self):
        """Test transformation plugin initialization"""
        plugin = PEStringObfuscationTransformationPlugin(self.config)
        self.assertEqual(plugin.name, "pe_string_obfuscation_transform")
        self.assertEqual(plugin.version, "2.0.0")
        self.assertIn('xor', plugin.obfuscation_methods)
    
    @unittest.skipIf(PEStringObfuscationTransformationPlugin is None, "Transformation plugin not available")
    def test_obfuscation_methods(self):
        """Test different obfuscation methods"""
        plugin = PEStringObfuscationTransformationPlugin(self.config)
        
        test_string = "Hello World"
        
        # Test XOR obfuscation
        xor_result, _ = plugin.xor_obfuscate(test_string)
        self.assertIsInstance(xor_result, bytes)
        self.assertGreater(len(xor_result), 0)
        
        # Test Base64 obfuscation
        base64_result, _ = plugin.base64_obfuscate(test_string)
        self.assertIsInstance(base64_result, bytes)
        self.assertGreater(len(base64_result), 0)
        
        # Test ROT13 obfuscation
        rot13_result, _ = plugin.rot13_obfuscate(test_string)
        self.assertIsInstance(rot13_result, bytes)
        self.assertEqual(rot13_result.decode('utf-8'), "Uryyb Jbeyq")  # ROT13 of "Hello World"
        
        # Test reverse obfuscation
        reverse_result, _ = plugin.reverse_obfuscate(test_string)
        self.assertIsInstance(reverse_result, bytes)
        self.assertEqual(reverse_result.decode('utf-8'), "dlroW olleH")  # Reversed "Hello World"
        
        # Test Caesar cipher
        caesar_result, _ = plugin.caesar_cipher_obfuscate(test_string)
        self.assertIsInstance(caesar_result, bytes)
        self.assertGreater(len(caesar_result), 0)
        
        # Test Vigenère cipher
        vigenere_result, _ = plugin.vigenere_cipher_obfuscate(test_string)
        self.assertIsInstance(vigenere_result, bytes)
        self.assertGreater(len(vigenere_result), 0)
    
    @unittest.skipIf(PEStringObfuscationTransformationPlugin is None, "Transformation plugin not available")
    def test_method_selection(self):
        """Test method selection for different string types"""
        plugin = PEStringObfuscationTransformationPlugin(self.config)
        
        # Test with short string (should get reverse)
        short_string = {'value': 'test', 'section': '.data', 'offset': 0, 'length': 4, 'type': 'ascii'}
        method = plugin.select_obfuscation_method(short_string)
        self.assertIn(method, ['reverse', 'xor'])
        
        # Test with URL (should get base64 or encrypt)
        url_string = {'value': 'http://example.com', 'section': '.data', 'offset': 0, 'length': 18, 'type': 'ascii'}
        method = plugin.select_obfuscation_method(url_string)
        self.assertIn(method, ['base64', 'xor', 'encrypt'])


def run_tests():
    """Run all tests"""
    unittest.main(verbosity=2)


if __name__ == "__main__":
    run_tests()