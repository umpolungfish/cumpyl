"""
Unit tests for the Go binary analysis plugin
"""
import unittest
from plugins.go_packer_plugin import get_analysis_plugin
from plugins.analysis import calculate_entropy_with_confidence

class TestAnalysis(unittest.TestCase):
    """Test analysis functions"""
    
    def test_calculate_entropy_empty(self):
        """Test entropy calculation with empty data"""
        result = calculate_entropy_with_confidence(b"")
        self.assertEqual(result["value"], 0.0)
        
    def test_calculate_entropy_uniform(self):
        """Test entropy calculation with uniform data"""
        data = b"A" * 1000
        result = calculate_entropy_with_confidence(data)
        self.assertLess(result["value"], 1.0)  # Low entropy for uniform data

class TestGoPackerPlugin(unittest.TestCase):
    """Test Go packer plugin"""
    
    def test_plugin_creation(self):
        """Test plugin creation"""
        plugin = get_analysis_plugin({})
        self.assertEqual(plugin.name, "go_binary_analyzer")
        self.assertFalse(plugin.allow_transform)

if __name__ == "__main__":
    unittest.main()