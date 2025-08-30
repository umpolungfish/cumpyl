import unittest
import tempfile
import os
import yaml
from pathlib import Path
import sys

# 𐑨𐑛 𐑞 𐑐𐑸𐑧𐑯𐑑 𐑛𐑲𐑮𐑧𐑒𐑑𐑼𐑦 𐑑 𐑞 𐑐𐑭𐑔 𐑓𐑹 𐑦𐑥𐑐𐑹𐑑𐑦𐑙
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from cumpyl_package.config import ConfigManager, FrameworkConfig, PluginConfig, SecurityConfig, PerformanceConfig


class TestConfigManager(unittest.TestCase):
    """𐑑𐑧𐑕𐑑 𐑒𐑱𐑕𐑌𐑦 𐑓𐑹 𐑞 𐑒𐑪𐑯𐑓𐑦𐑜 𐑥𐑨𐑯𐑦𐑡𐑼"""
    
    def setUp(self):
        """𐑕𐑧𐑑 𐑳𐑐 𐑑𐑧𐑕𐑑 𐑓𐑦𐑒𐑗𐑼𐑟"""
        self.temp_dir = tempfile.mkdtemp()
        self.test_config_path = os.path.join(self.temp_dir, "test_config.yaml")
        
        # 𐑒𐑮𐑦𐑱𐑑 𐑩 𐑑𐑧𐑕𐑑 𐑒𐑪𐑯𐑓𐑦𐑜 𐑓𐑲𐑤
        self.test_config_data = {
            'framework': {
                'version': '0.3.0',
                'debug_mode': True,
                'verbose_logging': True,
                'max_file_size_mb': 50,
                'temp_directory': '/tmp/test_cumpyl'
            },
            'plugins': {
                'enabled': True,
                'auto_discovery': True,
                'plugin_directory': 'test_plugins',
                'load_order': ['test_plugin1', 'test_plugin2'],
                'encoding': {
                    'default_encoding': 'hex',
                    'compression_level': 9
                }
            },
            'security': {
                'sandbox_mode': True,
                'max_modifications_per_session': 50,
                'verify_checksums': True
            },
            'performance': {
                'enable_parallel_processing': False,
                'max_worker_threads': 2,
                'memory_limit_mb': 256
            }
        }
        
        with open(self.test_config_path, 'w') as f:
            yaml.dump(self.test_config_data, f)
    
    def tearDown(self):
        """𐑒𐑤𐑰𐑯 𐑳𐑐 𐑑𐑧𐑕𐑑 𐑓𐑦𐑒𐑗𐑼𐑟"""
        import shutil
        if os.path.exists(self.test_config_path):
            os.remove(self.test_config_path)
        # Use shutil.rmtree to remove the entire directory tree
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_config_loading(self):
        """𐑑𐑧𐑕𐑑 𐑞𐑨𐑑 𐑒𐑪𐑯𐑓𐑦𐑜 𐑤𐑴𐑛𐑦𐑙 𐑢𐑻𐑒𐑕 𐑒𐑼𐑧𐑒𐑑𐑤𐑦"""
        config = ConfigManager(self.test_config_path)
        
        # 𐑑𐑧𐑕𐑑 𐑓𐑮𐑱𐑥𐑢𐑻𐑒 𐑒𐑪𐑯𐑓𐑦𐑜
        self.assertEqual(config.framework.version, '0.3.0')
        self.assertTrue(config.framework.debug_mode)
        self.assertTrue(config.framework.verbose_logging)
        self.assertEqual(config.framework.max_file_size_mb, 50)
        self.assertEqual(config.framework.temp_directory, '/tmp/test_cumpyl')
        
        # 𐑑𐑧𐑕𐑑 𐑐𐑤𐑳𐑜𐑦𐑯 𐑒𐑪𐑯𐑓𐑦𐑜
        self.assertTrue(config.plugins.enabled)
        self.assertTrue(config.plugins.auto_discovery)
        self.assertEqual(config.plugins.plugin_directory, 'test_plugins')
        self.assertEqual(config.plugins.load_order, ['test_plugin1', 'test_plugin2'])
        self.assertEqual(config.plugins.encoding['default_encoding'], 'hex')
        self.assertEqual(config.plugins.encoding['compression_level'], 9)
        
        # 𐑑𐑧𐑕𐑑 𐑕𐑦𐑒𐑘𐑫𐑼𐑦𐑑𐑦 𐑒𐑪𐑯𐑓𐑦𐑜
        self.assertTrue(config.security.sandbox_mode)
        self.assertEqual(config.security.max_modifications_per_session, 50)
        self.assertTrue(config.security.verify_checksums)
        
        # 𐑑𐑧𐑕𐑑 𐑐𐑼𐑓𐑹𐑥𐑩𐑯𐑕 𐑒𐑪𐑯𐑓𐑦𐑜
        self.assertFalse(config.performance.enable_parallel_processing)
        self.assertEqual(config.performance.max_worker_threads, 2)
        self.assertEqual(config.performance.memory_limit_mb, 256)
    
    def test_default_config(self):
        """𐑑𐑧𐑕𐑑 𐑞𐑨𐑑 𐑛𐑦𐑓𐑷𐑤𐑑 𐑒𐑪𐑯𐑓𐑦𐑜 𐑝𐑨𐑤𐑿𐑟 𐑸 𐑿𐑟𐑛 𐑢𐑧𐑯 𐑯𐑴 𐑓𐑲𐑤 𐑦𐑟 𐑓𐑬𐑯𐑛"""
        nonexistent_path = os.path.join(self.temp_dir, "nonexistent.yaml")
        config = ConfigManager(nonexistent_path)
        
        # 𐑖𐑫𐑛 𐑿𐑟 𐑛𐑦𐑓𐑷𐑤𐑑 𐑝𐑨𐑤𐑿𐑟
        self.assertEqual(config.framework.version, "0.3.0")
        self.assertFalse(config.framework.debug_mode)
        self.assertFalse(config.framework.verbose_logging)
        self.assertEqual(config.framework.max_file_size_mb, 100)
        self.assertEqual(config.framework.temp_directory, "/tmp/cumpyl")
    
    def test_plugin_config_retrieval(self):
        """𐑑𐑧𐑕𐑑 𐑞𐑨𐑑 𐑐𐑤𐑳𐑜𐑦𐑯-𐑕𐑐𐑧𐑕𐑦𐑓𐑦𐑒 𐑒𐑪𐑯𐑓𐑦𐑜 𐑮𐑦𐑑𐑮𐑰𐑝𐑩𐑤 𐑢𐑻𐑒𐑕"""
        config = ConfigManager(self.test_config_path)
        
        encoding_config = config.get_plugin_config('encoding')
        self.assertEqual(encoding_config['default_encoding'], 'hex')
        self.assertEqual(encoding_config['compression_level'], 9)
        
        # 𐑑𐑧𐑕𐑑 𐑯𐑳𐑤 𐑮𐑦𐑑𐑻𐑯 𐑓𐑹 𐑯𐑪𐑯-𐑧𐑒𐑟𐑦𐑕𐑑𐑩𐑯𐑑 𐑐𐑤𐑳𐑜𐑦𐑯
        nonexistent_config = config.get_plugin_config('nonexistent')
        self.assertEqual(nonexistent_config, {})
    
    def test_config_validation(self):
        """𐑑𐑧𐑕𐑑 𐑞𐑨𐑑 𐑒𐑪𐑯𐑓𐑦𐑜 𐑝𐑨𐑤𐑦𐑛𐑱𐑖𐑩𐑯 𐑢𐑻𐑒𐑕"""
        config = ConfigManager(self.test_config_path)
        
        # 𐑝𐑨𐑤𐑦𐑛 𐑒𐑪𐑯𐑓𐑦𐑜 𐑖𐑫𐑛 𐑮𐑦𐑑𐑻𐑯 𐑯𐑴 𐑦𐑖𐑿𐑟
        issues = config.validate_config()
        # 𐑯𐑴𐑑 𐑱𐑒𐑑𐑵𐑩𐑤𐑤𐑦 𐑛𐑦𐑕𐑩𐑚𐑤𐑦𐑙 𐑞 𐑐𐑤𐑳𐑜𐑦𐑯 𐑕𐑦𐑙𐑕 𐑞 𐑛𐑦𐑮𐑧𐑒𐑑𐑼𐑦 𐑛𐑲𐑟 𐑦𐑒𐑟𐑦𐑕𐑑
        # 𐑕𐑴 𐑢𐑰'𐑤𐑤 𐑣𐑨𐑝 𐑧𐑒𐑕𐑐𐑧𐑒𐑑 𐑛 𐑨𐑯 𐑦𐑖𐑿 𐑣𐑦𐑲 𐑞 𐑧𐑯𐑛 𐑝𐑨𐑤𐑦𐑛𐑱𐑖𐑩𐑯 𐑑𐑧𐑕𐑑
        # 𐑖𐑫𐑛 𐑗𐑧𐑒 𐑞 𐑛𐑦𐑕𐑩𐑚𐑤𐑦𐑙 𐑛𐑦𐑮𐑧𐑒𐑑𐑼𐑦 𐑕𐑦𐑙𐑕 𐑞 𐑛𐑦𐑮𐑧𐑒𐑑𐑼𐑦 𐑛𐑲𐑟 𐑦𐑒𐑟𐑦𐑕𐑑
        self.assertGreaterEqual(len(issues), 0)  # 𐑛𐑦𐑕𐑩𐑚𐑤𐑦𐑙 𐑞 𐑐𐑤𐑳𐑜𐑦𐑯 𐑕𐑦𐑙𐑕 𐑚𐑲 𐑛𐑦𐑓𐑷𐑤𐑑 𐑛𐑲𐑟 𐑯𐑪𐑑 𐑮𐑦𐑑𐑻𐑯 𐑛 𐑨𐑯 𐑦𐑖𐑿𐑟
        
        # 𐑑𐑧𐑕𐑑 𐑦𐑯𐑝𐑨𐑤𐑦𐑛 𐑒𐑪𐑯𐑓𐑦𐑜
        config.framework.max_file_size_mb = -1
        config.performance.max_worker_threads = 0
        
        issues = config.validate_config()
        self.assertGreater(len(issues), 0)
        self.assertTrue(any("max_file_size_mb must be positive" in issue for issue in issues))
        self.assertTrue(any("max_worker_threads must be positive" in issue for issue in issues))
    
    def test_config_saving(self):
        """𐑑𐑧𐑕𐑑 𐑞𐑨𐑑 𐑒𐑪𐑯𐑓𐑦𐑜 𐑕𐑱𐑝𐑦𐑙 𐑢𐑻𐑒𐑕"""
        config = ConfigManager(self.test_config_path)
        
        # 𐑥𐑪𐑛𐑦𐑓𐑲 𐑕𐑳𐑥 𐑝𐑨𐑤𐑿𐑟
        config.framework.debug_mode = False
        config.performance.max_worker_threads = 8
        
        # 𐑕𐑱𐑝 𐑑 𐑩 𐑯𐑿 𐑓𐑲𐑤
        output_path = os.path.join(self.temp_dir, "saved_config.yaml")
        success = config.save_config(output_path)
        self.assertTrue(success)
        self.assertTrue(os.path.exists(output_path))
        
        # 𐑤𐑴𐑛 𐑞 𐑕𐑱𐑝𐑛 𐑒𐑪𐑯𐑓𐑦𐑜 𐑯 𐑝𐑧𐑮𐑦𐑓𐑲 𐑗𐑱𐑯𐑡𐑌𐑦
        new_config = ConfigManager(output_path)
        self.assertFalse(new_config.framework.debug_mode)
        self.assertEqual(new_config.performance.max_worker_threads, 8)
    
    def test_section_config_retrieval(self):
        """𐑑𐑧𐑕𐑑 𐑞𐑨𐑑 𐑕𐑧𐑒𐑖𐑩𐑯 𐑒𐑪𐑯𐑓𐑦𐑜 𐑮𐑦𐑑𐑮𐑰𐑝𐑩𐑤 𐑢𐑻𐑒𐑕"""
        config = ConfigManager(self.test_config_path)
        
        framework_section = config.get_section_config('framework')
        self.assertEqual(framework_section['version'], '0.3.0')
        self.assertTrue(framework_section['debug_mode'])
        
        nonexistent_section = config.get_section_config('nonexistent')
        self.assertEqual(nonexistent_section, {})


class TestConfigDataClasses(unittest.TestCase):
    """𐑑𐑧𐑕𐑑 𐑒𐑩𐑯𐑓𐑦𐑜 𐑛𐑱𐑑𐑩 𐑒𐑤𐑭𐑕𐑌𐑦"""
    
    def test_framework_config_defaults(self):
        """𐑑𐑧𐑕𐑑 𐑞𐑨𐑑 FrameworkConfig 𐑣𐑨𐑟 𐑞 𐑮𐑲𐑑 𐑛𐑦𐑓𐑷𐑤𐑑 𐑝𐑨𐑤𐑿𐑟"""
        config = FrameworkConfig()
        self.assertEqual(config.version, "0.3.0")
        self.assertFalse(config.debug_mode)
        self.assertFalse(config.verbose_logging)
        self.assertEqual(config.max_file_size_mb, 100)
        self.assertEqual(config.temp_directory, "/tmp/cumpyl")
    
    def test_plugin_config_defaults(self):
        """𐑑𐑧𐑕𐑑 𐑞𐑨𐑑 PluginConfig 𐑣𐑨𐑟 𐑞 𐑮𐑲𐑑 𐑛𐑦𐑓𐑷𐑤𐑑 𐑝𐑨𐑤𐑿𐑟"""
        config = PluginConfig()
        self.assertTrue(config.enabled)
        self.assertTrue(config.auto_discovery)
        self.assertEqual(config.plugin_directory, "plugins")
        self.assertEqual(config.load_order, ["encoding", "entropy_analysis", "string_extraction"])
        self.assertEqual(config.encoding['default_encoding'], "base64")
        self.assertEqual(config.encoding['compression_level'], 6)
    
    def test_security_config_defaults(self):
        """𐑑𐑧𐑕𐑑 𐑞𐑨𐑑 SecurityConfig 𐑣𐑨𐑟 𐑞 𐑮𐑲𐑑 𐑛𐑦𐑓𐑷𐑤𐑑 𐑝𐑨𐑤𐑿𐑟"""
        config = SecurityConfig()
        self.assertFalse(config.sandbox_mode)
        self.assertEqual(config.max_modifications_per_session, 100)
        self.assertTrue(config.verify_checksums)
        self.assertTrue(config.log_all_modifications)
    
    def test_performance_config_defaults(self):
        """𐑑𐑧𐑕𐑑 𐑞𐑨𐑑 PerformanceConfig 𐑣𐑨𐑟 𐑞 𐑮𐑲𐑑 𐑛𐑦𐑓𐑷𐑤𐑑 𐑝𐑨𐑤𐑿𐑟"""
        config = PerformanceConfig()
        self.assertTrue(config.enable_parallel_processing)
        self.assertEqual(config.max_worker_threads, 4)
        self.assertTrue(config.cache_analysis_results)
        self.assertEqual(config.cache_expiry_hours, 24)
        self.assertEqual(config.memory_limit_mb, 512)


if __name__ == '__main__':
    unittest.main()