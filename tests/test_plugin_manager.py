import unittest
import tempfile
import os
import sys
from unittest.mock import Mock, patch

# 𐑨𐑛 𐑞 𐑐𐑸𐑧𐑯𐑑 𐑛𐑲𐑮𐑧𐑒𐑑𐑼𐑦 𐑑 𐑞 𐑐𐑭𐑔 𐑓𐑹 𐑦𐑥𐑐𐑹𐑑𐑦𐑙
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from cumpyl_package.plugin_manager import PluginManager, PluginInterface, AnalysisPlugin, TransformationPlugin, PluginLoadError
from cumpyl_package.config import ConfigManager


class MockAnalysisPlugin(AnalysisPlugin):
    """𐑥𐑪𐑒 𐑩𐑯𐑨𐑤𐑦𐑟𐑦𐑕 𐑐𐑤𐑳𐑜𐑦𐑯 𐑓𐑹 𐑑𐑧𐑕𐑑𐑦𐑙"""
    
    def __init__(self, config):
        super().__init__(config)
        self.name = "mock_analysis"
        self.version = "1.0.0"
        self.description = "Mock analysis plugin for testing"
    
    def analyze(self, rewriter):
        return {'test_key': 'test_value', 'plugin_name': self.name}


class MockTransformationPlugin(TransformationPlugin):
    """𐑥𐑪𐑒 𐑑𐑮𐑨𐑯𐑕𐑓𐑼𐑥𐑱𐑖𐑩𐑯 𐑐𐑤𐑳𐑜𐑦𐑯 𐑓𐑹 𐑑𐑧𐑕𐑑𐑦𐑙"""
    
    def __init__(self, config):
        super().__init__(config)
        self.name = "mock_transformation"
        self.version = "1.0.0"
        self.description = "Mock transformation plugin for testing"
    
    def transform(self, rewriter, analysis_result):
        return True


class MockPluginWithDependencies(AnalysisPlugin):
    """𐑥𐑪𐑒 𐑐𐑤𐑳𐑜𐑦𐑯 𐑢𐑦𐑞 𐑛𐑦𐑐𐑧𐑯𐑛𐑩𐑯𐑕𐑦𐑟"""
    
    def __init__(self, config):
        super().__init__(config)
        self.name = "mock_dependent"
        self.version = "1.0.0"
        self.description = "Mock plugin with dependencies"
        self.dependencies = ["mock_analysis"]
    
    def analyze(self, rewriter):
        return {'dependent_result': True}


class TestPluginManager(unittest.TestCase):
    """𐑑𐑧𐑕𐑑 𐑒𐑱𐑕𐑌𐑦 𐑓𐑹 𐑞 PluginManager"""
    
    def setUp(self):
        """𐑕𐑧𐑑 𐑳𐑐 𐑑𐑧𐑕𐑑 𐑓𐑦𐑒𐑗𐑼𐑟"""
        self.temp_dir = tempfile.mkdtemp()
        self.plugin_dir = os.path.join(self.temp_dir, "plugins")
        os.makedirs(self.plugin_dir)
        
        # 𐑒𐑮𐑦𐑱𐑑 𐑩 𐑥𐑪𐑒 𐑒𐑪𐑯𐑓𐑦𐑜
        self.mock_config = Mock(spec=ConfigManager)
        self.mock_config.plugins = Mock()
        self.mock_config.plugins.enabled = True
        self.mock_config.plugins.auto_discovery = True
        self.mock_config.plugins.plugin_directory = self.plugin_dir
        self.mock_config.plugins.load_order = []
        self.mock_config.framework = Mock()
        self.mock_config.framework.verbose_logging = False
        
        self.plugin_manager = PluginManager(self.mock_config)
    
    def tearDown(self):
        """𐑒𐑤𐑰𐑯 𐑳𐑐 𐑑𐑧𐑕𐑑 𐑓𐑦𐑒𐑗𐑼𐑟"""
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_plugin_manager_initialization(self):
        """𐑑𐑧𐑕𐑑 𐑞𐑨𐑑 PluginManager 𐑦𐑯𐑦𐑖𐑩𐑤𐑲𐑟𐑌𐑦 𐑒𐑼𐑧𐑒𐑑𐑤𐑦"""
        self.assertEqual(self.plugin_manager.config, self.mock_config)
        self.assertEqual(self.plugin_manager.plugin_directory, self.plugin_dir)
        self.assertEqual(len(self.plugin_manager.plugins), 0)
        self.assertEqual(len(self.plugin_manager.plugin_order), 0)
    
    def test_discover_plugins_empty_directory(self):
        """𐑑𐑧𐑕𐑑 𐑐𐑤𐑳𐑜𐑦𐑯 𐑛𐑦𐑕𐑒𐑳𐑝𐑼𐑦 𐑦𐑯 𐑧𐑥𐑐𐑑𐑦 𐑛𐑲𐑮𐑧𐑒𐑑𐑼𐑦"""
        discovered = self.plugin_manager.discover_plugins()
        self.assertEqual(len(discovered), 0)
    
    def test_discover_plugins_with_files(self):
        """𐑑𐑧𐑕𐑑 𐑐𐑤𐑳𐑜𐑦𐑯 𐑛𐑦𐑕𐑒𐑳𐑝𐑼𐑦 𐑢𐑦𐑞 𐑓𐑲𐑤𐑟"""
        # 𐑒𐑮𐑦𐑱𐑑 𐑕𐑳𐑥 𐑓𐑱𐑒 𐑐𐑤𐑳𐑜𐑦𐑯 𐑓𐑲𐑤𐑟
        test_plugin_file = os.path.join(self.plugin_dir, "test_plugin.py")
        with open(test_plugin_file, 'w') as f:
            f.write("# Test plugin")
        
        # 𐑒𐑮𐑦𐑱𐑑 𐑩 𐑯𐑪𐑯-𐑐𐑤𐑳𐑜𐑦𐑯 𐑓𐑲𐑤
        non_plugin_file = os.path.join(self.plugin_dir, "readme.txt")
        with open(non_plugin_file, 'w') as f:
            f.write("Not a plugin")
        
        # 𐑒𐑮𐑦𐑱𐑑 𐑩 𐑯𐑳𐑤 𐑓𐑲𐑤 (𐑖𐑫𐑛 𐑚𐑰 𐑦𐑜𐑯𐑹𐑛)
        null_file = os.path.join(self.plugin_dir, "__init__.py")
        with open(null_file, 'w') as f:
            f.write("# Package init")
        
        discovered = self.plugin_manager.discover_plugins()
        self.assertEqual(len(discovered), 1)
        self.assertIn("test_plugin", discovered)
    
    def test_manual_plugin_loading(self):
        """𐑑𐑧𐑕𐑑 𐑥𐑨𐑯𐑿𐑩𐑤 𐑐𐑤𐑳𐑜𐑦𐑯 𐑤𐑴𐑛𐑦𐑙 (𐑦𐑯 𐑥𐑧𐑥𐑼𐑦)"""
        # 𐑧𐑥𐑿𐑤𐑱𐑑 𐑤𐑴𐑛𐑦𐑙 𐑩 𐑐𐑤𐑳𐑜𐑦𐑯 𐑛𐑲𐑮𐑧𐑒𐑑𐑤𐑦
        plugin_instance = MockAnalysisPlugin(self.mock_config)
        self.plugin_manager.plugins['mock_analysis'] = plugin_instance
        self.plugin_manager.plugin_order.append('mock_analysis')
        
        # 𐑝𐑧𐑮𐑦𐑓𐑲 𐑦𐑑 𐑢𐑩𐑟 𐑨𐑛𐑦𐑛
        self.assertEqual(len(self.plugin_manager.plugins), 1)
        self.assertIn('mock_analysis', self.plugin_manager.plugins)
        self.assertEqual(self.plugin_manager.plugins['mock_analysis'].name, 'mock_analysis')
    
    def test_get_analysis_plugins(self):
        """𐑑𐑧𐑕𐑑 𐑞𐑨𐑑 AnalysisPlugin 𐑟 𐑸 𐑦𐑔𐑩𐑯𐑑𐑦𐑓𐑲𐑛 𐑒𐑼𐑧𐑒𐑑𐑤𐑦"""
        # 𐑒𐑮𐑦𐑱𐑑 𐑩𐑯𐑨𐑤𐑦𐑟𐑦𐑕 𐑐𐑤𐑳𐑜𐑦𐑯 𐑢𐑦𐑞 𐑪𐑝𐑻𐑮𐑲𐑛𐑩𐑯 𐑩𐑯𐑨𐑤𐑦𐑟𐑦𐑕 𐑥𐑧𐑑𐑣𐑪𐑛
        class CustomAnalysisPlugin(AnalysisPlugin):
            def __init__(self, config):
                super().__init__(config)
                self.name = "analysis_plugin"
            
            def analyze(self, rewriter):
                return {}
        
        # 𐑒𐑮𐑦𐑱𐑑 𐑑𐑮𐑨𐑯𐑕𐑓𐑼𐑥𐑱𐑖𐑩𐑯 𐑐𐑤𐑳𐑜𐑦𐑯 𐑢𐑦𐑞 𐑪𐑝𐑻𐑮𐑲𐑛𐑩𐑯 𐑑𐑮𐑨𐑯𐑕𐑓𐑼𐑥 𐑥𐑧𐑑𐑣𐑪𐑛
        class CustomTransformationPlugin(TransformationPlugin):
            def __init__(self, config):
                super().__init__(config)
                self.name = "transformation_plugin"
            
            def transform(self, rewriter, analysis_result):
                return True
        
        analysis_plugin = CustomAnalysisPlugin(self.mock_config)
        transformation_plugin = CustomTransformationPlugin(self.mock_config)
        
        self.plugin_manager.plugins['analysis_plugin'] = analysis_plugin
        self.plugin_manager.plugins['transformation_plugin'] = transformation_plugin
        
        analysis_plugins = self.plugin_manager.get_analysis_plugins()
        # 𐑒𐑳𐑯𐑑 𐑖𐑫𐑛 𐑚𐑰 1 𐑓𐑹 𐑞 𐑩𐑯𐑨𐑤𐑦𐑟𐑦𐑕 𐑐𐑤𐑳𐑜𐑦𐑯
        analysis_plugin_count = sum(1 for p in analysis_plugins if p.name == 'analysis_plugin')
        self.assertEqual(analysis_plugin_count, 1)
        
        # 𐑩𐑯𐑨𐑤𐑦𐑟𐑦𐑕 𐑐𐑤𐑳𐑜𐑦𐑯 𐑖𐑫𐑛 𐑯𐑪𐑑 𐑚𐑰 𐑦𐑯 𐑞 𐑑𐑮𐑨𐑯𐑕𐑓𐑼𐑥𐑱𐑖𐑩𐑯 𐑤𐑦𐑕𐑑
        transformation_plugin_count = sum(1 for p in analysis_plugins if p.name == 'transformation_plugin')
        self.assertEqual(transformation_plugin_count, 0)
    
    def test_get_transformation_plugins(self):
        """𐑑𐑧𐑕𐑑 𐑞𐑨𐑑 TransformationPlugin 𐑟 𐑸 𐑦𐑔𐑩𐑯𐑑𐑦𐑓𐑲𐑛 𐑒𐑼𐑧𐑒𐑑𐑤𐑦"""
        # 𐑒𐑮𐑦𐑱𐑑 𐑩𐑯𐑨𐑤𐑦𐑟𐑦𐑕 𐑐𐑤𐑳𐑜𐑦𐑯 𐑢𐑦𐑞 𐑪𐑝𐑻𐑮𐑲𐑛𐑩𐑯 𐑩𐑯𐑨𐑤𐑦𐑟𐑦𐑕 𐑥𐑧𐑑𐑣𐑪𐑛
        class CustomAnalysisPlugin(AnalysisPlugin):
            def __init__(self, config):
                super().__init__(config)
                self.name = "analysis_plugin"
            
            def analyze(self, rewriter):
                return {}
        
        # 𐑒𐑮𐑦𐑱𐑑 𐑑𐑮𐑨𐑯𐑕𐑓𐑼𐑥𐑱𐑖𐑩𐑯 𐑐𐑤𐑳𐑜𐑦𐑯 𐑢𐑦𐑞 𐑪𐑝𐑻𐑮𐑲𐑛𐑩𐑯 𐑑𐑮𐑨𐑯𐑕𐑓𐑼𐑥 𐑥𐑧𐑑𐑣𐑪𐑛
        class CustomTransformationPlugin(TransformationPlugin):
            def __init__(self, config):
                super().__init__(config)
                self.name = "transformation_plugin"
            
            def transform(self, rewriter, analysis_result):
                return True
        
        analysis_plugin = CustomAnalysisPlugin(self.mock_config)
        transformation_plugin = CustomTransformationPlugin(self.mock_config)
        
        self.plugin_manager.plugins['analysis_plugin'] = analysis_plugin
        self.plugin_manager.plugins['transformation_plugin'] = transformation_plugin
        
        transformation_plugins = self.plugin_manager.get_transformation_plugins()
        # 𐑒𐑳𐑯𐑑 𐑖𐑫𐑛 𐑚𐑰 1 𐑓𐑹 𐑞 𐑑𐑮𐑨𐑯𐑕𐑓𐑼𐑥𐑱𐑖𐑩𐑯 𐑐𐑤𐑳𐑜𐑦𐑯
        transformation_plugin_count = sum(1 for p in transformation_plugins if p.name == 'transformation_plugin')
        self.assertEqual(transformation_plugin_count, 1)
        
        # 𐑑𐑮𐑨𐑯𐑕𐑓𐑼𐑥𐑱𐑖𐑩𐑯 𐑐𐑤𐑳𐑜𐑦𐑯 𐑖𐑫𐑛 𐑯𐑪𐑑 𐑚𐑰 𐑦𐑯 𐑞 𐑩𐑯𐑨𐑤𐑦𐑟𐑦𐑕 𐑤𐑦𐑕𐑑
        analysis_plugin_count = sum(1 for p in transformation_plugins if p.name == 'analysis_plugin')
        self.assertEqual(analysis_plugin_count, 0)
    
    def test_execute_analysis_phase(self):
        """𐑑𐑧𐑕𐑑 𐑞𐑨𐑑 𐑩𐑯𐑨𐑤𐑦𐑟𐑦𐑕 𐑓𐑱𐑟 𐑦𐑒𐑕𐑦𐑒𐑿𐑖𐑩𐑯 𐑢𐑻𐑒𐑕"""
        plugin = MockAnalysisPlugin(self.mock_config)
        self.plugin_manager.plugins['mock_analysis'] = plugin
        
        mock_rewriter = Mock()
        results = self.plugin_manager.execute_analysis_phase(mock_rewriter)
        
        self.assertIn('mock_analysis', results)
        self.assertEqual(results['mock_analysis']['test_key'], 'test_value')
        self.assertEqual(results['mock_analysis']['plugin_name'], 'mock_analysis')
    
    def test_execute_transformation_phase(self):
        """𐑑𐑧𐑕𐑑 𐑞𐑨𐑑 𐑑𐑮𐑨𐑯𐑕𐑓𐑼𐑥𐑱𐑖𐑩𐑯 𐑓𐑱𐑟 𐑦𐑒𐑕𐑦𐑒𐑿𐑖𐑩𐑯 𐑢𐑻𐑒𐑕"""
        plugin = MockTransformationPlugin(self.mock_config)
        self.plugin_manager.plugins['mock_transformation'] = plugin
        
        mock_rewriter = Mock()
        analysis_results = {'mock_transformation': {'some': 'data'}}
        
        success = self.plugin_manager.execute_transformation_phase(mock_rewriter, analysis_results)
        self.assertTrue(success)
    
    def test_plugin_dependency_validation(self):
        """𐑑𐑧𐑕𐑑 𐑞𐑨𐑑 𐑐𐑤𐑳𐑜𐑦𐑯 𐑛𐑦𐑐𐑧𐑯𐑛𐑩𐑯𐑕𐑦 𐑝𐑨𐑤𐑦𐑛𐑱𐑖𐑩𐑯 𐑢𐑻𐑒𐑕"""
        # 𐑓𐑻𐑕𐑑 𐑨𐑛 𐑞 𐑛𐑦𐑐𐑧𐑯𐑛𐑧𐑯𐑕𐑦
        base_plugin = MockAnalysisPlugin(self.mock_config)
        self.plugin_manager.plugins['mock_analysis'] = base_plugin
        
        # 𐑞𐑧𐑯 𐑨𐑛 𐑞 𐑛𐑦𐑐𐑧𐑯𐑛𐑩𐑯𐑑 𐑐𐑤𐑳𐑜𐑦𐑯
        dependent_plugin = MockPluginWithDependencies(self.mock_config)
        
        # 𐑛𐑦𐑐𐑧𐑯𐑛𐑩𐑯𐑕𐑦 𐑝𐑨𐑤𐑦𐑛𐑱𐑖𐑩𐑯 𐑖𐑫𐑛 𐑐𐑭𐑕
        available_plugins = list(self.plugin_manager.plugins.keys())
        self.assertTrue(dependent_plugin.validate_dependencies(available_plugins))
        
        # 𐑛𐑦𐑐𐑧𐑯𐑛𐑩𐑯𐑕𐑦 𐑝𐑨𐑤𐑦𐑛𐑱𐑖𐑩𐑯 𐑖𐑫𐑛 𐑓𐑱𐑤 𐑦𐑓 𐑛𐑦𐑐𐑧𐑯𐑛𐑩𐑯𐑕𐑦 𐑦𐑟 𐑯𐑪𐑑 𐑩𐑝𐑱𐑤𐑩𐑚𐑩𐑤
        empty_plugins = []
        self.assertFalse(dependent_plugin.validate_dependencies(empty_plugins))
    
    def test_list_plugins(self):
        """𐑑𐑧𐑕𐑑 𐑞𐑨𐑑 𐑐𐑤𐑳𐑜𐑦𐑯 𐑤𐑦𐑕𐑑𐑦𐑙 𐑢𐑻𐑒𐑕"""
        plugin1 = MockAnalysisPlugin(self.mock_config)
        plugin2 = MockTransformationPlugin(self.mock_config)
        
        self.plugin_manager.plugins['plugin1'] = plugin1
        self.plugin_manager.plugins['plugin2'] = plugin2
        
        plugin_list = self.plugin_manager.list_plugins()
        self.assertEqual(len(plugin_list), 2)
        
        # 𐑗𐑧𐑒 𐑞𐑨𐑑 𐑐𐑤𐑳𐑜𐑦𐑯 𐑦𐑯𐑓𐑼𐑥𐑱𐑖𐑩𐑯 𐑦𐑟 𐑦𐑯𐑒𐑤𐑿𐑛𐑦𐑛
        plugin_names = [p['name'] for p in plugin_list]
        self.assertIn('mock_analysis', plugin_names)
        self.assertIn('mock_transformation', plugin_names)
    
    def test_plugin_get_config(self):
        """𐑑𐑧𐑕𐑑 𐑞𐑨𐑑 𐑐𐑤𐑳𐑜𐑦𐑯 𐑒𐑨𐑯 𐑮𐑦𐑑𐑮𐑰𐑝 𐑞𐑺 𐑒𐑪𐑯𐑓𐑦𐑜"""
        # 𐑞𐑧𐑝 𐑞 𐑥𐑪𐑒 𐑒𐑪𐑯𐑓𐑦𐑜 𐑑 𐑮𐑦𐑑𐑻𐑯 𐑕𐑳𐑥 𐑛𐑱𐑑𐑩
        test_config_data = {'setting1': 'value1', 'setting2': 42}
        self.mock_config.get_plugin_config = Mock(return_value=test_config_data)
        
        plugin = MockAnalysisPlugin(self.mock_config)
        config_data = plugin.get_config()
        
        self.assertEqual(config_data, test_config_data)
        self.mock_config.get_plugin_config.assert_called_with('mock_analysis')
    
    def test_disabled_plugins(self):
        """𐑑𐑧𐑕𐑑 𐑞𐑨𐑑 𐑛𐑦𐑟𐑱𐑚𐑩𐑤𐑛 𐑐𐑤𐑳𐑜𐑦𐑯𐑟 𐑸 𐑦𐑜𐑯𐑹𐑛"""
        # 𐑛𐑦𐑟𐑱𐑚𐑩𐑤 𐑐𐑤𐑳𐑜𐑦𐑯 𐑦𐑯 𐑒𐑪𐑯𐑓𐑦𐑜
        disabled_plugin = MockAnalysisPlugin(self.mock_config)
        disabled_plugin.enabled = False
        
        enabled_plugin = MockTransformationPlugin(self.mock_config)
        enabled_plugin.enabled = True
        
        self.plugin_manager.plugins['disabled'] = disabled_plugin
        self.plugin_manager.plugins['enabled'] = enabled_plugin
        
        mock_rewriter = Mock()
        
        # 𐑩𐑯𐑨𐑤𐑦𐑟𐑦𐑕 𐑓𐑱𐑟 - 𐑴𐑯𐑤𐑦 𐑦𐑯𐑱𐑚𐑩𐑤𐑛 𐑐𐑤𐑳𐑜𐑦𐑯 𐑖𐑫𐑛 𐑮𐑳𐑯
        results = self.plugin_manager.execute_analysis_phase(mock_rewriter)
        self.assertNotIn('disabled', results)
        
        # 𐑑𐑮𐑨𐑯𐑕𐑓𐑼𐑥𐑱𐑖𐑩𐑯 𐑓𐑱𐑟 - 𐑴𐑯𐑤𐑦 𐑦𐑯𐑱𐑚𐑩𐑤𐑛 𐑐𐑤𐑳𐑜𐑦𐑯 𐑖𐑫𐑛 𐑮𐑳𐑯
        success = self.plugin_manager.execute_transformation_phase(mock_rewriter, {})
        self.assertTrue(success)  # 𐑦𐑯𐑱𐑚𐑩𐑤𐑛 𐑐𐑤𐑳𐑜𐑦𐑯 𐑮𐑳𐑯, 𐑛𐑦𐑟𐑱𐑚𐑩𐑤𐑛 𐑛𐑦𐑛 𐑯𐑪𐑑


class TestPluginInterface(unittest.TestCase):
    """𐑑𐑧𐑕𐑑 𐑒𐑱𐑕𐑌𐑦 𐑓𐑹 PluginInterface"""
    
    def setUp(self):
        """𐑕𐑧𐑑 𐑳𐑐 𐑑𐑧𐑕𐑑 𐑓𐑦𐑒𐑗𐑼𐑟"""
        self.mock_config = Mock(spec=ConfigManager)
    
    def test_plugin_metadata(self):
        """𐑑𐑧𐑕𐑑 𐑞𐑨𐑑 𐑐𐑤𐑳𐑜𐑦𐑯 𐑥𐑧𐑑𐑩𐑛𐑱𐑑𐑩 𐑦𐑟 𐑒𐑼𐑧𐑒𐑑"""
        plugin = MockAnalysisPlugin(self.mock_config)
        metadata = plugin.get_metadata()
        
        self.assertEqual(metadata['name'], 'mock_analysis')
        self.assertEqual(metadata['version'], '1.0.0')
        self.assertEqual(metadata['description'], 'Mock analysis plugin for testing')
        self.assertEqual(metadata['author'], 'Unknown')
        self.assertEqual(metadata['dependencies'], [])
        self.assertTrue(metadata['enabled'])
    
    def test_plugin_with_dependencies_metadata(self):
        """𐑑𐑧𐑕𐑑 𐑞𐑨𐑑 𐑐𐑤𐑳𐑜𐑦𐑯 𐑢𐑦𐑞 𐑛𐑦𐑐𐑧𐑯𐑛𐑩𐑯𐑕𐑦𐑟 𐑦𐑯𐑒𐑤𐑿𐑛𐑟 𐑞𐑧𐑥"""
        plugin = MockPluginWithDependencies(self.mock_config)
        metadata = plugin.get_metadata()
        
        self.assertEqual(metadata['dependencies'], ['mock_analysis'])


if __name__ == '__main__':
    unittest.main()