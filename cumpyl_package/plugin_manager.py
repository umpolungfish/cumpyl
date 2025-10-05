import os
import sys
import importlib.util
import inspect
from typing import Dict, List, Any, Optional, Type
from abc import ABC, abstractmethod
from pathlib import Path
import yaml

# Try relative imports first (for when running as module)
try:
    from .config import ConfigManager
except ImportError:
    # Fallback to absolute imports (for direct script execution)
    try:
        from cumpyl_package.config import ConfigManager
    except ImportError:
        from config import ConfigManager

# Try to import PluginRegistry, but don't fail if it's not available
try:
    # First try relative import from plugins directory
    from plugins.plugin_registry import PluginRegistry
except ImportError:
    try:
        # Try absolute import
        from cumpyl_package.plugins.plugin_registry import PluginRegistry
    except ImportError:
        try:
            # Try direct import
            import plugins.plugin_registry
            PluginRegistry = plugins.plugin_registry.PluginRegistry
        except ImportError:
            PluginRegistry = None


class PluginInterface(ABC):
    """𐑚𐑱𐑕 𐑦𐑯𐑑𐑼𐑓𐑱𐑕 𐑓𐑹 𐑷𐑤 𐑐𐑤𐑳𐑜𐑦𐑯𐑟"""
    
    def __init__(self, config: ConfigManager):
        self.config = config
        self.name = self.__class__.__name__.lower().replace('plugin', '')
        self.version = "1.0.0"
        self.description = "Base plugin"
        self.author = "Unknown"
        self.dependencies = []
        self.enabled = True
    
    @abstractmethod
    def analyze(self, rewriter) -> Dict[str, Any]:
        """𐑐𐑼𐑓𐑹𐑥 𐑩𐑯𐑨𐑤𐑦𐑟𐑦𐑕 𐑪𐑯 𐑞 𐑚𐑲𐑯𐑩𐑮𐑦"""
        pass
    
    @abstractmethod
    def transform(self, rewriter, analysis_result: Dict[str, Any]) -> bool:
        """𐑑𐑮𐑨𐑯𐑕𐑓𐑹𐑥 𐑞 𐑚𐑲𐑯𐑩𐑮𐑦 𐑚𐑱𐑕𐑑 𐑪𐑯 𐑩𐑯𐑨𐑤𐑦𐑟𐑦𐑕"""
        pass
    
    def get_metadata(self) -> Dict[str, Any]:
        """𐑮𐑦𐑑𐑻𐑯 𐑐𐑤𐑳𐑜𐑦𐑯 𐑥𐑧𐑑𐑩𐑛𐑱𐑑𐑩"""
        return {
            'name': self.name,
            'version': self.version,
            'description': self.description,
            'author': self.author,
            'dependencies': self.dependencies,
            'enabled': self.enabled
        }
    
    def get_config(self) -> Dict[str, Any]:
        """𐑜𐑧𐑑 𐑒𐑪𐑯𐑓𐑦𐑜𐑘𐑼𐑱𐑖𐑩𐑯 𐑓𐑹 𐑞𐑦𐑕 𐑐𐑤𐑳𐑜𐑦𐑯"""
        return self.config.get_plugin_config(self.name)
    
    def validate_dependencies(self, available_plugins: List[str]) -> bool:
        """Validate that all dependencies are available"""
        for dep in self.dependencies:
            if dep not in available_plugins:
                # Check if it is an installed python package
                if importlib.util.find_spec(dep) is None:
                    return False
        return True


class AnalysisPlugin(PluginInterface):
    """𐑚𐑱𐑕 𐑒𐑤𐑭𐑕 𐑓𐑹 𐑩𐑯𐑨𐑤𐑦𐑟𐑦𐑕-𐑴𐑯𐑤𐑦 𐑐𐑤𐑳𐑜𐑦𐑯𐑟"""
    
    def transform(self, rewriter, analysis_result: Dict[str, Any]) -> bool:
        """𐑩𐑯𐑨𐑤𐑦𐑟𐑦𐑕 𐑐𐑤𐑳𐑜𐑦𐑯𐑟 𐑛𐑴𐑯𐑑 𐑑𐑮𐑨𐑯𐑕𐑓𐑹𐑥 𐑚𐑲 𐑛𐑦𐑓𐑷𐑤𐑑"""
        return True


class TransformationPlugin(PluginInterface):
    """𐑚𐑱𐑕 𐑒𐑤𐑭𐑕 𐑓𐑹 𐑑𐑮𐑨𐑯𐑕𐑓𐑼𐑥𐑱𐑖𐑩𐑯 𐑐𐑤𐑳𐑜𐑦𐑯𐑟"""
    
    def analyze(self, rewriter) -> Dict[str, Any]:
        """𐑑𐑮𐑨𐑯𐑕𐑓𐑼𐑥𐑱𐑖𐑩𐑯 𐑐𐑤𐑳𐑜𐑦𐑯𐑟 𐑥𐑱 𐑯𐑪𐑑 𐑯𐑰𐑛 𐑩𐑯𐑨𐑤𐑦𐑟𐑦𐑕"""
        return {}


class PluginLoadError(Exception):
    """𐑧𐑒𐑕𐑧𐑐𐑖𐑩𐑯 𐑮𐑱𐑕𐑛 𐑦𐑓 𐑩 𐑐𐑤𐑳𐑜𐑦𐑯 𐑓𐑱𐑤𐑟 𐑑 𐑤𐑴𐑛"""
    pass


class PluginManager:
    """𐑥𐑨𐑯𐑦𐑡 𐑐𐑤𐑳𐑜𐑦𐑯 𐑛𐑦𐑕𐑒𐑳𐑝𐑼𐑦, 𐑤𐑴𐑛𐑦𐑙, 𐑯 𐑧𐑒𐑟𐑦𐑒𐑿𐑖𐑩𐑯"""
    
    def __init__(self, config: ConfigManager):
        self.config = config
        self.plugins: Dict[str, PluginInterface] = {}
        self.plugin_order: List[str] = []
        self.loaded_modules: Dict[str, Any] = {}
        
        # 𐑜𐑧𐑑 𐑐𐑤𐑳𐑜𐑦𐑯 𐑛𐑲𐑮𐑧𐑒𐑑𐑼𐑦 𐑓𐑮𐑪𐑥 𐑒𐑪𐑯𐑓𐑦𐑜
        self.plugin_directory = self.config.plugins.plugin_directory
        if not os.path.isabs(self.plugin_directory):
            # 𐑥𐑱𐑒 𐑦𐑑 𐑮𐑦𐑤𐑩𐑑𐑦𐑝 𐑑 𐑞 𐑒𐑻𐑧𐑯𐑑 𐑛𐑲𐑮𐑧𐑒𐑑𐑼𐑦
            self.plugin_directory = os.path.join(os.getcwd(), self.plugin_directory)
    
    def discover_plugins(self) -> List[str]:
        """𐑛𐑦𐑕𐑒𐑳𐑝𐑼 𐑩𐑝𐑱𐑤𐑩𐑚𐑩𐑤 𐑐𐑤𐑳𐑜𐑦𐑯 𐑓𐑲𐑤𐑟"""
        discovered = []
        
        if not os.path.exists(self.plugin_directory):
            print(f"[!] Plugin directory not found: {self.plugin_directory}")
            return discovered
        
        # 𐑤𐑫𐑒 𐑓𐑹 Python 𐑓𐑲𐑤𐑟 𐑦𐑯 𐑞 𐑐𐑤𐑳𐑜𐑦𐑯 𐑛𐑲𐑮𐑧𐑒𐑑𐑼𐑦
        for filename in os.listdir(self.plugin_directory):
            if filename.endswith('.py') and not filename.startswith('__'):
                plugin_name = filename[:-3]  # 𐑮𐑦𐑵 .py 𐑧𐑒𐑕𐑑𐑧𐑯𐑖𐑩𐑯
                discovered.append(plugin_name)
        
        # 𐑤𐑫𐑒 𐑓𐑹 𐑐𐑤𐑳𐑜𐑦𐑯 𐑛𐑲𐑮𐑧𐑒𐑑𐑼𐑦𐑟 𐑢𐑦𐑞 __init__.py
        for item in os.listdir(self.plugin_directory):
            item_path = os.path.join(self.plugin_directory, item)
            if os.path.isdir(item_path):
                init_file = os.path.join(item_path, '__init__.py')
                if os.path.exists(init_file):
                    discovered.append(item)
        
        return discovered
    
    def load_plugin(self, plugin_name: str) -> bool:
        """𐑤𐑴𐑛 𐑩 𐑕𐑦𐑙𐑜𐑩𐑤 𐑐𐑤𐑳𐑜𐑦𐑯"""
        try:
            # 𐑒𐑪𐑯𐑕𐑑𐑮𐑳𐑒𐑑 𐑓𐑲𐑤 𐑐𐑭𐑔
            plugin_file = os.path.join(self.plugin_directory, f"{plugin_name}.py")
            plugin_dir = os.path.join(self.plugin_directory, plugin_name)
            
            module_path = None
            if os.path.exists(plugin_file):
                module_path = plugin_file
            elif os.path.exists(plugin_dir) and os.path.exists(os.path.join(plugin_dir, '__init__.py')):
                module_path = os.path.join(plugin_dir, '__init__.py')
            else:
                raise PluginLoadError(f"Plugin file not found: {plugin_name}")
            
            # 𐑤𐑴𐑛 𐑞 𐑥𐑪𐑛𐑿𐑤
            spec = importlib.util.spec_from_file_location(plugin_name, module_path)
            if spec is None or spec.loader is None:
                raise PluginLoadError(f"Failed to create module spec for {plugin_name}")
            
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self.loaded_modules[plugin_name] = module
            
            # 𐑓𐑲𐑯𐑛 𐑐𐑤𐑳𐑜𐑦𐑯 𐑒𐑤𐑭𐑕𐑌𐑦
            plugin_class = None
            plugin_factory = None
            
            # 𐑣𐑧𐑤𐑝 𐑩𐑯𐑦 𐑒𐑤𐑭𐑕𐑧𐑟 𐑢𐑦𐑞 𐑩𐑯𐑨𐑤𐑦𐑕𐑧 𐑯 𐑑𐑮𐑨𐑯𐑕𐑓𐑹𐑥 𐑥𐑧𐑑𐑣𐑪𐑛𐑕
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if (inspect.isclass(obj) and 
                    hasattr(obj, 'analyze') and 
                    hasattr(obj, 'transform') and
                    obj.__name__ not in ['PluginInterface', 'AnalysisPlugin', 'TransformationPlugin']):
                    try:
                        # 𐑩𐑛𐑦𐑖𐑩𐑯𐑩𐑤 𐑗𐑧𐑒: 𐑑𐑮𐑲 𐑑 𐑦𐑯𐑕𐑑𐑨𐑯𐑖𐑦𐑱𐑑 𐑦𐑑 𐑢𐑦𐑞 𐑩 𐑛𐑳𐑥𐑦 𐑒𐑪𐑯𐑓𐑦𐑜
                        test_instance = obj(self.config)
                        if hasattr(test_instance, 'name') and hasattr(test_instance, 'version'):
                            plugin_class = obj
                            break
                    except Exception as e:
                        # 𐑦𐑓 𐑦𐑯𐑕𐑑𐑨𐑯𐑖𐑦𐑱𐑖𐑩𐑯 𐑓𐑱𐑤𐑕, 𐑦𐑑'𐑕 𐑯𐑪𐑑 𐑩 𐑝𐑨𐑤𐑦𐑛 𐑐𐑤𐑳𐑜𐑦𐑯
                        if self.config.framework.verbose_logging:
                            print(f"[-] Class {obj.__name__} failed instantiation test: {e}")
                        continue
            
            # 𐑦𐑓 𐑯 𐑒𐑤𐑭𐑕 𐑢𐑨𐑟 𐑓𐑳𐑯𐑛, 𐑤𐑪𐑒 𐑓𐑹 𐑓𐑨𐑒𐑑𐑮𐑦 𐑓𐑳𐑯𐑒𐑖𐑩𐑯𐑟
            if plugin_class is None:
                print(f"[DEBUG] Looking for factory functions in {plugin_name}")
                for name, obj in inspect.getmembers(module, inspect.isfunction):
                    print(f"[DEBUG] Found function: {name}")
                    if name in ['get_plugin', 'get_transform_plugin']:
                        print(f"[DEBUG] Checking factory function: {name}")
                        try:
                            # 𐑑𐑮𐑲 𐑑 𐑦𐑯𐑕𐑑𐑨𐑯𐑖𐑦𐑱𐑑 𐑩 𐑐𐑤𐑳𐑜𐑦𐑯 𐑓𐑮𐑪𐑥 𐑞 𐑓𐑨𐑒𐑑𐑮𐑦 𐑓𐑳𐑯𐑒𐑖𐑩𐑯
                            test_instance = obj(self.config)
                            print(f"[DEBUG] Factory function {name} returned instance: {type(test_instance)}")
                            if hasattr(test_instance, 'analyze') and hasattr(test_instance, 'transform'):
                                print(f"[DEBUG] Factory function {name} is valid")
                                plugin_factory = obj
                                break
                            else:
                                print(f"[DEBUG] Factory function {name} missing analyze or transform methods")
                        except Exception as e:
                            print(f"[-] Factory function {name} failed test: {e}")
                            continue
            
            if plugin_class is None and plugin_factory is None:
                print(f"[-] No valid plugin class or factory function found in {plugin_name}")
                print(f"    plugin_class: {plugin_class}")
                print(f"    plugin_factory: {plugin_factory}")
                raise PluginLoadError(f"No valid plugin class or factory function found in {plugin_name}")
            
            # 𐑦𐑯𐑕𐑑𐑨𐑯𐑖𐑦𐑱𐑑 𐑞 𐑐𐑤𐑳𐑜𐑦𐑯
            if self.config.framework.verbose_logging:
                print(f"[+] Creating plugin instance for {plugin_name}")
                print(f"    plugin_class: {plugin_class}")
                print(f"    plugin_factory: {plugin_factory}")
                
            if plugin_class is not None:
                plugin_instance = plugin_class(self.config)
            else:
                plugin_instance = plugin_factory(self.config)
            
            # 𐑝𐑨𐑤𐑦𐑛𐑱𐑑 𐑛𐑦𐑐𐑧𐑯𐑛𐑩𐑯𐑕𐑦𐑟
            if not plugin_instance.validate_dependencies(list(self.plugins.keys())):
                raise PluginLoadError(f"Plugin {plugin_name} has unmet dependencies: {plugin_instance.dependencies}")
            
            # 𐑨𐑛 𐑑 𐑤𐑴𐑛𐑦𐑛 𐑐𐑤𐑳𐑜𐑦𐑯𐑟
            self.plugins[plugin_name] = plugin_instance
            
            # Register with centralized plugin registry
            try:
                # Determine plugin type based on inheritance
                if PluginRegistry is not None:
                    if isinstance(plugin_instance, AnalysisPlugin):
                        PluginRegistry.register('analysis', plugin_name, lambda config: plugin_instance)
                    elif isinstance(plugin_instance, TransformationPlugin):
                        PluginRegistry.register('transformation', plugin_name, lambda config: plugin_instance)
            except Exception as e:
                if self.config.framework.verbose_logging:
                    print(f"[-] Failed to register plugin {plugin_name} with centralized registry: {e}")
            
            if self.config.framework.verbose_logging:
                print(f"[+] Loaded plugin: {plugin_name} v{plugin_instance.version}")
            
            return True
            
        except Exception as e:
            print(f"[-] Failed to load plugin {plugin_name}: {e}")
            return False
    
    def load_all_plugins(self) -> int:
        """𐑤𐑴𐑛 𐑷𐑤 𐑩𐑝𐑱𐑤𐑩𐑚𐑩𐑤 𐑐𐑤𐑳𐑜𐑦𐑯𐑟"""
        if not self.config.plugins.enabled:
            print("[*] Plugin system disabled in configuration")
            return 0
        
        # 𐑛𐑦𐑕𐑒𐑳𐑝𐑼 𐑐𐑤𐑳𐑜𐑦𐑯𐑟
        if self.config.plugins.auto_discovery:
            discovered = self.discover_plugins()
            print(f"[*] Discovered {len(discovered)} plugin(s): {', '.join(discovered)}")
        else:
            discovered = self.config.plugins.load_order
        
        # 𐑤𐑴𐑛 𐑦𐑯 𐑞 𐑹𐑛𐑼 𐑕𐑐𐑧𐑕𐑦𐑓𐑲𐑛 𐑦𐑯 𐑒𐑪𐑯𐑓𐑦𐑜
        loaded_count = 0
        load_order = self.config.plugins.load_order if self.config.plugins.load_order else discovered
        
        for plugin_name in load_order:
            if plugin_name in discovered:
                if self.load_plugin(plugin_name):
                    loaded_count += 1
                    self.plugin_order.append(plugin_name)
        
        # 𐑤𐑴𐑛 𐑮𐑦𐑥𐑱𐑯𐑦𐑙 𐑛𐑦𐑕𐑒𐑳𐑝𐑼𐑛 𐑐𐑤𐑳𐑜𐑦𐑯𐑟 𐑯𐑪𐑑 𐑦𐑯 𐑤𐑴𐑛 𐑹𐑛𐑼
        for plugin_name in discovered:
            if plugin_name not in self.plugin_order:
                if self.load_plugin(plugin_name):
                    loaded_count += 1
                    self.plugin_order.append(plugin_name)
        
        print(f"[+] Loaded {loaded_count} plugin(s)")
        return loaded_count
    
    def get_plugin(self, plugin_name: str) -> Optional[PluginInterface]:
        """𐑜𐑧𐑑 𐑩 𐑤𐑴𐑛𐑦𐑛 𐑐𐑤𐑳𐑜𐑦𐑯 𐑚𐑲 𐑯𐑱𐑥"""
        return self.plugins.get(plugin_name)
    
    def get_analysis_plugins(self) -> List[PluginInterface]:
        """𐑜𐑧𐑑 𐑷𐑤 𐑤𐑴𐑛𐑦𐑛 𐑩𐑯𐑨𐑤𐑦𐑟𐑦𐑕 𐑐𐑤𐑳𐑜𐑦𐑯𐑟"""
        return [p for p in self.plugins.values() if isinstance(p, AnalysisPlugin)]
    
    def get_transformation_plugins(self) -> List[PluginInterface]:
        """𐑜𐑧𐑑 𐑷𐑤 𐑤𐑴𐑛𐑦𐑛 𐑑𐑮𐑨𐑯𐑕𐑓𐑼𐑥𐑱𐑖𐑩𐑯 𐑐𐑤𐑳𐑜𐑦𐑯𐑟"""
        return [p for p in self.plugins.values() if isinstance(p, TransformationPlugin)]
    
    def execute_analysis_phase(self, rewriter) -> Dict[str, Any]:
        """𐑮𐑳𐑯 𐑩𐑯𐑨𐑤𐑦𐑟𐑦𐑕 𐑓𐑱𐑟 𐑓𐑹 𐑷𐑤 𐑐𐑤𐑳𐑜𐑦𐑯𐑟"""
        results = {}
        analysis_plugins = self.get_analysis_plugins()
        
        # 𐑛𐑦𐑚𐑳𐑜: 𐑕𐑰 𐑦𐑓 𐑢𐑰 𐑣𐑨𐑝 𐑐𐑤𐑳𐑜𐑦𐑯𐑟
        if not analysis_plugins:
            print(f"[-] No analysis plugins found. Total plugins: {len(self.plugins)}")
            print(f"    Plugin types: {[type(p).__name__ for p in self.plugins.values()]}")
            return results
        
        for plugin in analysis_plugins:
            if plugin.enabled:
                try:
                    plugin_result = plugin.analyze(rewriter)
                    results[plugin.name] = plugin_result
                    if self.config.framework.verbose_logging:
                        print(f"[*] Analysis completed for plugin: {plugin.name}")
                except Exception as e:
                    print(f"[-] Analysis failed for plugin {plugin.name}: {e}")
                    import traceback
                    traceback.print_exc()
                    results[plugin.name] = {'error': str(e)}
        
        return results
    
    def execute_transformation_phase(self, rewriter, analysis_results: Dict[str, Any]) -> bool:
        """𐑮𐑳𐑯 𐑑𐑮𐑨𐑯𐑕𐑓𐑼𐑥𐑱𐑖𐑩𐑯 𐑓𐑱𐑟 𐑓𐑹 𐑷𐑤 𐑐𐑤𐑳𐑜𐑦𐑯𐑟"""
        transformation_plugins = self.get_transformation_plugins()
        all_success = True
        
        for plugin in transformation_plugins:
            if plugin.enabled:
                try:
                    plugin_analysis = analysis_results.get(plugin.name, {})
                    success = plugin.transform(rewriter, plugin_analysis)
                    if not success:
                        all_success = False
                    if self.config.framework.verbose_logging:
                        status = "completed" if success else "failed"
                        print(f"[*] Transformation {status} for plugin: {plugin.name}")
                except Exception as e:
                    print(f"[-] Transformation failed for plugin {plugin.name}: {e}")
                    all_success = False
        
        return all_success
    
    def list_plugins(self) -> List[Dict[str, Any]]:
        """𐑤𐑦𐑕𐑑 𐑷𐑤 𐑤𐑴𐑛𐑦𐑛 𐑐𐑤𐑳𐑜𐑦𐑯𐑟 𐑢𐑦𐑞 𐑞𐑺 𐑥𐑧𐑑𐑩𐑛𐑱𐑑𐑩"""
        return [plugin.get_metadata() for plugin in self.plugins.values()]
    
    def reload_plugin(self, plugin_name: str) -> bool:
        """𐑮𐑰𐑤𐑴𐑛 𐑩 𐑕𐑐𐑧𐑕𐑦𐑓𐑦𐑒 𐑐𐑤𐑳𐑜𐑦𐑯"""
        if plugin_name in self.plugins:
            # 𐑮𐑦𐑵 𐑞 𐑴𐑤𐑛 𐑐𐑤𐑳𐑜𐑦𐑯
            del self.plugins[plugin_name]
            if plugin_name in self.plugin_order:
                self.plugin_order.remove(plugin_name)
            if plugin_name in self.loaded_modules:
                del self.loaded_modules[plugin_name]
        
        # 𐑤𐑴𐑛 𐑞 𐑯𐑿 𐑐𐑤𐑳𐑜𐑦𐑯
        return self.load_plugin(plugin_name)
    
    def unload_plugin(self, plugin_name: str) -> bool:
        """𐑳𐑯𐑤𐑴𐑛 𐑩 𐑕𐑐𐑧𐑕𐑦𐑓𐑦𐑒 𐑐𐑤𐑳𐑜𐑦𐑯"""
        if plugin_name in self.plugins:
            del self.plugins[plugin_name]
            if plugin_name in self.plugin_order:
                self.plugin_order.remove(plugin_name)
            if plugin_name in self.loaded_modules:
                del self.loaded_modules[plugin_name]
            print(f"[+] Unloaded plugin: {plugin_name}")
            return True
        return False