"""Centralized plugin registration system."""
import logging
from typing import Dict, Any, Callable, Type

logger = logging.getLogger(__name__)

class PluginRegistry:
    """Central registry for all analysis and transformation plugins."""
    
    _registry = {
        'analysis': {},
        'transformation': {}
    }
    
    @classmethod
    def register(cls, plugin_type: str, name: str, factory: Callable):
        """Register a plugin factory."""
        if plugin_type not in cls._registry:
            raise ValueError(f"Invalid plugin type: {plugin_type}")
        cls._registry[plugin_type][name] = factory
        logger.info(f"Registered {plugin_type} plugin: {name}")
    
    @classmethod
    def get_plugin(cls, plugin_type: str, name: str, config: Dict[str, Any]):
        """Get a plugin instance by type and name."""
        if plugin_type not in cls._registry or name not in cls._registry[plugin_type]:
            raise ValueError(f"Plugin not found: {plugin_type}/{name}")
        return cls._registry[plugin_type][name](config)
    
    @classmethod
    def list_plugins(cls, plugin_type: str = None):
        """List all registered plugins."""
        if plugin_type:
            return list(cls._registry.get(plugin_type, {}).keys())
        return {pt: list(plugins.keys()) for pt, plugins in cls._registry.items()}

# Register all plugins in a central location
try:
    from plugins.packer_plugin import get_plugin as get_packer_plugin, get_transform_plugin as get_packer_transform_plugin
except ImportError:
    # If we can't import the plugins, don't register them
    get_packer_plugin = None
    get_packer_transform_plugin = None

if get_packer_plugin:
    PluginRegistry.register('analysis', 'packer', get_packer_plugin)
if get_packer_transform_plugin:
    PluginRegistry.register('transformation', 'packer_transform', get_packer_transform_plugin)