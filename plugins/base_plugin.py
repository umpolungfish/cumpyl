"""Base class for all plugins with common functionality."""
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any
from plugins.config_manager import ConfigManager
from plugins.exceptions import PluginError, ConfigurationError

logger = logging.getLogger(__name__)

class BasePlugin(ABC):
    """Base class for all analysis and transformation plugins."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config_manager = ConfigManager(config)
        self.config_manager.update_from_env()
        self._validate_config()
        
    def _validate_config(self):
        """Validate plugin configuration."""
        required = self.get_required_config()
        for field in required:
            if field not in self.config_manager.config:
                raise ConfigurationError(f"Missing required config field: {field}")
    
    def get_required_config(self) -> list:
        """Return list of required configuration fields."""
        return []
    
    @abstractmethod
    def analyze(self, rewriter) -> Dict[str, Any]:
        """Perform analysis on the binary."""
        pass
    
    def get_config_value(self, key: str, default: Any = None) -> Any:
        """Get configuration value with proper type conversion."""
        return self.config_manager.get(key, default)