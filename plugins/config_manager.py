"""Centralized configuration manager for Cumpyl Framework plugins."""
from typing import Dict, Any, Optional
import os
import logging

logger = logging.getLogger(__name__)

class ConfigManager:
    """Standardized configuration manager for plugin configurations."""
    
    PLUGIN_DEFAULTS = {
        'packer': {
            'compression_level': 6,
            'encrypt_sections': True,
            'safe_mode': True,
            'dry_run': True,
            'skip_pointer_sections': True
        },
        'cgo_packer': {
            'compression_level': 6,
            'encrypt_sections': True,
            'obfuscate_symbols': True,
            'preserve_cgo_symbols': True
        },
        'go_binary_analyzer': {
            'allow_transform': False,
            'entropy_threshold': 7.8
        }
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the configuration manager with provided config or defaults."""
        self.config = config or {}
        self.validate()
    
    def validate(self):
        """Validate required configuration fields and set defaults."""
        required_fields = ['allow_transform', 'compression_level', 'key_path']
        for field in required_fields:
            if field not in self.config:
                self.config[field] = self.get_default(field)
        
        # Validate configuration values with proper type checking
        validators = {
            'allow_transform': lambda x: isinstance(x, bool),
            'compression_level': lambda x: isinstance(x, int) and 1 <= x <= 9,
            'entropy_threshold': lambda x: isinstance(x, (int, float)) and 0 <= x <= 8,
            'dry_run': lambda x: isinstance(x, bool),
            'skip_pointer_sections': lambda x: isinstance(x, bool),
        }
        
        for key, validator in validators.items():
            if key in self.config and not validator(self.config[key]):
                # For compression_level and entropy_threshold, raise ValueError for out-of-range values
                if key == 'compression_level':
                    if not isinstance(self.config[key], int):
                        raise ValueError(f"Compression level must be an integer, got {type(self.config[key])}")
                    if self.config[key] < 1:
                        raise ValueError(f"Compression level must be at least 1, got {self.config[key]}")
                    if self.config[key] > 9:
                        raise ValueError(f"Compression level must be at most 9, got {self.config[key]}")
                elif key == 'entropy_threshold':
                    if not isinstance(self.config[key], (int, float)):
                        raise ValueError(f"Entropy threshold must be a number, got {type(self.config[key])}")
                    if self.config[key] < 0:
                        raise ValueError(f"Entropy threshold must be at least 0, got {self.config[key]}")
                    if self.config[key] > 8:
                        raise ValueError(f"Entropy threshold must be at most 8, got {self.config[key]}")
                else:
                    default_val = self.get_default(key)
                    logger.warning(f"Invalid value for {key}: {self.config[key]}, using default: {default_val}")
                    self.config[key] = default_val
                    
        # Validate key_path if set
        if 'key_path' in self.config and self.config['key_path']:
            if not os.path.isfile(self.config['key_path']):
                raise ValueError(f"Key file does not exist: {self.config['key_path']}")
            if not os.access(self.config['key_path'], os.R_OK):
                raise ValueError(f"Key file is not readable: {self.config['key_path']}")
    
    def get_default(self, field: str) -> Any:
        """Get default value for a configuration field."""
        defaults = {
            'allow_transform': False,
            'compression_level': 6,
            'key_path': None,
            'entropy_threshold': 7.8,
            'dry_run': True,
            'skip_pointer_sections': True,
            'integrity_key': None,
            'pbkdf2_salt': None
        }
        return defaults.get(field, None)
    
    def get(self, key: str, default: Optional[Any] = None) -> Any:
        """Get a configuration value with optional default."""
        return self.config.get(key, default if default is not None else self.get_default(key))
    
    def update_from_env(self):
        """Update config from environment variables."""
        env_map = {
            'ALLOW_TRANSFORM': 'allow_transform',
            'COMPRESSION_LEVEL': 'compression_level',
            'KEY_PATH': 'key_path',
            'ENTROPY_THRESHOLD': 'entropy_threshold',
            'DRY_RUN': 'dry_run',
            'SKIP_POINTER_SECTIONS': 'skip_pointer_sections',
            'INTEGRITY_KEY': 'integrity_key',
            'PBKDF2_SALT': 'pbkdf2_salt'
        }
        for env_key, config_key in env_map.items():
            if env_key in os.environ:
                value = os.environ[env_key]
                # Convert string values to appropriate types
                if config_key in ['allow_transform', 'dry_run', 'skip_pointer_sections']:
                    self.config[config_key] = value.lower() in ['true', '1', 'yes', 'on']
                elif config_key in ['compression_level', 'entropy_threshold']:
                    try:
                        self.config[config_key] = float(value) if '.' in value else int(value)
                    except ValueError:
                        # Keep default if conversion fails
                        pass
                else:
                    self.config[config_key] = value
    
    def get_plugin_config(self, plugin_name: str) -> Dict[str, Any]:
        """Get configuration with plugin-specific defaults."""
        defaults = self.PLUGIN_DEFAULTS.get(plugin_name, {})
        config = self.config.copy()
        
        # Apply plugin defaults for missing keys
        for key, default_value in defaults.items():
            if key not in config:
                config[key] = default_value
        
        return config