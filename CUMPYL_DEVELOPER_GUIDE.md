# Cumpyl Developer Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Development Setup](#development-setup)
3. [Plugin Architecture](#plugin-architecture)
4. [Creating Custom Plugins](#creating-custom-plugins)
5. [Plugin Types](#plugin-types)
6. [Plugin Registry](#plugin-registry)
7. [Core Framework Components](#core-framework-components)
8. [API Reference](#api-reference)
9. [Testing](#testing)
10. [Contributing](#contributing)

## Introduction

This guide is for developers who want to extend Cumpyl with custom plugins or contribute to the core framework. Cumpyl's flexible plugin architecture allows you to add new analysis capabilities, transformation methods, and other functionality.

## Development Setup

### Prerequisites

- Python 3.9 or higher
- Git
- Virtual environment tool (uv, conda, or venv)

### Setting Up Development Environment

```bash
git clone https://github.com/umpolungfish/cumpyl.git
cd cumpyl
pip install -e ".[dev,test]"
```

Or with uv (recommended):

```bash
uv sync --extra dev --extra test
source .venv/bin/activate
```

### Running Tests

```bash
pytest tests/
```

## Plugin Architecture

Cumpyl features a flexible plugin architecture that allows you to extend its functionality.

### Plugin Discovery

Plugins are automatically discovered in the `plugins/` directory. Each Python file in this directory is treated as a potential plugin.

### Plugin Loading

The PluginManager handles plugin loading and validation:
1. Discovers available plugins
2. Loads each plugin module
3. Instantiates plugin classes
4. Validates dependencies
5. Registers plugins with the system

### Plugin Lifecycle

1. **Discovery**: PluginManager scans the plugins directory
2. **Loading**: Plugin modules are imported and validated
3. **Registration**: Plugins are registered with the PluginRegistry
4. **Execution**: Plugins are executed during analysis/transform phases
5. **Cleanup**: Plugins are properly unloaded when no longer needed

## Creating Custom Plugins

To create a custom plugin, create a Python file in the `plugins/` directory:

```python
# plugins/my_custom_plugin.py
from cumpyl_package.plugin_manager import AnalysisPlugin
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)

class MyCustomPlugin(AnalysisPlugin):
    def __init__(self, config):
        super().__init__(config)
        self.name = "my_custom_plugin"
        self.version = "1.0.0"
        self.description = "Custom analysis plugin"
        self.author = "Your Name"
        self.dependencies = []
        
    def analyze(self, rewriter) -> Dict[str, Any]:
        """Perform analysis on the binary"""
        try:
            results = {
                "plugin_name": self.name,
                "version": self.version,
                "description": self.description,
                "analysis": {
                    "binary_size": len(rewriter.binary.content) if hasattr(rewriter.binary, 'content') else 0,
                    "sections_count": len(rewriter.binary.sections) if hasattr(rewriter.binary, 'sections') else 0,
                }
            }
            return results
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return {"error": str(e)}
    
    def transform(self, rewriter, analysis_result: Dict[str, Any]) -> bool:
        """Apply transformations to the binary"""
        # This is an analysis-only plugin, so we don't perform transformations
        return True

def get_plugin(config):
    """Factory function to get plugin instance"""
    return MyCustomPlugin(config)
```

### Plugin Interface Requirements

All plugins must implement the following:

1. **Constructor**: Accept a config parameter
2. **name**: Unique identifier for the plugin
3. **version**: Plugin version number
4. **description**: Brief description of the plugin
5. **author**: Plugin author
6. **dependencies**: List of plugin dependencies
7. **analyze()**: Method to perform analysis on the binary
8. **transform()**: Method to apply transformations to the binary
9. **get_plugin()**: Factory function that returns an instance of the plugin

### Plugin Configuration

Plugins can access configuration through the config parameter:

```python
def __init__(self, config):
    super().__init__(config)
    # Access plugin-specific configuration
    plugin_config = self.get_config()
    self.custom_setting = plugin_config.get('custom_setting', 'default_value')
```

## Plugin Types

Cumpyl supports two main plugin types:

### Analysis Plugins

Analysis plugins perform analysis on binaries without modifying them:

```python
from cumpyl_package.plugin_manager import AnalysisPlugin

class MyAnalysisPlugin(AnalysisPlugin):
    def analyze(self, rewriter) -> Dict[str, Any]:
        # Perform analysis
        return {"results": "analysis_data"}
    
    def transform(self, rewriter, analysis_result: Dict[str, Any]) -> bool:
        # Analysis plugins typically don't transform
        return True
```

### Transformation Plugins

Transformation plugins can modify binaries:

```python
from cumpyl_package.plugin_manager import TransformationPlugin

class MyTransformationPlugin(TransformationPlugin):
    def analyze(self, rewriter) -> Dict[str, Any]:
        # Prepare for transformation
        return {"prepared": True}
    
    def transform(self, rewriter, analysis_result: Dict[str, Any]) -> bool:
        # Apply transformations
        try:
            # Modify the binary
            return True
        except Exception as e:
            logger.error(f"Transformation failed: {e}")
            return False
```

## Plugin Registry

Cumpyl uses a centralized plugin registry for managing plugins:

### Registering Plugins

Plugins are automatically registered when loaded:

```python
# In plugin_registry.py
from .my_plugin import get_plugin as get_my_plugin

PluginRegistry.register('analysis', 'my_plugin', get_my_plugin)
```

### Accessing Plugins

Plugins can be accessed through the registry:

```python
from plugins.plugin_registry import PluginRegistry

plugin = PluginRegistry.get_plugin('analysis', 'my_plugin', config)
```

## Plugin Packer Menu

The plugin packer menu (`plugin_packer_menu.py`) provides a user-friendly interface for interacting with plugins. It allows users to:

1. Select analysis plugins for binary examination
2. Choose transformation plugins for binary modification
3. Configure plugin-specific options
4. View analysis results in a structured format

### Menu Architecture

The menu system dynamically discovers available plugins by scanning the `plugins/` directory. It categorizes plugins as either analysis or transformation types based on naming conventions and available factory functions.

### Extending the Menu

To make your plugin compatible with the menu system, implement the standard factory functions:

```python
# In your plugin file
def get_analysis_plugin(config):
    """Factory function for analysis plugin"""
    return MyAnalysisPlugin(config)

def get_transformation_plugin(config):
    """Factory function for transformation plugin"""
    return MyTransformationPlugin(config)

def get_plugins(config):
    """Factory function for both plugin types"""
    return {
        "analysis": get_analysis_plugin(config),
        "transformation": get_transformation_plugin(config)
    }
```

The menu will automatically detect and use these factory functions when loading your plugin.

### Plugin Menu Improvements

Recent improvements to the plugin packer menu include:
- Fixed binary saving functionality in transformation plugins
- Enhanced compatibility with Go and CGO packer plugins
- Improved error handling and user feedback
- Better configuration options for different plugin types
- Support for dry run mode to test transformations without modifying files
- Enhanced plugin loading and factory function detection

## Core Framework Components

### BinaryRewriter

The main class for binary analysis and manipulation:

```python
from cumpyl_package.cumpyl import BinaryRewriter

rewriter = BinaryRewriter("binary.exe", config)
if rewriter.load_binary():
    # Perform analysis
    analysis_results = rewriter.run_plugin_analysis()
    
    # Apply transformations
    rewriter.run_plugin_transformations(analysis_results)
    
    # Save modified binary
    rewriter.save_binary("modified.exe")
```

### ConfigManager

Handles configuration loading and validation:

```python
from cumpyl_package.config import ConfigManager

config = ConfigManager()
config.load_config("custom.yaml")
```

### PluginManager

Manages plugin discovery and execution:

```python
from cumpyl_package.plugin_manager import PluginManager

plugin_manager = PluginManager(config)
plugin_manager.load_all_plugins()
analysis_results = plugin_manager.execute_analysis_phase(rewriter)
```

## API Reference

### PluginInterface

Base class for all plugins:

#### Properties
- `name`: Unique identifier for the plugin
- `version`: Plugin version number
- `description`: Description of the plugin
- `author`: Plugin author
- `dependencies`: List of plugin dependencies

#### Methods
- `analyze(rewriter)`: Perform analysis on the binary
- `transform(rewriter, analysis_result)`: Apply transformations to the binary
- `get_config()`: Get plugin-specific configuration

### AnalysisPlugin

Base class for analysis-only plugins:

```python
class AnalysisPlugin(PluginInterface):
    def transform(self, rewriter, analysis_result: Dict[str, Any]) -> bool:
        # Analysis plugins typically don't transform
        return True
```

### TransformationPlugin

Base class for transformation plugins:

```python
class TransformationPlugin(PluginInterface):
    def analyze(self, rewriter) -> Dict[str, Any]:
        # Prepare for transformation
        return {}
```

## Testing

### Unit Tests

Write unit tests for your plugins:

```python
# tests/test_my_plugin.py
import pytest
from plugins.my_plugin import MyCustomPlugin

def test_plugin_analysis():
    plugin = MyCustomPlugin({})
    # Test analysis functionality
    assert plugin.name == "my_custom_plugin"
```

### Integration Tests

Test plugin integration with the framework:

```python
def test_plugin_integration():
    from cumpyl_package.plugin_manager import PluginManager
    from cumpyl_package.config import ConfigManager
    
    config = ConfigManager()
    plugin_manager = PluginManager(config)
    # Test plugin loading and execution
```

### Running Tests

```bash
# Run all tests
pytest tests/

# Run specific test file
pytest tests/test_my_plugin.py

# Run with coverage
pytest --cov=plugins tests/
```

## Contributing

We welcome contributions to Cumpyl!

### Getting Started

1. Fork the repository
2. Create a new branch for your feature or bug fix
3. Make your changes
4. Write tests for your changes
5. Ensure all tests pass
6. Submit a pull request

### Code Style

We use `black` for code formatting and `ruff` for linting:

```bash
# Format code
black .

# Lint code
ruff check .
```

### Documentation

Update documentation when adding new features:
- Update README.md for major features
- Add docstrings to new functions and classes
- Update CLI documentation if adding new commands

### Pull Request Process

1. Ensure your code follows the project's coding standards
2. Write clear, descriptive commit messages
3. Include tests for new functionality
4. Update documentation as needed
5. Submit a pull request with a clear description of changes