# Plugin Development

Cumpyl features a flexible plugin architecture that allows you to extend its functionality.

## Creating Custom Plugins

To create a custom plugin, create a Python file in the `plugins/` directory:

```python
# plugins/my_custom_plugin.py
from cumpyl_package.plugin_manager import PluginInterface
from typing import Dict, Any

class MyCustomPlugin(PluginInterface):
    @property
    def name(self) -> str:
        return "my_custom_plugin"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    def analyze(self, rewriter) -> Dict[str, Any]:
        results = {
            "plugin_name": self.name,
            "binary_size": len(rewriter.binary.content) if rewriter.binary else 0,
        }
        return results
    
    def transform(self, rewriter, analysis_result: Dict[str, Any]) -> bool:
        return True

def get_plugin():
    return MyCustomPlugin()
```

## Plugin Interface

All plugins must implement the `PluginInterface` which requires:

1. `name` property - A unique identifier for the plugin
2. `version` property - The plugin version
3. `analyze` method - Performs analysis on the binary
4. `transform` method - Applies transformations to the binary
5. `get_plugin` function - Returns an instance of the plugin

## Available Hooks

Plugins can hook into various stages of the analysis process:

- **Pre-analysis**: Before any analysis begins
- **Analysis**: During the main analysis phase
- **Post-analysis**: After analysis is complete
- **Pre-transformation**: Before applying transformations
- **Transformation**: During the transformation phase
- **Post-transformation**: After transformations are applied

## Plugin Configuration

Plugins can be configured through the `cumpyl.yaml` configuration file:

```yaml
plugins:
  enabled: true
  plugin_directory: "plugins"
  auto_discover: true
  my_custom_plugin:
    enabled: true
    custom_setting: "value"
```

## Windowbrick Plugin Example

For a comprehensive example of plugin development, see the Windowbrick plugin (`plugins/windowbrick_plugin.py`). This plugin demonstrates advanced obfuscation techniques with multiple factory functions and proper configuration handling:

```python
# plugins/windowbrick_plugin.py
from cumpyl_package.plugin_manager import AnalysisPlugin, TransformationPlugin
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)

class WindowbrickAnalysisPlugin(AnalysisPlugin):
    def __init__(self, config):
        super().__init__(config)
        self.name = "windowbrick_analysis"
        self.version = "1.0.0"
        self.description = "String obfuscation analysis using windowbrick techniques (XOR, rotation, substitution)"
        self.author = "Cumpyl Framework Team"
        self.dependencies = []

        # Initialize configuration
        plugin_config = self.get_config()
        self.rotation_amount = plugin_config.get('rotation_amount', 3)
        self.enable_anti_analysis = plugin_config.get('enable_anti_analysis', False)
        self.obfuscation_mode = plugin_config.get('obfuscation_mode', 'full')

    def analyze(self, rewriter) -> Dict[str, Any]:
        """Analyze binary for potential obfuscation opportunities"""
        results = {
            "plugin_name": self.name,
            "version": self.version,
            "description": self.description,
            "analysis": {
                "recommended_strings": [],
                "obfuscation_opportunities": []
            }
        }
        return results

class WindowbrickTransformationPlugin(TransformationPlugin):
    def __init__(self, config):
        super().__init__(config)
        self.name = "windowbrick_transform"
        self.version = "1.0.0"
        self.description = "String obfuscation transformation using windowbrick techniques"
        self.author = "Cumpyl Framework Team"
        self.dependencies = ["windowbrick_analysis"]

    def analyze(self, rewriter) -> Dict[str, Any]:
        return {"plugin_name": self.name}

    def transform(self, rewriter, analysis_result: Dict[str, Any]) -> bool:
        """Transform binary with string obfuscation"""
        return True

# Factory functions for plugin registry
def get_analysis_plugin(config):
    """Factory function to get analysis plugin instance"""
    return WindowbrickAnalysisPlugin(config)

def get_transformation_plugin(config):
    """Factory function to get transformation plugin instance"""
    return WindowbrickTransformationPlugin(config)
```

## Best Practices

1. **Keep plugins focused**: Each plugin should have a single, well-defined purpose
2. **Handle errors gracefully**: Use try/except blocks to handle potential errors
3. **Document your plugin**: Include clear documentation on what your plugin does
4. **Test thoroughly**: Write tests for your plugin functionality
5. **Follow naming conventions**: Use descriptive names for your plugins and functions
6. **Proper inheritance**: Use AnalysisPlugin for analysis-only, TransformationPlugin for modifications
7. **Factory functions**: Implement proper factory functions for plugin registration
8. **Configuration handling**: Use plugin-specific configuration with fallbacks
9. **Reversible operations**: For obfuscation plugins, ensure operations can be reversed
10. **CLI awareness**: Note that the main CLI runs all plugins via `--run-analysis` rather than individual plugins