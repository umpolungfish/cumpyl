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

## Best Practices

1. **Keep plugins focused**: Each plugin should have a single, well-defined purpose
2. **Handle errors gracefully**: Use try/except blocks to handle potential errors
3. **Document your plugin**: Include clear documentation on what your plugin does
4. **Test thoroughly**: Write tests for your plugin functionality
5. **Follow naming conventions**: Use descriptive names for your plugins and functions