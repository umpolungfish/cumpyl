import yaml
import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field


@dataclass
class FrameworkConfig:
    """𐑓𐑮𐑱𐑥𐑢𐑻𐑒 𐑒𐑩𐑮 𐑒𐑪𐑯𐑓𐑦𐑜𐑘𐑼𐑱𐑖𐑩𐑯 𐑕𐑧𐑑𐑦𐑙𐑟"""
    version: str = "0.3.0"
    debug_mode: bool = False
    verbose_logging: bool = False
    max_file_size_mb: int = 100
    temp_directory: str = "/tmp/cumpyl"


@dataclass
class PluginConfig:
    """𐑐𐑤𐑳𐑜𐑦𐑯 𐑒𐑪𐑯𐑓𐑦𐑜𐑘𐑼𐑱𐑖𐑩𐑯 𐑕𐑧𐑑𐑦𐑙𐑟"""
    enabled: bool = True
    auto_discovery: bool = True
    plugin_directory: str = "plugins"
    load_order: List[str] = field(default_factory=lambda: ["encoding", "entropy_analysis", "string_extraction"])
    
    # 𐑦𐑯𐑛𐑦𐑝𐑦𐑛𐑘𐑫𐑩𐑤 𐑐𐑤𐑳𐑜𐑦𐑯 𐑕𐑧𐑑𐑦𐑙𐑟
    encoding: Dict[str, Any] = field(default_factory=lambda: {
        "default_encoding": "base64",
        "compression_level": 6,
        "max_encode_size_mb": 10
    })
    
    entropy_analysis: Dict[str, Any] = field(default_factory=lambda: {
        "block_size": 256,
        "threshold_high": 7.5,
        "threshold_low": 1.0
    })
    
    string_extraction: Dict[str, Any] = field(default_factory=lambda: {
        "min_string_length": 4,
        "max_string_length": 200,
        "include_unicode": True,
        "extract_patterns": True
    })


@dataclass
class SecurityConfig:
    """𐑕𐑦𐑒𐑘𐑫𐑼𐑦𐑑𐑦 𐑒𐑪𐑯𐑓𐑦𐑜𐑘𐑼𐑱𐑖𐑩𐑯 𐑕𐑧𐑑𐑦𐑙𐑟"""
    sandbox_mode: bool = False
    max_modifications_per_session: int = 100
    verify_checksums: bool = True
    log_all_modifications: bool = True


@dataclass
class PerformanceConfig:
    """𐑐𐑼𐑓𐑹𐑥𐑩𐑯𐑕 𐑒𐑪𐑯𐑓𐑦𐑜𐑘𐑼𐑱𐑖𐑩𐑯 𐑕𐑧𐑑𐑦𐑙𐑟"""
    enable_parallel_processing: bool = True
    max_worker_threads: int = 4
    cache_analysis_results: bool = True
    cache_expiry_hours: int = 24
    memory_limit_mb: int = 512


@dataclass  
class OutputConfig:
    """𐑬𐑑𐑐𐑫𐑑 𐑯 𐑮𐑦𐑐𐑹𐑑 𐑒𐑪𐑯𐑓𐑦𐑜𐑘𐑼𐑱𐑖𐑩𐑯 𐑕𐑧𐑑𐑦𐑙𐑟"""
    default_format: str = "yaml"
    available_formats: List[str] = field(default_factory=lambda: ["json", "xml", "yaml", "html"])
    create_backups: bool = True
    backup_directory: str = "backups"
    
    # 𐑮𐑦𐑐𐑹𐑑 𐑕𐑧𐑑𐑦𐑙𐑟
    include_metadata: bool = True
    include_analysis_time: bool = True
    include_plugin_versions: bool = True
    compress_large_reports: bool = True
    
    # 𐑓𐑲𐑤 𐑕𐑐𐑤𐑦𐑑𐑦𐑙 𐑕𐑧𐑑𐑦𐑙𐑟
    split_large_reports: bool = True
    max_report_size_mb: int = 50
    files_per_chunk: int = 10


class ConfigManager:
    """𐑥𐑨𐑯𐑦𐑡 𐑒𐑪𐑯𐑓𐑦𐑜𐑘𐑼𐑱𐑖𐑩𐑯 𐑓𐑲𐑤𐑟 𐑯 𐑕𐑧𐑑𐑦𐑙𐑟"""
    
    def __init__(self, config_path: Optional[str] = None):
        """𐑦𐑯𐑦𐑖𐑩𐑤𐑲𐑟 𐑞 𐑒𐑪𐑯𐑓𐑦𐑜 𐑥𐑨𐑯𐑦𐑡𐑼"""
        self.config_path = config_path or self._find_config_file()
        self.config_data: Dict[str, Any] = {}
        self.framework: FrameworkConfig = FrameworkConfig()
        self.plugins: PluginConfig = PluginConfig()
        self.security: SecurityConfig = SecurityConfig()
        self.performance: PerformanceConfig = PerformanceConfig()
        self.output: OutputConfig = OutputConfig()
        
        self.load_config()
    
    def _find_config_file(self) -> str:
        """𐑓𐑲𐑯𐑛 𐑞 𐑒𐑪𐑯𐑓𐑦𐑜 𐑓𐑲𐑤 𐑦𐑯 𐑞 𐑒𐑻𐑧𐑯𐑑 𐑛𐑲𐑮𐑧𐑒𐑑𐑼𐑦 𐑹 𐑐𐑸𐑧𐑯𐑑 𐑛𐑲𐑮𐑧𐑒𐑑𐑼𐑦𐑟"""
        possible_paths = [
            "cumpyl.yaml",
            "cumpyl.yml", 
            "../cumpyl.yaml",
            "../cumpyl.yml",
            os.path.expanduser("~/.cumpyl/cumpyl.yaml"),
            "/etc/cumpyl/cumpyl.yaml"
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
        
        # 𐑦𐑓 𐑯𐑴 𐑒𐑪𐑯𐑓𐑦𐑜 𐑓𐑲𐑤 𐑓𐑬𐑯𐑛, 𐑿𐑟 𐑛𐑦𐑓𐑷𐑤𐑑 𐑦𐑯 𐑞 𐑓𐑮𐑱𐑥𐑢𐑻𐑒 𐑮𐑵𐑑
        framework_root = Path(__file__).parent.parent
        default_config = framework_root / "cumpyl.yaml"
        return str(default_config)
    
    def load_config(self) -> bool:
        """𐑤𐑴𐑛 𐑒𐑪𐑯𐑓𐑦𐑜𐑘𐑼𐑱𐑖𐑩𐑯 𐑓𐑮𐑪𐑥 YAML 𐑓𐑲𐑤"""
        try:
            if not os.path.exists(self.config_path):
                print(f"[!] Configuration file not found: {self.config_path}")
                print("[*] Using default configuration values")
                return True
            
            with open(self.config_path, 'r', encoding='utf-8') as f:
                self.config_data = yaml.safe_load(f) or {}
            
            # 𐑤𐑴𐑛 𐑦𐑯𐑛𐑦𐑝𐑦𐑛𐑘𐑫𐑩𐑤 𐑒𐑪𐑯𐑓𐑦𐑜 𐑕𐑧𐑒𐑖𐑩𐑯𐑟
            self._load_framework_config()
            self._load_plugin_config()
            self._load_security_config()
            self._load_performance_config()
            self._load_output_config()
            
            return True
            
        except yaml.YAMLError as e:
            print(f"[-] Error parsing YAML configuration: {e}")
            return False
        except Exception as e:
            print(f"[-] Error loading configuration: {e}")
            return False
    
    def _load_framework_config(self):
        """𐑤𐑴𐑛 𐑓𐑮𐑱𐑥𐑢𐑻𐑒 𐑒𐑪𐑯𐑓𐑦𐑜𐑘𐑼𐑱𐑖𐑩𐑯"""
        framework_data = self.config_data.get('framework', {})
        self.framework = FrameworkConfig(
            version=framework_data.get('version', self.framework.version),
            debug_mode=framework_data.get('debug_mode', self.framework.debug_mode),
            verbose_logging=framework_data.get('verbose_logging', self.framework.verbose_logging),
            max_file_size_mb=framework_data.get('max_file_size_mb', self.framework.max_file_size_mb),
            temp_directory=framework_data.get('temp_directory', self.framework.temp_directory)
        )
    
    def _load_plugin_config(self):
        """𐑤𐑴𐑛 𐑐𐑤𐑳𐑜𐑦𐑯 𐑒𐑪𐑯𐑓𐑦𐑜𐑘𐑼𐑱𐑖𐑩𐑯"""
        plugin_data = self.config_data.get('plugins', {})
        self.plugins = PluginConfig(
            enabled=plugin_data.get('enabled', self.plugins.enabled),
            auto_discovery=plugin_data.get('auto_discovery', self.plugins.auto_discovery),
            plugin_directory=plugin_data.get('plugin_directory', self.plugins.plugin_directory),
            load_order=plugin_data.get('load_order', self.plugins.load_order),
            encoding=plugin_data.get('encoding', self.plugins.encoding),
            entropy_analysis=plugin_data.get('entropy_analysis', self.plugins.entropy_analysis),
            string_extraction=plugin_data.get('string_extraction', self.plugins.string_extraction)
        )
    
    def _load_security_config(self):
        """𐑤𐑴𐑛 𐑕𐑦𐑒𐑘𐑫𐑼𐑦𐑑𐑦 𐑒𐑪𐑯𐑓𐑦𐑜𐑘𐑼𐑱𐑖𐑩𐑯"""
        security_data = self.config_data.get('security', {})
        self.security = SecurityConfig(
            sandbox_mode=security_data.get('sandbox_mode', self.security.sandbox_mode),
            max_modifications_per_session=security_data.get('max_modifications_per_session', self.security.max_modifications_per_session),
            verify_checksums=security_data.get('verify_checksums', self.security.verify_checksums),
            log_all_modifications=security_data.get('log_all_modifications', self.security.log_all_modifications)
        )
    
    def _load_performance_config(self):
        """𐑤𐑴𐑛 𐑐𐑼𐑓𐑹𐑥𐑩𐑯𐑕 𐑒𐑪𐑯𐑓𐑦𐑜𐑘𐑼𐑱𐑖𐑩𐑯"""
        performance_data = self.config_data.get('performance', {})
        self.performance = PerformanceConfig(
            enable_parallel_processing=performance_data.get('enable_parallel_processing', self.performance.enable_parallel_processing),
            max_worker_threads=performance_data.get('max_worker_threads', self.performance.max_worker_threads),
            cache_analysis_results=performance_data.get('cache_analysis_results', self.performance.cache_analysis_results),
            cache_expiry_hours=performance_data.get('cache_expiry_hours', self.performance.cache_expiry_hours),
            memory_limit_mb=performance_data.get('memory_limit_mb', self.performance.memory_limit_mb)
        )
    
    def _load_output_config(self):
        """𐑤𐑴𐑛 𐑬𐑑𐑐𐑫𐑑 𐑒𐑪𐑯𐑓𐑦𐑜𐑘𐑼𐑱𐑖𐑩𐑯"""
        output_data = self.config_data.get('output', {})
        reports_data = output_data.get('reports', {})
        
        self.output = OutputConfig(
            default_format=output_data.get('default_format', self.output.default_format),
            available_formats=output_data.get('available_formats', self.output.available_formats),
            create_backups=output_data.get('create_backups', self.output.create_backups),
            backup_directory=output_data.get('backup_directory', self.output.backup_directory),
            include_metadata=reports_data.get('include_metadata', self.output.include_metadata),
            include_analysis_time=reports_data.get('include_analysis_time', self.output.include_analysis_time),
            include_plugin_versions=reports_data.get('include_plugin_versions', self.output.include_plugin_versions),
            compress_large_reports=reports_data.get('compress_large_reports', self.output.compress_large_reports),
            split_large_reports=reports_data.get('split_large_reports', self.output.split_large_reports),
            max_report_size_mb=reports_data.get('max_report_size_mb', self.output.max_report_size_mb),
            files_per_chunk=reports_data.get('files_per_chunk', self.output.files_per_chunk)
        )
    
    def get_plugin_config(self, plugin_name: str) -> Dict[str, Any]:
        """𐑜𐑧𐑑 𐑒𐑪𐑯𐑓𐑦𐑜𐑘𐑼𐑱𐑖𐑩𐑯 𐑓𐑹 𐑩 𐑕𐑐𐑧𐑕𐑦𐑓𐑦𐑒 𐑐𐑤𐑳𐑜𐑦𐑯"""
        return getattr(self.plugins, plugin_name, {})
    
    def get_profile_config(self, profile_name: str) -> Dict[str, Any]:
        """𐑜𐑧𐑑 𐑒𐑪𐑯𐑓𐑦𐑜𐑘𐑼𐑱𐑖𐑩𐑯 𐑓𐑹 𐑩 𐑕𐑐𐑧𐑕𐑦𐑓𐑦𐑒 𐑐𐑮𐑴𐑓𐑲𐑤"""
        profiles = self.config_data.get('profiles', {})
        return profiles.get(profile_name, {})
    
    def get_section_config(self, section_name: str) -> Any:
        """𐑜𐑧𐑑 𐑞 𐑝𐑨𐑤𐑿 𐑝 𐑩 𐑕𐑐𐑧𐑕𐑦𐑓𐑦𐑒 𐑒𐑪𐑯𐑓𐑦𐑜 𐑕𐑧𐑒𐑖𐑩𐑯"""
        return self.config_data.get(section_name, {})
    
    def get_encoding_config(self) -> Dict[str, Any]:
        """𐑜𐑧𐑑 𐑦𐑯𐑒𐑴𐑛𐑦𐑙 𐑒𐑪𐑯𐑓𐑦𐑜𐑘𐑼𐑱𐑖𐑩𐑯"""
        return self.config_data.get('encoding', {})
    
    def get_output_config(self) -> Dict[str, Any]:
        """𐑜𐑧𐑑 𐑬𐑑𐑐𐑫𐑑 𐑒𐑪𐑯𐑓𐑦𐑜𐑘𐑼𐑱𐑖𐑩𐑯"""
        return self.config_data.get('output', {})
    
    def save_config(self, output_path: Optional[str] = None) -> bool:
        """𐑕𐑱𐑝 𐑞 𐑒𐑻𐑧𐑯𐑑 𐑒𐑪𐑯𐑓𐑦𐑜𐑘𐑼𐑱𐑖𐑩𐑯 𐑑 𐑩 YAML 𐑓𐑲𐑤"""
        try:
            output_file = output_path or self.config_path
            
            # 𐑮𐑦𐑚𐑦𐑤𐑛 𐑒𐑪𐑯𐑓𐑦𐑜 𐑛𐑱𐑑𐑩 𐑓𐑮𐑪𐑥 𐑒𐑻𐑧𐑯𐑑 𐑪𐑚𐑡𐑧𐑒𐑑 𐑕𐑑𐑱𐑑
            updated_config = {
                'framework': {
                    'version': self.framework.version,
                    'debug_mode': self.framework.debug_mode,
                    'verbose_logging': self.framework.verbose_logging,
                    'max_file_size_mb': self.framework.max_file_size_mb,
                    'temp_directory': self.framework.temp_directory
                },
                'plugins': {
                    'enabled': self.plugins.enabled,
                    'auto_discovery': self.plugins.auto_discovery,
                    'plugin_directory': self.plugins.plugin_directory,
                    'load_order': self.plugins.load_order,
                    'encoding': self.plugins.encoding,
                    'entropy_analysis': self.plugins.entropy_analysis,
                    'string_extraction': self.plugins.string_extraction
                },
                'security': {
                    'sandbox_mode': self.security.sandbox_mode,
                    'max_modifications_per_session': self.security.max_modifications_per_session,
                    'verify_checksums': self.security.verify_checksums,
                    'log_all_modifications': self.security.log_all_modifications
                },
                'performance': {
                    'enable_parallel_processing': self.performance.enable_parallel_processing,
                    'max_worker_threads': self.performance.max_worker_threads,
                    'cache_analysis_results': self.performance.cache_analysis_results,
                    'cache_expiry_hours': self.performance.cache_expiry_hours,
                    'memory_limit_mb': self.performance.memory_limit_mb
                }
            }
            
            # 𐑥𐑻𐑡 𐑢𐑦𐑞 𐑧𐑒𐑟𐑦𐑕𐑑𐑦𐑙 𐑒𐑪𐑯𐑓𐑦𐑜 𐑛𐑱𐑑𐑩
            self.config_data.update(updated_config)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                yaml.dump(self.config_data, f, default_flow_style=False, allow_unicode=True)
            
            return True
            
        except Exception as e:
            print(f"[-] Error saving configuration: {e}")
            return False
    
    def validate_config(self) -> List[str]:
        """𐑝𐑨𐑤𐑦𐑛𐑱𐑑 𐑞 𐑒𐑻𐑧𐑯𐑑 𐑒𐑪𐑯𐑓𐑦𐑜𐑘𐑼𐑱𐑖𐑩𐑯 𐑯 𐑮𐑦𐑑𐑻𐑯 𐑩 𐑤𐑦𐑕𐑑 𐑝 𐑦𐑖𐑿𐑟"""
        issues = []
        
        # 𐑝𐑨𐑤𐑦𐑛𐑱𐑑 𐑓𐑮𐑱𐑥𐑢𐑻𐑒 𐑕𐑧𐑑𐑦𐑙𐑟
        if self.framework.max_file_size_mb <= 0:
            issues.append("Framework max_file_size_mb must be positive")
        
        if not os.path.exists(self.framework.temp_directory):
            try:
                os.makedirs(self.framework.temp_directory, exist_ok=True)
            except Exception:
                issues.append(f"Cannot create temp directory: {self.framework.temp_directory}")
        
        # 𐑝𐑨𐑤𐑦𐑛𐑱𐑑 𐑐𐑤𐑳𐑜𐑦𐑯 𐑕𐑧𐑑𐑦𐑙𐑟
        if self.plugins.enabled and not os.path.exists(self.plugins.plugin_directory):
            issues.append(f"Plugin directory does not exist: {self.plugins.plugin_directory}")
        
        # 𐑝𐑨𐑤𐑦𐑛𐑱𐑑 𐑐𐑼𐑓𐑹𐑥𐑩𐑯𐑕 𐑕𐑧𐑑𐑦𐑙𐑟
        if self.performance.max_worker_threads <= 0:
            issues.append("Performance max_worker_threads must be positive")
        
        if self.performance.memory_limit_mb <= 0:
            issues.append("Performance memory_limit_mb must be positive")
        
        return issues


# 𐑜𐑤𐑴𐑚𐑩𐑤 𐑒𐑪𐑯𐑓𐑦𐑜 𐑦𐑯𐑕𐑑𐑩𐑯𐑕
_global_config: Optional[ConfigManager] = None


def get_config() -> ConfigManager:
    """𐑜𐑧𐑑 𐑞 𐑜𐑤𐑴𐑚𐑩𐑤 𐑒𐑪𐑯𐑓𐑦𐑜 𐑦𐑯𐑕𐑑𐑩𐑯𐑕"""
    global _global_config
    if _global_config is None:
        _global_config = ConfigManager()
    return _global_config


def init_config(config_path: Optional[str] = None) -> ConfigManager:
    """𐑦𐑯𐑦𐑖𐑩𐑤𐑲𐑟 𐑞 𐑜𐑤𐑴𐑚𐑩𐑤 𐑒𐑪𐑯𐑓𐑦𐑜 𐑦𐑯𐑕𐑑𐑩𐑯𐑕"""
    global _global_config
    _global_config = ConfigManager(config_path)
    return _global_config