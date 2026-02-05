"""
Cumpyl Integration Module
Connects AjintK agent framework with cumpyl's configuration and plugin systems.
"""
import os
import sys
import yaml
import json
import asyncio
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime

logger = logging.getLogger(__name__)

# Paths
AJINTK_ROOT = Path(__file__).parent.parent
CUMPYL_ROOT = AJINTK_ROOT.parent
CUMPYL_CONFIG = CUMPYL_ROOT / "cumpyl.yaml"


class CumpylConfig:
    """
    Manages cumpyl configuration for agent integration.
    """

    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path or CUMPYL_CONFIG
        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load cumpyl configuration."""
        if self.config_path.exists():
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f) or {}
        return {}

    def get_plugin_config(self, plugin_name: str) -> Dict[str, Any]:
        """Get configuration for a specific plugin."""
        plugins = self.config.get("plugins", {})
        return plugins.get(plugin_name, {})

    def get_agent_config(self, agent_name: str) -> Dict[str, Any]:
        """Get configuration for a specific agent."""
        agents = self.config.get("agents", {})
        return agents.get(agent_name, {})

    def get_enabled_plugins(self) -> List[str]:
        """Get list of enabled plugins."""
        plugins = self.config.get("plugins", {})
        return [
            name for name, settings in plugins.items()
            if isinstance(settings, dict) and settings.get("enabled", True)
        ]

    def get_safety_tiers(self) -> Dict[str, List[str]]:
        """Get section safety tier definitions."""
        return self.config.get("obfuscation", {}).get("section_tiers", {
            "ADVANCED": [".rdata", ".rodata"],
            "INTERMEDIATE": [".data", ".bss"],
            "BASIC": [".pdata", ".xdata"],
            "AVOID": [".text", ".idata", ".reloc"]
        })

    def get_encoding_methods(self) -> List[str]:
        """Get available encoding methods."""
        return self.config.get("encoding", {}).get("available_methods", [
            "base64", "xor", "rot13", "hex", "unicode", "reverse"
        ])


class AgentPipelineBuilder:
    """
    Builds and configures agent pipelines for common cumpyl workflows.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.cumpyl_config = CumpylConfig()

    def build_analysis_pipeline(self) -> List[Dict[str, Any]]:
        """
        Build a standard analysis pipeline.

        Pipeline: BinaryAnalysis -> ThreatIntel -> Reporting
        """
        return [
            {
                "agent_type": "analysis",
                "name": "binary_analysis",
                "config": {
                    "provider": self.config.get("provider", "anthropic"),
                    "model": self.config.get("model", "claude-3-5-sonnet-20241022"),
                    "max_tokens": 4000,
                    "temperature": 0.3
                }
            },
            {
                "agent_type": "threat_intel",
                "name": "threat_assessment",
                "config": {
                    "provider": self.config.get("provider", "anthropic"),
                    "model": self.config.get("model", "claude-3-5-sonnet-20241022"),
                    "max_tokens": 3000,
                    "temperature": 0.2
                }
            },
            {
                "agent_type": "reporting",
                "name": "final_report",
                "config": {
                    "provider": self.config.get("provider", "anthropic"),
                    "model": self.config.get("model", "claude-3-5-sonnet-20241022"),
                    "max_tokens": 4000,
                    "temperature": 0.2
                }
            }
        ]

    def build_obfuscation_pipeline(self) -> List[Dict[str, Any]]:
        """
        Build an obfuscation pipeline.

        Pipeline: BinaryAnalysis -> ObfuscationPlanner -> QA
        """
        return [
            {
                "agent_type": "analysis",
                "name": "pre_obfuscation_analysis",
                "config": {
                    "provider": self.config.get("provider", "anthropic"),
                    "model": self.config.get("model", "claude-3-5-sonnet-20241022"),
                    "max_tokens": 3000,
                    "temperature": 0.3
                }
            },
            {
                "agent_type": "obfuscation_planner",
                "name": "obfuscation_planning",
                "config": {
                    "provider": self.config.get("provider", "anthropic"),
                    "model": self.config.get("model", "claude-3-5-sonnet-20241022"),
                    "max_tokens": 4000,
                    "temperature": 0.2
                }
            },
            {
                "agent_type": "qa",
                "name": "post_obfuscation_qa",
                "config": {
                    "provider": self.config.get("provider", "anthropic"),
                    "model": self.config.get("model", "claude-3-5-sonnet-20241022"),
                    "max_tokens": 2000,
                    "temperature": 0.1
                }
            }
        ]

    def build_batch_pipeline(self) -> List[Dict[str, Any]]:
        """
        Build a batch processing pipeline.

        Pipeline: BatchOrchestrator -> Reporting
        """
        return [
            {
                "agent_type": "batch",
                "name": "batch_processing",
                "config": {
                    "provider": self.config.get("provider", "anthropic"),
                    "model": self.config.get("model", "claude-3-5-sonnet-20241022"),
                    "max_tokens": 3000,
                    "temperature": 0.3,
                    "max_concurrent": 5
                }
            },
            {
                "agent_type": "reporting",
                "name": "batch_report",
                "config": {
                    "provider": self.config.get("provider", "anthropic"),
                    "model": self.config.get("model", "claude-3-5-sonnet-20241022"),
                    "max_tokens": 4000,
                    "temperature": 0.2
                }
            }
        ]

    def build_swarm_config(self, task_type: str = "analysis") -> Dict[str, Any]:
        """
        Build configuration for swarm mode (parallel agents).

        Args:
            task_type: Type of analysis ("analysis", "threat", "qa")
        """
        base_config = {
            "provider": self.config.get("provider", "anthropic"),
            "model": self.config.get("model", "claude-3-5-sonnet-20241022"),
            "max_tokens": 3000,
            "temperature": 0.3
        }

        swarm_configs = {
            "analysis": {
                "agents": ["analysis", "threat_intel"],
                "max_concurrent": 2,
                "aggregate_results": True
            },
            "full": {
                "agents": ["analysis", "threat_intel", "qa"],
                "max_concurrent": 3,
                "aggregate_results": True
            }
        }

        return {
            "base_config": base_config,
            "swarm_config": swarm_configs.get(task_type, swarm_configs["analysis"])
        }


class CumpylAgentIntegration:
    """
    Main integration class that bridges AjintK agents with cumpyl.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.cumpyl_config = CumpylConfig()
        self.pipeline_builder = AgentPipelineBuilder(config)
        self._setup_logging()

    def _setup_logging(self):
        """Configure logging for agent integration."""
        log_level = self.config.get("log_level", "INFO")
        logging.basicConfig(
            level=getattr(logging, log_level),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

    def get_default_agent_config(self, agent_type: str) -> Dict[str, Any]:
        """Get default configuration for an agent type."""
        defaults = {
            "analysis": {
                "provider": "anthropic",
                "model": "claude-3-5-sonnet-20241022",
                "max_tokens": 4000,
                "temperature": 0.3
            },
            "obfuscation_planner": {
                "provider": "anthropic",
                "model": "claude-3-5-sonnet-20241022",
                "max_tokens": 4000,
                "temperature": 0.2
            },
            "batch": {
                "provider": "anthropic",
                "model": "claude-3-5-sonnet-20241022",
                "max_tokens": 3000,
                "temperature": 0.3,
                "max_concurrent": 5
            },
            "qa": {
                "provider": "anthropic",
                "model": "claude-3-5-sonnet-20241022",
                "max_tokens": 2000,
                "temperature": 0.1
            },
            "reporting": {
                "provider": "anthropic",
                "model": "claude-3-5-sonnet-20241022",
                "max_tokens": 4000,
                "temperature": 0.2
            },
            "threat_intel": {
                "provider": "anthropic",
                "model": "claude-3-5-sonnet-20241022",
                "max_tokens": 3000,
                "temperature": 0.2
            }
        }

        return defaults.get(agent_type, defaults["analysis"])

    def validate_binary_path(self, path: str) -> bool:
        """Validate that a binary path exists and is readable."""
        p = Path(path)
        return p.exists() and p.is_file()

    def get_supported_formats(self) -> List[str]:
        """Get supported binary formats."""
        return ["PE", "ELF", "Mach-O"]

    def get_available_pipelines(self) -> Dict[str, str]:
        """Get descriptions of available pipelines."""
        return {
            "analysis": "Full analysis pipeline: Binary Analysis -> Threat Intel -> Report",
            "obfuscation": "Obfuscation pipeline: Analysis -> Planning -> QA Validation",
            "batch": "Batch processing: Batch Orchestrator -> Summary Report"
        }


class WorkflowRunner:
    """
    Runs complete agent workflows.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.integration = CumpylAgentIntegration(config)
        self.results_history = []

    async def run_analysis_workflow(
        self,
        binary_path: str,
        report_output: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Run complete analysis workflow on a binary.

        Args:
            binary_path: Path to binary file
            report_output: Optional path for report output

        Returns:
            Workflow results with all agent outputs
        """
        from .orchestrator import AgentOrchestrator
        from ..agents.cumpyl_agents import create_cumpyl_agent

        if not self.integration.validate_binary_path(binary_path):
            return {"status": "error", "error": f"Invalid binary path: {binary_path}"}

        pipeline = self.integration.pipeline_builder.build_analysis_pipeline()

        orchestrator = AgentOrchestrator({
            "max_concurrent_agents": 3
        })

        # Register agents
        for agent_spec in pipeline:
            agent = create_cumpyl_agent(agent_spec["agent_type"], agent_spec["config"])
            orchestrator.register_agent(agent_spec["name"], agent)

        # Run pipeline
        agent_ids = [spec["name"] for spec in pipeline]
        results = await orchestrator.run_pipeline(
            task=f"Analyze binary: {binary_path}",
            agent_ids=agent_ids,
            initial_context={"binary_path": binary_path}
        )

        # Save to history
        self.results_history.append({
            "workflow": "analysis",
            "binary": binary_path,
            "results": results,
            "timestamp": datetime.now().isoformat()
        })

        return results

    async def run_obfuscation_workflow(
        self,
        binary_path: str,
        output_path: Optional[str] = None,
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """
        Run obfuscation planning workflow.

        Args:
            binary_path: Path to binary file
            output_path: Optional path for obfuscated output
            dry_run: If True, only plan without executing

        Returns:
            Workflow results with obfuscation plan
        """
        from .orchestrator import AgentOrchestrator
        from ..agents.cumpyl_agents import create_cumpyl_agent

        if not self.integration.validate_binary_path(binary_path):
            return {"status": "error", "error": f"Invalid binary path: {binary_path}"}

        pipeline = self.integration.pipeline_builder.build_obfuscation_pipeline()

        orchestrator = AgentOrchestrator({
            "max_concurrent_agents": 3
        })

        # Register agents
        for agent_spec in pipeline:
            agent = create_cumpyl_agent(agent_spec["agent_type"], agent_spec["config"])
            orchestrator.register_agent(agent_spec["name"], agent)

        # Run pipeline
        agent_ids = [spec["name"] for spec in pipeline]
        results = await orchestrator.run_pipeline(
            task=f"Plan obfuscation for: {binary_path}",
            agent_ids=agent_ids,
            initial_context={
                "binary_path": binary_path,
                "output_path": output_path,
                "dry_run": dry_run
            }
        )

        self.results_history.append({
            "workflow": "obfuscation",
            "binary": binary_path,
            "results": results,
            "timestamp": datetime.now().isoformat()
        })

        return results

    async def run_batch_workflow(
        self,
        directory: str,
        pattern: str = "*.exe",
        recursive: bool = False,
        output_dir: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Run batch processing workflow.

        Args:
            directory: Directory containing binaries
            pattern: File pattern to match
            recursive: Search subdirectories
            output_dir: Directory for output reports

        Returns:
            Batch processing results
        """
        from .orchestrator import AgentOrchestrator
        from ..agents.cumpyl_agents import create_cumpyl_agent

        if not Path(directory).is_dir():
            return {"status": "error", "error": f"Invalid directory: {directory}"}

        pipeline = self.integration.pipeline_builder.build_batch_pipeline()

        orchestrator = AgentOrchestrator({
            "max_concurrent_agents": 2
        })

        for agent_spec in pipeline:
            agent = create_cumpyl_agent(agent_spec["agent_type"], agent_spec["config"])
            orchestrator.register_agent(agent_spec["name"], agent)

        agent_ids = [spec["name"] for spec in pipeline]
        results = await orchestrator.run_pipeline(
            task=f"Batch analyze directory: {directory}",
            agent_ids=agent_ids,
            initial_context={
                "directory": directory,
                "pattern": pattern,
                "recursive": recursive,
                "output_dir": output_dir
            }
        )

        self.results_history.append({
            "workflow": "batch",
            "directory": directory,
            "results": results,
            "timestamp": datetime.now().isoformat()
        })

        return results

    def get_history(self) -> List[Dict[str, Any]]:
        """Get workflow execution history."""
        return self.results_history


# Convenience functions
def get_integration(config: Optional[Dict[str, Any]] = None) -> CumpylAgentIntegration:
    """Get a configured integration instance."""
    return CumpylAgentIntegration(config)


def get_workflow_runner(config: Optional[Dict[str, Any]] = None) -> WorkflowRunner:
    """Get a configured workflow runner."""
    return WorkflowRunner(config)


__all__ = [
    "CumpylConfig",
    "AgentPipelineBuilder",
    "CumpylAgentIntegration",
    "WorkflowRunner",
    "get_integration",
    "get_workflow_runner",
]
