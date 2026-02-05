"""
Claude Agent Framework with Multi-Provider LLM Support
A reusable framework for building multi-agent systems with multiple LLM providers.

Extended with Cumpyl integration for binary analysis and obfuscation agents.
"""

from .base_agent import BaseAgent, AgentStatus
from .orchestrator import AgentOrchestrator
from .tools import ToolDefinitions, ToolExecutor
from .memory import AgentMemory
from .communication import AgentCommunication, Message, MessageType
from .enhanced_llm_provider import (
    get_llm_provider,
    get_adaptive_provider,
    AnthropicProvider,
    GoogleProvider,
    DeepSeekProvider,
    QwenProvider,
    MistralProvider,
    ModelRouter
)

# Cumpyl-specific extensions
from .cumpyl_tools import CumpylToolDefinitions, CumpylToolExecutor
from .cumpyl_integration import (
    CumpylConfig,
    AgentPipelineBuilder,
    CumpylAgentIntegration,
    WorkflowRunner,
    get_integration,
    get_workflow_runner
)

__version__ = "2.1.0"

__all__ = [
    # Core framework
    "BaseAgent",
    "AgentStatus",
    "AgentOrchestrator",
    "ToolDefinitions",
    "ToolExecutor",
    "AgentMemory",
    "AgentCommunication",
    "Message",
    "MessageType",
    # LLM providers
    "get_llm_provider",
    "get_adaptive_provider",
    "AnthropicProvider",
    "GoogleProvider",
    "DeepSeekProvider",
    "QwenProvider",
    "MistralProvider",
    "ModelRouter",
    # Cumpyl integration
    "CumpylToolDefinitions",
    "CumpylToolExecutor",
    "CumpylConfig",
    "AgentPipelineBuilder",
    "CumpylAgentIntegration",
    "WorkflowRunner",
    "get_integration",
    "get_workflow_runner",
]
