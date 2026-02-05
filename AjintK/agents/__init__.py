"""
Agent Implementations
Pre-built agents including example agents and specialized cumpyl agents.
"""

from .example_agent import ResearchAgent, AnalysisAgent

# Cumpyl specialized agents
from .cumpyl_agents import (
    BinaryAnalysisAgent,
    ObfuscationPlannerAgent,
    BatchOrchestratorAgent,
    QualityAssuranceAgent,
    ReportingAgent,
    ThreatIntelAgent,
    create_cumpyl_agent
)

__all__ = [
    # Example agents
    "ResearchAgent",
    "AnalysisAgent",
    # Cumpyl agents
    "BinaryAnalysisAgent",
    "ObfuscationPlannerAgent",
    "BatchOrchestratorAgent",
    "QualityAssuranceAgent",
    "ReportingAgent",
    "ThreatIntelAgent",
    "create_cumpyl_agent",
]
