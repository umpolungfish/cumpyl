#!/usr/bin/env python3
"""
Cumpyl Agent Workflow Examples
Demonstrates how to use the specialized agents for binary analysis and obfuscation.
"""
import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from framework import (
    AgentOrchestrator,
    get_workflow_runner,
    CumpylAgentIntegration,
    AgentPipelineBuilder
)
from agents.cumpyl_agents import (
    BinaryAnalysisAgent,
    ObfuscationPlannerAgent,
    BatchOrchestratorAgent,
    QualityAssuranceAgent,
    ReportingAgent,
    ThreatIntelAgent,
    create_cumpyl_agent
)


# Default configuration
DEFAULT_CONFIG = {
    "provider": "anthropic",
    "model": "claude-3-5-sonnet-20241022",
    "max_tokens": 4000,
    "temperature": 0.3
}


async def example_single_agent_analysis(binary_path: str):
    """
    Example 1: Single Agent Analysis
    Run a single BinaryAnalysisAgent on a target binary.
    """
    print("\n" + "="*60)
    print("Example 1: Single Agent Binary Analysis")
    print("="*60)

    # Create the agent
    agent = BinaryAnalysisAgent(DEFAULT_CONFIG)

    # Run analysis
    result = await agent.run(
        task=f"Analyze the binary at {binary_path}",
        context={"binary_path": binary_path}
    )

    print(f"\nStatus: {result['status']}")
    if result['status'] == 'success':
        print(f"Recommendations:\n{result.get('recommendations', 'N/A')[:500]}...")

    return result


async def example_pipeline_analysis(binary_path: str):
    """
    Example 2: Pipeline Mode
    Run agents sequentially: Analysis -> ThreatIntel -> Reporting
    """
    print("\n" + "="*60)
    print("Example 2: Pipeline Analysis (Sequential)")
    print("="*60)

    # Create orchestrator
    orchestrator = AgentOrchestrator({"max_concurrent_agents": 3})

    # Create and register agents
    analysis_agent = create_cumpyl_agent("analysis", DEFAULT_CONFIG)
    threat_agent = create_cumpyl_agent("threat_intel", DEFAULT_CONFIG)
    report_agent = create_cumpyl_agent("reporting", DEFAULT_CONFIG)

    orchestrator.register_agent("analyzer", analysis_agent)
    orchestrator.register_agent("threat_intel", threat_agent)
    orchestrator.register_agent("reporter", report_agent)

    # Run pipeline
    result = await orchestrator.run_pipeline(
        task=f"Complete analysis of {binary_path}",
        agent_ids=["analyzer", "threat_intel", "reporter"],
        initial_context={"binary_path": binary_path}
    )

    print(f"\nPipeline completed!")
    print(f"Stages processed: {len(result.get('pipeline_results', []))}")

    return result


async def example_swarm_analysis(binary_path: str):
    """
    Example 3: Swarm Mode
    Run multiple agents in parallel for different perspectives.
    """
    print("\n" + "="*60)
    print("Example 3: Swarm Analysis (Parallel)")
    print("="*60)

    # Create orchestrator
    orchestrator = AgentOrchestrator({"max_concurrent_agents": 3})

    # Create agents with slightly different configurations
    config_analysis = {**DEFAULT_CONFIG, "temperature": 0.3}
    config_threat = {**DEFAULT_CONFIG, "temperature": 0.2}

    analysis_agent = create_cumpyl_agent("analysis", config_analysis)
    threat_agent = create_cumpyl_agent("threat_intel", config_threat)

    orchestrator.register_agent("analyzer", analysis_agent)
    orchestrator.register_agent("threat_intel", threat_agent)

    # Run swarm (parallel execution)
    result = await orchestrator.run_swarm(
        task=f"Analyze {binary_path} from multiple perspectives",
        agent_ids=["analyzer", "threat_intel"],
        context={"binary_path": binary_path}
    )

    print(f"\nSwarm completed!")
    print(f"Agents completed: {len(result.get('swarm_results', []))}")

    return result


async def example_obfuscation_planning(binary_path: str):
    """
    Example 4: Obfuscation Planning Pipeline
    Plan obfuscation strategy with validation.
    """
    print("\n" + "="*60)
    print("Example 4: Obfuscation Planning Pipeline")
    print("="*60)

    orchestrator = AgentOrchestrator({"max_concurrent_agents": 3})

    # Create pipeline agents
    analysis_agent = create_cumpyl_agent("analysis", DEFAULT_CONFIG)
    planner_agent = create_cumpyl_agent("obfuscation_planner", DEFAULT_CONFIG)
    qa_agent = create_cumpyl_agent("qa", DEFAULT_CONFIG)

    orchestrator.register_agent("pre_analysis", analysis_agent)
    orchestrator.register_agent("planner", planner_agent)
    orchestrator.register_agent("qa", qa_agent)

    # Run pipeline
    result = await orchestrator.run_pipeline(
        task=f"Plan obfuscation for {binary_path}",
        agent_ids=["pre_analysis", "planner", "qa"],
        initial_context={
            "binary_path": binary_path,
            "dry_run": True
        }
    )

    print(f"\nObfuscation planning completed!")

    return result


async def example_batch_processing(directory: str, pattern: str = "*.exe"):
    """
    Example 5: Batch Processing
    Process multiple binaries in a directory.
    """
    print("\n" + "="*60)
    print("Example 5: Batch Processing")
    print("="*60)

    orchestrator = AgentOrchestrator({"max_concurrent_agents": 2})

    batch_config = {**DEFAULT_CONFIG, "max_concurrent": 5}
    batch_agent = create_cumpyl_agent("batch", batch_config)
    report_agent = create_cumpyl_agent("reporting", DEFAULT_CONFIG)

    orchestrator.register_agent("batch", batch_agent)
    orchestrator.register_agent("reporter", report_agent)

    result = await orchestrator.run_pipeline(
        task=f"Batch analyze all binaries in {directory}",
        agent_ids=["batch", "reporter"],
        initial_context={
            "directory": directory,
            "pattern": pattern,
            "recursive": False
        }
    )

    print(f"\nBatch processing completed!")

    return result


async def example_workflow_runner(binary_path: str):
    """
    Example 6: Using the Workflow Runner
    High-level convenience interface for common workflows.
    """
    print("\n" + "="*60)
    print("Example 6: Using Workflow Runner")
    print("="*60)

    # Get a configured workflow runner
    runner = get_workflow_runner(DEFAULT_CONFIG)

    # Run analysis workflow
    result = await runner.run_analysis_workflow(binary_path)

    print(f"\nWorkflow completed!")
    print(f"History entries: {len(runner.get_history())}")

    return result


async def example_custom_pipeline(binary_path: str):
    """
    Example 7: Custom Pipeline with Pipeline Builder
    Build a custom pipeline configuration.
    """
    print("\n" + "="*60)
    print("Example 7: Custom Pipeline")
    print("="*60)

    # Use pipeline builder
    builder = AgentPipelineBuilder(DEFAULT_CONFIG)

    # Get analysis pipeline configuration
    pipeline_spec = builder.build_analysis_pipeline()

    print("Pipeline specification:")
    for stage in pipeline_spec:
        print(f"  - {stage['name']}: {stage['agent_type']}")

    # Create orchestrator and run
    orchestrator = AgentOrchestrator({"max_concurrent_agents": 3})

    for spec in pipeline_spec:
        agent = create_cumpyl_agent(spec["agent_type"], spec["config"])
        orchestrator.register_agent(spec["name"], agent)

    result = await orchestrator.run_pipeline(
        task=f"Custom pipeline analysis of {binary_path}",
        agent_ids=[spec["name"] for spec in pipeline_spec],
        initial_context={"binary_path": binary_path}
    )

    return result


async def example_qa_validation(original_path: str, modified_path: str):
    """
    Example 8: QA Validation
    Validate a modified binary against the original.
    """
    print("\n" + "="*60)
    print("Example 8: QA Validation (Binary Comparison)")
    print("="*60)

    qa_agent = create_cumpyl_agent("qa", DEFAULT_CONFIG)

    result = await qa_agent.run(
        task="Validate modified binary",
        context={
            "original_path": original_path,
            "modified_path": modified_path
        }
    )

    print(f"\nValidation passed: {result.get('validation_passed', False)}")

    return result


def print_usage():
    """Print usage instructions."""
    print("""
Cumpyl Agent Workflow Examples
==============================

Usage:
    python cumpyl_workflows.py <example_number> [binary_path] [additional_args]

Examples:
    1. Single agent analysis:
       python cumpyl_workflows.py 1 /path/to/binary.exe

    2. Pipeline analysis (sequential):
       python cumpyl_workflows.py 2 /path/to/binary.exe

    3. Swarm analysis (parallel):
       python cumpyl_workflows.py 3 /path/to/binary.exe

    4. Obfuscation planning:
       python cumpyl_workflows.py 4 /path/to/binary.exe

    5. Batch processing:
       python cumpyl_workflows.py 5 /path/to/directory "*.exe"

    6. Workflow runner (high-level):
       python cumpyl_workflows.py 6 /path/to/binary.exe

    7. Custom pipeline:
       python cumpyl_workflows.py 7 /path/to/binary.exe

    8. QA validation:
       python cumpyl_workflows.py 8 /path/to/original.exe /path/to/modified.exe

Environment Variables:
    ANTHROPIC_API_KEY: Required for Anthropic provider
    GOOGLE_API_KEY: Optional, for Google Gemini
    DEEPSEEK_API_KEY: Optional, for DeepSeek
    """)


async def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print_usage()
        return

    example_num = sys.argv[1]

    if example_num == "1":
        if len(sys.argv) < 3:
            print("Error: Binary path required")
            return
        await example_single_agent_analysis(sys.argv[2])

    elif example_num == "2":
        if len(sys.argv) < 3:
            print("Error: Binary path required")
            return
        await example_pipeline_analysis(sys.argv[2])

    elif example_num == "3":
        if len(sys.argv) < 3:
            print("Error: Binary path required")
            return
        await example_swarm_analysis(sys.argv[2])

    elif example_num == "4":
        if len(sys.argv) < 3:
            print("Error: Binary path required")
            return
        await example_obfuscation_planning(sys.argv[2])

    elif example_num == "5":
        if len(sys.argv) < 3:
            print("Error: Directory path required")
            return
        pattern = sys.argv[3] if len(sys.argv) > 3 else "*.exe"
        await example_batch_processing(sys.argv[2], pattern)

    elif example_num == "6":
        if len(sys.argv) < 3:
            print("Error: Binary path required")
            return
        await example_workflow_runner(sys.argv[2])

    elif example_num == "7":
        if len(sys.argv) < 3:
            print("Error: Binary path required")
            return
        await example_custom_pipeline(sys.argv[2])

    elif example_num == "8":
        if len(sys.argv) < 4:
            print("Error: Original and modified paths required")
            return
        await example_qa_validation(sys.argv[2], sys.argv[3])

    else:
        print(f"Unknown example: {example_num}")
        print_usage()


if __name__ == "__main__":
    asyncio.run(main())
