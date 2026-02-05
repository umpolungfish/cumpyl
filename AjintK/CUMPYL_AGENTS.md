# Cumpyl Agent Framework

Specialized autonomous agents for binary analysis, obfuscation planning, and transformation using the AjintK multi-agent framework.

## Overview

The Cumpyl Agent Framework extends AjintK to provide specialized agents for:
- **Binary Analysis**: Comprehensive PE/ELF/Mach-O analysis
- **Obfuscation Planning**: Intelligent obfuscation strategy generation
- **Batch Processing**: Large-scale binary processing orchestration
- **Quality Assurance**: Binary validation and comparison
- **Reporting**: Multi-format report generation
- **Threat Intelligence**: IOC extraction and threat assessment

## Architecture

```
AjintK Framework
├── framework/
│   ├── base_agent.py          # Base agent class
│   ├── orchestrator.py        # Agent coordination
│   ├── cumpyl_tools.py        # Cumpyl-specific tools     [NEW]
│   └── cumpyl_integration.py  # Framework integration     [NEW]
├── agents/
│   ├── example_agent.py       # Example agents
│   └── cumpyl_agents.py       # Specialized agents        [NEW]
└── examples/
    └── cumpyl_workflows.py    # Workflow examples         [NEW]
```

## Quick Start

### 1. Single Agent Analysis

```python
import asyncio
from agents.cumpyl_agents import BinaryAnalysisAgent

config = {
    "provider": "anthropic",
    "model": "claude-3-5-sonnet-20241022",
    "max_tokens": 4000,
    "temperature": 0.3
}

async def analyze():
    agent = BinaryAnalysisAgent(config)
    result = await agent.run(
        task="Analyze binary",
        context={"binary_path": "/path/to/binary.exe"}
    )
    print(result["recommendations"])

asyncio.run(analyze())
```

### 2. Pipeline Mode (Sequential)

```python
from framework import AgentOrchestrator
from agents.cumpyl_agents import create_cumpyl_agent

async def pipeline_analysis():
    orchestrator = AgentOrchestrator({"max_concurrent_agents": 3})

    # Register agents
    orchestrator.register_agent("analyzer", create_cumpyl_agent("analysis", config))
    orchestrator.register_agent("threat", create_cumpyl_agent("threat_intel", config))
    orchestrator.register_agent("reporter", create_cumpyl_agent("reporting", config))

    # Run pipeline
    result = await orchestrator.run_pipeline(
        task="Complete binary analysis",
        agent_ids=["analyzer", "threat", "reporter"],
        initial_context={"binary_path": "/path/to/binary.exe"}
    )
    return result
```

### 3. Swarm Mode (Parallel)

```python
async def swarm_analysis():
    orchestrator = AgentOrchestrator({"max_concurrent_agents": 3})

    orchestrator.register_agent("analyzer", create_cumpyl_agent("analysis", config))
    orchestrator.register_agent("threat", create_cumpyl_agent("threat_intel", config))

    # Run in parallel
    result = await orchestrator.run_swarm(
        task="Multi-perspective analysis",
        agent_ids=["analyzer", "threat"],
        context={"binary_path": "/path/to/binary.exe"}
    )
    return result
```

### 4. High-Level Workflow Runner

```python
from framework import get_workflow_runner

async def easy_analysis():
    runner = get_workflow_runner(config)
    result = await runner.run_analysis_workflow("/path/to/binary.exe")
    return result
```

## Specialized Agents

### BinaryAnalysisAgent

Comprehensive binary analysis with intelligent recommendations.

**Capabilities:**
- Multi-format binary detection (PE, ELF, Mach-O)
- Section entropy analysis
- String extraction and categorization
- Packer/protector detection
- Security risk assessment
- Obfuscation tier recommendations

**Tools:**
- `analyze_binary`: Perform comprehensive analysis
- `suggest_obfuscation`: Get obfuscation recommendations
- `extract_strings`: Extract readable strings
- `hex_view`: View binary content

**Usage:**
```python
agent = BinaryAnalysisAgent(config)
result = await agent.run(
    task="Analyze binary structure and strings",
    context={"binary_path": "/path/to/file.exe"}
)
```

### ObfuscationPlannerAgent

Creates comprehensive obfuscation strategies.

**Capabilities:**
- Section safety tier analysis
- Multi-method obfuscation planning
- Risk assessment for transformations
- Step-by-step plan generation
- Plugin chain optimization

**Safety Tiers:**
| Tier | Sections | Obfuscation Level |
|------|----------|-------------------|
| ADVANCED | .rdata, .rodata | Heavy obfuscation safe |
| INTERMEDIATE | .data, .bss | Moderate obfuscation |
| BASIC | .pdata, .xdata | Light obfuscation only |
| AVOID | .text, .idata, .reloc | Do not modify |

**Usage:**
```python
agent = ObfuscationPlannerAgent(config)
result = await agent.run(
    task="Plan obfuscation",
    context={
        "binary_path": "/path/to/file.exe",
        "analysis": previous_analysis_results
    }
)
```

### BatchOrchestratorAgent

Coordinates large-scale batch processing.

**Capabilities:**
- Multi-file batch processing
- Parallel task execution
- Progress tracking
- Failure recovery
- Result aggregation

**Usage:**
```python
agent = BatchOrchestratorAgent(config)
result = await agent.run(
    task="Batch analyze directory",
    context={
        "directory": "/path/to/binaries",
        "pattern": "*.exe",
        "recursive": True
    }
)
```

### QualityAssuranceAgent

Validates transformed binaries.

**Capabilities:**
- Binary structure validation
- Checksum verification
- Import/export table validation
- Section integrity checks
- Pre/post comparison

**Usage:**
```python
agent = QualityAssuranceAgent(config)
result = await agent.run(
    task="Validate transformation",
    context={
        "original_path": "/path/to/original.exe",
        "modified_path": "/path/to/modified.exe"
    }
)
print(f"Validation passed: {result['validation_passed']}")
```

### ReportingAgent

Generates comprehensive analysis reports.

**Capabilities:**
- Multi-format report generation (JSON, HTML, YAML, XML)
- Executive summaries
- Technical deep-dives
- Visualization recommendations

**Usage:**
```python
agent = ReportingAgent(config)
result = await agent.run(
    task="Generate analysis report",
    context={
        "binary_path": "/path/to/file.exe",
        "analysis": analysis_results
    }
)
```

### ThreatIntelAgent

Correlates binary analysis with threat intelligence.

**Capabilities:**
- IOC extraction (URLs, IPs, domains, etc.)
- Pattern matching
- Threat classification
- Behavioral analysis
- Risk scoring

**Usage:**
```python
agent = ThreatIntelAgent(config)
result = await agent.run(
    task="Threat assessment",
    context={
        "binary_path": "/path/to/file.exe",
        "analysis": analysis_results
    }
)
```

## Cumpyl Tools

The framework provides specialized tools that interface with cumpyl's CLI:

| Tool | Description |
|------|-------------|
| `analyze_binary` | Comprehensive binary analysis |
| `suggest_obfuscation` | Get obfuscation recommendations |
| `run_plugin` | Execute specific cumpyl plugin |
| `list_plugins` | List available plugins |
| `encode_section` | Encode binary sections |
| `generate_report` | Generate analysis reports |
| `hex_view` | View binary in hex format |
| `batch_analyze` | Batch process multiple files |
| `pe_string_obfuscate` | Apply string obfuscation |
| `disassemble` | Disassemble binary code |
| `validate_binary` | Validate binary integrity |
| `compare_binaries` | Compare two binaries |
| `extract_strings` | Extract readable strings |

## Pipelines

### Analysis Pipeline
```
BinaryAnalysis → ThreatIntel → Reporting
```
Full analysis with threat assessment and comprehensive reporting.

### Obfuscation Pipeline
```
BinaryAnalysis → ObfuscationPlanner → QA
```
Plan and validate obfuscation transformations.

### Batch Pipeline
```
BatchOrchestrator → Reporting
```
Process multiple binaries with aggregated reporting.

## Configuration

See `cumpyl_agents_config.yaml` for full configuration options:

```yaml
api:
  provider: "anthropic"
  model: "claude-3-5-sonnet-20241022"
  max_tokens: 4000
  temperature: 0.3

agents:
  binary_analysis:
    enabled: true
    settings:
      default_analysis_type: "sections"
      include_strings: true

  obfuscation_planner:
    enabled: true
    settings:
      risk_level: "moderate"
      enforce_safety_tiers: true
```

## Examples

Run the example workflows:

```bash
# Single agent analysis
python examples/cumpyl_workflows.py 1 /path/to/binary.exe

# Pipeline analysis
python examples/cumpyl_workflows.py 2 /path/to/binary.exe

# Swarm analysis (parallel)
python examples/cumpyl_workflows.py 3 /path/to/binary.exe

# Obfuscation planning
python examples/cumpyl_workflows.py 4 /path/to/binary.exe

# Batch processing
python examples/cumpyl_workflows.py 5 /path/to/directory "*.exe"

# QA validation
python examples/cumpyl_workflows.py 8 /path/to/original.exe /path/to/modified.exe
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | Required for Anthropic Claude |
| `GOOGLE_API_KEY` | Optional for Google Gemini |
| `DEEPSEEK_API_KEY` | Optional for DeepSeek |
| `QWEN_API_KEY` | Optional for Alibaba Qwen |
| `MISTRAL_API_KEY` | Optional for Mistral AI |

## Integration with Cumpyl

The agents integrate with cumpyl's:
- **Plugin System**: Can invoke any cumpyl plugin
- **Configuration**: Respects cumpyl.yaml settings
- **Reporting**: Uses cumpyl's report generation
- **Batch Processing**: Leverages cumpyl's batch processor

## Best Practices

1. **Start with Analysis**: Always run BinaryAnalysisAgent first to understand the binary
2. **Use Pipelines for Workflows**: Chain agents for comprehensive analysis
3. **Validate Transformations**: Always run QA after obfuscation
4. **Respect Safety Tiers**: Don't modify sections marked as AVOID
5. **Review Plans**: Use dry_run mode before applying transformations

## Troubleshooting

**Agent not finding binary:**
- Ensure absolute paths are used
- Verify file exists and is readable

**LLM errors:**
- Check API key is set correctly
- Verify model name is correct
- Reduce max_tokens if hitting limits

**Cumpyl CLI errors:**
- Ensure cumpyl is properly installed
- Check cumpyl.yaml configuration
- Verify plugin dependencies

## License

Same license as the parent cumpyl project.
