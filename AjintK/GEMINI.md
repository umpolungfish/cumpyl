# AjintK Project Context

## Project Overview
AjintK is a "Claude Agent Framework with Multi-Provider LLM Support"—a production-ready, modular framework for building and orchestrating multi-agent AI systems. It abstracts the complexities of agent communication, state management, and LLM provider integration.

### Core Architecture
- **Agents**: Built on `BaseAgent`, agents implement specific logic in a `run()` method and can utilize a suite of tools.
- **Orchestrator**: `AgentOrchestrator` manages agent execution in three modes:
  - **Single**: Run a single agent.
  - **Swarm**: Run multiple agents in parallel using `ThreadPoolExecutor`.
  - **Pipeline**: Run agents sequentially, passing context from one to the next.
- **Multi-Provider LLM System**: An enhanced provider system that supports:
  - Anthropic (Claude), Google (Gemini), DeepSeek, Alibaba (Qwen), and Mistral.
  - **Intelligent Routing**: A `ModelRouter` can select the best provider based on task type (coding, reasoning, analysis, etc.).
  - **Caching**: Automatic SHA-256 based response caching to `.llm_cache.json`.
- **Infrastructure**:
  - **Tool System**: Standardized tool definitions (file, web, JSON).
  - **Memory System**: Persistent JSON-based storage for agent state.
  - **Communication**: Inter-agent messaging system.

## Key Technologies
- **Language**: Python 3.x
- **LLM SDKs**: `anthropic`, `google-generativeai`, `mistralai`
- **Networking**: `requests`
- **Configuration**: `pyyaml`
- **Concurrency**: `concurrent.futures`

## Project Structure
- `framework/`: Core framework implementation.
  - `base_agent.py`: Abstract base class for agents.
  - `enhanced_llm_provider.py`: Multi-provider factory and routing.
  - `orchestrator.py`: Execution management (Swarm/Pipeline).
  - `tools.py`: Tool definitions and execution logic.
  - `memory.py`: Persistent storage management.
  - `communication.py`: Inter-agent messaging.
- `agents/`: Specialized agent implementations (e.g., `ResearchAgent`, `AnalysisAgent`).
- `examples/`: Usage demonstrations for simple agents, swarms, and pipelines.
- `test_integration.py`: Main integration test suite.

## Building and Running

### Setup
1. **Environment**: Use a Python virtual environment.
2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
3. **Configuration**:
   ```bash
   cp config_template.yaml config.yaml
   # Edit config.yaml with your settings
   ```
4. **API Keys**: Set environment variables for the providers you intend to use:
   - `ANTHROPIC_API_KEY`
   - `GOOGLE_API_KEY`
   - `DEEPSEEK_API_KEY`
   - `QWEN_API_KEY`
   - `MISTRAL_API_KEY`

### Execution
- **Run Examples**:
  ```bash
  python examples/simple_agent.py
  python examples/multi_agent_swarm.py
  python examples/pipeline.py
  ```
- **Run Tests**:
  ```bash
  python test_integration.py
  ```

## Development Conventions
- **Creating Agents**: Inherit from `BaseAgent`, implement `run(task, context)`, and optionally override `get_tools()`.
- **Adding Providers**: Inherit from `LLMProvider`, implement `query(prompt)`, and update `get_llm_provider` in `enhanced_llm_provider.py`.
- **Logging**: Use the standard `logging` module. The framework expects an `INFO` level by default.
- **Artifacts**: Agents should use `self.save_artifact(data, type)` to persist outputs.
- **State**: Agent status transitions: `IDLE` -> `RUNNING` -> `COMPLETED`/`FAILED`.
