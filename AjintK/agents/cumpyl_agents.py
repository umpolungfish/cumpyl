"""
Cumpyl Specialized Agents
Autonomous agents for binary analysis, obfuscation planning, and transformation.
"""
from typing import Dict, List, Any, Optional
import sys
import json
import asyncio
from pathlib import Path
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from framework import BaseAgent, ToolDefinitions
from framework.cumpyl_tools import CumpylToolDefinitions, CumpylToolExecutor


class BinaryAnalysisAgent(BaseAgent):
    """
    Autonomous agent for comprehensive binary analysis.

    Capabilities:
    - Multi-format binary detection (PE, ELF, Mach-O)
    - Section analysis and entropy calculation
    - String extraction and risk assessment
    - Packer/protector detection
    - Obfuscation recommendation generation
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(
            agent_id="binary_analysis_agent",
            name="Binary Analysis Agent",
            description="Performs comprehensive binary analysis with intelligent recommendations",
            capabilities=[
                "Multi-format binary detection",
                "Section entropy analysis",
                "String extraction and categorization",
                "Packer/protector detection",
                "Security risk assessment",
                "Obfuscation tier recommendations"
            ],
            config=config
        )
        self.cumpyl_executor = CumpylToolExecutor()

    def get_tools(self) -> List[Dict[str, Any]]:
        """Define tools available to this agent."""
        return [
            CumpylToolDefinitions.analyze_binary(),
            CumpylToolDefinitions.suggest_obfuscation(),
            CumpylToolDefinitions.extract_strings(),
            CumpylToolDefinitions.hex_view(),
            ToolDefinitions.file_read(),
            ToolDefinitions.file_write(),
        ]

    async def run(self, task: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Execute binary analysis task.

        Args:
            task: Analysis task description or binary path
            context: Optional context from previous agents

        Returns:
            Analysis results with recommendations
        """
        self.start()
        print(f"[{self.name}] Starting analysis: {task}")

        try:
            # Extract binary path from task or context
            binary_path = self._extract_binary_path(task, context)

            if not binary_path:
                # Use LLM to understand the task
                response = await self._analyze_with_llm(task, context)
                self.complete({"status": "llm_analysis", "findings": response})
                return self.results

            # Perform comprehensive analysis
            analysis_results = await self._perform_analysis(binary_path)

            # Generate LLM-enhanced recommendations
            recommendations = await self._generate_recommendations(binary_path, analysis_results)

            results = {
                "status": "success",
                "binary_path": str(binary_path),
                "analysis": analysis_results,
                "recommendations": recommendations,
                "artifacts": self.artifacts,
                "timestamp": datetime.now().isoformat()
            }

            self.complete(results)
            print(f"[{self.name}] Analysis completed successfully")
            return results

        except Exception as e:
            error_msg = str(e)
            print(f"[{self.name}] Error: {error_msg}")
            self.fail(error_msg)
            return {
                "status": "error",
                "error": error_msg,
                "analysis": None,
                "recommendations": None
            }

    def _extract_binary_path(self, task: str, context: Optional[Dict[str, Any]]) -> Optional[Path]:
        """Extract binary path from task or context."""
        # Check context first
        if context and "binary_path" in context:
            return Path(context["binary_path"])

        # Try to extract path from task string
        words = task.split()
        for word in words:
            path = Path(word)
            if path.exists() and path.is_file():
                return path

        return None

    async def _perform_analysis(self, binary_path: Path) -> Dict[str, Any]:
        """Perform comprehensive binary analysis."""
        results = {}

        # Section analysis
        section_result = await self.cumpyl_executor.execute_tool(
            "analyze_binary",
            {"binary_path": str(binary_path), "analysis_type": "sections"}
        )
        results["sections"] = section_result
        self.save_artifact(section_result, "section_analysis")

        # Obfuscation suggestions
        obf_result = await self.cumpyl_executor.execute_tool(
            "suggest_obfuscation",
            {"binary_path": str(binary_path)}
        )
        results["obfuscation_suggestions"] = obf_result
        self.save_artifact(obf_result, "obfuscation_suggestions")

        # String extraction
        strings_result = await self.cumpyl_executor.execute_tool(
            "extract_strings",
            {"binary_path": str(binary_path)}
        )
        results["strings"] = strings_result
        self.save_artifact(strings_result, "strings_analysis")

        return results

    async def _generate_recommendations(self, binary_path: Path, analysis: Dict[str, Any]) -> str:
        """Generate LLM-enhanced recommendations based on analysis."""
        prompt = f"""You are an expert binary analyst. Based on the following analysis results,
provide detailed recommendations for the binary file.

Binary: {binary_path}

Analysis Results:
{json.dumps(analysis, indent=2, default=str)[:4000]}

Provide:
1. Security Assessment: Rate the binary's security posture
2. Obfuscation Strategy: Recommend specific obfuscation techniques
3. Risk Factors: Identify any concerning patterns
4. Priority Actions: List top 3 recommended actions

Keep recommendations practical and actionable."""

        return await self.call_llm(
            prompt=prompt,
            max_tokens=self.config.get("max_tokens", 2000),
            temperature=0.3
        )

    async def _analyze_with_llm(self, task: str, context: Optional[Dict[str, Any]]) -> str:
        """Use LLM for general analysis queries."""
        ctx_str = json.dumps(context, default=str) if context else "No context"

        prompt = f"""You are a binary analysis expert. Answer the following query:

Query: {task}

Context: {ctx_str}

Provide a detailed, technical response."""

        return await self.call_llm(
            prompt=prompt,
            max_tokens=self.config.get("max_tokens", 2000),
            temperature=0.5
        )


class ObfuscationPlannerAgent(BaseAgent):
    """
    Agent for creating comprehensive obfuscation strategies.

    Capabilities:
    - Analyzes binary characteristics
    - Plans multi-layer obfuscation strategies
    - Considers section safety tiers
    - Generates step-by-step transformation plans
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(
            agent_id="obfuscation_planner_agent",
            name="Obfuscation Planner Agent",
            description="Creates intelligent obfuscation strategies based on binary analysis",
            capabilities=[
                "Section safety tier analysis",
                "Multi-method obfuscation planning",
                "Risk assessment for transformations",
                "Step-by-step plan generation",
                "Encoding method selection",
                "Plugin chain optimization"
            ],
            config=config
        )
        self.cumpyl_executor = CumpylToolExecutor()

        # Safety tier definitions
        self.safety_tiers = {
            "ADVANCED": [".rdata", ".rodata", ".data.rel.ro"],
            "INTERMEDIATE": [".data", ".bss"],
            "BASIC": [".pdata", ".xdata", ".eh_frame"],
            "AVOID": [".text", ".idata", ".reloc", ".edata"]
        }

    def get_tools(self) -> List[Dict[str, Any]]:
        """Define tools available to this agent."""
        return [
            CumpylToolDefinitions.analyze_binary(),
            CumpylToolDefinitions.suggest_obfuscation(),
            CumpylToolDefinitions.list_plugins(),
            CumpylToolDefinitions.encode_section(),
            ToolDefinitions.file_read(),
            ToolDefinitions.file_write(),
        ]

    async def run(self, task: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Create an obfuscation plan.

        Args:
            task: Planning task or binary path
            context: Context from analysis agent

        Returns:
            Comprehensive obfuscation plan
        """
        self.start()
        print(f"[{self.name}] Creating obfuscation plan: {task}")

        try:
            # Extract analysis from context or perform new analysis
            analysis = context.get("analysis") if context else None
            binary_path = context.get("binary_path") if context else None

            if not binary_path:
                # Try to extract from task
                words = task.split()
                for word in words:
                    path = Path(word)
                    if path.exists() and path.is_file():
                        binary_path = str(path)
                        break

            # Get analysis if not provided
            if not analysis and binary_path:
                analysis_result = await self.cumpyl_executor.execute_tool(
                    "analyze_binary",
                    {"binary_path": binary_path, "analysis_type": "sections"}
                )
                analysis = {"sections": analysis_result}

            # Generate the obfuscation plan
            plan = await self._create_obfuscation_plan(binary_path, analysis, task)

            results = {
                "status": "success",
                "binary_path": binary_path,
                "obfuscation_plan": plan,
                "artifacts": self.artifacts,
                "timestamp": datetime.now().isoformat()
            }

            self.complete(results)
            print(f"[{self.name}] Obfuscation plan created")
            return results

        except Exception as e:
            error_msg = str(e)
            print(f"[{self.name}] Error: {error_msg}")
            self.fail(error_msg)
            return {
                "status": "error",
                "error": error_msg,
                "obfuscation_plan": None
            }

    async def _create_obfuscation_plan(
        self,
        binary_path: Optional[str],
        analysis: Optional[Dict[str, Any]],
        task: str
    ) -> Dict[str, Any]:
        """Create a comprehensive obfuscation plan."""

        # Get available plugins
        plugins_result = await self.cumpyl_executor.execute_tool(
            "list_plugins", {}
        )

        # Use LLM to create intelligent plan
        prompt = f"""You are an expert in binary obfuscation planning. Create a comprehensive
obfuscation strategy based on the following information.

Binary: {binary_path or 'Not specified'}
Task: {task}

Analysis Results:
{json.dumps(analysis, indent=2, default=str)[:3000] if analysis else 'No analysis available'}

Available Plugins:
{plugins_result[:1000]}

Section Safety Tiers:
- ADVANCED (safe for heavy obfuscation): {self.safety_tiers['ADVANCED']}
- INTERMEDIATE (moderate obfuscation): {self.safety_tiers['INTERMEDIATE']}
- BASIC (light obfuscation only): {self.safety_tiers['BASIC']}
- AVOID (do not modify): {self.safety_tiers['AVOID']}

Create an obfuscation plan with the following structure:
1. PHASE 1: Pre-processing steps
2. PHASE 2: String obfuscation (methods and targets)
3. PHASE 3: Section encoding (methods and sections)
4. PHASE 4: Additional transformations
5. PHASE 5: Validation steps

For each step, specify:
- Plugin/method to use
- Target sections/strings
- Risk level (LOW/MEDIUM/HIGH)
- Expected outcome

Output as JSON with phases as keys."""

        plan_text = await self.call_llm(
            prompt=prompt,
            max_tokens=self.config.get("max_tokens", 3000),
            temperature=0.3
        )

        self.save_artifact(plan_text, "obfuscation_plan")

        return {
            "plan_text": plan_text,
            "safety_tiers": self.safety_tiers,
            "plugins_available": plugins_result[:500]
        }


class BatchOrchestratorAgent(BaseAgent):
    """
    Agent for coordinating large-scale batch processing operations.

    Capabilities:
    - Multi-file batch processing
    - Progress tracking and reporting
    - Failure handling and retry logic
    - Result aggregation and statistics
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(
            agent_id="batch_orchestrator_agent",
            name="Batch Orchestrator Agent",
            description="Coordinates large-scale batch binary processing operations",
            capabilities=[
                "Multi-file batch processing",
                "Parallel task execution",
                "Progress tracking",
                "Failure recovery",
                "Result aggregation",
                "Statistical reporting"
            ],
            config=config
        )
        self.cumpyl_executor = CumpylToolExecutor()
        self.max_concurrent = config.get("max_concurrent", 5)

    def get_tools(self) -> List[Dict[str, Any]]:
        """Define tools available to this agent."""
        return [
            CumpylToolDefinitions.batch_analyze(),
            CumpylToolDefinitions.analyze_binary(),
            CumpylToolDefinitions.generate_report(),
            ToolDefinitions.file_read(),
            ToolDefinitions.file_write(),
            ToolDefinitions.run_command(),
        ]

    async def run(self, task: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Execute batch processing operation.

        Args:
            task: Batch processing task description
            context: Configuration context

        Returns:
            Batch processing results with statistics
        """
        self.start()
        print(f"[{self.name}] Starting batch operation: {task}")

        try:
            # Extract batch parameters
            params = self._extract_batch_params(task, context)

            if params.get("directory"):
                # Use cumpyl's batch processing
                batch_result = await self.cumpyl_executor.execute_tool(
                    "batch_analyze",
                    {
                        "directory": params["directory"],
                        "pattern": params.get("pattern", "*.exe"),
                        "recursive": params.get("recursive", False),
                        "output_dir": params.get("output_dir"),
                        "operation": params.get("operation", "analyze")
                    }
                )

                # Generate summary with LLM
                summary = await self._generate_batch_summary(batch_result, params)

                results = {
                    "status": "success",
                    "batch_results": batch_result,
                    "summary": summary,
                    "parameters": params,
                    "artifacts": self.artifacts,
                    "timestamp": datetime.now().isoformat()
                }
            else:
                # Handle as query
                response = await self._handle_batch_query(task, context)
                results = {
                    "status": "success",
                    "response": response,
                    "artifacts": self.artifacts
                }

            self.complete(results)
            print(f"[{self.name}] Batch operation completed")
            return results

        except Exception as e:
            error_msg = str(e)
            print(f"[{self.name}] Error: {error_msg}")
            self.fail(error_msg)
            return {
                "status": "error",
                "error": error_msg,
                "batch_results": None
            }

    def _extract_batch_params(self, task: str, context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract batch processing parameters."""
        params = {}

        if context:
            params.update(context)

        # Try to extract directory from task
        words = task.split()
        for word in words:
            path = Path(word)
            if path.exists() and path.is_dir():
                params["directory"] = str(path)
                break

        # Extract pattern if specified
        for i, word in enumerate(words):
            if word == "--pattern" and i + 1 < len(words):
                params["pattern"] = words[i + 1]

        return params

    async def _generate_batch_summary(self, batch_result: str, params: Dict[str, Any]) -> str:
        """Generate a summary of batch processing results."""
        prompt = f"""Analyze the following batch processing results and provide a summary:

Parameters Used:
{json.dumps(params, indent=2)}

Batch Results:
{batch_result[:4000]}

Provide:
1. Total files processed
2. Success/failure counts
3. Common patterns observed
4. Recommendations for further action"""

        return await self.call_llm(
            prompt=prompt,
            max_tokens=1500,
            temperature=0.3
        )

    async def _handle_batch_query(self, task: str, context: Optional[Dict[str, Any]]) -> str:
        """Handle general batch processing queries."""
        prompt = f"""You are an expert in batch binary processing. Answer the following:

Query: {task}
Context: {json.dumps(context, default=str) if context else 'None'}

Provide practical guidance for batch operations."""

        return await self.call_llm(
            prompt=prompt,
            max_tokens=1500,
            temperature=0.5
        )


class QualityAssuranceAgent(BaseAgent):
    """
    Agent for validating transformed binaries.

    Capabilities:
    - Binary integrity validation
    - Pre/post transformation comparison
    - Execution testing (sandboxed)
    - Structural verification
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(
            agent_id="qa_agent",
            name="Quality Assurance Agent",
            description="Validates binary integrity after transformations",
            capabilities=[
                "Binary structure validation",
                "Checksum verification",
                "Import/export table validation",
                "Section integrity checks",
                "Pre/post comparison",
                "Transformation impact assessment"
            ],
            config=config
        )
        self.cumpyl_executor = CumpylToolExecutor()

    def get_tools(self) -> List[Dict[str, Any]]:
        """Define tools available to this agent."""
        return [
            CumpylToolDefinitions.validate_binary(),
            CumpylToolDefinitions.compare_binaries(),
            CumpylToolDefinitions.analyze_binary(),
            CumpylToolDefinitions.hex_view(),
            ToolDefinitions.file_read(),
            ToolDefinitions.run_command(),
        ]

    async def run(self, task: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Execute QA validation.

        Args:
            task: Validation task or binary path
            context: Context with original/modified paths

        Returns:
            Validation results with pass/fail status
        """
        self.start()
        print(f"[{self.name}] Starting QA validation: {task}")

        try:
            # Extract paths
            original_path = context.get("original_path") if context else None
            modified_path = context.get("modified_path") if context else None

            if not modified_path:
                # Try to extract from task
                words = task.split()
                for word in words:
                    path = Path(word)
                    if path.exists() and path.is_file():
                        modified_path = str(path)
                        break

            validation_results = {}

            # Validate modified binary
            if modified_path:
                validation_results["structure_check"] = await self.cumpyl_executor.execute_tool(
                    "validate_binary",
                    {"binary_path": modified_path}
                )
                self.save_artifact(validation_results["structure_check"], "structure_validation")

            # Compare if original provided
            if original_path and modified_path:
                validation_results["comparison"] = await self.cumpyl_executor.execute_tool(
                    "compare_binaries",
                    {
                        "original_path": original_path,
                        "modified_path": modified_path
                    }
                )
                self.save_artifact(validation_results["comparison"], "binary_comparison")

            # Generate QA report
            qa_report = await self._generate_qa_report(validation_results, original_path, modified_path)

            # Determine overall status
            passed = "PASSED" in str(validation_results.get("structure_check", ""))

            results = {
                "status": "success",
                "validation_passed": passed,
                "validation_results": validation_results,
                "qa_report": qa_report,
                "original_path": original_path,
                "modified_path": modified_path,
                "artifacts": self.artifacts,
                "timestamp": datetime.now().isoformat()
            }

            self.complete(results)
            print(f"[{self.name}] QA validation completed - {'PASSED' if passed else 'FAILED'}")
            return results

        except Exception as e:
            error_msg = str(e)
            print(f"[{self.name}] Error: {error_msg}")
            self.fail(error_msg)
            return {
                "status": "error",
                "error": error_msg,
                "validation_passed": False
            }

    async def _generate_qa_report(
        self,
        validation_results: Dict[str, Any],
        original_path: Optional[str],
        modified_path: Optional[str]
    ) -> str:
        """Generate a comprehensive QA report."""
        prompt = f"""You are a QA engineer specializing in binary validation.
Create a QA report based on these validation results:

Original Binary: {original_path or 'Not provided'}
Modified Binary: {modified_path or 'Not provided'}

Validation Results:
{json.dumps(validation_results, indent=2, default=str)[:4000]}

Create a QA report with:
1. SUMMARY: Overall pass/fail status
2. STRUCTURAL INTEGRITY: Section validation results
3. COMPARISON: Key differences (if applicable)
4. RISK ASSESSMENT: Potential issues
5. RECOMMENDATIONS: Next steps

Be specific and technical."""

        return await self.call_llm(
            prompt=prompt,
            max_tokens=2000,
            temperature=0.2
        )


class ReportingAgent(BaseAgent):
    """
    Agent for generating comprehensive analysis reports.

    Capabilities:
    - Multi-format report generation
    - Executive summaries
    - Technical deep-dives
    - Visualization recommendations
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(
            agent_id="reporting_agent",
            name="Reporting Agent",
            description="Generates comprehensive analysis reports in multiple formats",
            capabilities=[
                "Multi-format report generation",
                "Executive summary creation",
                "Technical detail compilation",
                "Trend analysis",
                "Visualization recommendations",
                "Report aggregation"
            ],
            config=config
        )
        self.cumpyl_executor = CumpylToolExecutor()

    def get_tools(self) -> List[Dict[str, Any]]:
        """Define tools available to this agent."""
        return [
            CumpylToolDefinitions.generate_report(),
            CumpylToolDefinitions.analyze_binary(),
            ToolDefinitions.file_read(),
            ToolDefinitions.file_write(),
        ]

    async def run(self, task: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Generate analysis reports.

        Args:
            task: Report generation task
            context: Analysis results from previous agents

        Returns:
            Generated report with multiple formats
        """
        self.start()
        print(f"[{self.name}] Generating report: {task}")

        try:
            binary_path = context.get("binary_path") if context else None
            analysis = context.get("analysis") if context else None

            # Generate cumpyl report if binary available
            cumpyl_report = None
            if binary_path:
                cumpyl_report = await self.cumpyl_executor.execute_tool(
                    "generate_report",
                    {
                        "binary_path": binary_path,
                        "report_format": "json"
                    }
                )
                self.save_artifact(cumpyl_report, "cumpyl_report")

            # Generate executive summary
            exec_summary = await self._generate_executive_summary(task, context, cumpyl_report)

            # Generate technical report
            tech_report = await self._generate_technical_report(task, context, cumpyl_report)

            results = {
                "status": "success",
                "executive_summary": exec_summary,
                "technical_report": tech_report,
                "cumpyl_report": cumpyl_report,
                "artifacts": self.artifacts,
                "timestamp": datetime.now().isoformat()
            }

            self.complete(results)
            print(f"[{self.name}] Report generated successfully")
            return results

        except Exception as e:
            error_msg = str(e)
            print(f"[{self.name}] Error: {error_msg}")
            self.fail(error_msg)
            return {
                "status": "error",
                "error": error_msg
            }

    async def _generate_executive_summary(
        self,
        task: str,
        context: Optional[Dict[str, Any]],
        cumpyl_report: Optional[str]
    ) -> str:
        """Generate an executive summary."""
        prompt = f"""Create an executive summary for binary analysis results.

Task: {task}

Context:
{json.dumps(context, indent=2, default=str)[:2000] if context else 'No context'}

Cumpyl Analysis:
{cumpyl_report[:2000] if cumpyl_report else 'No analysis available'}

Write a concise executive summary (300-400 words) covering:
1. Overview of findings
2. Key security considerations
3. Recommended actions
4. Risk level assessment

Use clear, non-technical language suitable for management."""

        return await self.call_llm(
            prompt=prompt,
            max_tokens=1000,
            temperature=0.3
        )

    async def _generate_technical_report(
        self,
        task: str,
        context: Optional[Dict[str, Any]],
        cumpyl_report: Optional[str]
    ) -> str:
        """Generate a technical deep-dive report."""
        prompt = f"""Create a detailed technical report for binary analysis.

Task: {task}

Context:
{json.dumps(context, indent=2, default=str)[:3000] if context else 'No context'}

Cumpyl Analysis:
{cumpyl_report[:3000] if cumpyl_report else 'No analysis available'}

Create a technical report with:
1. BINARY CHARACTERISTICS
   - File type, architecture, sections
2. SECTION ANALYSIS
   - Entropy values, permissions, sizes
3. STRING ANALYSIS
   - Notable strings, potential IOCs
4. OBFUSCATION ASSESSMENT
   - Current protection level
   - Recommended improvements
5. TECHNICAL RECOMMENDATIONS
   - Specific transformations
   - Risk mitigation steps

Be thorough and technically detailed."""

        return await self.call_llm(
            prompt=prompt,
            max_tokens=3000,
            temperature=0.2
        )


class ThreatIntelAgent(BaseAgent):
    """
    Agent for threat intelligence correlation.

    Capabilities:
    - Pattern matching against known threats
    - IOC extraction and analysis
    - Behavioral pattern identification
    - Threat scoring and classification
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(
            agent_id="threat_intel_agent",
            name="Threat Intelligence Agent",
            description="Correlates binary analysis with threat intelligence",
            capabilities=[
                "IOC extraction",
                "Pattern matching",
                "Threat classification",
                "Behavioral analysis",
                "Risk scoring",
                "Attribution hints"
            ],
            config=config
        )
        self.cumpyl_executor = CumpylToolExecutor()

    def get_tools(self) -> List[Dict[str, Any]]:
        """Define tools available to this agent."""
        return [
            CumpylToolDefinitions.analyze_binary(),
            CumpylToolDefinitions.extract_strings(),
            ToolDefinitions.file_read(),
            ToolDefinitions.web_fetch(),
        ]

    async def run(self, task: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform threat intelligence analysis.

        Args:
            task: Threat intel task
            context: Analysis context from previous agents

        Returns:
            Threat intelligence assessment
        """
        self.start()
        print(f"[{self.name}] Performing threat intel analysis: {task}")

        try:
            binary_path = context.get("binary_path") if context else None
            analysis = context.get("analysis") if context else None

            # Extract IOCs
            iocs = await self._extract_iocs(binary_path, analysis)

            # Perform threat assessment
            threat_assessment = await self._perform_threat_assessment(task, context, iocs)

            results = {
                "status": "success",
                "iocs": iocs,
                "threat_assessment": threat_assessment,
                "artifacts": self.artifacts,
                "timestamp": datetime.now().isoformat()
            }

            self.complete(results)
            print(f"[{self.name}] Threat intel analysis completed")
            return results

        except Exception as e:
            error_msg = str(e)
            print(f"[{self.name}] Error: {error_msg}")
            self.fail(error_msg)
            return {
                "status": "error",
                "error": error_msg
            }

    async def _extract_iocs(
        self,
        binary_path: Optional[str],
        analysis: Optional[Dict[str, Any]]
    ) -> Dict[str, List[str]]:
        """Extract indicators of compromise."""
        iocs = {
            "urls": [],
            "ips": [],
            "domains": [],
            "file_hashes": [],
            "registry_keys": [],
            "mutex_names": [],
            "suspicious_strings": []
        }

        if binary_path:
            strings_result = await self.cumpyl_executor.execute_tool(
                "extract_strings",
                {"binary_path": binary_path}
            )
            self.save_artifact(strings_result, "extracted_strings")

            # Use LLM to extract IOCs from strings
            prompt = f"""Extract potential IOCs from these binary strings:

{strings_result[:4000]}

Identify and categorize:
- URLs
- IP addresses
- Domain names
- Registry keys
- Mutex names
- Suspicious API calls
- Encryption indicators

Output as JSON with categories as keys."""

            ioc_text = await self.call_llm(prompt=prompt, max_tokens=1500, temperature=0.1)

            # Try to parse JSON response
            try:
                if "```json" in ioc_text:
                    json_str = ioc_text.split("```json")[1].split("```")[0].strip()
                    iocs.update(json.loads(json_str))
            except:
                iocs["raw_analysis"] = ioc_text

        return iocs

    async def _perform_threat_assessment(
        self,
        task: str,
        context: Optional[Dict[str, Any]],
        iocs: Dict[str, Any]
    ) -> str:
        """Perform comprehensive threat assessment."""
        prompt = f"""You are a threat intelligence analyst. Assess the following binary analysis:

Task: {task}

Context:
{json.dumps(context, indent=2, default=str)[:2000] if context else 'No context'}

Extracted IOCs:
{json.dumps(iocs, indent=2, default=str)}

Provide a threat assessment including:
1. THREAT CLASSIFICATION: Category and severity (1-10)
2. BEHAVIORAL INDICATORS: What the binary appears to do
3. ATTRIBUTION HINTS: Any indicators of origin
4. MITIGATION RECOMMENDATIONS: How to defend against this type of threat
5. FURTHER INVESTIGATION: Suggested next steps

Be analytical and evidence-based."""

        return await self.call_llm(
            prompt=prompt,
            max_tokens=2500,
            temperature=0.2
        )


# Factory function for creating agents
def create_cumpyl_agent(agent_type: str, config: Dict[str, Any]) -> BaseAgent:
    """
    Factory function to create cumpyl agents.

    Args:
        agent_type: Type of agent to create
        config: Agent configuration

    Returns:
        Configured agent instance
    """
    agents = {
        "analysis": BinaryAnalysisAgent,
        "obfuscation_planner": ObfuscationPlannerAgent,
        "batch": BatchOrchestratorAgent,
        "qa": QualityAssuranceAgent,
        "reporting": ReportingAgent,
        "threat_intel": ThreatIntelAgent,
    }

    if agent_type not in agents:
        raise ValueError(f"Unknown agent type: {agent_type}. Available: {list(agents.keys())}")

    return agents[agent_type](config)


# Export all agents
__all__ = [
    "BinaryAnalysisAgent",
    "ObfuscationPlannerAgent",
    "BatchOrchestratorAgent",
    "QualityAssuranceAgent",
    "ReportingAgent",
    "ThreatIntelAgent",
    "create_cumpyl_agent",
]
