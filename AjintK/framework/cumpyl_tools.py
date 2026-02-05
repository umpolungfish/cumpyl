"""
Cumpyl-Specific Tool Definitions for Agent Framework
Provides tools that interface with cumpyl's binary analysis and obfuscation capabilities.
"""
import asyncio
import os
import json
import logging
from typing import Dict, List, Any, Callable, Awaitable, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

# Path to cumpyl package
CUMPYL_ROOT = Path(__file__).parent.parent.parent
CUMPYL_CLI = CUMPYL_ROOT / "cumpyl_package" / "cumpyl.py"


class CumpylToolDefinitions:
    """
    Cumpyl-specific tool definitions for binary analysis and obfuscation.
    """

    @staticmethod
    def analyze_binary() -> Dict[str, Any]:
        """Analyze a binary file using cumpyl's analysis engine."""
        return {
            "name": "analyze_binary",
            "description": "Perform comprehensive analysis on a binary file (PE, ELF, or Mach-O)",
            "input_schema": {
                "type": "object",
                "properties": {
                    "binary_path": {"type": "string", "description": "Path to the binary file to analyze"},
                    "analysis_type": {
                        "type": "string",
                        "enum": ["quick", "deep", "sections", "strings", "entropy"],
                        "description": "Type of analysis to perform"
                    },
                    "output_format": {
                        "type": "string",
                        "enum": ["json", "yaml", "text"],
                        "description": "Output format for analysis results"
                    }
                },
                "required": ["binary_path"]
            }
        }

    @staticmethod
    def suggest_obfuscation() -> Dict[str, Any]:
        """Get obfuscation recommendations for a binary."""
        return {
            "name": "suggest_obfuscation",
            "description": "Get intelligent obfuscation recommendations based on binary analysis",
            "input_schema": {
                "type": "object",
                "properties": {
                    "binary_path": {"type": "string", "description": "Path to the binary file"},
                    "risk_level": {
                        "type": "string",
                        "enum": ["conservative", "moderate", "aggressive"],
                        "description": "Risk tolerance for obfuscation recommendations"
                    }
                },
                "required": ["binary_path"]
            }
        }

    @staticmethod
    def run_plugin() -> Dict[str, Any]:
        """Execute a specific cumpyl plugin."""
        return {
            "name": "run_plugin",
            "description": "Execute a specific cumpyl analysis or transformation plugin",
            "input_schema": {
                "type": "object",
                "properties": {
                    "binary_path": {"type": "string", "description": "Path to the binary file"},
                    "plugin_name": {
                        "type": "string",
                        "description": "Name of the plugin to execute (e.g., entropy_analysis, pe_string_obfuscation)"
                    },
                    "plugin_args": {
                        "type": "object",
                        "description": "Additional arguments to pass to the plugin"
                    }
                },
                "required": ["binary_path", "plugin_name"]
            }
        }

    @staticmethod
    def list_plugins() -> Dict[str, Any]:
        """List available cumpyl plugins."""
        return {
            "name": "list_plugins",
            "description": "List all available cumpyl plugins with their descriptions",
            "input_schema": {
                "type": "object",
                "properties": {
                    "plugin_type": {
                        "type": "string",
                        "enum": ["all", "analysis", "transformation"],
                        "description": "Filter plugins by type"
                    }
                }
            }
        }

    @staticmethod
    def encode_section() -> Dict[str, Any]:
        """Encode a section of a binary."""
        return {
            "name": "encode_section",
            "description": "Encode a specific section of a binary using various encoding methods",
            "input_schema": {
                "type": "object",
                "properties": {
                    "binary_path": {"type": "string", "description": "Path to the binary file"},
                    "section_name": {"type": "string", "description": "Name of the section to encode (e.g., .rdata)"},
                    "encoding_method": {
                        "type": "string",
                        "enum": ["base64", "xor", "rot13", "hex", "unicode", "reverse", "compressed_b64"],
                        "description": "Encoding method to apply"
                    },
                    "output_path": {"type": "string", "description": "Path for the encoded binary output"}
                },
                "required": ["binary_path", "section_name", "encoding_method"]
            }
        }

    @staticmethod
    def generate_report() -> Dict[str, Any]:
        """Generate an analysis report."""
        return {
            "name": "generate_report",
            "description": "Generate a comprehensive analysis report in various formats",
            "input_schema": {
                "type": "object",
                "properties": {
                    "binary_path": {"type": "string", "description": "Path to the binary file"},
                    "report_format": {
                        "type": "string",
                        "enum": ["json", "yaml", "xml", "html"],
                        "description": "Format for the report"
                    },
                    "output_path": {"type": "string", "description": "Path to save the report"},
                    "include_sections": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Specific sections to include in report"
                    }
                },
                "required": ["binary_path", "report_format"]
            }
        }

    @staticmethod
    def hex_view() -> Dict[str, Any]:
        """View binary content in hex format."""
        return {
            "name": "hex_view",
            "description": "View binary content in hexadecimal format",
            "input_schema": {
                "type": "object",
                "properties": {
                    "binary_path": {"type": "string", "description": "Path to the binary file"},
                    "offset": {"type": "integer", "description": "Starting offset in bytes"},
                    "length": {"type": "integer", "description": "Number of bytes to display"},
                    "section": {"type": "string", "description": "Specific section to view"}
                },
                "required": ["binary_path"]
            }
        }

    @staticmethod
    def batch_analyze() -> Dict[str, Any]:
        """Analyze multiple binaries in batch."""
        return {
            "name": "batch_analyze",
            "description": "Analyze multiple binary files in batch mode",
            "input_schema": {
                "type": "object",
                "properties": {
                    "directory": {"type": "string", "description": "Directory containing binaries"},
                    "pattern": {"type": "string", "description": "File pattern to match (e.g., *.exe)"},
                    "recursive": {"type": "boolean", "description": "Search subdirectories"},
                    "output_dir": {"type": "string", "description": "Directory for output reports"},
                    "operation": {
                        "type": "string",
                        "enum": ["analyze", "report", "transform"],
                        "description": "Operation to perform on each file"
                    }
                },
                "required": ["directory"]
            }
        }

    @staticmethod
    def pe_string_obfuscate() -> Dict[str, Any]:
        """Perform PE string obfuscation."""
        return {
            "name": "pe_string_obfuscate",
            "description": "Apply string obfuscation to a PE binary",
            "input_schema": {
                "type": "object",
                "properties": {
                    "binary_path": {"type": "string", "description": "Path to the PE binary"},
                    "method": {
                        "type": "string",
                        "enum": ["xor", "rot13", "reverse", "all"],
                        "description": "Obfuscation method to apply"
                    },
                    "output_path": {"type": "string", "description": "Path for the obfuscated binary"},
                    "dry_run": {"type": "boolean", "description": "Preview changes without applying"}
                },
                "required": ["binary_path"]
            }
        }

    @staticmethod
    def disassemble() -> Dict[str, Any]:
        """Disassemble binary code."""
        return {
            "name": "disassemble",
            "description": "Disassemble binary code to assembly instructions",
            "input_schema": {
                "type": "object",
                "properties": {
                    "binary_path": {"type": "string", "description": "Path to the binary file"},
                    "section": {"type": "string", "description": "Section to disassemble (default: .text)"},
                    "offset": {"type": "integer", "description": "Starting offset"},
                    "length": {"type": "integer", "description": "Number of bytes to disassemble"},
                    "architecture": {
                        "type": "string",
                        "enum": ["x86", "x64", "arm", "arm64"],
                        "description": "Target architecture"
                    }
                },
                "required": ["binary_path"]
            }
        }

    @staticmethod
    def validate_binary() -> Dict[str, Any]:
        """Validate a binary file's integrity."""
        return {
            "name": "validate_binary",
            "description": "Validate binary file integrity and structure",
            "input_schema": {
                "type": "object",
                "properties": {
                    "binary_path": {"type": "string", "description": "Path to the binary file"},
                    "check_signatures": {"type": "boolean", "description": "Verify digital signatures"},
                    "check_checksums": {"type": "boolean", "description": "Verify checksums"},
                    "check_imports": {"type": "boolean", "description": "Validate import table"}
                },
                "required": ["binary_path"]
            }
        }

    @staticmethod
    def compare_binaries() -> Dict[str, Any]:
        """Compare two binary files."""
        return {
            "name": "compare_binaries",
            "description": "Compare two binary files to identify differences",
            "input_schema": {
                "type": "object",
                "properties": {
                    "original_path": {"type": "string", "description": "Path to the original binary"},
                    "modified_path": {"type": "string", "description": "Path to the modified binary"},
                    "compare_sections": {"type": "boolean", "description": "Compare section by section"},
                    "show_bytes": {"type": "boolean", "description": "Show byte-level differences"}
                },
                "required": ["original_path", "modified_path"]
            }
        }

    @staticmethod
    def extract_strings() -> Dict[str, Any]:
        """Extract strings from a binary."""
        return {
            "name": "extract_strings",
            "description": "Extract readable strings from a binary file",
            "input_schema": {
                "type": "object",
                "properties": {
                    "binary_path": {"type": "string", "description": "Path to the binary file"},
                    "min_length": {"type": "integer", "description": "Minimum string length (default: 4)"},
                    "encoding": {
                        "type": "string",
                        "enum": ["ascii", "unicode", "both"],
                        "description": "String encoding to search for"
                    },
                    "include_section": {"type": "string", "description": "Limit to specific section"}
                },
                "required": ["binary_path"]
            }
        }

    @staticmethod
    def get_all_cumpyl_tools() -> List[Dict[str, Any]]:
        """Return all cumpyl-specific tool definitions."""
        return [
            CumpylToolDefinitions.analyze_binary(),
            CumpylToolDefinitions.suggest_obfuscation(),
            CumpylToolDefinitions.run_plugin(),
            CumpylToolDefinitions.list_plugins(),
            CumpylToolDefinitions.encode_section(),
            CumpylToolDefinitions.generate_report(),
            CumpylToolDefinitions.hex_view(),
            CumpylToolDefinitions.batch_analyze(),
            CumpylToolDefinitions.pe_string_obfuscate(),
            CumpylToolDefinitions.disassemble(),
            CumpylToolDefinitions.validate_binary(),
            CumpylToolDefinitions.compare_binaries(),
            CumpylToolDefinitions.extract_strings(),
        ]


class CumpylToolExecutor:
    """
    Asynchronously executes cumpyl-specific tool calls.
    """

    def __init__(self, cumpyl_root: Optional[Path] = None):
        self.cumpyl_root = cumpyl_root or CUMPYL_ROOT
        self.cumpyl_cli = self.cumpyl_root / "cumpyl_package" / "cumpyl.py"
        self.handlers: Dict[str, Callable[[Dict[str, Any]], Awaitable[Any]]] = {}
        self._register_handlers()

    def _register_handlers(self):
        """Register all cumpyl tool handlers."""
        self.handlers["analyze_binary"] = self._handle_analyze_binary
        self.handlers["suggest_obfuscation"] = self._handle_suggest_obfuscation
        self.handlers["run_plugin"] = self._handle_run_plugin
        self.handlers["list_plugins"] = self._handle_list_plugins
        self.handlers["encode_section"] = self._handle_encode_section
        self.handlers["generate_report"] = self._handle_generate_report
        self.handlers["hex_view"] = self._handle_hex_view
        self.handlers["batch_analyze"] = self._handle_batch_analyze
        self.handlers["pe_string_obfuscate"] = self._handle_pe_string_obfuscate
        self.handlers["disassemble"] = self._handle_disassemble
        self.handlers["validate_binary"] = self._handle_validate_binary
        self.handlers["compare_binaries"] = self._handle_compare_binaries
        self.handlers["extract_strings"] = self._handle_extract_strings

    async def execute_tool(self, tool_name: str, tool_input: Dict[str, Any]) -> Any:
        """Execute a cumpyl tool."""
        if tool_name not in self.handlers:
            return f"Error: No handler for tool: {tool_name}"

        handler = self.handlers[tool_name]
        try:
            return await handler(tool_input)
        except Exception as e:
            logger.error(f"Error executing cumpyl tool {tool_name}: {e}")
            return f"Error executing {tool_name}: {str(e)}"

    async def _run_cumpyl_command(self, args: List[str], timeout: int = 120) -> str:
        """Run a cumpyl CLI command."""
        cmd = ["python", str(self.cumpyl_cli)] + args

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(self.cumpyl_root)
        )

        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
            result = stdout.decode().strip()
            error = stderr.decode().strip()

            if process.returncode != 0 and error:
                return f"Error: {error}"
            return result if result else error
        except asyncio.TimeoutError:
            process.kill()
            return "Error: Command timed out"

    async def _handle_analyze_binary(self, tool_input: Dict[str, Any]) -> str:
        """Handle binary analysis."""
        binary_path = tool_input["binary_path"]
        analysis_type = tool_input.get("analysis_type", "quick")
        output_format = tool_input.get("output_format", "json")

        args = [binary_path]

        if analysis_type == "deep":
            args.append("--run-analysis")
        elif analysis_type == "sections":
            args.append("--analyze-sections")
        elif analysis_type == "entropy":
            args.extend(["--run-analysis"])
        else:
            args.append("--analyze-sections")

        args.extend(["--report-format", output_format])

        return await self._run_cumpyl_command(args)

    async def _handle_suggest_obfuscation(self, tool_input: Dict[str, Any]) -> str:
        """Handle obfuscation suggestion."""
        binary_path = tool_input["binary_path"]
        args = [binary_path, "--suggest-obfuscation"]
        return await self._run_cumpyl_command(args)

    async def _handle_run_plugin(self, tool_input: Dict[str, Any]) -> str:
        """Handle plugin execution."""
        binary_path = tool_input["binary_path"]
        plugin_name = tool_input["plugin_name"]

        args = [binary_path, "--run-analysis"]
        # Plugin-specific handling can be added here

        return await self._run_cumpyl_command(args)

    async def _handle_list_plugins(self, tool_input: Dict[str, Any]) -> str:
        """Handle plugin listing."""
        args = ["--list-plugins"]
        return await self._run_cumpyl_command(args)

    async def _handle_encode_section(self, tool_input: Dict[str, Any]) -> str:
        """Handle section encoding."""
        binary_path = tool_input["binary_path"]
        section_name = tool_input["section_name"]
        encoding_method = tool_input["encoding_method"]
        output_path = tool_input.get("output_path")

        args = [
            binary_path,
            "--encode-section", section_name,
            "--encoding", encoding_method
        ]

        if output_path:
            args.extend(["--output", output_path])

        return await self._run_cumpyl_command(args)

    async def _handle_generate_report(self, tool_input: Dict[str, Any]) -> str:
        """Handle report generation."""
        binary_path = tool_input["binary_path"]
        report_format = tool_input["report_format"]
        output_path = tool_input.get("output_path")

        args = [
            binary_path,
            "--generate-report",
            "--report-format", report_format
        ]

        if output_path:
            args.extend(["--report-output", output_path])

        return await self._run_cumpyl_command(args)

    async def _handle_hex_view(self, tool_input: Dict[str, Any]) -> str:
        """Handle hex viewing."""
        binary_path = tool_input["binary_path"]
        offset = tool_input.get("offset", 0)
        length = tool_input.get("length", 256)
        section = tool_input.get("section")

        args = [binary_path, "--hex-view"]

        if section:
            args.extend(["--hex-view-section", section])
        else:
            args.extend(["--hex-view-offset", str(offset)])
            args.extend(["--hex-view-bytes", str(length)])

        return await self._run_cumpyl_command(args)

    async def _handle_batch_analyze(self, tool_input: Dict[str, Any]) -> str:
        """Handle batch analysis."""
        directory = tool_input["directory"]
        pattern = tool_input.get("pattern", "*.exe")
        recursive = tool_input.get("recursive", False)
        output_dir = tool_input.get("output_dir")
        operation = tool_input.get("operation", "analyze")

        args = [
            "--batch",
            "--batch-directory", directory,
            "--batch-pattern", pattern,
            "--batch-operation", operation
        ]

        if recursive:
            args.append("--batch-recursive")

        if output_dir:
            args.extend(["--batch-output-dir", output_dir])

        return await self._run_cumpyl_command(args, timeout=300)

    async def _handle_pe_string_obfuscate(self, tool_input: Dict[str, Any]) -> str:
        """Handle PE string obfuscation."""
        binary_path = tool_input["binary_path"]
        output_path = tool_input.get("output_path")

        args = [binary_path, "--pe-string-obfuscate"]

        if output_path:
            args.extend(["--output", output_path])

        return await self._run_cumpyl_command(args)

    async def _handle_disassemble(self, tool_input: Dict[str, Any]) -> str:
        """Handle disassembly."""
        binary_path = tool_input["binary_path"]
        section = tool_input.get("section", ".text")

        args = [binary_path, "--disassemble-section-raw", section]

        return await self._run_cumpyl_command(args)

    async def _handle_validate_binary(self, tool_input: Dict[str, Any]) -> str:
        """Handle binary validation."""
        binary_path = tool_input["binary_path"]

        # Use basic analysis for validation
        args = [binary_path, "--analyze-sections"]
        result = await self._run_cumpyl_command(args)

        # Check if file can be parsed
        if "Error" in result:
            return f"Validation FAILED: {result}"
        return f"Validation PASSED: Binary structure is valid\n{result}"

    async def _handle_compare_binaries(self, tool_input: Dict[str, Any]) -> str:
        """Handle binary comparison."""
        original_path = tool_input["original_path"]
        modified_path = tool_input["modified_path"]

        # Analyze both binaries
        args1 = [original_path, "--analyze-sections"]
        args2 = [modified_path, "--analyze-sections"]

        result1 = await self._run_cumpyl_command(args1)
        result2 = await self._run_cumpyl_command(args2)

        return f"=== ORIGINAL ===\n{result1}\n\n=== MODIFIED ===\n{result2}"

    async def _handle_extract_strings(self, tool_input: Dict[str, Any]) -> str:
        """Handle string extraction."""
        binary_path = tool_input["binary_path"]

        # Use strings analysis
        args = [binary_path, "--run-analysis"]
        return await self._run_cumpyl_command(args)
