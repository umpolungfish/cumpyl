"""CFG extraction plugin for the cumpyl framework"""
import logging
from typing import Dict, Any
import angr
import networkx as nx
from plugins.base_plugin import BasePlugin
from cumpyl_package.plugin_manager import AnalysisPlugin

logger = logging.getLogger(__name__)

class CFGExtractorPlugin(AnalysisPlugin, BasePlugin):
    """CFG extraction plugin for cumpyl framework"""

    def __init__(self, config):
        BasePlugin.__init__(self, config)
        AnalysisPlugin.__init__(self, config)
        self.name = "cfg_extractor"
        self.version = "1.0.0"
        self.description = "Extracts the Control Flow Graph (CFG) from a binary."
        self.author = "Cumpyl Framework Team"
        self.dependencies = ["angr"]

    def analyze(self, rewriter) -> Dict[str, Any]:
        """Extract the CFG from the binary"""
        results = {
            "plugin_name": self.name,
            "version": self.version,
            "description": self.description,
            "cfg_dot": None,
            "error": None,
        }

        if not rewriter or not hasattr(rewriter, 'binary') or not rewriter.binary:
            results["error"] = "No binary provided for analysis."
            logger.error(results["error"])
            return results

        try:
            binary_path = rewriter.input_file
            if not binary_path:
                results["error"] = "Cannot determine the binary path."
                logger.error(results["error"])
                return results

            # Load the binary with angr
            project = angr.Project(binary_path, auto_load_libs=False)

            # Perform CFG analysis
            cfg = project.analyses.CFGFast()

            # Manually generate DOT file with simplified node IDs and full labels
            dot_lines = ["digraph {"]
            node_map = {node: f'node{i}' for i, node in enumerate(cfg.graph.nodes())}

            for node, node_id in node_map.items():
                label = str(node).replace('"', '\\"') # Escape quotes in the label
                dot_lines.append(f'    {node_id} [label="{label}"];')

            for u, v in cfg.graph.edges():
                dot_lines.append(f'    {node_map[u]} -> {node_map[v]};')

            dot_lines.append("}")
            dot_graph = "\n".join(dot_lines)
            results["cfg_dot"] = dot_graph

        except Exception as e:
            error_message = f"CFG extraction failed: {str(e)}"
            results["error"] = error_message
            logger.exception(error_message)

        return results

def get_plugin(config):
    """Factory function to get analysis plugin instance"""
    return CFGExtractorPlugin(config)