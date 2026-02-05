import os
import logging
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.text import Text

from cumpyl_package.batch_processor import BatchProcessor
from plugins.cfg_extractor_plugin import CFGExtractorPlugin

logger = logging.getLogger(__name__)

class MockRewriter:
    """
    A mock rewriter object to satisfy the CFGExtractorPlugin's analyze method requirements.
    """
    def __init__(self, binary_path):
        self.input_file = binary_path
        self.binary = True # Just needs to be truthy

class CFGBatchProcessor(BatchProcessor):
    """
    Batch processor for extracting CFGs from multiple binary files.
    """
    def __init__(self, input_path, output_path, config=None, console=None):
        super().__init__(config, output_dir=output_path)
        # CFGExtractorPlugin expects a dict, not a ConfigManager object
        plugin_config = {}
        if config and hasattr(config, 'get_plugin_config'):
            plugin_config = config.get_plugin_config('cfg_extractor') or {}
        elif isinstance(config, dict):
            plugin_config = config
        self.cfg_extractor = CFGExtractorPlugin(plugin_config)
        self.console = console if console else Console()
        logger.info(f"Initialized CFGBatchProcessor with input: {input_path}, output: {output_path}")

    def process_file(self, file_path):
        """
        Processes a single binary file to extract its CFG.
        """
        self.console.print(f"[cyan]Processing file:[/cyan] {file_path}")
        try:
            mock_rewriter = MockRewriter(file_path)
            results = self.cfg_extractor.analyze(mock_rewriter)

            if results.get("error"):
                self.console.print(f"[red]❌ Error processing {file_path}:[/red] {results['error']}")
                logger.error(f"Error processing {file_path}: {results['error']}")
                return False

            cfg_dot = results.get("cfg_dot")
            if cfg_dot:
                output_filename = os.path.basename(file_path) + ".dot"
                output_full_path = os.path.join(self.output_path, output_filename)
                os.makedirs(self.output_path, exist_ok=True)
                with open(output_full_path, "w") as f:
                    f.write(cfg_dot)
                self.console.print(f"[green]✔ Extracted CFG for {file_path} to[/green] {output_full_path}")
                return True
            else:
                self.console.print(f"[yellow]⚠ No CFG DOT graph generated for {file_path}[/yellow]")
                logger.warning(f"No CFG DOT graph generated for {file_path}")
                return False
        except Exception as e:
            self.console.print(f"[red]❌ Unhandled exception while processing {file_path}:[/red] {e}")
            logger.exception(f"Unhandled exception while processing {file_path}: {e}")
            return False

def launch_batch_cfg_menu(config=None):
    console = Console()
    console.print(Panel(
        Text("Batch CFG Extraction", justify="center", style="bold magenta"),
        border_style="magenta"
    ))

    input_path = Prompt.ask("[bold cyan]Enter path to input binaries (file or directory):[/bold cyan]")
    if not os.path.exists(input_path):
        console.print(f"[red]❌ Error: Input path does not exist: {input_path}[/red]")
        Prompt.ask("Press Enter to continue", default="")
        return

    output_path = Prompt.ask("[bold cyan]Enter path to output directory for CFG DOT files:[/bold cyan]")
    if not os.path.isdir(output_path):
        console.print(f"[yellow]Creating output directory:[/yellow] {output_path}")
        os.makedirs(output_path, exist_ok=True)

    processor = CFGBatchProcessor(input_path, output_path, config, console)
    # Add files to the batch processor
    processor.add_directory(input_path)
    # Configure the CFG extraction operation for all added jobs
    processor.configure_operation('plugin_analysis')
    # Process all jobs
    processor.process_all()

    console.print(Panel(
        Text("Batch CFG Extraction Complete!", justify="center", style="bold green"),
        border_style="green"
    ))
    Prompt.ask("Press Enter to continue", default="")