#!/usr/bin/env python3
"""
Build-a-Binary Menu System for Cumpyl Framework
Binary editor and obfuscator module
"""

import os
import subprocess
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt, Confirm

try:
    from .config import ConfigManager
    from .hex_viewer import launch_textual_hex_viewer
    from .cumpyl import BinaryRewriter
except ImportError:
    try:
        from config import ConfigManager
        from hex_viewer import launch_textual_hex_viewer
        from cumpyl import BinaryRewriter
    except ImportError:
        # Set to None to avoid errors during import
        ConfigManager = None
        launch_textual_hex_viewer = None
        BinaryRewriter = None


class BuildBinaryMenu:
    """Build-a-Binary Menu for Cumpyl Framework"""
    
    def __init__(self, config: ConfigManager = None):
        """Initialize the Build-a-Binary menu"""
        self.console = Console()
        self.config = config
        self.target_file = None
        
    def show_banner(self):
        """Display the Build-a-Binary Banner"""
        banner_text = Text()
        banner_text.append("BUILD-A-BINARY MODULE\n", style="bold yellow")
        banner_text.append("Binary Analysis & Obfuscation Tools\n", style="bold cyan")
        banner_text.append("Part of Cumpyl Framework", style="bold blue")
        
        banner_panel = Panel(
            banner_text,
            border_style="bright_blue",
            padding=(1, 2),
            title="Build-a-Binary",
            title_align="center"
        )
        
        self.console.print(banner_panel)
        self.console.print()
        
    def select_target_file(self) -> bool:
        """Select the target binary file"""
        self.console.print(Panel(" Target File Selection", style="bold green"))
        
        # Present files in current directory
        current_dir = os.getcwd()
        binary_files = []
        
        # Look for common binary files
        for root, dirs, files in os.walk(current_dir):
            # Skip directories that start with a dot or are named ca_packer
            dirs[:] = [d for d in dirs if not d.startswith('.') and d != 'ca_packer']
            
            for file in files:
                if file.lower().endswith(('.exe', '.dll', '.so', '.bin', '.elf')):
                    rel_path = os.path.relpath(os.path.join(root, file), current_dir)
                    if len(rel_path) < 80:  # Only reasonable length paths
                        binary_files.append(rel_path)
                if len(binary_files) >= 20:  # Limit to 20 files
                    break
            if len(binary_files) >= 20:
                break
        
        if binary_files:
            self.console.print(" Found binary files in current directory:")
            
            table = Table(show_header=True, header_style="bold")
            table.add_column("Index", style="cyan", width=8)
            table.add_column("File Path", style="green")
            table.add_column("Size", style="yellow", width=12)
            
            for i, file_path in enumerate(binary_files[:15]):  # Show top 15
                try:
                    size = os.path.getsize(file_path)
                    if size > 1024*1024:
                        size_str = f"{size/(1024*1024):.1f} MB"
                    elif size > 1024:
                        size_str = f"{size/1024:.1f} KB"
                    else:
                        size_str = f"{size} bytes"
                except:
                    size_str = "Unknown"
                
                table.add_row(str(i), file_path, size_str)
            
            self.console.print(table)
            self.console.print()
            
            choice = Prompt.ask(
                "Select file by index, or enter custom path",
                default="0"
            )
            
            if choice.isdigit() and 0 <= int(choice) < len(binary_files):
                self.target_file = binary_files[int(choice)]
            else:
                self.target_file = choice
        else:
            self.target_file = Prompt.ask("Enter path to binary file")
        
        # Verify the file exists
        if not os.path.exists(self.target_file):
            self.console.print(f"[red] File not found: {self.target_file}[/red]")
            return False
        
        self.console.print(f"[green] Target selected: {self.target_file}[/green]")
        return True
        
    def show_main_menu(self) -> str:
        """Display the Build-a-Binary main menu"""
        menu_options = [
            ("1", "Quick Analysis", "Fast section analysis and obfuscation suggestions"),
            ("2", "Deep Analysis", "Comprehensive plugin-based analysis with reporting"),
            ("3", "Interactive Hex Viewer", "Explore binary with interactive hex dump"),
            ("4", "Encoding Operations", "Obfuscate specific sections with various encodings"),
            ("5", "Generate Reports", "Create detailed analysis reports in multiple formats"),
            ("6", "Change Target", "Select a different binary file"),
            ("b", "Back", "Return to main start menu"),
            ("h", "Help", "Show detailed help and examples"),
            ("q", "Quit", "Exit the framework")
        ]
        
        self.console.print(Panel(f" Target: {self.target_file}", style="bold blue"))
        
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Option", style="bold cyan", width=8)
        table.add_column("Action", style="bold white", width=25)
        table.add_column("Description", style="dim")
        
        for option, action, description in menu_options:
            table.add_row(option, action, description)
        
        menu_panel = Panel(
            table,
            title="🛠️ Build-a-Binary Menu",
            border_style="bright_green",
            padding=(1, 1)
        )
        
        self.console.print(menu_panel)
        
        return Prompt.ask(
            "\n[bold yellow]Select an option[/bold yellow]",
            choices=[opt[0] for opt in menu_options],
            default="1"
        )
        
    def quick_analysis_menu(self):
        """Quick analysis menu"""
        self.console.print(Panel(" Quick Analysis Options", style="bold green"))
        
        options = [
            ("1", "Section Analysis Only", f"cumpyl {self.target_file} --analyze-sections"),
            ("2", "Obfuscation Suggestions", f"cumpyl {self.target_file} --suggest-obfuscation"),
            ("3", "Both Analysis + Suggestions", f"cumpyl {self.target_file} --analyze-sections --suggest-obfuscation"),
            ("4", "With Basic Hex View", f"cumpyl {self.target_file} --analyze-sections --suggest-obfuscation --hex-view"),
            ("b", "Back to Main Menu", "")
        ]
        
        table = Table(show_header=True, header_style="bold")
        table.add_column("Option", style="cyan", width=8)
        table.add_column("Description", style="white", width=30)
        table.add_column("Command Preview", style="dim")
        
        for opt, desc, cmd in options:
            table.add_row(opt, desc, cmd)
        
        self.console.print(table)
        
        choice = Prompt.ask(
            "\n[yellow]Select quick analysis option[/yellow]",
            choices=[opt[0] for opt in options],
            default="3"
        )
        
        if choice == "b":
            return
        
        # Execute the selected command
        cmd = options[int(choice) - 1][2]
        self.execute_command(cmd)
        
    def hex_viewer_menu(self):
        """Interactive hex viewer menu"""
        self.console.print(Panel(" Interactive Hex Viewer Options", style="bold magenta"))
        
        options = [
            ("1", "Basic Hex View (HTML)", f"cumpyl {self.target_file} --hex-view"),
            ("2", "Interactive Section Selection (HTML)", f"cumpyl {self.target_file} --hex-view --hex-view-interactive"),
            ("3", "Interactive Terminal Hex Viewer", "Launch TUI hex viewer with navigation"),
            ("4", "Hex + Analysis + Obfuscation Suggestions", f"cumpyl {self.target_file} --hex-view --run-analysis --suggest-obfuscation"),
            ("5", "Custom Range (specify offset)", "Custom command builder"),
            ("6", "View Specific Section", "Custom section selector"),
            ("7", "Large File View (8KB)", f"cumpyl {self.target_file} --hex-view --hex-view-bytes 8192"),
            ("b", "Back to Main Menu", "")
        ]
        
        table = Table(show_header=True, header_style="bold")
        table.add_column("Option", style="cyan", width=8)
        table.add_column("Description", style="white", width=30)
        table.add_column("Command/Action", style="dim")
        
        for opt, desc, cmd in options:
            table.add_row(opt, desc, cmd)
        
        self.console.print(table)
        
        choice = Prompt.ask(
            "\n[yellow]Select hex viewer option[/yellow]",
            choices=[opt[0] for opt in options],
            default="3"
        )
        
        if choice == "b":
            return
        elif choice == "3":
            # Launch interactive textual hex viewer
            self.launch_textual_hex_viewer()
        elif choice == "5":
            # Custom range input
            offset = Prompt.ask("Enter starting offset (hex like 0x1000 or decimal)", default="0x0")
            bytes_count = Prompt.ask("Enter number of bytes to display", default="2048")
            analysis = Confirm.ask("Include analysis and suggestions?", default=True)
            
            cmd = f"cumpyl {self.target_file} --hex-view --hex-view-offset {offset} --hex-view-bytes {bytes_count}"
            if analysis:
                cmd += " --run-analysis --suggest-obfuscation"
            
            self.execute_command(cmd)
        elif choice == "6":
            # Section selector
            section = Prompt.ask("Enter section name (e.g., .text, .data, .rdata)", default=".text")
            analysis = Confirm.ask("Include analysis and suggestions?", default=True)
            
            cmd = f"cumpyl {self.target_file} --hex-view --hex-view-section {section}"
            if analysis:
                cmd += " --run-analysis --suggest-obfuscation"
            
            self.execute_command(cmd)
        else:
            cmd = options[int(choice) - 1][2]
            self.execute_command(cmd)
    
    def deep_analysis_menu(self):
        """Deep analysis menu"""
        self.console.print(Panel(" Deep Analysis Options", style="bold blue"))
        
        options = [
            ("1", "Plugin Analysis Only", f"cumpyl {self.target_file} --run-analysis"),
            ("2", "Analysis + HTML Report", f"cumpyl {self.target_file} --run-analysis --report-format html --report-output analysis.html"),
            ("3", "Analysis + JSON Report", f"cumpyl {self.target_file} --run-analysis --report-format json --report-output analysis.json"),
            ("4", "Full Workflow + Hex View", f"cumpyl {self.target_file} --run-analysis --suggest-obfuscation --hex-view"),
            ("5", "Malware Analysis Profile", f"cumpyl {self.target_file} --profile malware_analysis --run-analysis"),
            ("6", "Forensics Profile", f"cumpyl {self.target_file} --profile forensics --run-analysis"),
            ("b", "Back to Main Menu", "")
        ]
        
        table = Table(show_header=True, header_style="bold")
        table.add_column("Option", style="cyan", width=8)
        table.add_column("Description", style="white", width=35)
        table.add_column("Command Preview", style="dim")
        
        for opt, desc, cmd in options:
            table.add_row(opt, desc, cmd)
        
        self.console.print(table)
        
        choice = Prompt.ask(
            "\n[yellow]Select deep analysis option[/yellow]",
            choices=[opt[0] for opt in options],
            default="4"
        )
        
        if choice == "b":
            return
        
        cmd = options[int(choice) - 1][2]
        self.execute_command(cmd)
    
    def encoding_operations_menu(self):
        """Encoding operations menu"""
        self.console.print(Panel(" Encoding Operations", style="bold red"))
        
        options = [
            ("1", "Encode Single Section", f"cumpyl {self.target_file} --encode-section .text --encoding base64 -o encoded.exe"),
            ("2", "Encode Multiple Sections", f"cumpyl {self.target_file} --encode-section .text --encode-section .data --encoding hex"),
            ("3", "Custom Range Encoding", "Encode specific byte ranges with custom parameters"),
            ("b", "Back to Main Menu", "")
        ]
        
        table = Table(show_header=True, header_style="bold")
        table.add_column("Option", style="cyan", width=8)
        table.add_column("Description", style="white", width=30)
        table.add_column("Command Preview", style="dim")
        
        for opt, desc, cmd in options:
            table.add_row(opt, desc, cmd)
        
        self.console.print(table)
        
        choice = Prompt.ask(
            "\n[yellow]Select encoding option[/yellow]",
            choices=[opt[0] for opt in options],
            default="1"
        )
        
        if choice == "b":
            return
        elif choice == "3":
            section = Prompt.ask("Section name", default=".text")
            offset = Prompt.ask("Start offset", default="0")
            length = Prompt.ask("Length (bytes)", default="256")
            encoding = Prompt.ask("Encoding type", choices=["hex", "base64", "compressed_base64"], default="base64")
            output = Prompt.ask("Output file", default="encoded.exe")
            
            cmd = f"cumpyl {self.target_file} --encode-section {section} --encode-offset {offset} --encode-length {length} --encoding {encoding} -o {output}"
            self.execute_command(cmd)
        else:
            cmd = options[int(choice) - 1][2]
            self.execute_command(cmd)
    
    def report_generation_menu(self):
        """Report generation menu"""
        self.console.print(Panel(" Report Generation Options", style="bold green"))
        
        options = [
            ("1", "HTML Report", f"cumpyl {self.target_file} --run-analysis --report-format html --report-output analysis.html"),
            ("2", "JSON Report", f"cumpyl {self.target_file} --run-analysis --report-format json --report-output analysis.json"),
            ("3", "YAML Report", f"cumpyl {self.target_file} --run-analysis --report-format yaml --report-output analysis.yaml"),
            ("4", "XML Report", f"cumpyl {self.target_file} --run-analysis --report-format xml --report-output analysis.xml"),
            ("5", "Custom Report", "Generate custom report with specific options"),
            ("b", "Back to Main Menu", "")
        ]
        
        table = Table(show_header=True, header_style="bold")
        table.add_column("Option", style="cyan", width=8)
        table.add_column("Description", style="white", width=25)
        table.add_column("Command Preview", style="dim")
        
        for opt, desc, cmd in options:
            table.add_row(opt, desc, cmd)
        
        self.console.print(table)
        
        choice = Prompt.ask(
            "\n[yellow]Select report format[/yellow]",
            choices=[opt[0] for opt in options],
            default="1"
        )
        
        if choice == "b":
            return
        elif choice == "5":
            format_choice = Prompt.ask("Report format", choices=["html", "json", "yaml", "xml"], default="html")
            output_file = Prompt.ask("Output filename", default=f"custom_report.{format_choice}")
            include_hex = Confirm.ask("Include hex view?", default=True)
            include_suggestions = Confirm.ask("Include obfuscation suggestions?", default=True)
            
            cmd = f"cumpyl {self.target_file} --run-analysis --report-format {format_choice} --report-output {output_file}"
            if include_hex:
                cmd += " --hex-view"
            if include_suggestions:
                cmd += " --suggest-obfuscation"
            
            self.execute_command(cmd)
        else:
            cmd = options[int(choice) - 1][2]
            self.execute_command(cmd)
    
    def launch_textual_hex_viewer(self):
        """Launch the interactive textual hex viewer"""
        self.console.print("[yellow]Loading file for interactive hex viewer...[/yellow]")
        
        self.console.print(f"[cyan]Launching advanced hex viewer for: {self.target_file}[/cyan]")
        
        try:
            # Check if we're in an interactive terminal
            import sys
            if not sys.stdin.isatty() or not sys.stdout.isatty():
                self.console.print("[yellow]Non-interactive terminal detected, using fallback viewer[/yellow]")
                raise Exception("Non-interactive terminal")
            
            launch_textual_hex_viewer(self.target_file)
            return
        except Exception as hex_error:
            if "Non-interactive terminal" not in str(hex_error):
                self.console.print(f"[red]Textual hex viewer error: {hex_error}[/red]")
            self.console.print("[yellow]Using fallback hex viewer...[/yellow]")
            
        # Fallback to basic implementation if textual viewer fails
        try:
            with open(self.target_file, 'rb') as f:
                binary_data = f.read()
                
            if not binary_data:
                self.console.print(f"[red]File is empty: {self.target_file}[/red]")
                return
        except Exception as e:
            self.console.print(f"[red]Error reading file: {e}[/red]")
            return
        
        # Fallback hex dump implementation
        from .hex_viewer import HexViewer
        hex_viewer = HexViewer(self.config)
        rewriter = None
        try:
            rewriter = BinaryRewriter(self.target_file, self.config)
            if rewriter.load_binary():
                self.console.print("[green] Detected structured binary (PE/ELF/Mach-O)[/green]")
                # Add section annotations
                if rewriter.binary and hasattr(rewriter.binary, 'sections'):
                    sections = list(rewriter.binary.sections)
                    hex_viewer.add_section_annotations(sections)
                    
                # Ask for analysis plugins
                from rich.prompt import Confirm
                if Confirm.ask("Run analysis plugins for enhanced annotations?", default=True):
                    try:
                        analysis_results = rewriter.run_plugin_analysis()
                        hex_viewer.add_analysis_annotations(analysis_results)
                        
                        # Add obfuscation suggestions
                        suggestions = rewriter.suggest_obfuscation()
                        hex_viewer.add_suggestion_annotations(suggestions)
                    except Exception as e:
                        self.console.print(f"[yellow]⚠️  Analysis failed, continuing with basic hex view: {str(e)}[/yellow]")
            else:
                self.console.print("[blue]ℹ️  Raw binary file (no structured format detected)[/blue]")
        except Exception as e:
            self.console.print(f"[blue]ℹ️  Treating as raw binary file: {str(e)}[/blue]")
            
        self.console.print(f"[green] Loaded {len(binary_data)} bytes for hex viewing[/green]")
        self.console.print("[green]Launching fallback hex viewer...[/green]")
        self.console.print("[yellow]Note: For the full interactive experience, use the Textual hex viewer option[/yellow]")
        
        # Basic hex dump implementation as fallback
        self.console.print(f"\n[bold cyan]Hex dump of first 512 bytes:[/bold cyan]")
        hex_lines = []
        for i in range(0, min(512, len(binary_data)), 16):
            line_data = binary_data[i:i+16]
            hex_part = ' '.join(f'{b:02x}' for b in line_data)
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in line_data)
            hex_lines.append(f"{i:08x}  {hex_part:<48} |{ascii_part}|")
        
        for line in hex_lines:
            self.console.print(f"[dim]{line}[/dim]")
        
        if len(binary_data) > 512:
            self.console.print(f"\n[yellow]... and {len(binary_data) - 512} more bytes[/yellow]")
    
    def execute_command(self, command: str):
        """Execute a Cumpyl command"""
        self.console.print(f"\n[bold green]🚀 Executing:[/bold green] [cyan]{command}[/cyan]")
        self.console.print("─" * 80)
        
        try:
            # Run the command as a cumpyl command
            result = subprocess.run(
                ["python", "-m", "cumpyl_package.cumpyl"] + command.split()[1:],
                capture_output=False,
                text=True
            )
            
            self.console.print("─" * 80)
            if result.returncode == 0:
                self.console.print("[bold green] Command completed successfully![/bold green]")
            else:
                self.console.print(f"[bold red] Command failed with return code: {result.returncode}[/bold red]")
                
        except Exception as e:
            self.console.print(f"[bold red] Error executing command: {e}[/bold red]")
        
        self.console.print()
        Prompt.ask("Press Enter to continue", default="")
    
    def show_help(self):
        """Display help information"""
        help_text = """
**BUILD-A-BINARY MODULE** - Binary Analysis & Obfuscation

**Features:**
• **Quick Analysis**: Fast section analysis and obfuscation suggestions
• **Deep Analysis**: Comprehensive plugin-based analysis with detailed reports
• **Interactive Hex Viewer**: Explore binary with rich annotations
• **Encoding Operations**: Obfuscate specific sections with various encodings
• **Report Generation**: Create detailed analysis reports in multiple formats

**Key Features:**
• Section analysis with safety assessment
• Plugin system for entropy analysis, string extraction, etc.
• Multiple report formats (HTML, JSON, YAML, XML)
• Interactive hex viewer with color-coded annotations
• Custom range specification with hex notation support

**Command Examples:**
• Quick analysis: `cumpyl binary.exe --analyze-sections --suggest-obfuscation`
• Interactive hex: `cumpyl binary.exe --hex-view-interactive`
• Full workflow: `cumpyl binary.exe --hex-view --run-analysis --suggest-obfuscation`
• Custom range: `cumpyl binary.exe --hex-view --hex-view-offset 0x1000 --hex-view-bytes 2048`

For detailed documentation, check the CLAUDE.md file in the project directory.
        """
        
        help_panel = Panel(
            help_text.strip(),
            title="Build-a-Binary Help",
            border_style="bright_yellow",
            padding=(1, 2)
        )
        
        self.console.print(help_panel)
        Prompt.ask("\nPress Enter to continue", default="")
    
    def run(self):
        """Run the Build-a-Binary menu loop"""
        self.show_banner()
        
        # If no target file is set, select one
        if not self.target_file:
            if not self.select_target_file():
                return
        
        while True:
            try:
                choice = self.show_main_menu()
                
                if choice == "q":
                    self.console.print("[bold green]👋 Exiting Cumpyl Framework![/bold green]")
                    break
                elif choice == "b":
                    # Return to start menu
                    break
                elif choice == "1":
                    self.quick_analysis_menu()
                elif choice == "2":
                    self.deep_analysis_menu()
                elif choice == "3":
                    self.hex_viewer_menu()
                elif choice == "4":
                    self.encoding_operations_menu()
                elif choice == "5":
                    self.report_generation_menu()
                elif choice == "6":
                    self.select_target_file()
                elif choice == "h":
                    self.show_help()
                    
            except KeyboardInterrupt:
                self.console.print("\n[bold yellow]Use 'q' to quit gracefully[/bold yellow]")
            except Exception as e:
                self.console.print(f"[bold red] Menu error: {e}[/bold red]")
                Prompt.ask("Press Enter to continue", default="")

def launch_build_binary_menu(config: ConfigManager = None, target_file: str = None):
    """Launch the Build-a-Binary menu"""
    menu = BuildBinaryMenu(config)
    if target_file:
        menu.target_file = target_file
    menu.run()

if __name__ == "__main__":
    launch_build_binary_menu()