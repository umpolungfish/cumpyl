#!/usr/bin/env python3
"""
𐑦𐑯𐑑𐑼𐑨𐑒𐑑𐑦𐑝 𐑥𐑧𐑯𐑿 𐑕𐑦𐑕𐑑𐑩𐑥 𐑓𐑹 Cumpyl Framework
Interactive menu system for Cumpyl Framework
"""

import os
import subprocess
from typing import Optional, Dict, Any, List
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.columns import Columns
from rich.layout import Layout

try:
    from .config import ConfigManager
except ImportError:
    from config import ConfigManager


class CumpylMenu:
    """𐑦𐑯𐑑𐑼𐑨𐑒𐑑𐑦𐑝 𐑥𐑧𐑯𐑿 𐑕𐑦𐑕𐑑𐑩𐑥 𐑓𐑹 Cumpyl"""
    
    def __init__(self, config: ConfigManager = None):
        """𐑦𐑯𐑦𐑖𐑩𐑤𐑲𐑟 𐑞 𐑥𐑧𐑯𐑿 𐑕𐑦𐑕𐑑𐑩𐑥"""
        self.console = Console()
        self.config = config
        self.target_file = None
        
    def show_banner(self):
        """𐑛𐑦𐑕𐑐𐑤𐑱 𐑞 Cumpyl 𐑚𐑨𐑯𐑼"""
        banner_text = Text()
        banner_text.append("CUMPYL FRAMEWORK v0.3.0\n", style="bold red")
        banner_text.append("Advanced Binary Analysis & Rewriting Platform\n", style="bold cyan")
        banner_text.append("Interactive Menu System", style="bold yellow")
        
        banner_panel = Panel(
            banner_text,
            border_style="bright_blue",
            padding=(1, 2),
            title="Welcome",
            title_align="center"
        )
        
        self.console.print(banner_panel)
        self.console.print()
        
    def select_target_file(self) -> bool:
        """𐑕𐑧𐑤𐑧𐑒𐑑 𐑞 𐑑𐑸𐑜𐑧𐑑 𐑚𐑲𐑯𐑩𐑮𐑦 𐑓𐑲𐑤"""
        self.console.print(Panel("Target File Selection", style="bold green"))
        
        # 𐑕𐑴 𐑮𐑦𐑕𐑧𐑯𐑑 𐑓𐑲𐑤𐑟 𐑦𐑯 𐑞 𐑒𐑻𐑩𐑯𐑑 𐑛𐑲𐑮𐑧𐑒𐑑𐑼𐑦
        current_dir = os.getcwd()
        binary_files = []
        
        # 𐑤𐑵𐑒 𐑓𐑹 𐑒𐑪𐑥𐑩𐑯 𐑚𐑲𐑯𐑩𐑮𐑦 𐑦𐑒𐑕𐑑𐑧𐑯𐑖𐑩𐑯𐑟
        for root, dirs, files in os.walk(current_dir):
            for file in files:
                if file.lower().endswith(('.exe', '.dll', '.so', '.bin', '.elf')):
                    rel_path = os.path.relpath(os.path.join(root, file), current_dir)
                    if len(rel_path) < 80:  # 𐑴𐑯𐑤𐑦 𐑕𐑴 𐑮𐑰𐑟𐑩𐑯𐑩𐑚𐑩𐑤 𐑤𐑧𐑙𐑔 𐑐𐑨𐑔𐑟
                        binary_files.append(rel_path)
                if len(binary_files) >= 20:  # 𐑤𐑦𐑥𐑦𐑑 𐑑 20 𐑓𐑲𐑤𐑟
                    break
            if len(binary_files) >= 20:
                break
        
        if binary_files:
            self.console.print("Found binary files in current directory:")
            
            table = Table(show_header=True, header_style="bold")
            table.add_column("Index", style="cyan", width=8)
            table.add_column("File Path", style="green")
            table.add_column("Size", style="yellow", width=12)
            
            for i, file_path in enumerate(binary_files[:15]):  # 𐑕𐑴 𐑑𐑩𐑐 15
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
        
        # 𐑝𐑧𐑮𐑦𐑓𐑲 𐑞 𐑓𐑲𐑤 𐑦𐑜𐑟𐑦𐑕𐑑𐑕
        if not os.path.exists(self.target_file):
            self.console.print(f"[red]File not found: {self.target_file}[/red]")
            return False
        
        self.console.print(f"[green]Target selected: {self.target_file}[/green]")
        return True
        
    def show_main_menu(self) -> str:
        """𐑛𐑦𐑕𐑐𐑤𐑱 𐑞 𐑥𐑱𐑯 𐑥𐑧𐑯𐑿"""
        menu_options = [
            ("1", "🔍 Quick Analysis", "Fast section analysis and obfuscation suggestions"),
            ("2", "🧪 Deep Analysis", "Comprehensive plugin-based analysis with reporting"),
            ("3", "🔧 Interactive Hex Viewer", "Explore binary with interactive hex dump"),
            ("4", "⚡ Batch Processing", "Process multiple files with automated workflows"),
            ("5", "🎯 Encoding Operations", "Obfuscate specific sections with various encodings"),
            ("6", "🔓 Payload Transmutation", "Transform payloads with advanced obfuscation techniques"),
            ("7", "📦 Binary Packers", "Analyze and pack binaries with compression and encryption (Plugin-based and Real Packer)"),
            ("8", "📊 Generate Reports", "Create detailed analysis reports in multiple formats"),
            ("9", "⚙️ Configuration", "View and modify framework settings"),
            ("10", "📁 Change Target", "Select a different binary file"),
            ("h", "❓ Help", "Show detailed help and examples"),
            ("q", "🚪 Quit", "Exit the menu system")
        ]
        
        self.console.print(Panel(f"Target: {self.target_file}", style="bold blue"))
        
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Option", style="bold cyan", width=8)
        table.add_column("Action", style="bold white", width=25)
        table.add_column("Description", style="dim")
        
        for option, action, description in menu_options:
            table.add_row(option, action, description)
        
        menu_panel = Panel(
            table,
            title="Main Menu",
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
        """𐑒𐑢𐑦𐑒 𐑩𐑯𐑨𐑤𐑦𐑟𐑦𐑕 𐑥𐑧𐑯𐑿"""
        self.console.print(Panel("Quick Analysis Options", style="bold green"))
        
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
        
        # 𐑧𐑒𐑕𐑦𐑒𐑿𐑑 𐑞 𐑧𐑤𐑧𐑒𐑑𐑦𐑛 𐑒𐑩𐑥𐑭𐑯𐑛
        cmd = options[int(choice) - 1][2]
        self.execute_command(cmd)
        
    def hex_viewer_menu(self):
        """𐑦𐑯𐑑𐑼𐑨𐑒𐑑𐑦𐑝 𐑣𐑧𐑒𐑕 𐑝𐑿𐑼 𐑥𐑧𐑯𐑿"""
        self.console.print(Panel("Interactive Hex Viewer Options", style="bold magenta"))
        
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
            # 𐑤𐑷𐑯𐑗 𐑦𐑯𐑑𐑼𐑨𐑒𐑑𐑦𐑝 𐑑𐑧𐑒𐑕𐑑𐑿𐑩𐑤 𐑣𐑧𐑒𐑕 𐑝𐑿𐑼
            self.launch_textual_hex_viewer()
        elif choice == "5":
            # 𐑒𐑩𐑕𐑑𐑩𐑥 𐑮𐑱𐑯𐑡 𐑦𐑯𐑐𐑫𐑑
            offset = Prompt.ask("Enter starting offset (hex like 0x1000 or decimal)", default="0x0")
            bytes_count = Prompt.ask("Enter number of bytes to display", default="2048")
            analysis = Confirm.ask("Include analysis and suggestions?", default=True)
            
            cmd = f"cumpyl {self.target_file} --hex-view --hex-view-offset {offset} --hex-view-bytes {bytes_count}"
            if analysis:
                cmd += " --run-analysis --suggest-obfuscation"
            
            self.execute_command(cmd)
        elif choice == "6":
            # 𐑕𐑧𐑒𐑖𐑩𐑯 𐑕𐑧𐑤𐑧𐑒𐑑𐑼
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
        """𐑛𐑰𐑐 𐑩𐑯𐑨𐑤𐑦𐑟𐑦𐑕 𐑥𐑧𐑯𐑿"""
        self.console.print(Panel("Deep Analysis Options", style="bold blue"))
        
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
    
    def batch_processing_menu(self):
        """Batch processing menu"""
        self.console.print(Panel("Batch Processing Options", style="bold yellow"))
        
        options = [
            ("1", "Process Directory", "Process all binaries in a directory"),
            ("2", "Pattern-based Processing", "Process files matching specific patterns"),
            ("3", "Multi-operation Batch", "Apply multiple operations to files"),
            ("4", "Custom Batch Job", "Build custom batch processing command"),
            ("b", "Back to Main Menu", "")
        ]
        
        table = Table(show_header=True, header_style="bold")
        table.add_column("Option", style="cyan", width=8)
        table.add_column("Description", style="white", width=30)
        table.add_column("Details", style="dim")
        
        for opt, desc, details in options:
            table.add_row(opt, desc, details)
        
        self.console.print(table)
        
        choice = Prompt.ask(
            "\\n[yellow]Select batch processing option[/yellow]",
            choices=[opt[0] for opt in options],
            default="1"
        )
        
        if choice == "b":
            return
        elif choice == "1":
            directory = Prompt.ask("Enter directory path", default=".r4g3c4g3")
            operation = Prompt.ask("Select operation", choices=["analyze_sections", "plugin_analysis", "hex_view"], default="plugin_analysis")
            cmd = f"cumpyl --batch-directory {directory} --batch-operation {operation} --report-format json --report-output batch_results.json"
            self.execute_command(cmd)
        elif choice == "4":
            self.console.print("[green]Building custom batch command...[/green]")
            directory = Prompt.ask("Directory path", default=".")
            extensions = Prompt.ask("File extensions (comma-separated)", default=".exe,.dll")
            operations = Prompt.ask("Operations (comma-separated)", default="plugin_analysis")
            workers = Prompt.ask("Max workers", default="4")
            
            cmd = f"cumpyl --batch-directory {directory} --batch-extensions {extensions} --batch-operation {operations} --max-workers {workers}"
            self.execute_command(cmd)
        else:
            self.console.print("[yellow]Feature coming soon![/yellow]")
            Prompt.ask("Press Enter to continue", default="")
    
    def encoding_operations_menu(self):
        """Encoding operations menu"""
        self.console.print(Panel("Encoding Operations", style="bold red"))
        
        options = [
            ("1", "Encode Single Section", f"cumpyl {self.target_file} --encode-section .text --encoding base64 -o encoded.exe"),
            ("2", "Encode Multiple Sections", f"cumpyl {self.target_file} --encode-section .text --encode-section .data --encoding hex"),
            ("3", "Custom Range Encoding", "Encode specific byte ranges with custom parameters"),
            ("4", "Batch Section Encoding", "Encode sections across multiple files"),
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
            "\\n[yellow]Select encoding option[/yellow]",
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
    
    def pe_packer_menu(self):
        """Binary Packers menu with plugin support"""
        # Launch the new plugin-based packer menu
        try:
            from .plugin_packer_menu import launch_plugin_packer_menu
            launch_plugin_packer_menu(self.config, self.target_file)
        except ImportError as e:
            self.console.print(f"[red]Failed to load plugin packer menu: {e}[/red]")
            self.console.print("[yellow]Falling back to real packer integration...[/yellow]")
            
            # Fallback to original real packer integration
            self.console.print(Panel("Binary Packers", style="bold magenta"))
            
            options = [
                ("1", "Analyze for Packing Opportunities", f"python {os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'real_packer.py'))} {self.target_file} --analyze"),
                ("2", "Pack Binary (Generic PE)", f"python {os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'real_packer.py'))} {self.target_file} --pack -o packed_{os.path.basename(self.target_file)}"),
                ("3", "Pack Binary (Go-aware)", f"python {os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'real_packer.py'))} {self.target_file} --pack -o packed_go_{os.path.basename(self.target_file)}"),
                ("4", "Pack Binary (CGO-aware)", f"python {os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'real_packer.py'))} {self.target_file} --pack -o packed_cgo_{os.path.basename(self.target_file)}"),
                ("5", "Pack with Custom Settings", "Pack with custom compression level and password"),
                ("6", "Unpack Binary", "Restore a previously packed binary"),
                ("b", "Back to Main Menu", "")
            ]
            
            table = Table(show_header=True, header_style="bold")
            table.add_column("Option", style="cyan", width=8)
            table.add_column("Description", style="white", width=35)
            table.add_column("Details", style="dim")
            
            for opt, desc, cmd in options:
                table.add_row(opt, desc, cmd)
                
            self.console.print(table)
            
            choice = Prompt.ask(
                "\n[yellow]Select packer option[/yellow]",
                choices=[opt[0] for opt in options],
                default="2"
            )
            
            if choice == "b":
                return
            elif choice == "1":
                # Analyze for Packing Opportunities
                cmd = options[0][2]
                self.execute_command(cmd)
            elif choice == "2":
                # Pack Binary (Generic PE)
                self.console.print("[bold blue]Generic PE Binary Packing[/bold blue]")
                self.console.print("[dim]Packing binary with standard compression and encryption[/dim]")
                
                # Use the real packer for generic packing
                output_file = f"packed_{os.path.basename(self.target_file)}"
                cmd = f"python {os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'real_packer.py'))} {self.target_file} --pack -o {output_file}"
                self.execute_command(cmd)
            elif choice == "3":
                # Pack Binary (Go-aware)
                self.console.print("[bold blue]Go-aware Binary Packing[/bold blue]")
                self.console.print("[dim]Packing Go binary with Go-specific anti-detection techniques[/dim]")
                
                # Use the real packer but with Go-specific output naming
                output_file = f"packed_go_{os.path.basename(self.target_file)}"
                cmd = f"python {os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'real_packer.py'))} {self.target_file} --pack -o {output_file}"
                self.execute_command(cmd)
            elif choice == "4":
                # Pack Binary (CGO-aware)
                self.console.print("[bold blue]CGO-aware Binary Packing[/bold blue]")
                self.console.print("[dim]Packing CGO binary with CGO-specific anti-detection techniques[/dim]")
                
                # Use the real packer but with CGO-specific output naming
                output_file = f"packed_cgo_{os.path.basename(self.target_file)}"
                cmd = f"python {os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'real_packer.py'))} {self.target_file} --pack -o {output_file}"
                self.execute_command(cmd)
            elif choice == "5":
                # Custom packer settings
                compression_level = Prompt.ask("Compression level (1-9)", default="6")
                password = Prompt.ask("Encryption password (leave empty for random)", default="")
                
                output_file = Prompt.ask("Output file name", default=f"packed_{os.path.basename(self.target_file)}")
                
                cmd = f"python {os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'real_packer.py'))} {self.target_file} --pack -o {output_file} --compression-level {compression_level}"
                if password:
                    cmd += f" --password {password}"
                    
                self.execute_command(cmd)
            elif choice == "6":
                # Unpack binary
                password = Prompt.ask("Encryption password", default="")
                output_file = Prompt.ask("Output file name", default=f"unpacked_{os.path.basename(self.target_file)}")
                
                cmd = f"python {os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'real_packer.py'))} {self.target_file} --unpack -o {output_file}"
                if password:
                    cmd += f" --password {password}"
                    
                self.execute_command(cmd)
    
    def report_generation_menu(self):
        """𐑮𐑦𐑐𐑹𐑑 𐑡𐑧𐑯𐑼𐑱𐑖𐑩𐑯 𐑥𐑧𐑯𐑿"""
        self.console.print(Panel("Report Generation Options", style="bold green"))
        
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
            "\\n[yellow]Select report format[/yellow]",
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
    
    def configuration_menu(self):
        """𐑒𐑪𐑯𐑓𐑦𐑜𐑘𐑼𐑱𐑖𐑩𐑯 𐑥𐑧𐑯𐑿"""
        self.console.print(Panel("Configuration Options", style="bold magenta"))
        
        options = [
            ("1", "Show Current Config", "cumpyl --show-config"),
            ("2", "Validate Config", "cumpyl --validate-config"),
            ("3", "List Available Profiles", "View predefined analysis profiles"),
            ("4", "Plugin Information", "cumpyl --list-plugins"),
            ("b", "Back to Main Menu", "")
        ]
        
        table = Table(show_header=True, header_style="bold")
        table.add_column("Option", style="cyan", width=8)
        table.add_column("Description", style="white", width=25)
        table.add_column("Command", style="dim")
        
        for opt, desc, cmd in options:
            table.add_row(opt, desc, cmd)
        
        self.console.print(table)
        
        choice = Prompt.ask(
            "\\n[yellow]Select configuration option[/yellow]",
            choices=[opt[0] for opt in options],
            default="1"
        )
        
        if choice == "b":
            return
        elif choice == "3":
            self.console.print("\\n[bold cyan]Available Analysis Profiles:[/bold cyan]")
            profiles = [
                ("malware_analysis", "Advanced malware detection and analysis"),
                ("forensics", "Digital forensics and evidence collection"),
                ("research", "Academic research and reverse engineering")
            ]
            
            profile_table = Table(show_header=True, header_style="bold")
            profile_table.add_column("Profile", style="green")
            profile_table.add_column("Description", style="white")
            
            for profile, desc in profiles:
                profile_table.add_row(profile, desc)
            
            self.console.print(profile_table)
            self.console.print("\\n[dim]Use --profile <name> to apply a profile[/dim]")
            Prompt.ask("Press Enter to continue", default="")
        else:
            cmd = options[int(choice) - 1][2]
            self.execute_command(cmd)
    
    def launch_textual_hex_viewer(self):
        """𐑤𐑷𐑯𐑗 𐑦𐑯𐑑𐑼𐑨𐑒𐑑𐑦𐑝 𐑑𐑧𐑒𐑕𐑑𐑿𐑩𐑤 𐑣𐑧𐑒𐑕 𐑝𐑿𐑼"""
        try:
            from .hex_viewer import launch_textual_hex_viewer
            from .cumpyl import BinaryRewriter
        except ImportError:
            import sys
            import os
            sys.path.append(os.path.dirname(os.path.abspath(__file__)))
            from hex_viewer import launch_textual_hex_viewer
            from cumpyl import BinaryRewriter
            
        self.console.print("[yellow]Loading file for interactive hex viewer...[/yellow]")
        
        # ✅ Launch the new Textual hex viewer directly with file path
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
        
        # 📊 𐑞𐑮𐑲 𐑑 𐑤𐑴𐑛 𐑨𐑟 𐑚𐑲𐑯𐑩𐑮𐑦 𐑓𐑹 𐑧𐑯𐑣𐑨𐑯𐑕𐑑 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯𐑟 (𐑪𐑐𐑖𐑩𐑯𐑩𐑤)
        from .hex_viewer import HexViewer
        hex_viewer = HexViewer(self.config)
        rewriter = None
        try:
            rewriter = BinaryRewriter(self.target_file, self.config)
            if rewriter.load_binary():
                self.console.print("[green]Detected structured binary (PE/ELF/Mach-O)[/green]")
                # 𐑨𐑛 𐑕𐑧𐑒𐑖𐑩𐑯 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯𐑟
                if rewriter.binary and hasattr(rewriter.binary, 'sections'):
                    sections = list(rewriter.binary.sections)
                    hex_viewer.add_section_annotations(sections)
                    
                # 🔍 𐑩𐑕𐑒 𐑓𐑹 𐑧𐑯𐑣𐑨𐑯𐑕𐑑 𐑨𐑯𐑨𐑤𐑦𐑟𐑦𐑕
                from rich.prompt import Confirm
                if Confirm.ask("Run analysis plugins for enhanced annotations?", default=True):
                    try:
                        analysis_results = rewriter.run_plugin_analysis()
                        hex_viewer.add_analysis_annotations(analysis_results)
                        
                        # 𐑨𐑛 𐑪𐑚𐑓𐑳𐑕𐑒𐑱𐑖𐑩𐑯 𐑕𐑩𐑜𐑧𐑕𐑑𐑩𐑯𐑟
                        suggestions = rewriter.suggest_obfuscation()
                        hex_viewer.add_suggestion_annotations(suggestions)
                    except Exception as e:
                        self.console.print(f"[yellow]Analysis failed, continuing with basic hex view: {str(e)}[/yellow]")
            else:
                self.console.print("[blue]Raw binary file (no structured format detected)[/blue]")
        except Exception as e:
            self.console.print(f"[blue]Treating as raw binary file: {str(e)}[/blue]")
            
        self.console.print(f"[green]Loaded {len(binary_data)} bytes for hex viewing[/green]")
        self.console.print("[green]Launching fallback hex viewer...[/green]")
        self.console.print("[yellow]Note: For the full interactive experience, use the Textual hex viewer option[/yellow]")
        
        # 📋 Basic hex dump implementation as fallback
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
        """𐑧𐑒𐑕𐑦𐑒𐑿𐑑 𐑩 Cumpyl 𐑒𐑩𐑥𐑭𐑯𐑛"""
        self.console.print(f"\n[bold green]Executing:[/bold green] [cyan]{command}[/cyan]")
        self.console.print("─" * 80)
        
        try:
            # 𐑮𐑩𐑯 𐑞 𐑒𐑩𐑥𐑭𐑯𐑛 𐑦𐑯 𐑞 𐑕𐑱𐑥 Python 𐑧𐑯𐑝𐑲𐑼𐑩𐑯𐑥𐑩𐑯𐑑
            # Check if this is a packer CLI command
            if "packer_cli.py" in command or "real_packer.py" in command:
                # Run the command directly without prepending cumpyl_package.cumpyl
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=False,
                    text=True
                )
            else:
                # Run the command as a cumpyl command
                result = subprocess.run(
                    ["python", "-m", "cumpyl_package.cumpyl"] + command.split()[1:],
                    capture_output=False,
                    text=True
                )
            
            self.console.print("─" * 80)
            if result.returncode == 0:
                self.console.print("[bold green]Command completed successfully![/bold green]")
            else:
                self.console.print(f"[bold red]Command failed with return code: {result.returncode}[/bold red]")
                
        except Exception as e:
            self.console.print(f"[bold red]Error executing command: {e}[/bold red]")
        
        self.console.print()
        Prompt.ask("Press Enter to continue", default="")
    
    def show_help(self):
        """𐑛𐑦𐑕𐑐𐑤𐑱 𐑣𐑧𐑤𐑐 𐑦𐑯𐑓𐑼𐑥𐑱𐑖𐑩𐑯"""
        help_text = """
🔥 **CUMPYL FRAMEWORK** - Advanced Binary Analysis & Rewriting Platform

**Quick Start Guide:**
1. Use menu option 1 for fast analysis and obfuscation suggestions
2. Use menu option 3 for interactive hex exploration with visual tooltips
3. Use menu option 2 for comprehensive analysis with detailed reports

**Key Features:**
• **Interactive Hex Viewer**: Hover over bytes for detailed analysis tooltips
• **Section Analysis**: Automatic classification and safety assessment
• **Plugin System**: Entropy analysis, string extraction, and more
• **Batch Processing**: Analyze multiple files simultaneously
• **Multiple Report Formats**: HTML, JSON, YAML, XML output options

**Hex Viewer Highlights:**
• Color-coded annotations by type and severity
• Interactive section selection with tabular overview
• Custom range specification with hex notation support
• Real-time annotation counting and display
• Working hover tooltips with detailed information

**Analysis Capabilities:**
• Shannon entropy calculation for packed binary detection
• Advanced string extraction with context scoring
• Section-by-section safety assessment for obfuscation
• Multi-tier recommendation system (Advanced/Intermediate/Basic/Avoid)

**Command Examples:**
• Quick analysis: `cumpyl binary.exe --analyze-sections --suggest-obfuscation`
• Interactive hex: `cumpyl binary.exe --hex-view-interactive`
• Full workflow: `cumpyl binary.exe --hex-view --run-analysis --suggest-obfuscation`
• Custom range: `cumpyl binary.exe --hex-view --hex-view-offset 0x1000 --hex-view-bytes 2048`

**File Support:**
• PE files (.exe, .dll)
• ELF files (.so, .bin)
• Mach-O files
• Raw binary files

For detailed documentation, check the CLAUDE.md file in the project directory.
        """
        
        help_panel = Panel(
            help_text.strip(),
            title="Cumpyl Framework Help",
            border_style="bright_yellow",
            padding=(1, 2)
        )
        
        self.console.print(help_panel)
        Prompt.ask("\nPress Enter to continue", default="")
    
    def run(self):
        """𐑮𐑳𐑯 𐑞 𐑦𐑯𐑑𐑼𐑨𐑒𐑑𐑦𐑝 𐑥𐑧𐑯𐑿 𐑤𐑵𐑐"""
        self.show_banner()
        
        # 𐑦𐑓 𐑯𐑴 𐑑𐑸𐑜𐑧𐑑 𐑓𐑲𐑤 𐑦𐑟 𐑕𐑧𐑑, 𐑕𐑧𐑤𐑧𐑒𐑑 𐑢𐑳𐑯
        if not self.target_file:
            if not self.select_target_file():
                return
        
        while True:
            try:
                choice = self.show_main_menu()
                
                if choice == "q":
                    self.console.print("[bold green]👋 Thank you for using Cumpyl Framework![/bold green]")
                    break
                elif choice == "1":
                    self.quick_analysis_menu()
                elif choice == "2":
                    self.deep_analysis_menu()
                elif choice == "3":
                    self.hex_viewer_menu()
                elif choice == "4":
                    self.batch_processing_menu()
                elif choice == "5":
                    self.encoding_operations_menu()
                elif choice == "6":
                    # Launch the new payload transmutation menu
                    try:
                        # Use absolute import instead of relative import to avoid issues
                        from cumpyl_package.payload_transmutation_menu import PayloadTransmutationMenu
                        pt_menu = PayloadTransmutationMenu(self.config)
                        pt_menu.run()
                    except ImportError as e:
                        self.console.print(f"[red]Import error: {e}[/red]")
                        self.console.print("[yellow]Make sure the payload_transmutation_menu module is properly installed[/yellow]")
                        Prompt.ask("Press Enter to continue", default="")
                elif choice == "7":
                    # Launch the PE Packer menu
                    self.pe_packer_menu()
                elif choice == "8":
                    self.report_generation_menu()
                elif choice == "9":
                    self.configuration_menu()
                elif choice == "10":
                    self.select_target_file()
                elif choice == "h":
                    self.show_help()
                    
            except KeyboardInterrupt:
                self.console.print("\n[bold yellow]Use 'q' to quit gracefully[/bold yellow]")
            except Exception as e:
                self.console.print(f"[bold red]Menu error: {e}[/bold red]")
                Prompt.ask("Press Enter to continue", default="")


def launch_menu(config: ConfigManager = None, target_file: str = None):
    """𐑤𐑷𐑯𐑗 𐑞 𐑦𐑯𐑑𐑼𐑨𐑒𐑑𐑦𐑝 𐑥𐑧𐑯𐑿"""
    menu = CumpylMenu(config)
    if target_file:
        menu.target_file = target_file
    menu.run()


if __name__ == "__main__":
    launch_menu()