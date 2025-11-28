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
        self.rewriter: Optional[BinaryRewriter] = None
        
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
            self.rewriter = None
            return False
        
        self.console.print(f"[green] Target selected: {self.target_file}[/green]")
        self.rewriter = BinaryRewriter(self.target_file, self.config)
        if not self.rewriter.load_binary():
            self.console.print(f"[red]Failed to load binary: {self.target_file}[/red]")
            self.rewriter = None
            return False
        self.rewriter.load_plugins()
        return True
        
    def show_main_menu(self) -> str:
        """Display the Build-a-Binary main menu"""
        menu_options = [
            ("1", "Quick Analysis", "Fast section analysis and obfuscation suggestions"),
            ("2", "Deep Analysis", "Comprehensive plugin-based analysis with reporting"),
            ("3", "Interactive Hex Viewer", "Explore binary with interactive hex dump"),
            ("4", "Encoding Operations", "Obfuscate specific sections with various encodings"),
            ("5", "Generate Reports", "Create detailed analysis reports in multiple formats"),
            ("6", "CFG Analysis", "Extract Control Flow Graph from the binary"),
            ("7", "PE String Obfuscation", "Advanced PE-specific string analysis and obfuscation"),
            ("8", "Change Target", "Select a different binary file"),
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
    
    def run_cfg_analysis(self):
        """Run the CFG analysis"""
        self.console.print(Panel(" CFG Analysis", style="bold yellow"))

        if not self.rewriter:
            self.console.print("[red]No target file loaded.[/red]")
            return

        try:
            analysis_results = self.rewriter.run_plugin_analysis()
            cfg_result = analysis_results.get("cfg_extractor")

            if not cfg_result or cfg_result.get("error"):
                error = cfg_result.get('error') if cfg_result else 'Unknown error'
                self.console.print(f"[red]CFG analysis failed: {error}[/red]")
                return

            dot_graph = cfg_result.get("cfg_dot")
            if not dot_graph:
                self.console.print("[red]CFG analysis did not produce a graph.[/red]")
                return

            output_filename = f"{os.path.basename(self.target_file)}_cfg.dot"
            with open(output_filename, "w") as f:
                f.write(dot_graph)

            self.console.print(f"[green]CFG graph saved to {output_filename}[/green]")
            self.console.print("You can visualize this graph using Graphviz.")
            self.console.print(f"For small graphs, use [cyan]dot[/cyan]:")
            self.console.print(f"[cyan]dot -Tpng {output_filename} -o {os.path.basename(self.target_file)}_cfg.png[/cyan]")
            self.console.print(f"For large graphs, use [cyan]sfdp[/cyan] to avoid long processing times:")
            self.console.print(f"[cyan]sfdp -Tpng {output_filename} -o {os.path.basename(self.target_file)}_cfg.png[/cyan]")

        except Exception as e:
            self.console.print(f"[red]An error occurred during CFG analysis: {e}[/red]")

    def pe_string_obfuscation_menu(self):
        """Enhanced PE String Obfuscation menu with interactive features"""
        self.console.print(Panel(" PE String Obfuscation - Enhanced Interactive Mode", style="bold magenta"))

        # Run initial analysis if not already done
        if not self.rewriter:
            self.console.print("[red]No binary loaded. Please select a target first.[/red]")
            return

        options = [
            ("1", "Quick Analysis", "Analyze strings without modification"),
            ("2", "Interactive String Browser", "Browse and select strings interactively"),
            ("3", "Preview Obfuscation", "Preview changes before applying"),
            ("4", "Export Strings to CSV", "Export found strings for review"),
            ("5", "Generate Analysis Report", "Create detailed analysis report"),
            ("6", "Apply Obfuscation (⚠️ Advanced)", "Obfuscate selected strings (WARNING: May break binary)"),
            ("b", "Back to Main Menu", "")
        ]

        table = Table(show_header=True, header_style="bold")
        table.add_column("Option", style="cyan", width=8)
        table.add_column("Action", style="white", width=30)
        table.add_column("Description", style="dim")

        for opt, action, desc in options:
            table.add_row(opt, action, desc)

        self.console.print(table)

        choice = Prompt.ask(
            "\n[yellow]Select option[/yellow]",
            choices=[opt[0] for opt in options],
            default="1"
        )

        if choice == "b":
            return
        elif choice == "1":
            self.pe_string_analysis()
        elif choice == "2":
            self.pe_string_browser()
        elif choice == "3":
            self.pe_preview_obfuscation()
        elif choice == "4":
            self.pe_export_strings_csv()
        elif choice == "5":
            self.pe_generate_report()
        elif choice == "6":
            self.pe_apply_obfuscation_with_warnings()

    def pe_string_analysis(self):
        """Run PE string analysis and display results"""
        self.console.print(Panel(" Analyzing PE Strings...", style="bold cyan"))

        try:
            # Run analysis using the plugin
            analysis_results = self.rewriter.run_plugin_analysis()

            if 'pe_string_obfuscation' in analysis_results:
                pe_results = analysis_results['pe_string_obfuscation']
                self._display_string_analysis_summary(pe_results)
            else:
                self.console.print("[yellow]PE String Obfuscation plugin not found or didn't run[/yellow]")

        except Exception as e:
            self.console.print(f"[red]Analysis failed: {e}[/red]")

        Prompt.ask("\nPress Enter to continue", default="")

    def _display_string_analysis_summary(self, pe_results):
        """Display summary of string analysis"""
        analysis = pe_results.get('analysis', {})

        # Summary statistics
        summary_table = Table(title="String Analysis Summary", show_header=True, header_style="bold green")
        summary_table.add_column("Metric", style="cyan", width=30)
        summary_table.add_column("Count/Value", style="white", width=15)

        summary_table.add_row("Total Strings Found", str(analysis.get('total_strings_found', 0)))
        summary_table.add_row("High-Risk Strings", str(len(analysis.get('high_risk_strings', []))))
        summary_table.add_row("Obfuscation Opportunities", str(len(analysis.get('obfuscation_opportunities', []))))

        # Strings by section
        strings_by_section = analysis.get('strings_by_section', {})
        for section, data in strings_by_section.items():
            summary_table.add_row(f"  ↳ {section}", str(data.get('count', 0)))

        self.console.print(summary_table)

        # High-risk strings preview
        high_risk = analysis.get('high_risk_strings', [])
        if high_risk:
            self.console.print("\n[bold red]High-Risk Strings Detected:[/bold red]")
            risk_table = Table(show_header=True, header_style="bold red")
            risk_table.add_column("Category", style="yellow", width=20)
            risk_table.add_column("String Preview", style="white", width=40)
            risk_table.add_column("Section", style="cyan", width=10)

            for item in high_risk[:10]:  # Show first 10
                string_info = item.get('string', {})
                category = item.get('category', 'Unknown')
                value = string_info.get('value', '')
                section = string_info.get('section', 'N/A')

                preview = value[:40] + "..." if len(value) > 40 else value
                risk_table.add_row(category, preview, section)

            self.console.print(risk_table)

            if len(high_risk) > 10:
                self.console.print(f"\n[dim]... and {len(high_risk) - 10} more high-risk strings[/dim]")

    def pe_string_browser(self):
        """Interactive string browser with filtering"""
        self.console.print(Panel(" Interactive String Browser", style="bold blue"))

        try:
            # Run analysis
            analysis_results = self.rewriter.run_plugin_analysis()

            if 'pe_string_obfuscation' not in analysis_results:
                self.console.print("[red]PE String analysis not available[/red]")
                Prompt.ask("\nPress Enter to continue", default="")
                return

            pe_results = analysis_results['pe_string_obfuscation']
            all_strings = pe_results.get('strings', [])

            if not all_strings:
                self.console.print("[yellow]No strings found in binary[/yellow]")
                Prompt.ask("\nPress Enter to continue", default="")
                return

            # Pagination variables
            page_size = 20
            current_page = 0
            total_pages = (len(all_strings) + page_size - 1) // page_size
            filter_section = None
            filter_type = None

            while True:
                # Apply filters
                filtered_strings = all_strings
                if filter_section:
                    filtered_strings = [s for s in filtered_strings if s.get('section') == filter_section]
                if filter_type:
                    filtered_strings = [s for s in filtered_strings if s.get('type') == filter_type]

                # Paginate
                start_idx = current_page * page_size
                end_idx = min(start_idx + page_size, len(filtered_strings))
                page_strings = filtered_strings[start_idx:end_idx]

                # Display current page
                self.console.clear()
                self.console.print(Panel(f" String Browser - Page {current_page + 1}/{max(1, (len(filtered_strings) + page_size - 1) // page_size)}", style="bold blue"))

                if filter_section or filter_type:
                    filter_info = f"[yellow]Filters: Section={filter_section or 'All'}, Type={filter_type or 'All'}[/yellow]"
                    self.console.print(filter_info)

                browser_table = Table(show_header=True, header_style="bold")
                browser_table.add_column("Index", style="cyan", width=6)
                browser_table.add_column("Offset", style="green", width=12)
                browser_table.add_column("Section", style="yellow", width=10)
                browser_table.add_column("Type", style="magenta", width=8)
                browser_table.add_column("String Preview", style="white")

                for idx, string_info in enumerate(page_strings, start=start_idx):
                    offset = string_info.get('offset', 0)
                    section = string_info.get('section', 'N/A')
                    str_type = string_info.get('type', 'unknown')
                    value = string_info.get('value', '')

                    preview = value[:50] + "..." if len(value) > 50 else value
                    browser_table.add_row(
                        str(idx),
                        f"0x{offset:08x}",
                        section,
                        str_type,
                        preview
                    )

                self.console.print(browser_table)
                self.console.print(f"\n[dim]Showing {start_idx + 1}-{end_idx} of {len(filtered_strings)} strings[/dim]")

                # Navigation options
                self.console.print("\n[bold]Navigation:[/bold] [n]ext [p]revious [f]ilter [v]iew [s]earch [b]ack")
                nav_choice = Prompt.ask("Action", default="n")

                if nav_choice == 'n' and current_page < total_pages - 1:
                    current_page += 1
                elif nav_choice == 'p' and current_page > 0:
                    current_page -= 1
                elif nav_choice == 'f':
                    filter_section = Prompt.ask("Filter by section (or 'all')", default="all")
                    if filter_section.lower() == 'all':
                        filter_section = None
                    filter_type = Prompt.ask("Filter by type (ascii/unicode/pattern or 'all')", default="all")
                    if filter_type.lower() == 'all':
                        filter_type = None
                    current_page = 0
                elif nav_choice == 'v':
                    view_idx = Prompt.ask("Enter string index to view in detail")
                    try:
                        idx = int(view_idx)
                        if 0 <= idx < len(all_strings):
                            self._display_string_detail(all_strings[idx])
                    except ValueError:
                        self.console.print("[red]Invalid index[/red]")
                        Prompt.ask("Press Enter to continue", default="")
                elif nav_choice == 's':
                    search_term = Prompt.ask("Search for")
                    search_results = [s for s in all_strings if search_term.lower() in s.get('value', '').lower()]
                    self.console.print(f"\n[green]Found {len(search_results)} matches[/green]")
                    if search_results:
                        for i, s in enumerate(search_results[:10]):
                            self.console.print(f"  [{i}] {s.get('value', '')[:60]}")
                    Prompt.ask("\nPress Enter to continue", default="")
                elif nav_choice == 'b':
                    break

        except Exception as e:
            self.console.print(f"[red]Browser error: {e}[/red]")
            import traceback
            traceback.print_exc()

        Prompt.ask("\nPress Enter to continue", default="")

    def _display_string_detail(self, string_info):
        """Display detailed information about a specific string"""
        self.console.clear()
        self.console.print(Panel(" String Detail View", style="bold cyan"))

        detail_table = Table(show_header=False, box=None)
        detail_table.add_column("Property", style="bold cyan", width=15)
        detail_table.add_column("Value", style="white")

        detail_table.add_row("Offset", f"0x{string_info.get('offset', 0):08x}")
        detail_table.add_row("Section", string_info.get('section', 'N/A'))
        detail_table.add_row("Type", string_info.get('type', 'unknown'))
        detail_table.add_row("Length", f"{string_info.get('length', 0)} bytes")
        detail_table.add_row("Value", string_info.get('value', ''))

        self.console.print(detail_table)
        Prompt.ask("\nPress Enter to return", default="")

    def pe_preview_obfuscation(self):
        """Preview obfuscation changes without applying"""
        self.console.print(Panel(" Obfuscation Preview", style="bold yellow"))
        self.console.print("[yellow]This feature previews how strings would be obfuscated[/yellow]\n")

        try:
            # Run analysis
            analysis_results = self.rewriter.run_plugin_analysis()

            if 'pe_string_obfuscation' not in analysis_results:
                self.console.print("[red]PE String analysis not available[/red]")
                Prompt.ask("\nPress Enter to continue", default="")
                return

            pe_results = analysis_results['pe_string_obfuscation']
            recommended = pe_results.get('analysis', {}).get('recommended_methods', {})

            # Show preview for each method
            preview_table = Table(title="Obfuscation Preview", show_header=True, header_style="bold")
            preview_table.add_column("Method", style="cyan", width=15)
            preview_table.add_column("String Count", style="yellow", width=12)
            preview_table.add_column("Example Before", style="white", width=25)
            preview_table.add_column("Example After", style="green", width=25)

            for method, strings in recommended.items():
                if strings and len(strings) > 0:
                    example_string = strings[0].get('value', '')

                    # Simulate obfuscation
                    if method == 'xor':
                        obf_preview = self._simulate_xor(example_string)
                    elif method == 'base64':
                        import base64
                        obf_preview = base64.b64encode(example_string.encode()).decode()[:25]
                    elif method == 'reverse':
                        obf_preview = example_string[::-1]
                    else:
                        obf_preview = "[obfuscated]"

                    preview_table.add_row(
                        method,
                        str(len(strings)),
                        example_string[:25] + "..." if len(example_string) > 25 else example_string,
                        obf_preview[:25] + "..." if len(obf_preview) > 25 else obf_preview
                    )

            self.console.print(preview_table)

            # Warning box
            warning_panel = Panel(
                "[bold red]⚠️  IMPORTANT WARNINGS ⚠️[/bold red]\n\n"
                "1. Current implementation does NOT inject deobfuscation stubs\n"
                "2. Obfuscated binaries will NOT function correctly\n"
                "3. String obfuscation modifies data but NOT code references\n"
                "4. This is for ANALYSIS and TESTING purposes only\n\n"
                "[yellow]Functional obfuscation requires stub injection (not yet implemented)[/yellow]",
                title="Obfuscation Limitations",
                border_style="red",
                padding=(1, 2)
            )
            self.console.print("\n")
            self.console.print(warning_panel)

        except Exception as e:
            self.console.print(f"[red]Preview error: {e}[/red]")

        Prompt.ask("\nPress Enter to continue", default="")

    def _simulate_xor(self, string):
        """Simulate XOR obfuscation for preview"""
        key = 0x42
        return ''.join(f'{ord(c) ^ key:02x}' for c in string[:10])

    def pe_export_strings_csv(self):
        """Export strings to CSV file"""
        self.console.print(Panel(" Export Strings to CSV", style="bold green"))

        try:
            import csv
            from datetime import datetime

            # Run analysis
            analysis_results = self.rewriter.run_plugin_analysis()

            if 'pe_string_obfuscation' not in analysis_results:
                self.console.print("[red]PE String analysis not available[/red]")
                Prompt.ask("\nPress Enter to continue", default="")
                return

            pe_results = analysis_results['pe_string_obfuscation']
            all_strings = pe_results.get('strings', [])

            if not all_strings:
                self.console.print("[yellow]No strings to export[/yellow]")
                Prompt.ask("\nPress Enter to continue", default="")
                return

            # Generate filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"{os.path.basename(self.target_file)}_strings_{timestamp}.csv"

            # Write CSV
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Index', 'Offset', 'Section', 'Type', 'Length', 'String'])

                for idx, s in enumerate(all_strings):
                    writer.writerow([
                        idx,
                        f"0x{s.get('offset', 0):08x}",
                        s.get('section', 'N/A'),
                        s.get('type', 'unknown'),
                        s.get('length', 0),
                        s.get('value', '')
                    ])

            self.console.print(f"[green]✓ Exported {len(all_strings)} strings to: {output_file}[/green]")

        except Exception as e:
            self.console.print(f"[red]Export failed: {e}[/red]")

        Prompt.ask("\nPress Enter to continue", default="")

    def pe_generate_report(self):
        """Generate detailed analysis report"""
        self.console.print(Panel(" Generate Analysis Report", style="bold cyan"))

        format_choice = Prompt.ask(
            "Select report format",
            choices=["html", "json", "yaml"],
            default="html"
        )

        output_file = Prompt.ask(
            "Output filename",
            default=f"pe_string_analysis.{format_choice}"
        )

        cmd = f"cumpyl {self.target_file} --run-analysis --report-format {format_choice} --report-output {output_file}"
        self.execute_command(cmd)

    def pe_apply_obfuscation_with_warnings(self):
        """Apply obfuscation with comprehensive warnings and backup"""
        self.console.clear()

        # Display critical warnings
        warning_panel = Panel(
            "[bold yellow]⚠️  IMPORTANT - READ CAREFULLY ⚠️[/bold yellow]\n\n"
            "[bold green]V3 Architecture (Functional Obfuscation):[/bold green]\n"
            "  ✅ Deobfuscation stub injection implemented\n"
            "  ✅ Code reference patching implemented\n"
            "  ✅ Runtime deobfuscation support enabled\n"
            "  ✅ Produces FUNCTIONAL obfuscated binaries\n\n"
            "[bold cyan]Supported Methods:[/bold cyan]\n"
            "  • XOR cipher (x86 + x64)\n"
            "  • ROT13 cipher (x86)\n"
            "  • String reversal (x86)\n\n"
            "[bold yellow]Known Limitations:[/bold yellow]\n"
            "  ⚠️  Limited x64 support (XOR only)\n"
            "  ⚠️  No thread-safe deobfuscation (single-threaded programs only)\n"
            "  ⚠️  Binary size overhead: ~13-14 KB\n"
            "  ⚠️  Performance impact: <0.1% overall\n\n"
            "[bold]This will MODIFY your binary - backup created automatically![/bold]",
            title="⚠️  String Obfuscation V3",
            border_style="yellow",
            padding=(1, 2)
        )

        self.console.print(warning_panel)
        self.console.print()

        # First confirmation
        if not Confirm.ask("\n[bold cyan]Do you understand the V3 features and limitations?[/bold cyan]", default=False):
            self.console.print("[yellow]Obfuscation cancelled[/yellow]")
            Prompt.ask("\nPress Enter to continue", default="")
            return

        # Second confirmation with backup
        if not Confirm.ask("\n[bold green]Create backup and proceed with functional obfuscation?[/bold green]", default=False):
            self.console.print("[yellow]Obfuscation cancelled[/yellow]")
            Prompt.ask("\nPress Enter to continue", default="")
            return

        # Create backup
        try:
            backup_path = self._create_backup(self.target_file)
            self.console.print(f"\n[green]✓ Backup created: {backup_path}[/green]")
        except Exception as e:
            self.console.print(f"\n[red]✗ Backup failed: {e}[/red]")
            self.console.print("[red]Obfuscation cancelled for safety[/red]")
            Prompt.ask("\nPress Enter to continue", default="")
            return

        # Execute obfuscation
        self.console.print("\n[bold]Proceeding with obfuscation...[/bold]")
        cmd = f"cumpyl {self.target_file} --pe-string-obfuscate"
        self.execute_command(cmd)

        # Post-obfuscation info
        self.console.print("\n[bold yellow]⚠️  Binary has been modified[/bold yellow]")
        self.console.print(f"[green]Backup location: {backup_path}[/green]")
        self.console.print("\n[yellow]To restore original:[/yellow]")
        self.console.print(f"[cyan]  cp {backup_path} {self.target_file}[/cyan]")

        Prompt.ask("\nPress Enter to continue", default="")

    def _create_backup(self, binary_path):
        """Create timestamped backup with metadata"""
        import shutil
        import json
        import hashlib
        from datetime import datetime

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = os.path.join(os.path.dirname(binary_path) or ".", ".cumpyl_backups")
        os.makedirs(backup_dir, exist_ok=True)

        backup_filename = f"{os.path.basename(binary_path)}.{timestamp}.bak"
        backup_path = os.path.join(backup_dir, backup_filename)

        # Copy file
        shutil.copy2(binary_path, backup_path)

        # Calculate hash
        with open(binary_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()

        # Create metadata
        metadata = {
            'original_file': os.path.abspath(binary_path),
            'backup_file': os.path.abspath(backup_path),
            'timestamp': timestamp,
            'sha256': file_hash,
            'file_size': os.path.getsize(binary_path)
        }

        # Save metadata
        metadata_path = backup_path + ".meta.json"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)

        return backup_path

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
• **PE String Obfuscation**: Advanced PE-specific string analysis and obfuscation

**Key Features:**
• Section analysis with safety assessment
• Plugin system for entropy analysis, string extraction, etc.
• Multiple report formats (HTML, JSON, YAML, XML)
• Interactive hex viewer with color-coded annotations
• Custom range specification with hex notation support
• Advanced PE string detection and multiple obfuscation methods

**Command Examples:**
• Quick analysis: `cumpyl binary.exe --analyze-sections --suggest-obfuscation`
• Interactive hex: `cumpyl binary.exe --hex-view-interactive`
• Full workflow: `cumpyl binary.exe --hex-view --run-analysis --suggest-obfuscation`
• Custom range: `cumpyl binary.exe --hex-view --hex-view-offset 0x1000 --hex-view-bytes 2048`
• PE String analysis: `cumpyl binary.exe --pe-string-obfuscate`
• PE String report: `cumpyl binary.exe --pe-string-obfuscate --report-format html --report-output report.html`
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
                    self.run_cfg_analysis()
                elif choice == "7":
                    self.pe_string_obfuscation_menu()
                elif choice == "8":
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