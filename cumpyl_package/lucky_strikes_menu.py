#!/usr/bin/env python3
"""
Lucky Strikes Menu System for Cumpyl Framework
Binary Packers and compression tools module
"""

import os
import sys
import importlib
import json
import subprocess
from typing import Dict, Any, List
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt, Confirm

# Add the plugins directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'plugins'))

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


class LuckyStrikesMenu:
    """Lucky Strikes Menu for Cumpyl Framework"""
    
    def __init__(self, config: ConfigManager = None):
        """Initialize the Lucky Strikes menu"""
        self.console = Console()
        self.config = config
        self.target_file = None
        
    def show_banner(self):
        """Display the Lucky Strikes Banner"""
        banner_text = Text()
        banner_text.append("LUCKY STRIKES MODULE", style="bold red")
        banner_text.append("Binary Packers & Compression Tools", style="bold cyan")
        banner_text.append("Part of Cumpyl Framework", style="bold blue")
        
        banner_panel = Panel(
            banner_text,
            border_style="bright_blue",
            padding=(1, 2),
            title="Lucky Strikes",
            title_align="center"
        )
        
        self.console.print(banner_panel)
        self.console.print()
        
    def select_target_file(self) -> bool:
        """Select the target binary file"""
        self.console.print(Panel("🎯 Target File Selection", style="bold green"))
        
        # Present files in current directory
        current_dir = os.getcwd()
        binary_files = []
        
        # Look for common binary files
        for root, dirs, files in os.walk(current_dir):
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
            self.console.print("📁 Found binary files in current directory:")
            
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
            self.console.print(f"[red]❌ File not found: {self.target_file}[/red]")
            return False
        
        self.console.print(f"[green]✅ Target selected: {self.target_file}[/green]")
        return True
        
    def show_main_menu(self) -> str:
        """Display the Lucky Strikes main menu"""
        menu_options = [
            ("1", "Analyze Binary", "Analyze binary for packing opportunities"),
            ("2", "Pack Binary", "Apply packing with various techniques"),
            ("3", "Interactive Hex Viewer", "Explore packed binary with interactive hex dump"),
            ("4", "View Analysis Results", "Display previous analysis results"),
            ("5", "Change Target", "Select a different binary file"),
            ("b", "Back", "Return to main start menu"),
            ("h", "Help", "Show detailed help and examples"),
            ("q", "Quit", "Exit the framework")
        ]
        
        self.console.print(Panel(f"🎯 Target: {self.target_file}", style="bold blue"))
        
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Option", style="bold cyan", width=8)
        table.add_column("Action", style="bold white", width=25)
        table.add_column("Description", style="dim")
        
        for option, action, description in menu_options:
            table.add_row(option, action, description)
        
        menu_panel = Panel(
            table,
            title="🎯 Lucky Strikes Menu",
            border_style="bright_green",
            padding=(1, 1)
        )
        
        self.console.print(menu_panel)
        
        return Prompt.ask(
            "[bold yellow]Select an option[/bold yellow]",
            choices=[opt[0] for opt in menu_options],
            default="1"
        )
    
    def list_available_plugins(self) -> Dict[str, List[str]]:
        """List all available plugins in the plugins directory."""
        plugins_dir = os.path.join(os.path.dirname(__file__), '..', 'plugins')
        packing_plugins = []
        
        # Look for plugin files
        for filename in os.listdir(plugins_dir):
            if filename.endswith('_plugin.py') and filename not in ['base_plugin.py']:
                plugin_name = filename.replace('_plugin.py', '')
                # Exclude test plugins and transmuter plugin (has its own menu)
                if plugin_name.startswith('test_') or plugin_name == 'transmuter':
                    continue
                # Exclude packer_transform as it's the same as packer plugin
                if plugin_name == 'packer_transform':
                    continue
                # Add all packing plugins - they should all be transformative
                packing_plugins.append(plugin_name)
        
        # Ensure packer is included
        if 'packer' not in packing_plugins:
            packing_plugins.append('packer')
        
        return {
            'analysis': packing_plugins,  # All plugins can do analysis
            'transformation': packing_plugins  # All plugins can do transformation
        }
    
    def load_plugin(self, plugin_name: str, plugin_type: str):
        """Dynamically load a plugin module."""
        try:
            # Handle packer_transform as an alias for packer
            if plugin_name == 'packer_transform':
                plugin_name = 'packer'
            
            if plugin_name == 'packer' and plugin_type == 'analysis':
                from plugins.packer_plugin import get_plugin
                return get_plugin
            elif plugin_name == 'packer' and plugin_type == 'transformation':
                from plugins.packer_plugin import get_transform_plugin
                return get_transform_plugin
            else:
                # Try to load other plugins dynamically
                # Use direct import instead of importlib for better path handling
                if plugin_name == 'cgo_packer':
                    import plugins.cgo_packer_plugin
                    module = plugins.cgo_packer_plugin
                elif plugin_name == 'go_packer':
                    import plugins.go_packer_plugin
                    module = plugins.go_packer_plugin
                elif plugin_name == 'transmuter':
                    import plugins.transmuter_plugin
                    module = plugins.transmuter_plugin
                else:
                    # Fallback to importlib
                    module_name = f"plugins.{plugin_name}_plugin"
                    module = importlib.import_module(module_name)
                
                if plugin_type == 'analysis':
                    if hasattr(module, 'get_analysis_plugin'):
                        return getattr(module, 'get_analysis_plugin')
                    elif hasattr(module, 'get_plugin'):
                        return getattr(module, 'get_plugin')
                elif plugin_type == 'transformation':
                    if hasattr(module, 'get_transformation_plugin'):
                        return getattr(module, 'get_transformation_plugin')
                    elif hasattr(module, 'get_transform_plugin'):
                        return getattr(module, 'get_transform_plugin')
                
                # Fallback to get_plugins if it exists
                if hasattr(module, 'get_plugins'):
                    plugins = getattr(module, 'get_plugins')({})
                    return plugins.get(plugin_type)
                    
        except Exception as e:
            print(f"Error loading {plugin_type} plugin '{plugin_name}': {e}")
            return None
    
    def configure_plugin(self, plugin_name: str) -> Dict[str, Any]:
        """Get configuration for a plugin from user input."""
        config = {}
        print(f"Configuring {plugin_name} plugin:")
        
        # Common configuration options
        if plugin_name in ['packer', 'packer_transform']:
            compression = Prompt.ask("Compression level (1-9, default 6)", default="6").strip()
            if compression:
                try:
                    config['compression_level'] = int(compression)
                except ValueError:
                    config['compression_level'] = 6
            
            key_path = Prompt.ask("Encryption key path (leave empty to disable encryption)", default="").strip()
            if key_path:
                config['key_path'] = key_path
                config['encrypt_sections'] = True
            else:
                config['encrypt_sections'] = False
                
            safe_mode = Prompt.ask("Enable safe mode? (y/n, default y)", default="y").strip().lower()
            config['safe_mode'] = safe_mode != 'n'
            
            dry_run = Prompt.ask("Enable dry run mode? (y/n, default n)", default="n").strip().lower()
            config['dry_run'] = dry_run == 'y'
            
            skip_pointer = Prompt.ask("Skip pointer sections? (y/n, default y)", default="y").strip().lower()
            config['skip_pointer_sections'] = skip_pointer != 'n'
        elif plugin_name == 'cgo_packer':
            # CGO packer specific configuration
            compression = Prompt.ask("Compression level (1-9, default 6)", default="6").strip()
            if compression:
                try:
                    config['compression_level'] = int(compression)
                except ValueError:
                    config['compression_level'] = 6
            
            # For CGO packer, disable dry run by default to actually save files
            dry_run = Prompt.ask("Enable dry run mode? (y/n, default n)", default="n").strip().lower()
            config['dry_run'] = dry_run == 'y'
            
            encrypt_sections = Prompt.ask("Encrypt sections? (y/n, default y)", default="y").strip().lower()
            config['encrypt_sections'] = encrypt_sections != 'n'
            
            obfuscate_symbols = Prompt.ask("Obfuscate symbols? (y/n, default y)", default="y").strip().lower()
            config['obfuscate_symbols'] = obfuscate_symbols != 'n'
            
            preserve_cgo_symbols = Prompt.ask("Preserve CGO symbols? (y/n, default y)", default="y").strip().lower()
            config['preserve_cgo_symbols'] = preserve_cgo_symbols != 'n'
        elif plugin_name == 'go_packer':
            # Go packer specific configuration
            compression = Prompt.ask("Compression level (1-9, default 6)", default="6").strip()
            if compression:
                try:
                    config['compression_level'] = int(compression)
                except ValueError:
                    config['compression_level'] = 6
            
            # For Go packer, disable dry run by default to actually save files
            dry_run = Prompt.ask("Enable dry run mode? (y/n, default n)", default="n").strip().lower()
            config['dry_run'] = dry_run == 'y'
            
            encrypt_sections = Prompt.ask("Encrypt sections? (y/n, default y)", default="y").strip().lower()
            config['encrypt_sections'] = encrypt_sections != 'n'
            
            obfuscate_symbols = Prompt.ask("Obfuscate symbols? (y/n, default y)", default="y").strip().lower()
            config['obfuscate_symbols'] = obfuscate_symbols != 'n'
            
            preserve_cgo_symbols = Prompt.ask("Preserve CGO symbols? (y/n, default y)", default="y").strip().lower()
            config['preserve_cgo_symbols'] = preserve_cgo_symbols != 'n'
        
        return config
    
    def analyze_binary_with_plugin(self, plugin_factory, config: Dict[str, Any], binary_path: str):
        """Analyze a binary using the selected plugin."""
        try:
            # Import required modules
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'cumpyl_package'))
            
            # Create config and rewriter
            config_manager = ConfigManager()  # Create with default config
            # Update with our custom config
            if hasattr(config_manager, 'config_data'):
                config_manager.config_data.update(config)
            rewriter = BinaryRewriter(binary_path, config_manager)
            
            # Load the binary
            if not rewriter.load_binary():
                print("[-] Failed to load binary")
                return None
                
            # Create plugin instance
            plugin = plugin_factory(config_manager)
            
            # Analyze with plugin
            print(f"[+] Analyzing binary with {plugin.name if hasattr(plugin, 'name') else 'selected'} plugin...")
            analysis_result = plugin.analyze(rewriter)
            
            return analysis_result
        except Exception as e:
            print(f"[-] Analysis failed: {e}")
            return None
    
    def transform_binary_with_plugin(self, plugin_factory, config: Dict[str, Any], binary_path: str, analysis_result: Dict[str, Any]):
        """Transform a binary using the selected plugin."""
        try:
            # Create config and rewriter
            config_manager = ConfigManager()  # Create with default config
            # Update with our custom config
            if hasattr(config_manager, 'config_data'):
                config_manager.config_data.update(config)
            rewriter = BinaryRewriter(binary_path, config_manager)
            
            # Load the binary
            if not rewriter.load_binary():
                print("[-] Failed to load binary")
                return False
                
            # Create plugin instance
            plugin = plugin_factory(config_manager)
            
            # Transform with plugin
            print(f"[+] Transforming binary with {plugin.name if hasattr(plugin, 'name') else 'selected'} plugin...")
            transform_result = plugin.transform(rewriter, analysis_result)
            
            if transform_result:
                # Save transformed binary
                output_file = config.get('output_path', f"packed_{os.path.basename(binary_path)}")
                
                # Check if plugin has save_packed_binary method
                if hasattr(plugin, 'save_packed_binary'):
                    # Only save if not in dry run mode
                    if not config.get('dry_run', True):
                        save_result = plugin.save_packed_binary(rewriter, output_file)
                        if save_result:
                            print(f"[+] Saved transformed binary to: {output_file}")
                        else:
                            print("[-] Failed to save transformed binary")
                    else:
                        print("[+] Dry run mode: Transformation completed but binary not saved")
                else:
                    # Try to save using rewriter's save_binary method
                    # Only save if not in dry run mode
                    if not config.get('dry_run', True):
                        save_result = rewriter.save_binary(output_file)
                        if save_result:
                            print(f"[+] Saved transformed binary to: {output_file}")
                        else:
                            print("[-] Failed to save transformed binary")
                    else:
                        print("[+] Dry run mode: Transformation completed but binary not saved")
                return True
            else:
                print("[-] Transformation failed")
                return False
        except Exception as e:
            print(f"[-] Transformation failed: {e}")
            return False
    
    def display_analysis_results(self, results: Dict[str, Any]):
        """Display analysis results in a user-friendly format."""
        if not results:
            print("No analysis results to display")
            return
        
        print("" + "="*50)
        print("ANALYSIS RESULTS")
        print("="*50)
        
        # Basic plugin info
        print(f"Plugin: {results.get('plugin_name', 'Unknown')}")
        print(f"Version: {results.get('version', 'Unknown')}")
        print(f"Description: {results.get('description', 'No description')}")
        
        # Binary format if available
        if 'binary_format' in results:
            print(f"Binary Format: {results['binary_format']}")
        
        # Analysis details
        if 'analysis' in results:
            analysis = results['analysis']
            print(f"Binary Size: {analysis.get('binary_size', 0)} bytes")
            print(f"Sections Count: {analysis.get('sections_count', 0)}")
            
            # Sections
            sections = analysis.get('sections', [])
            if sections:
                print("Sections:")
                print("-" * 60)
                for section in sections:
                    perms = ""
                    if section.get('is_executable'):
                        perms += "X"
                    if section.get('is_readable'):
                        perms += "R"
                    if section.get('is_writable'):
                        perms += "W"
                    print(f"  {section['name']:<15} {section['size']:>10} bytes  {perms}")
            
            # Packing opportunities
            opportunities = analysis.get('packing_opportunities', [])
            if opportunities:
                print("Packing Opportunities:")
                print("-" * 60)
                for opp in opportunities:
                    opp_type = opp.get('type', 'Unknown')
                    print(f"  {opp.get('section', 'Unknown'):<15} {opp.get('size', 0):>10} bytes  {opp_type}")
            
            # Go detection (if present)
            if 'go_detection' in analysis:
                go_detection = analysis['go_detection']
                if go_detection.get('detected'):
                    print(f"Go Binary Detected:")
                    print(f"  Confidence: {go_detection.get('confidence', 0.0):.2f}")
                    print(f"  Method: {go_detection.get('method', 'Unknown')}")
        
        # Suggestions
        suggestions = results.get('suggestions', [])
        if suggestions:
            print("Suggestions:")
            print("-" * 60)
            for suggestion in suggestions:
                print(f"  {suggestion.get('description', 'No description')}")
                if 'recommendation' in suggestion:
                    print(f"    Recommendation: {suggestion['recommendation']}")
        
        # Transformation plan (if present)
        if 'transformation_plan' in results:
            plan = results['transformation_plan']
            if plan and plan.get('actions'):
                print("Transformation Plan:")
                print("-" * 60)
                for action in plan['actions']:
                    print(f"  {action.get('type', 'Unknown action')}: {action.get('description', 'No description')}")
    
    def analyze_binary_menu(self):
        """Analyze binary menu"""
        self.console.print(Panel("🔍 Binary Analysis Options", style="bold green"))
        
        # Get available plugins
        plugins = self.list_available_plugins()
        analysis_plugins = plugins['analysis']
        
        if not analysis_plugins:
            self.console.print("[red]No analysis plugins available[/red]")
            return
        
        # Display plugin options
        plugin_options = []
        for i, plugin_name in enumerate(analysis_plugins, 1):
            plugin_options.append((str(i), f"{plugin_name} plugin", f"Analyze with {plugin_name} plugin"))
        
        plugin_options.append(("b", "Back to Main Menu", ""))
        
        table = Table(show_header=True, header_style="bold")
        table.add_column("Option", style="cyan", width=8)
        table.add_column("Plugin", style="white", width=20)
        table.add_column("Description", style="dim")
        
        for opt, plugin, desc in plugin_options:
            table.add_row(opt, plugin, desc)
        
        self.console.print(table)
        
        choice = Prompt.ask(
            "[yellow]Select analysis plugin[/yellow]",
            choices=[opt[0] for opt in plugin_options],
            default="1"
        )
        
        if choice == "b":
            return
        
        # Get selected plugin
        selected_index = int(choice) - 1
        if selected_index < 0 or selected_index >= len(analysis_plugins):
            self.console.print("[red]Invalid plugin selection[/red]")
            return
            
        selected_plugin = analysis_plugins[selected_index]
        self.console.print(f"[green]Selected plugin: {selected_plugin}[/green]")
        
        # Configure plugin
        config = self.configure_plugin(selected_plugin)
        
        # Load plugin
        plugin_factory = self.load_plugin(selected_plugin, 'analysis')
        if not plugin_factory:
            self.console.print("[red]Failed to load plugin[/red]")
            return
        
        # Analyze binary
        results = self.analyze_binary_with_plugin(plugin_factory, config, self.target_file)
        if results:
            self.display_analysis_results(results)
            
            # Ask if user wants to save results
            save_choice = Prompt.ask("Save analysis results to file? (y/n)", default="n").strip().lower()
            if save_choice == 'y':
                output_file = Prompt.ask("Enter output filename (default: analysis_results.json)", default="analysis_results.json").strip()
                try:
                    with open(output_file, 'w') as f:
                        json.dump(results, f, indent=2)
                    self.console.print(f"[green]Results saved to {output_file}[/green]")
                except Exception as e:
                    self.console.print(f"[red]Failed to save results: {e}[/red]")
        else:
            self.console.print("[red]Analysis failed[/red]")
    
    def pack_binary_menu(self):
        """Pack binary menu"""
        self.console.print(Panel("📦 Binary Packing Options", style="bold red"))
        
        # Get available plugins
        plugins = self.list_available_plugins()
        transform_plugins = plugins['transformation']
        
        # Display plugin options including CA Packer
        plugin_options = []
        for i, plugin_name in enumerate(transform_plugins, 1):
            plugin_options.append((str(i), f"{plugin_name} plugin", f"Pack with {plugin_name} plugin"))
        
        # Add CA Packer as a single option
        plugin_options.append((str(len(transform_plugins) + 1), "CA Packer", "Cellular Automata-based packer"))
        plugin_options.append(("b", "Back to Main Menu", ""))
        
        table = Table(show_header=True, header_style="bold")
        table.add_column("Option", style="cyan", width=8)
        table.add_column("Plugin", style="white", width=20)
        table.add_column("Description", style="dim")
        
        for opt, plugin, desc in plugin_options:
            table.add_row(opt, plugin, desc)
        
        self.console.print(table)
        
        choice = Prompt.ask(
            "[yellow]Select packing plugin[/yellow]",
            choices=[opt[0] for opt in plugin_options],
            default="1"
        )
        
        if choice == "b":
            return
        
        # Check if CA Packer was selected
        ca_packer_index = str(len(transform_plugins) + 1)
        if choice == ca_packer_index:
            # Show CA Packer submenu
            self.ca_packer_menu()
            return
        
        # Get selected plugin
        selected_index = int(choice) - 1
        if selected_index < 0 or selected_index >= len(transform_plugins):
            self.console.print("[red]Invalid plugin selection[/red]")
            return
            
        selected_plugin = transform_plugins[selected_index]
        self.console.print(f"[green]Selected plugin: {selected_plugin}[/green]")
        
        # Configure plugin
        config = self.configure_plugin(selected_plugin)
        
        # Get output path
        output_path = Prompt.ask("Output file path (leave empty for default)", default="").strip()
        if output_path:
            config['output_path'] = output_path
        
        # Load plugin
        plugin_factory = self.load_plugin(selected_plugin, 'transformation')
        if not plugin_factory:
            self.console.print("[red]Failed to load plugin[/red]")
            return
        
        # First run analysis (required for most transformation plugins)
        self.console.print("[yellow]Running preliminary analysis...[/yellow]")
        analysis_plugin_factory = self.load_plugin('packer', 'analysis')  # Use packer as default analysis
        if analysis_plugin_factory:
            analysis_results = self.analyze_binary_with_plugin(analysis_plugin_factory, config, self.target_file)
            if analysis_results:
                # Transform binary
                success = self.transform_binary_with_plugin(plugin_factory, config, self.target_file, analysis_results)
                if success:
                    self.console.print("[green]Transformation completed successfully[/green]")
                else:
                    self.console.print("[red]Transformation failed[/red]")
            else:
                self.console.print("[red]Preliminary analysis failed[/red]")
        else:
            self.console.print("[red]Failed to load analysis plugin[/red]")
    
    def hex_viewer_menu(self):
        """Interactive hex viewer menu"""
        self.console.print(Panel("🔧 Interactive Hex Viewer Options", style="bold magenta"))
        
        options = [
            ("1", "Basic Hex View (HTML)", f"cumpyl {self.target_file} --hex-view"),
            ("2", "Interactive Section Selection (HTML)", f"cumpyl {self.target_file} --hex-view --hex-view-interactive"),
            ("3", "Interactive Terminal Hex Viewer", "Launch TUI hex viewer with navigation"),
            ("4", "Hex + Full Analysis", f"cumpyl {self.target_file} --hex-view --run-analysis --suggest-obfuscation"),
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
            "[yellow]Select hex viewer option[/yellow]",
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
                self.console.print("[green]✅ Detected structured binary (PE/ELF/Mach-O)[/green]")
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
            
        self.console.print(f"[green]📁 Loaded {len(binary_data)} bytes for hex viewing[/green]")
        self.console.print("[green]Launching fallback hex viewer...[/green]")
        self.console.print("[yellow]Note: For the full interactive experience, use the Textual hex viewer option[/yellow]")
        
        # Basic hex dump implementation as fallback
        self.console.print(f"[bold cyan]Hex dump of first 512 bytes:[/bold cyan]")
        hex_lines = []
        for i in range(0, min(512, len(binary_data)), 16):
            line_data = binary_data[i:i+16]
            hex_part = ' '.join(f'{b:02x}' for b in line_data)
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in line_data)
            hex_lines.append(f"{i:08x}  {hex_part:<48} |{ascii_part}|")
        
        for line in hex_lines:
            self.console.print(f"[dim]{line}[/dim]")
        
        if len(binary_data) > 512:
            self.console.print(f"[yellow]... and {len(binary_data) - 512} more bytes[/yellow]")
    
    def execute_command(self, command: str):
        """Execute a Cumpyl command"""
        self.console.print(f"[bold green]🚀 Executing:[/bold green] [cyan]{command}[/cyan]")
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
                self.console.print("[bold green]✅ Command completed successfully![/bold green]")
            else:
                self.console.print(f"[bold red]❌ Command failed with return code: {result.returncode}[/bold red]")
                
        except Exception as e:
            self.console.print(f"[bold red]❌ Error executing command: {e}[/bold red]")
        
        self.console.print()
        Prompt.ask("Press Enter to continue", default="")
    
    def ca_packer_menu(self):
        """CA Packer submenu"""
        while True:
            self.console.print(Panel("Cellular Automata Packer", style="bold red"))
            
            # CA Packer options
            ca_options = [
                ("1", "Quick Pack", "Quick pack with default settings (100 steps, 1 iteration)"),
                ("2", "Choose Steps", "Choose number of CA steps for packing"),
                ("3", "Iterative Packing", "Iterative packing with custom steps and iterations"),
                ("b", "Back to Pack Binary Menu", "")
            ]
            
            table = Table(show_header=True, header_style="bold")
            table.add_column("Option", style="cyan", width=8)
            table.add_column("Action", style="white", width=20)
            table.add_column("Description", style="dim")
            
            for opt, action, desc in ca_options:
                table.add_row(opt, action, desc)
            
            self.console.print(table)
            
            choice = Prompt.ask(
                "[yellow]Select CA Packer option[/yellow]",
                choices=[opt[0] for opt in ca_options],
                default="1"
            )
            
            if choice == "b":
                return
            elif choice == "1":
                # CA Quick Pack
                self.run_ca_packer_quick()
            elif choice == "2":
                # CA Steps
                self.run_ca_packer_steps()
            elif choice == "3":
                # CA Iterative
                self.run_ca_packer_iterative()
    
    def run_ca_packer_quick(self):
        """Run the Cellular Automata-based packer with quick default settings"""
        self.console.print(Panel("CA Quick Pack", style="bold red"))
        
        # Use default settings: 100 CA steps, 1 iteration
        ca_steps = 100
        iterations = 1
        
        # Get output file name
        default_output = f"ca_quick_packed_{os.path.basename(self.target_file)}"
        output_file = Prompt.ask(f"Output file name (default: {default_output})", default=default_output)
        
        # Build command using the correct path
        cmd = f"python -m greenbay.ca_packer.packer {self.target_file} {output_file} --ca-steps {ca_steps}"
        
        # Execute command
        self.execute_ca_command(cmd)
    
    def run_ca_packer_steps(self):
        """Run the Cellular Automata-based packer with custom CA steps"""
        self.console.print(Panel("CA Steps", style="bold red"))
        
        # Get CA steps from user
        ca_steps = Prompt.ask("Enter number of CA steps (default: 100)", default="100")
        try:
            ca_steps = int(ca_steps)
        except ValueError:
            self.console.print("[yellow]Invalid CA steps, using default value of 100[/yellow]")
            ca_steps = 100
        
        # Use default iterations: 1
        iterations = 1
        
        # Get output file name
        default_output = f"ca_steps_packed_{os.path.basename(self.target_file)}"
        output_file = Prompt.ask(f"Output file name (default: {default_output})", default=default_output)
        
        # Build command using the correct path
        cmd = f"python -m greenbay.ca_packer.packer {self.target_file} {output_file} --ca-steps {ca_steps}"
        
        # Execute command
        self.execute_ca_command(cmd)
    
    def run_ca_packer_iterative(self):
        """Run the Cellular Automata-based packer with iterative packing"""
        self.console.print(Panel("CA Iterative Packing", style="bold red"))
        
        # Get CA steps from user
        ca_steps = Prompt.ask("Enter number of CA steps (default: 100)", default="100")
        try:
            ca_steps = int(ca_steps)
        except ValueError:
            self.console.print("[yellow]Invalid CA steps, using default value of 100[/yellow]")
            ca_steps = 100
        
        # Get number of iterations
        iterations = Prompt.ask("Enter number of packing iterations (default: 1)", default="1")
        try:
            iterations = int(iterations)
        except ValueError:
            self.console.print("[yellow]Invalid iterations, using default value of 1[/yellow]")
            iterations = 1
        
        # Get output file name
        default_output = f"ca_iter_packed_{os.path.basename(self.target_file)}"
        output_file = Prompt.ask(f"Output file name (default: {default_output})", default=default_output)
        
        # Build command using the correct path
        cmd = f"python -m greenbay.ca_packer.packer {self.target_file} {output_file} --ca-steps {ca_steps}"
        
        # For iterative packing, we'll need to run the packer multiple times
        if iterations > 1:
            self.console.print(f"[yellow]Iterative packing: {iterations} iterations with {ca_steps} CA steps each[/yellow]")
            current_input = self.target_file
            for i in range(iterations):
                iter_output = f"ca_iter_packed_{i+1}_{os.path.basename(self.target_file)}"
                iter_cmd = f"python -m greenbay.ca_packer.packer {current_input} {iter_output} --ca-steps {ca_steps}"
                
                self.console.print(f"[cyan]Running iteration {i+1}/{iterations}[/cyan]")
                self.execute_ca_command(iter_cmd)
                
                # For next iteration, use the output of this iteration as input
                current_input = iter_output
                
                # For the final iteration, use the user-specified output name
                if i == iterations - 1:
                    os.rename(iter_output, output_file)
        else:
            # Single iteration
            self.execute_ca_command(cmd)
    
    def execute_ca_command(self, command: str):
        """Execute a CA packer command"""
        self.console.print(f"[bold green]🚀 Executing CA Packer:[/bold green] [cyan]{command}[/cyan]")
        self.console.print("─" * 80)
        
        try:
            # Run the command with the correct working directory and PYTHONPATH
            env = os.environ.copy()
            project_root = os.path.join(os.path.dirname(__file__), '..')
            env['PYTHONPATH'] = project_root + ':' + env.get('PYTHONPATH', '')
            
            result = subprocess.run(
                command.split(),
                capture_output=True,
                text=True,
                cwd=project_root,
                env=env
            )
            
            self.console.print("─" * 80)
            if result.returncode == 0:
                self.console.print("[bold green]✅ CA Packer completed successfully![/bold green]")
                if result.stdout:
                    self.console.print(f"[dim]{result.stdout}[/dim]")
            else:
                self.console.print(f"[bold red]❌ CA Packer failed with return code: {result.returncode}[/bold red]")
                if result.stderr:
                    self.console.print(f"[red]{result.stderr}[/red]")
                    
        except Exception as e:
            self.console.print(f"[bold red]❌ Error executing CA Packer: {e}[/bold red]")
        
        self.console.print()
        Prompt.ask("Press Enter to continue", default="")
    
    def show_help(self):
        """Display help information"""
        help_text = """
🎯 **LUCKY STRIKES MODULE** - Binary Packers & Compression Tools

**💣 Features:**
• **Binary Analysis**: Analyze binaries for packing opportunities
• **Binary Packing**: Apply packing with various techniques (Generic, Go-aware, CGO-aware)
• **Plugin System**: Multiple packer plugins with different capabilities
• **Interactive Hex Viewer**: Explore packed binaries with rich annotations
• **Configuration Options**: Fine-tune compression, encryption, and other settings

**🔧 Key Features:**
• Multiple packer plugins (Generic, Go-aware, CGO-aware)
• Compression with configurable levels (1-9)
• Encryption with key management
• Anti-detection techniques
• Dry-run mode for testing
• Safe mode for cautious operations

**⚡ Command Examples:**
• Analyze: Use the analysis menu to identify packing opportunities
• Pack: Use the packing menu to apply transformations
• View: Examine packed binaries with the hex viewer

For detailed documentation, check the CLAUDE.md file in the project directory.
        """
        
        help_panel = Panel(
            help_text.strip(),
            title="📚 Lucky Strikes Help",
            border_style="bright_yellow",
            padding=(1, 2)
        )
        
        self.console.print(help_panel)
        Prompt.ask("Press Enter to continue", default="")
    
    def run(self):
        """Run the Lucky Strikes menu loop"""
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
                    self.analyze_binary_menu()
                elif choice == "2":
                    self.pack_binary_menu()
                elif choice == "3":
                    self.hex_viewer_menu()
                elif choice == "4":
                    # TODO: Implement viewing of previous analysis results
                    self.console.print("[yellow]Viewing previous analysis results coming soon![/yellow]")
                    Prompt.ask("Press Enter to continue", default="")
                elif choice == "5":
                    self.select_target_file()
                elif choice == "h":
                    self.show_help()
                    
            except KeyboardInterrupt:
                self.console.print("[bold yellow]💡 Use 'q' to quit gracefully[/bold yellow]")
            except Exception as e:
                self.console.print(f"[bold red]❌ Menu error: {e}[/bold red]")
                Prompt.ask("Press Enter to continue", default="")

def launch_lucky_strikes_menu(config: ConfigManager = None, target_file: str = None):
    """Launch the Lucky Strikes menu"""
    menu = LuckyStrikesMenu(config)
    if target_file:
        menu.target_file = target_file
    menu.run()

if __name__ == "__main__":
    launch_lucky_strikes_menu()