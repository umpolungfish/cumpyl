#!/usr/bin/env python3
"""
Start Menu System for Cumpyl Framework
Main entry point with three core modules:
1. Build-a-Binary (Binary editor and obfuscator)
2. Lucky Strikes (Packers)
3. Silly String (string/payload obfuscator)
"""

import os
import sys
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt

try:
    from .config import ConfigManager
except ImportError:
    try:
        from config import ConfigManager
    except ImportError:
        ConfigManager = None

# Import CumpylMenu for fallback options
try:
    from .menu_system import CumpylMenu
except ImportError:
    try:
        from menu_system import CumpylMenu
    except ImportError:
        CumpylMenu = None

class CumpylStartMenu:
    """Main Start Menu for Cumpyl Framework"""
    
    def __init__(self, config: ConfigManager = None):
        """Initialize the start menu"""
        self.console = Console()
        self.config = config
        
    def show_banner(self):
        """Display the Cumpyl Start Banner"""
        banner_text = Text()
        banner_text.append("CUMPYL FRAMEWORK v0.3.0\n", style="bold red")
        banner_text.append("Advanced Binary Analysis & Rewriting Platform\n", style="bold cyan")
        banner_text.append("Modular Menu System", style="bold yellow")
        
        banner_panel = Panel(
            banner_text,
            border_style="bright_blue",
            padding=(1, 2),
            title="Welcome",
            title_align="center"
        )
        
        self.console.print(banner_panel)
        self.console.print()
        
    def show_main_menu(self) -> str:
        """Display the main start menu"""
        menu_options = [
            ("1", "Build-a-Binary", "Binary editor and obfuscator"),
            ("2", "Lucky Strikes", "Binary Packers and compression tools"),
            ("3", "Silly String", "Payload and string obfuscation tools"),
            ("h", "Help", "Show detailed help and examples"),
            ("q", "Quit", "Exit the framework")
        ]
        
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Option", style="bold cyan", width=8)
        table.add_column("Module", style="bold white", width=25)
        table.add_column("Description", style="dim")
        
        for option, module, description in menu_options:
            table.add_row(option, module, description)
        
        menu_panel = Panel(
            table,
            title="Cumpyl Start Menu",
            border_style="bright_green",
            padding=(1, 1)
        )
        
        self.console.print(menu_panel)
        
        return Prompt.ask(
            "\n[bold yellow]Select a module[/bold yellow]",
            choices=[opt[0] for opt in menu_options],
            default="1"
        )
        
    def launch_build_a_binary(self):
        """Launch the Build-a-Binary menu"""
        try:
            # Import here to avoid circular imports
            from .build_binary_menu import BuildBinaryMenu
            build_menu = BuildBinaryMenu(self.config)
            build_menu.run()
        except ImportError:
            # Fallback to main menu if specialized menu not available
            self.console.print("[yellow]Build-a-Binary menu not available, launching main menu[/yellow]")
            menu = CumpylMenu(self.config)
            menu.run()
        
    def launch_lucky_strikes(self):
        """Launch the Lucky Strikes (Packers) menu"""
        try:
            # Import the Lucky Strikes menu
            from .lucky_strikes_menu import launch_lucky_strikes_menu
            # We need a target file for the packer menu
            target_file = self.select_target_file()
            if target_file:
                launch_lucky_strikes_menu(self.config, target_file)
        except ImportError:
            # Fallback to original packer menu in main menu
            self.console.print("[yellow]Lucky Strikes menu not available, launching main menu[/yellow]")
            menu = CumpylMenu(self.config)
            # Directly call the packer menu
            menu.pe_packer_menu()
            
    def launch_silly_string(self):
        """Launch the Silly String (Payload Obfuscation) menu"""
        try:
            # Import the payload transmutation menu
            from .payload_transmutation_menu import PayloadTransmutationMenu
            pt_menu = PayloadTransmutationMenu(self.config)
            pt_menu.run()
        except ImportError:
            self.console.print("[red]Payload transmutation menu not available[/red]")
            self.console.print("[yellow]Make sure the payload_transmutation_menu module is properly installed[/yellow]")
            
    def select_target_file(self) -> Optional[str]:
        """Select a target binary file"""
        self.console.print(Panel("Target File Selection", style="bold green"))
        
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
            self.console.print("Found binary files in current directory:")
            
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
                return binary_files[int(choice)]
            else:
                return choice
        else:
            return Prompt.ask("Enter path to binary file")
            
    def show_help(self):
        """Display help information"""
        help_text = """
CUMPYL FRAMEWORK - Advanced Binary Analysis & Rewriting Platform

Core Modules:
1. Build-a-Binary: 
   - Binary analysis and modification
   - Section analysis and obfuscation
   - Interactive hex viewer
   - Encoding operations

2. Lucky Strikes: 
   - Binary packing and compression
   - Plugin-based packers (Go, CGO, Generic)
   - Encryption and anti-detection techniques
   - Integration with real packer tools

3. Silly String: 
   - Payload transmutation and obfuscation
   - Multiple encoding techniques
   - Environment variable substitution
   - Compound encoding chains

Interface Features:
• Rich text interface with color-coded panels
• Interactive menus with clear options
• Detailed help and examples for each module
• Configurable settings and profiles

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
        """Run the start menu loop"""
        self.show_banner()
        
        while True:
            try:
                choice = self.show_main_menu()
                
                if choice == "q":
                    self.console.print("[bold green]Thank you for using Cumpyl Framework![/bold green]")
                    break
                elif choice == "1":
                    self.launch_build_a_binary()
                elif choice == "2":
                    self.launch_lucky_strikes()
                elif choice == "3":
                    self.launch_silly_string()
                elif choice == "h":
                    self.show_help()
                    
            except KeyboardInterrupt:
                self.console.print("\n[bold yellow]Use 'q' to quit gracefully[/bold yellow]")
            except Exception as e:
                self.console.print(f"[bold red]Menu error: {e}[/bold red]")
                Prompt.ask("Press Enter to continue", default="")

def launch_start_menu(config: ConfigManager = None):
    """Launch the start menu"""
    menu = CumpylStartMenu(config)
    menu.run()

if __name__ == "__main__":
    launch_start_menu()