#!/usr/bin/env python3
"""
Silly String Menu System for Cumpyl Framework
Payload and string obfuscation tools module
"""

import os
import sys
from typing import Optional, Dict, Any
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt, Confirm
import argparse

try:
    from .config import ConfigManager
    # Try to import transmuter components
    from .transmuter import PayloadTransmuter, TransmuteConfig, TransmuteMethod, PayloadLibrary
except ImportError:
    try:
        from config import ConfigManager
        # Try to import transmuter components
        from transmuter import PayloadTransmuter, TransmuteConfig, TransmuteMethod, PayloadLibrary
    except ImportError:
        # Set to None to avoid errors during import
        ConfigManager = None
        PayloadTransmuter = None
        TransmuteConfig = None
        TransmuteMethod = None
        PayloadLibrary = None


class SillyStringMenu:
    """Silly String Menu for Cumpyl Framework"""
    
    def __init__(self, config: ConfigManager = None):
        """Initialize the Silly String menu"""
        self.console = Console()
        self.config = config
        
    def show_banner(self):
        """Display the Silly String Banner"""
        banner_text = Text()
        banner_text.append("SILLY STRING MODULE", style="bold magenta")
        banner_text.append("Payload & String Obfuscation Tools", style="bold cyan")
        banner_text.append("Part of Cumpyl Framework", style="bold blue")
        
        banner_panel = Panel(
            banner_text,
            border_style="bright_blue",
            padding=(1, 2),
            title="Silly String",
            title_align="center"
        )
        
        self.console.print(banner_panel)
        self.console.print()
        
    def show_main_menu(self) -> str:
        """Display the Silly String main menu"""
        menu_options = [
            ("1", "Single Payload", "Transmute a single payload"),
            ("2", "Payload Library", "Use built-in payload templates"),
            ("3", "File Processing", "Process payloads from a file"),
            ("4", "Configuration", "View and modify transmuter settings"),
            ("5", "List Methods", "List available transmutation methods"),
            ("6", "List Templates", "List available payload templates"),
            ("b", "Back", "Return to main start menu"),
            ("h", "Help", "Show detailed help and examples"),
            ("q", "Quit", "Exit the framework")
        ]
        
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Option", style="bold cyan", width=8)
        table.add_column("Action", style="bold white", width=20)
        table.add_column("Description", style="dim")
        
        for option, action, description in menu_options:
            table.add_row(option, action, description)
        
        menu_panel = Panel(
            table,
            title="Silly Strings",
            border_style="bright_green",
            padding=(1, 1)
        )
        
        self.console.print(menu_panel)
        
        return Prompt.ask(
            "[bold yellow]Select an option[/bold yellow]",
            choices=[opt[0] for opt in menu_options],
            default="1"
        )
        
    def single_payload_menu(self):
        """Single payload transmutation menu"""
        self.console.print(Panel("Single Payload Transmutation", style="bold magenta"))
        
        # Get payload from user
        payload = Prompt.ask("Enter payload to transmute")
        if not payload:
            self.console.print("[red]No payload provided[/red]")
            return
        
        # Select method
        method = self.select_transmutation_method()
        if not method:
            return
        
        # Configure transmuter
        config = TransmuteConfig()
        transmuter = PayloadTransmuter(config, verbose=True)
        
        try:
            # Perform transmutation
            result = transmuter.transmute(payload, method)
            
            # Display result
            self.display_transmutation_result(payload, method, result)
            
            # Ask if user wants to save results
            save_choice = Prompt.ask("\nSave results to file? (y/n)", default="n").strip().lower()
            if save_choice == 'y':
                output_file = Prompt.ask("Enter output filename", default="transmuted_payload.txt").strip()
                self.save_transmutation_result(payload, method, result, output_file)
        except Exception as e:
            self.console.print(f"[red]Error during transmutation: {e}[/red]")
    
    def payload_library_menu(self):
        """Payload library menu"""
        self.console.print(Panel("Payload Library", style="bold blue"))
        
        # List categories
        categories = PayloadLibrary.list_categories()
        if not categories:
            self.console.print("[red]No payload templates available[/red]")
            return
        
        # Display categories
        category_options = []
        for i, category in enumerate(categories, 1):
            payloads = PayloadLibrary.get_payloads(category)
            category_options.append((str(i), category, f"{len(payloads)} payloads"))
        
        category_options.append(("b", "Back to Main Menu", ""))
        
        table = Table(show_header=True, header_style="bold")
        table.add_column("Option", style="cyan", width=8)
        table.add_column("Category", style="white", width=20)
        table.add_column("Description", style="dim")
        
        for opt, category, desc in category_options:
            table.add_row(opt, category, desc)
        
        self.console.print(table)
        
        choice = Prompt.ask(
            "[yellow]Select payload category[/yellow]",
            choices=[opt[0] for opt in category_options],
            default="1"
        )
        
        if choice == "b":
            return
        
        # Get selected category
        selected_index = int(choice) - 1
        if selected_index < 0 or selected_index >= len(categories):
            self.console.print("[red]Invalid category selection[/red]")
            return
            
        selected_category = categories[selected_index]
        payloads = PayloadLibrary.get_payloads(selected_category)
        
        # Display payloads in category
        payload_options = []
        for i, payload in enumerate(payloads, 1):
            # Show preview of payload
            preview = payload[:50] + "..." if len(payload) > 50 else payload
            payload_options.append((str(i), preview, ""))
        
        payload_options.append(("b", "Back to Category Menu", ""))
        
        table = Table(show_header=True, header_style="bold")
        table.add_column("Option", style="cyan", width=8)
        table.add_column("Payload Preview", style="white")
        table.add_column("", style="dim")
        
        for opt, preview, _ in payload_options:
            table.add_row(opt, preview, "")
        
        self.console.print(table)
        
        choice = Prompt.ask(
            "[yellow]Select payload[/yellow]",
            choices=[opt[0] for opt in payload_options],
            default="1"
        )
        
        if choice == "b":
            return
        
        # Get selected payload
        selected_index = int(choice) - 1
        if selected_index < 0 or selected_index >= len(payloads):
            self.console.print("[red]Invalid payload selection[/red]")
            return
            
        selected_payload = payloads[selected_index]
        
        # Select method
        method = self.select_transmutation_method()
        if not method:
            return
        
        # Configure transmuter
        config = TransmuteConfig()
        transmuter = PayloadTransmuter(config, verbose=True)
        
        try:
            # Perform transmutation
            result = transmuter.transmute(selected_payload, method)
            
            # Display result
            self.display_transmutation_result(selected_payload, method, result)
            
            # Ask if user wants to save results
            save_choice = Prompt.ask("Save results to file? (y/n)", default="n").strip().lower()
            if save_choice == 'y':
                output_file = Prompt.ask("Enter output filename", default="transmuted_payload.txt").strip()
                self.save_transmutation_result(selected_payload, method, result, output_file)
        except Exception as e:
            self.console.print(f"[red]Error during transmutation: {e}[/red]")
    
    def file_processing_menu(self):
        """File processing menu"""
        self.console.print(Panel("File Processing", style="bold yellow"))
        
        # Get input file
        input_file = Prompt.ask("Enter path to input file (one payload per line)")
        if not input_file or not os.path.exists(input_file):
            self.console.print("[red]Invalid input file[/red]")
            return
        
        # Select method
        method = self.select_transmutation_method()
        if not method:
            return
        
        # Get output file
        output_file = Prompt.ask("Enter output file path", default="transmuted_payloads.txt").strip()
        
        try:
            # Read payloads from file
            with open(input_file, 'r') as f:
                payloads = [line.strip() for line in f if line.strip()]
            
            if not payloads:
                self.console.print("[red]No payloads found in input file[/red]")
                return
            
            # Configure transmuter
            config = TransmuteConfig()
            transmuter = PayloadTransmuter(config, verbose=False)  # Less verbose for batch processing
            
            # Process each payload
            results = {}
            for i, payload in enumerate(payloads):
                try:
                    result = transmuter.transmute(payload, method)
                    results[f"payload_{i+1}"] = {
                        "original": payload,
                        "method": method.value,
                        "transmuted": result
                    }
                    self.console.print(f"[green]Processed payload {i+1}/{len(payloads)}[/green]")
                except Exception as e:
                    self.console.print(f"[red]Error processing payload {i+1}: {e}[/red]")
                    results[f"payload_{i+1}"] = {
                        "original": payload,
                        "method": method.value,
                        "error": str(e)
                    }
            
            # Save all results
            self.save_batch_transmutation_results(results, output_file)
            self.console.print(f"[green]All results saved to {output_file}[/green]")
        except Exception as e:
            self.console.print(f"[red]Error during file processing: {e}[/red]")
    
    def configuration_menu(self):
        """Configuration menu"""
        self.console.print(Panel("Transmuter Configuration", style="bold cyan"))
        
        # TODO: Implement configuration management
        self.console.print("[yellow]Configuration management coming soon![/yellow]")
        Prompt.ask("Press Enter to continue", default="")
    
    def list_methods_menu(self):
        """List available transmutation methods"""
        self.console.print(Panel("Available Transmutation Methods", style="bold green"))
        
        table = Table(show_header=True, header_style="bold")
        table.add_column("Method", style="cyan")
        table.add_column("Description", style="white")
        
        # Method descriptions
        descriptions = {
            "null_padding": "Null byte padding transmutation",
            "unicode": "Unicode escape sequence encoding",
            "hex": "Hexadecimal encoding",
            "octal": "Octal encoding",
            "mixed": "Mixed encoding using multiple methods",
            "env_var": "Environment variable substitution",
            "base64": "Base64 encoding",
            "url_encode": "URL encoding",
            "compressed_b64": "Compressed Base64 encoding",
            "reverse": "Reverse string encoding",
            "rot13": "ROT13 encoding",
            "double_url": "Double URL encoding",
            "compound": "Compound encoding - chain multiple methods"
        }
        
        for method in TransmuteMethod:
            desc = descriptions.get(method.value, "No description available")
            table.add_row(method.value, desc)
        
        self.console.print(table)
        Prompt.ask("Press Enter to continue", default="")
    
    def list_templates_menu(self):
        """List available payload templates"""
        self.console.print(Panel("Available Payload Templates", style="bold blue"))
        
        categories = PayloadLibrary.list_categories()
        if not categories:
            self.console.print("[red]No payload templates available[/red]")
            return
        
        for category in categories:
            payloads = PayloadLibrary.get_payloads(category)
            self.console.print(f"[bold]{category}[/bold] ({len(payloads)} payloads):")
            
            for i, payload in enumerate(payloads, 1):
                # Show preview of payload
                preview = payload[:60] + "..." if len(payload) > 60 else payload
                self.console.print(f"  {i}. {preview}")
        
        Prompt.ask("Press Enter to continue", default="")
    
    def select_transmutation_method(self) -> Optional[TransmuteMethod]:
        """Prompt user to select a transmutation method"""
        # List methods with descriptions
        method_options = []
        descriptions = {
            "null_padding": "Null byte padding",
            "unicode": "Unicode escape sequences",
            "hex": "Hexadecimal encoding",
            "octal": "Octal encoding",
            "mixed": "Mixed encoding methods",
            "env_var": "Environment variable substitution",
            "base64": "Base64 encoding",
            "url_encode": "URL encoding",
            "compressed_b64": "Compressed Base64",
            "reverse": "Reverse string",
            "rot13": "ROT13 encoding",
            "double_url": "Double URL encoding",
            "compound": "Compound encoding chain"
        }
        
        for i, method in enumerate(TransmuteMethod, 1):
            desc = descriptions.get(method.value, "No description")
            method_options.append((str(i), method.value, desc))
        
        method_options.append(("b", "Back to Main Menu", ""))
        
        table = Table(show_header=True, header_style="bold")
        table.add_column("Option", style="cyan", width=8)
        table.add_column("Method", style="white", width=20)
        table.add_column("Description", style="dim")
        
        for opt, method, desc in method_options:
            table.add_row(opt, method, desc)
        
        self.console.print(table)
        
        choice = Prompt.ask(
            "[yellow]Select transmutation method[/yellow]",
            choices=[opt[0] for opt in method_options],
            default="1"
        )
        
        if choice == "b":
            return None
        
        # Get selected method
        selected_index = int(choice) - 1
        if selected_index < 0 or selected_index >= len(TransmuteMethod):
            self.console.print("[red]Invalid method selection[/red]")
            return None
            
        selected_method = list(TransmuteMethod)[selected_index]
        return selected_method
    
    def display_transmutation_result(self, original: str, method: TransmuteMethod, result: Any):
        """Display transmutation result"""
        self.console.print("\n" + "="*60)
        self.console.print("TRANSMUTATION RESULT", style="bold magenta")
        self.console.print("="*60)
        
        self.console.print(f"[bold]Original:[/bold] {original}")
        self.console.print(f"[bold]Method:[/bold] {method.value}")
        
        if isinstance(result, dict):
            # Mixed encoding result
            self.console.print("[bold]Results:[/bold]")
            for sub_method, sub_result in result.items():
                self.console.print(f"  [cyan]{sub_method}:[/cyan] {sub_result}")
        else:
            # Single result
            self.console.print(f"[bold]Transmuted:[/bold] {result}")
    
    def save_transmutation_result(self, original: str, method: TransmuteMethod, result: Any, output_file: str):
        """Save transmutation result to file"""
        try:
            with open(output_file, 'w') as f:
                f.write("TRANSMUTATION RESULT\n")
                f.write("="*60 + "\n")
                f.write(f"Original: {original}\n")
                f.write(f"Method: {method.value}\n\n")
                
                if isinstance(result, dict):
                    # Mixed encoding result
                    f.write("Results:\n")
                    for sub_method, sub_result in result.items():
                        f.write(f"  {sub_method}: {sub_result}\n")
                else:
                    # Single result
                    f.write(f"Transmuted: {result}\n")
            
            self.console.print(f"[green]Result saved to {output_file}[/green]")
        except Exception as e:
            self.console.print(f"[red]Error saving result: {e}[/red]")
    
    def save_batch_transmutation_results(self, results: Dict, output_file: str):
        """Save batch transmutation results to file"""
        try:
            with open(output_file, 'w') as f:
                f.write("BATCH TRANSMUTATION RESULTS\n")
                f.write("="*60 + "\n\n")
                
                for key, data in results.items():
                    f.write(f"--- {key} ---\n")
                    f.write(f"Original: {data.get('original', 'N/A')}\n")
                    f.write(f"Method: {data.get('method', 'N/A')}\n")
                    
                    if 'error' in data:
                        f.write(f"Error: {data['error']}\n")
                    else:
                        f.write(f"Transmuted: {data.get('transmuted', 'N/A')}\n")
                    
                    f.write("\n")
            
            self.console.print(f"[green]Batch results saved to {output_file}[/green]")
        except Exception as e:
            self.console.print(f"[red]Error saving batch results: {e}[/red]")
    
    def show_help(self):
        """Display help information"""
        help_text = """
SILLY STRING MODULE - Payload & String Obfuscation Tools

Features:
• Single Payload: Transmute individual payloads
• Payload Library: Use built-in payload templates
• File Processing: Process payloads from a file
• Multiple Methods: 13+ transmutation techniques
• Batch Processing: Handle multiple payloads at once

Transmutation Methods:
• Null Padding: Insert null bytes between characters
• Unicode: Convert to Unicode escape sequences
• Hex: Convert to hexadecimal representation
• Octal: Convert to octal representation
• Mixed: Combine multiple encoding methods
• Environment Variables: Substitute with env vars
• Base64: Standard Base64 encoding
• URL Encoding: Percent-encode characters
• Compressed B64: Compress then Base64 encode
• Reverse: Reverse the string
• ROT13: Rotate by 13 places
• Double URL: Apply URL encoding twice
• Compound: Chain multiple methods together

Payload Categories:
• SQL Injection
• Command Injection
• XSS (Cross-Site Scripting)
• Path Traversal
• File Inclusion
• Buffer Overflow

For detailed documentation, check the CLAUDE.md file in the project directory.
        """
        
        help_panel = Panel(
            help_text.strip(),
            title="Silly String Help",
            border_style="bright_yellow",
            padding=(1, 2)
        )
        
        self.console.print(help_panel)
        Prompt.ask("Press Enter to continue", default="")
    
    def run(self):
        """Run the Silly String menu loop"""
        self.show_banner()
        
        while True:
            try:
                choice = self.show_main_menu()
                
                if choice == "q":
                    self.console.print("[bold green]Exiting Cumpyl Framework![/bold green]")
                    break
                elif choice == "b":
                    # Return to start menu
                    break
                elif choice == "1":
                    self.single_payload_menu()
                elif choice == "2":
                    self.payload_library_menu()
                elif choice == "3":
                    self.file_processing_menu()
                elif choice == "4":
                    self.configuration_menu()
                elif choice == "5":
                    self.list_methods_menu()
                elif choice == "6":
                    self.list_templates_menu()
                elif choice == "h":
                    self.show_help()
                    
            except KeyboardInterrupt:
                self.console.print("[bold yellow]Use 'q' to quit gracefully[/bold yellow]")
            except Exception as e:
                self.console.print(f"[bold red]Menu error: {e}[/bold red]")
                Prompt.ask("Press Enter to continue", default="")

def launch_silly_string_menu(config: ConfigManager = None):
    """Launch the Silly String menu"""
    menu = SillyStringMenu(config)
    menu.run()

if __name__ == "__main__":
    launch_silly_string_menu()