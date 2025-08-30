#!/usr/bin/env python3
"""
Payload Transmutation Menu Implementation for Cumpyl Framework
This module implements the payload transmutation menu functionality
"""

import os
import sys
import json
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
    from .transmuter import PayloadTransmuter, TransmuteConfig, TransmuteMethod, PayloadLibrary
except ImportError as e:
    # Fallback for direct script execution
    try:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from cumpyl_package.config import ConfigManager
        from cumpyl_package.transmuter import PayloadTransmuter, TransmuteConfig, TransmuteMethod, PayloadLibrary
    except ImportError as e2:
        print(f"Import error: {e}")
        print(f"Fallback import error: {e2}")
        sys.exit(1)


class PayloadTransmutationMenu:
    """Payload transmutation menu implementation"""
    
    def __init__(self, config: ConfigManager = None):
        """Initialize the payload transmutation menu"""
        self.console = Console()
        self.config = config
        
    def show_menu(self) -> str:
        """Display the payload transmutation menu"""
        menu_options = [
            ("1", "Single Payload Transmutation", "Transmute a single payload with selected method"),
            ("2", "File-based Transmutation", "Transmute payloads from a file"),
            ("3", "Template-based Transmutation", "Use built-in payload templates"),
            ("4", "Compound Encoding", "Chain multiple encoding methods together"),
            ("5", "List Methods", "Show available transmutation methods"),
            ("6", "List Templates", "Show available payload templates"),
            ("b", "Back to Main Menu", "")
        ]
        
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Option", style="bold cyan", width=8)
        table.add_column("Action", style="bold white", width=30)
        table.add_column("Description", style="dim")
        
        for option, action, description in menu_options:
            table.add_row(option, action, description)
        
        menu_panel = Panel(
            table,
            title="🔓 Silly String Menu",
            border_style="bright_magenta",
            padding=(1, 1)
        )
        
        self.console.print(menu_panel)
        
        return Prompt.ask(
            "\n[bold yellow]Select an option[/bold yellow]",
            choices=[opt[0] for opt in menu_options],
            default="1"
        )
        
    def run(self):
        """Run the payload transmutation menu loop"""
        banner_text = Text()
        banner_text.append("SILLY STRING MODULE\n", style="bold magenta")
        banner_text.append("Payload & String Obfuscation Tools\n", style="bold yellow")
        banner_text.append("Part of Cumpyl Framework", style="bold blue")
        
        banner_panel = Panel(
            banner_text,
            border_style="bright_cyan",
            padding=(1, 2),
            title="🔓 Silly String",
            title_align="center"
        )
        
        self.console.print(banner_panel)
        self.console.print()
        
        while True:
            try:
                choice = self.show_menu()
                
                if choice == "b":
                    break
                elif choice == "1":
                    self.single_payload_transmutation()
                elif choice == "2":
                    self.file_based_transmutation()
                elif choice == "3":
                    self.template_based_transmutation()
                elif choice == "4":
                    self.compound_encoding()
                elif choice == "5":
                    self.list_methods()
                elif choice == "6":
                    self.list_templates()
                    
            except KeyboardInterrupt:
                self.console.print("\n[bold yellow]Returning to main menu...[/bold yellow]")
                break
            except Exception as e:
                self.console.print(f"[bold red]❌ Menu error: {e}[/bold red]")
                Prompt.ask("Press Enter to continue", default="")
                
    def single_payload_transmutation(self):
        """Single payload transmutation"""
        self.console.print(Panel("🔄 Single Payload Transmutation", style="bold blue"))
        
        payload = Prompt.ask("Enter payload to transmute")
        if not payload:
            self.console.print("[yellow]No payload entered[/yellow]")
            return
            
        # Show available methods
        self.console.print("\n[bold cyan]Available methods:[/bold cyan]")
        methods = [method.value for method in TransmuteMethod]
        for i, method in enumerate(methods, 1):
            self.console.print(f"  {i}. {method}")
            
        method_choice = Prompt.ask(
            "Select method (number or name)", 
            choices=[str(i) for i in range(1, len(methods)+1)] + methods,
            default="1"
        )
        
        # Convert to method enum
        if method_choice.isdigit():
            method = TransmuteMethod(methods[int(method_choice)-1])
        else:
            method = TransmuteMethod(method_choice)
        
        # Transmute
        config = TransmuteConfig()
        transmuter = PayloadTransmuter(config, verbose=True)
        result = transmuter.transmute(payload, method)
        
        # Display result
        self.console.print(f"\n[green]✅ Transmutation Result:[/green]")
        if isinstance(result, dict):
            for sub_method, sub_result in result.items():
                self.console.print(f"  [bold]{sub_method}:[/bold] {sub_result}")
        else:
            self.console.print(f"  [bold]{method.value}:[/bold] {result}")
            
        # Wait for user input
        Prompt.ask("\nPress Enter to continue", default="")
        
    def file_based_transmutation(self):
        """File-based transmutation"""
        self.console.print(Panel("📁 File-based Transmutation", style="bold blue"))
        
        file_path = Prompt.ask("Enter path to payload file (one per line)")
        if not os.path.exists(file_path):
            self.console.print(f"[red]❌ File not found: {file_path}[/red]")
            return
            
        # Read payloads
        with open(file_path, 'r') as f:
            payloads = [line.strip() for line in f if line.strip()]
            
        if not payloads:
            self.console.print("[yellow]No payloads found in file[/yellow]")
            return
            
        # Select method
        self.console.print("\n[bold cyan]Available methods:[/bold cyan]")
        methods = [method.value for method in TransmuteMethod]
        for i, method in enumerate(methods, 1):
            self.console.print(f"  {i}. {method}")
            
        method_choice = Prompt.ask(
            "Select method (number or name)", 
            choices=[str(i) for i in range(1, len(methods)+1)] + methods,
            default="1"
        )
        
        # Convert to method enum
        if method_choice.isdigit():
            method = TransmuteMethod(methods[int(method_choice)-1])
        else:
            method = TransmuteMethod(method_choice)
        
        # Output file
        output_file = Prompt.ask("Output file path (optional)", default="")
        
        # Transmute all payloads
        config = TransmuteConfig()
        transmuter = PayloadTransmuter(config, verbose=True)
        
        results = {}
        for i, payload in enumerate(payloads):
            self.console.print(f"\n[blue]Processing payload {i+1}/{len(payloads)}[/blue]")
            try:
                result = transmuter.transmute(payload, method)
                results[f"payload_{i+1}"] = {
                    "original": payload,
                    "method": method.value,
                    "transmuted": result
                }
                
                # Print result
                if isinstance(result, dict):
                    for sub_method, sub_result in result.items():
                        self.console.print(f"  [bold]{sub_method}:[/bold] {sub_result}")
                else:
                    self.console.print(f"  [bold]{method.value}:[/bold] {result}")
            except Exception as e:
                self.console.print(f"[red]❌ Error transmuting payload: {e}[/red]")
                results[f"payload_{i+1}"] = {
                    "original": payload,
                    "method": method.value,
                    "error": str(e)
                }
        
        # Save results if requested
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            self.console.print(f"\n[green]💾 Results saved to: {output_file}[/green]")
            
        # Wait for user input
        Prompt.ask("\nPress Enter to continue", default="")
        
    def template_based_transmutation(self):
        """Template-based transmutation"""
        self.console.print(Panel("💀 Template-based Transmutation", style="bold blue"))
        
        # Show available templates
        self.console.print("\n[bold cyan]Available templates:[/bold cyan]")
        templates = PayloadLibrary.list_categories()
        for i, template in enumerate(templates, 1):
            payloads = PayloadLibrary.get_payloads(template)
            self.console.print(f"  {i}. {template} ({len(payloads)} payloads)")
            
        if not templates:
            self.console.print("[yellow]No templates available[/yellow]")
            return
            
        template_choice = Prompt.ask(
            "Select template (number or name)", 
            choices=[str(i) for i in range(1, len(templates)+1)] + templates,
            default="1"
        )
        
        # Get template name
        if template_choice.isdigit():
            template_name = templates[int(template_choice)-1]
        else:
            template_name = template_choice
            
        # Get payloads
        payloads = PayloadLibrary.get_payloads(template_name)
        if not payloads:
            self.console.print(f"[yellow]No payloads in template: {template_name}[/yellow]")
            return
            
        # Select method
        self.console.print("\n[bold cyan]Available methods:[/bold cyan]")
        methods = [method.value for method in TransmuteMethod]
        for i, method in enumerate(methods, 1):
            self.console.print(f"  {i}. {method}")
            
        method_choice = Prompt.ask(
            "Select method (number or name)", 
            choices=[str(i) for i in range(1, len(methods)+1)] + methods,
            default="1"
        )
        
        # Convert to method enum
        if method_choice.isdigit():
            method = TransmuteMethod(methods[int(method_choice)-1])
        else:
            method = TransmuteMethod(method_choice)
        
        # Output file
        output_file = Prompt.ask("Output file path (optional)", default="")
        
        # Transmute all payloads
        config = TransmuteConfig()
        transmuter = PayloadTransmuter(config, verbose=True)
        
        results = {}
        for i, payload in enumerate(payloads):
            self.console.print(f"\n[blue]Processing payload {i+1}/{len(payloads)} from {template_name}[/blue]")
            try:
                result = transmuter.transmute(payload, method)
                results[f"payload_{i+1}"] = {
                    "original": payload,
                    "template": template_name,
                    "method": method.value,
                    "transmuted": result
                }
                
                # Print result
                if isinstance(result, dict):
                    for sub_method, sub_result in result.items():
                        self.console.print(f"  [bold]{sub_method}:[/bold] {sub_result}")
                else:
                    self.console.print(f"  [bold]{method.value}:[/bold] {result}")
            except Exception as e:
                self.console.print(f"[red]❌ Error transmuting payload: {e}[/red]")
                results[f"payload_{i+1}"] = {
                    "original": payload,
                    "template": template_name,
                    "method": method.value,
                    "error": str(e)
                }
        
        # Save results if requested
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            self.console.print(f"\n[green]💾 Results saved to: {output_file}[/green]")
            
        # Wait for user input
        Prompt.ask("\nPress Enter to continue", default="")
    
    def compound_encoding(self):
        """Compound encoding - chain multiple encoding methods together"""
        self.console.print(Panel("🔗 Compound Encoding", style="bold magenta"))
        
        payload = Prompt.ask("Enter payload to transmute")
        if not payload:
            self.console.print("[yellow]No payload entered[/yellow]")
            return
            
        # Get number of iterations
        iterations = Prompt.ask("Enter number of encoding iterations", default="3")
        try:
            iterations = int(iterations)
            if iterations < 1:
                iterations = 3
        except ValueError:
            iterations = 3
            
        # Ask if user wants to specify methods or use wildcard
        use_wildcard = Confirm.ask("Use random methods for each iteration? (wildcard mode)", default=False)
        
        methods = None
        if not use_wildcard:
            # Show available methods
            self.console.print("\n[bold cyan]Available methods:[/bold cyan]")
            available_methods = [method.value for method in TransmuteMethod if method != TransmuteMethod.COMPOUND and method != TransmuteMethod.MIXED]
            for i, method in enumerate(available_methods, 1):
                self.console.print(f"  {i}. {method}")
                
            # Get methods from user
            methods_input = Prompt.ask("Enter space-separated method names or numbers (e.g., 'hex base64 unicode' or '1 2 3')", default="")
            if methods_input:
                methods = []
                for item in methods_input.split():
                    if item.isdigit() and 1 <= int(item) <= len(available_methods):
                        methods.append(available_methods[int(item)-1])
                    elif item in available_methods:
                        methods.append(item)
                        
                if not methods:
                    methods = ["base64", "hex", "unicode"]  # Default methods
            else:
                methods = ["base64", "hex", "unicode"]  # Default methods
                
        # Output file
        output_file = Prompt.ask("Output file path (optional)", default="")
        
        # Transmute
        config = TransmuteConfig()
        transmuter = PayloadTransmuter(config, verbose=True)
        try:
            result = transmuter.transmute(
                payload, 
                TransmuteMethod.COMPOUND, 
                iterations=iterations,
                methods=methods,
                wildcard=use_wildcard
            )
            
            self.console.print(f"\n[green]✅ Compound Encoding Result:[/green]")
            self.console.print(f"  [bold]compound:[/bold] {result}")
            
            # Save result if requested
            if output_file:
                with open(output_file, 'w') as f:
                    json.dump({
                        "original": payload,
                        "method": "compound",
                        "iterations": iterations,
                        "methods": methods if not use_wildcard else "wildcard",
                        "transmuted": result
                    }, f, indent=2)
                self.console.print(f"\n[green]💾 Result saved to: {output_file}[/green]")
                
        except Exception as e:
            self.console.print(f"[red]❌ Error during compound encoding: {e}[/red]")
            
        # Wait for user input
        Prompt.ask("\nPress Enter to continue", default="")
        
    def list_methods(self):
        """List available transmutation methods"""
        self.console.print("\n[bold cyan]Available Transmutation Methods:[/bold cyan]")
        for method in TransmuteMethod:
            self.console.print(f"  • {method.value}")
            
        # Wait for user input
        Prompt.ask("\nPress Enter to continue", default="")
        
    def list_templates(self):
        """List available payload templates"""
        self.console.print("\n[bold cyan]Available Payload Templates:[/bold cyan]")
        for category in PayloadLibrary.list_categories():
            payloads = PayloadLibrary.get_payloads(category)
            self.console.print(f"  • {category} ({len(payloads)} payloads)")
            
        # Wait for user input
        Prompt.ask("\nPress Enter to continue", default="")


# Test function
def test_menu():
    """Test the payload transmutation menu"""
    config = ConfigManager()
    menu = PayloadTransmutationMenu(config)
    
    # Check if all methods exist
    methods_to_check = [
        'show_menu',
        'run',
        'single_payload_transmutation',
        'file_based_transmutation',
        'template_based_transmutation',
        'list_methods',
        'list_templates'
    ]
    
    missing_methods = []
    for method in methods_to_check:
        if not hasattr(menu, method):
            missing_methods.append(method)
            
    if missing_methods:
        print(f"❌ Missing methods: {missing_methods}")
        return False
    else:
        print("✅ All methods exist")
        return True


if __name__ == "__main__":
    test_menu()