#!/usr/bin/env python3
"""Test string obfuscation on multiple binaries"""

import sys
import os
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cumpyl_package import BinaryRewriter, ConfigManager
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

def test_binary(binary_path: str, output_dir: str) -> dict:
    """Test string obfuscation on a single binary"""
    result = {
        'binary': os.path.basename(binary_path),
        'original_size': 0,
        'obfuscated_size': 0,
        'strings_found': 0,
        'strings_obfuscated': 0,
        'success': False,
        'error': None
    }

    try:
        # Get original size
        if os.path.exists(binary_path):
            result['original_size'] = os.path.getsize(binary_path)

        config = ConfigManager()
        rewriter = BinaryRewriter(binary_path, config)

        # Load binary
        if not rewriter.load_binary():
            result['error'] = "Failed to load binary"
            return result

        # Discover and load plugins
        discovered = rewriter.plugin_manager.discover_plugins()
        for plugin_name in discovered:
            rewriter.plugin_manager.load_plugin(plugin_name)

        # Run analysis
        analysis_results = rewriter.run_plugin_analysis()

        # Get string count from PE analysis
        if 'pe_string_obfuscation' in analysis_results:
            pe_results = analysis_results['pe_string_obfuscation']
            if 'analysis' in pe_results:
                result['strings_found'] = pe_results['analysis'].get('total_strings_found', 0)

        # Run transformation
        console.print(f"\n[cyan]Processing {result['binary']}...[/cyan]")
        success = rewriter.run_plugin_transformations(analysis_results)

        if not success:
            result['error'] = "Transformation failed"
            return result

        # Save obfuscated binary
        output_path = os.path.join(output_dir, f"obfuscated_{os.path.basename(binary_path)}")
        if rewriter.save_binary(output_path):
            result['obfuscated_size'] = os.path.getsize(output_path)
            result['success'] = True
            console.print(f"[green]✓ Saved to {output_path}[/green]")
        else:
            result['error'] = "Failed to save binary"

    except Exception as e:
        result['error'] = str(e)
        console.print(f"[red]✗ Error: {e}[/red]")

    return result

def main():
    """Test obfuscation on 5 binaries"""
    console.print(Panel("[bold cyan]String Obfuscation Batch Test[/bold cyan]",
                       style="bold blue"))

    # Get binaries from RUBBISH/BIG_EXE
    source_dir = "/home/mrnob0dy666/RUBBISH/BIG_EXE"
    output_dir = "/home/mrnob0dy666/cumpyl/test_output"

    # Create output directory
    os.makedirs(output_dir, exist_ok=True)

    # Find up to 5 EXE files
    exe_files = []
    for file in sorted(Path(source_dir).glob("*.exe")):
        if len(exe_files) < 5:
            exe_files.append(str(file))

    if not exe_files:
        console.print("[red]No .exe files found in RUBBISH/BIG_EXE[/red]")
        return

    console.print(f"\n[bold]Found {len(exe_files)} binaries to test:[/bold]")
    for i, exe in enumerate(exe_files, 1):
        size_mb = os.path.getsize(exe) / (1024 * 1024)
        console.print(f"  {i}. {os.path.basename(exe)} ({size_mb:.2f} MB)")

    # Test each binary
    results = []
    for binary in exe_files:
        result = test_binary(binary, output_dir)
        results.append(result)

    # Display summary
    console.print("\n")
    console.print(Panel("[bold cyan]Test Results Summary[/bold cyan]", style="bold green"))

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Binary", style="cyan", width=30)
    table.add_column("Original", style="white", width=10)
    table.add_column("Obfuscated", style="white", width=10)
    table.add_column("Strings", style="yellow", width=8)
    table.add_column("Status", style="green", width=15)

    success_count = 0
    for r in results:
        status = "✓ Success" if r['success'] else f"✗ {r['error'][:20]}" if r['error'] else "✗ Failed"
        status_style = "green" if r['success'] else "red"

        orig_size = f"{r['original_size'] / 1024:.1f}K" if r['original_size'] else "N/A"
        obf_size = f"{r['obfuscated_size'] / 1024:.1f}K" if r['obfuscated_size'] else "N/A"

        table.add_row(
            r['binary'],
            orig_size,
            obf_size,
            str(r['strings_found']),
            f"[{status_style}]{status}[/{status_style}]"
        )

        if r['success']:
            success_count += 1

    console.print(table)
    console.print(f"\n[bold]Summary: {success_count}/{len(results)} binaries successfully obfuscated[/bold]")
    console.print(f"[dim]Output directory: {output_dir}[/dim]")

if __name__ == "__main__":
    main()
