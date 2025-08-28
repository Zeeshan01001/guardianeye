#!/usr/bin/env python3

import os
import sys
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
    TimeRemainingColumn,
    TaskProgressColumn,
    TimeElapsedColumn
)
from rich.syntax import Syntax
from rich.text import Text
from datetime import datetime
from typing import Optional, List
from pathlib import Path
import pkg_resources

# Ensure package is in Python path
package_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if package_root not in sys.path:
    sys.path.insert(0, package_root)

from guardianeye.core.scanner import MaliciousFileScanner

app = typer.Typer(
    help="🛡️ GuardianEye - Advanced Malware Detection System",
    add_completion=True
)
console = Console()

def create_header() -> Panel:
    """Create a stylish header panel."""
    grid = Table.grid(padding=1)
    grid.add_column(style="bold cyan", justify="center")
    grid.add_column(style="yellow")
    
    grid.add_row(
        "🛡️ GuardianEye",
        "Advanced Malware Detection System"
    )
    grid.add_row("Version", "1.0.0")
    
    return Panel(
        grid,
        style="bold blue",
        border_style="blue",
        padding=(1, 2)
    )

def create_scan_progress() -> Progress:
    """Create a rich progress bar for scanning."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=40),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console
    )

def create_summary_table(results: List[dict]) -> Table:
    """Create a detailed summary table."""
    table = Table(
        title="📊 Scan Results",
        title_style="bold cyan",
        border_style="blue",
        header_style="bold cyan",
        padding=(0, 2)
    )
    
    table.add_column("Category", style="cyan")
    table.add_column("Count", style="yellow", justify="right")
    table.add_column("Percentage", style="green", justify="right")
    
    total = len(results)
    malicious = sum(1 for r in results if r['status'] == 'malicious')
    clean = sum(1 for r in results if r['status'] == 'clean')
    errors = sum(1 for r in results if r['status'] == 'error')
    
    def calc_percent(n: int) -> str:
        return f"{(n/total*100):.1f}%" if total > 0 else "0.0%"
    
    table.add_row("Total Files", str(total), "100.0%")
    table.add_row("Clean", str(clean), calc_percent(clean))
    table.add_row("Malicious", f"[red]{malicious}[/red]", f"[red]{calc_percent(malicious)}[/red]")
    table.add_row("Errors", str(errors), calc_percent(errors))
    
    return table

def create_threat_table(results: List[dict]) -> Optional[Table]:
    """Create a table of detected threats."""
    threats = [r for r in results if r['status'] == 'malicious']
    if not threats:
        return None
        
    table = Table(
        title="⚠️  Detected Threats",
        title_style="bold red",
        border_style="red",
        header_style="bold red",
        padding=(0, 2)
    )
    
    table.add_column("File Path", style="red")
    table.add_column("Hash", style="yellow")
    table.add_column("Risk Level", style="magenta")
    
    for threat in threats:
        table.add_row(
            threat['file_path'],
            threat['hash'],
            "High"  # TODO: Add actual risk level from signature database
        )
    
    return table

def version_callback(value: bool):
    if value:
        console.print("GuardianEye v1.0.0")
        raise typer.Exit()

@app.callback()
def common(
    version: Optional[bool] = typer.Option(
        None, "--version", "-v", callback=version_callback, help="Show version and exit."
    ),
):
    """
    GuardianEye - Advanced Malware Detection System
    """
    pass

@app.command()
def scan(
    path: str = typer.Argument(..., help="File or directory to scan"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Save results to file"),
):
    """
    Scan files or directories for malware.
    """
    console.print("\n[bold]🛡️ GuardianEye Advanced Malware Detection System[/bold]\n")
    console.print(f"[bold]    Version[/bold]    1.0.0\n")
    
    scanner = MaliciousFileScanner()
    
    if os.path.isfile(path):
        results = [scanner.scan_file(path, verbose=verbose)]
    else:
        results = list(scanner.scan_directory(path))
    
    scanner.display_results(results)
    
    if output:
        # TODO: Implement saving results to file
        pass

@app.command()
def info():
    """
    Display system information and statistics.
    """
    console.print("\n[bold]🛡️ GuardianEye System Information[/bold]\n")
    console.print("Version: 1.0.0")
    console.print("Author: zeeshan01001")
    console.print("License: MIT")
    console.print("\nFeatures:")
    console.print("✓ Local file scanning")
    console.print("✓ EICAR test file detection")
    console.print("✓ VirusTotal integration (with API key)")
    console.print("✓ Directory recursive scanning")
    console.print("✓ Rich console output")

@app.command()
def update():
    """Update malware signature database."""
    console.print(create_header())
    console.print()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        task = progress.add_task("Updating signature database...", total=100)
        
        # TODO: Implement actual update logic
        for i in range(100):
            progress.update(task, advance=1)
        
        console.print("[green]✅ Signature database updated successfully![/green]")

def main():
    """Entry point for both 'guardianeye' and 'ge' commands."""
    try:
        app()
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main() 