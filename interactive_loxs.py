#!/usr/bin/env python3
"""
ShadowX - Interactive XSS Scanner (LOXS Style)
Created by: adce626
Real-time payload testing with visual feedback like LOXS
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.interactive_scanner import InteractiveXSSScanner
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
import time

def display_main_banner():
    """Display main application banner"""
    console = Console()
    
    banner_text = """
╔═══════════════════════════════════════════════════════════════╗
║   ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗██╗  ██╗  ║
║   ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║╚██╗██╔╝  ║
║   ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║ ╚███╔╝   ║
║   ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║ ██╔██╗   ║
║   ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝██╔╝ ██╗  ║
║   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝  ║
║                                                             ║
║          🎯 INTERACTIVE XSS SCANNER - LOXS STYLE            ║
║                     Created by: adce626                    ║
║              Real-time Payload Testing Interface           ║
║                                                             ║
║  Features:                                                  ║
║  • Live payload testing with color feedback                ║
║  • Real-time vulnerability detection                       ║
║  • Advanced XSS payload collection                         ║
║  • DOM-based execution verification                        ║
║  • WAF bypass techniques                                   ║
╚═══════════════════════════════════════════════════════════════╝
    """
    
    panel = Panel(
        Text(banner_text, style="bold cyan"),
        title="ShadowX Interactive XSS Scanner",
        border_style="bright_blue"
    )
    console.print(panel)

def show_usage_examples():
    """Show usage examples"""
    console = Console()
    
    examples_text = """
[bold yellow]📚 Example Target URLs:[/bold yellow]

[cyan]1. Search Parameter:[/cyan]
   https://example.com/search?q=test

[cyan]2. Login Form:[/cyan]
   https://example.com/login?username=admin&password=test

[cyan]3. Contact Form:[/cyan]
   https://example.com/contact?name=test&email=test@test.com&message=hello

[cyan]4. Multiple Parameters:[/cyan]
   https://example.com/page?param1=value1&param2=value2&param3=value3

[bold red]⚠️  Warning:[/bold red] Only test URLs you own or have permission to test!
    """
    
    panel = Panel(examples_text, title="Usage Examples", border_style="yellow")
    console.print(panel)

def main():
    """Main application entry point"""
    console = Console()
    
    try:
        # Clear screen
        os.system('clear' if os.name == 'posix' else 'cls')
        
        # Display banner
        display_main_banner()
        time.sleep(1)
        
        # Show examples
        show_usage_examples()
        
        # Get target URL from user
        console.print("\n[bold green]🎯 Enter target URL for XSS testing:[/bold green]")
        target_url = input("Target URL: ").strip()
        
        if not target_url:
            console.print("[red]❌ No URL provided. Exiting...[/red]")
            sys.exit(1)
        
        # Validate URL format
        if not target_url.startswith(('http://', 'https://')):
            console.print("[yellow]⚠️  Adding https:// prefix to URL[/yellow]")
            target_url = f"https://{target_url}"
        
        # Check if URL has parameters
        if '?' not in target_url:
            console.print("[red]❌ URL must contain parameters to test (e.g., ?param=value)[/red]")
            sys.exit(1)
        
        console.print(f"\n[bold yellow]🚀 Starting interactive XSS scan on:[/bold yellow] {target_url}")
        time.sleep(2)
        
        # Initialize and run scanner
        scanner = InteractiveXSSScanner()
        scanner.run_interactive_scan(target_url)
        
    except KeyboardInterrupt:
        console.print(f"\n[yellow]⚠️ Scan interrupted by user. Goodbye![/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]❌ Fatal error: {e}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main()