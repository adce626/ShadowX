#!/usr/bin/env python3
"""
ShadowX - Advanced XSS Vulnerability Scanner
Created by: adce626
Version: 1.0
"""

import os
import sys
import argparse
import time
import asyncio
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from colorama import init, Fore, Style
import requests
from urllib.parse import urlparse
import signal

# Initialize colorama
init(autoreset=True)

# Import core modules
from core.scanner import XSSScanner
from core.context_engine import ContextEngine
from core.blind import BlindXSSManager
from core.report import ReportGenerator
from core.interactive_scanner import InteractiveXSSScanner

class ShadowX:
    def __init__(self):
        self.console = Console()
        self.scanner = None
        self.blind_manager = None
        self.report_generator = None
        self.results = []
        
    def display_banner(self):
        """Display the ShadowX banner"""
        try:
            with open('banner.txt', 'r') as f:
                banner = f.read()
        except FileNotFoundError:
            banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║   ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗██╗  ██╗  ║
    ║   ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║╚██╗██╔╝  ║
    ║   ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║ ╚███╔╝   ║
    ║   ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║ ██╔██╗   ║
    ║   ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝██╔╝ ██╗  ║
    ║   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝  ║
    ╠═══════════════════════════════════════════════════════════════╣
    ║              Advanced XSS Vulnerability Scanner              ║
    ║                     Created by: adce626                      ║
    ║                        Version: 1.0                         ║
    ╚═══════════════════════════════════════════════════════════════╝
            """
        
        panel = Panel(
            banner,
            style="bold cyan",
            border_style="red",
            title="[bold red]ShadowX Scanner[/bold red]",
            subtitle="[italic]Professional XSS Detection Suite[/italic]"
        )
        self.console.print(panel)
        
    def setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(sig, frame):
            self.console.print("\n[red]Scan interrupted by user. Generating report...[/red]")
            if self.results:
                self.generate_report()
            sys.exit(0)
            
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
    def validate_urls(self, urls):
        """Validate URL format"""
        valid_urls = []
        invalid_urls = []
        
        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.scheme and parsed.netloc:
                    valid_urls.append(url)
                else:
                    invalid_urls.append(url)
            except Exception:
                invalid_urls.append(url)
                
        return valid_urls, invalid_urls
        
    def load_urls_from_file(self, file_path):
        """Load URLs from file"""
        try:
            with open(file_path, 'r') as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            return urls
        except FileNotFoundError:
            self.console.print(f"[red]Error: URL file '{file_path}' not found[/red]")
            return []
        except Exception as e:
            self.console.print(f"[red]Error reading URL file: {e}[/red]")
            return []
            
    def load_payloads_from_file(self, file_path):
        """Load payloads from file"""
        try:
            with open(file_path, 'r') as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            return payloads
        except FileNotFoundError:
            self.console.print(f"[red]Error: Payload file '{file_path}' not found[/red]")
            return []
        except Exception as e:
            self.console.print(f"[red]Error reading payload file: {e}[/red]")
            return []
            
    def run_scan(self, args):
        """Run the XSS scan"""
        start_time = time.time()
        
        # Load URLs
        if args.url_file:
            urls = self.load_urls_from_file(args.url_file)
        elif args.url:
            urls = [args.url]
        else:
            self.console.print("[red]Error: No URLs specified. Use --url or --url-file[/red]")
            return
            
        # Validate URLs
        valid_urls, invalid_urls = self.validate_urls(urls)
        
        if invalid_urls:
            self.console.print(f"[yellow]Warning: {len(invalid_urls)} invalid URLs skipped[/yellow]")
            
        if not valid_urls:
            self.console.print("[red]Error: No valid URLs to scan[/red]")
            return
            
        # Load payloads
        if args.payloads:
            payloads = self.load_payloads_from_file(args.payloads)
        else:
            payloads = self.load_payloads_from_file('assets/payloads.txt')
            
        if not payloads:
            self.console.print("[red]Error: No payloads loaded[/red]")
            return
            
        # Initialize components
        self.scanner = XSSScanner(
            headless=not args.gui,
            timeout=args.timeout,
            threads=args.threads,
            screenshot_dir=args.output_dir
        )
        
        if args.blind:
            self.blind_manager = BlindXSSManager(
                webhook_url=args.webhook_url,
                interaction_timeout=args.blind_timeout
            )
            
        self.report_generator = ReportGenerator(args.output_dir)
        
        # Display scan information
        info_table = Table(title="Scan Configuration")
        info_table.add_column("Parameter", style="cyan")
        info_table.add_column("Value", style="white")
        
        info_table.add_row("Target URLs", str(len(valid_urls)))
        info_table.add_row("Payloads", str(len(payloads)))
        info_table.add_row("Threads", str(args.threads))
        info_table.add_row("Timeout", f"{args.timeout}s")
        info_table.add_row("Output Directory", args.output_dir)
        info_table.add_row("Blind XSS", "Enabled" if args.blind else "Disabled")
        
        self.console.print(info_table)
        self.console.print()
        
        # Run scan with progress bar
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            
            task = progress.add_task("Scanning for XSS vulnerabilities...", total=len(valid_urls))
            
            # Use ThreadPoolExecutor for concurrent scanning
            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                futures = []
                
                for url in valid_urls:
                    future = executor.submit(
                        self.scanner.scan_url,
                        url,
                        payloads,
                        blind_manager=self.blind_manager if args.blind else None
                    )
                    futures.append((future, url))
                    
                for future, url in futures:
                    try:
                        result = future.result(timeout=args.timeout * 2)
                        if result:
                            self.results.extend(result)
                            progress.console.print(f"[green]✓[/green] {url} - {len(result)} vulnerabilities found")
                        else:
                            progress.console.print(f"[dim]○[/dim] {url} - No vulnerabilities")
                    except Exception as e:
                        progress.console.print(f"[red]✗[/red] {url} - Error: {str(e)}")
                    finally:
                        progress.advance(task)
                        
        # Calculate scan statistics
        end_time = time.time()
        scan_duration = end_time - start_time
        
        # Display results summary
        self.display_results_summary(len(valid_urls), scan_duration)
        
        # Generate report
        if self.results or args.report_only:
            self.generate_report()
            
        # Cleanup
        if self.scanner:
            self.scanner.cleanup()
            
    def display_results_summary(self, total_urls, duration):
        """Display scan results summary"""
        vulnerable_urls = len(set(result['url'] for result in self.results))
        total_vulns = len(self.results)
        
        # Create results table
        results_table = Table(title="Scan Results Summary")
        results_table.add_column("Metric", style="cyan")
        results_table.add_column("Value", style="white")
        
        results_table.add_row("Total URLs Scanned", str(total_urls))
        results_table.add_row("Vulnerable URLs", str(vulnerable_urls))
        results_table.add_row("Total Vulnerabilities", str(total_vulns))
        results_table.add_row("Scan Duration", f"{duration:.2f}s")
        
        if total_vulns > 0:
            results_table.add_row("Success Rate", f"{(vulnerable_urls/total_urls)*100:.1f}%")
            
        self.console.print()
        self.console.print(results_table)
        
        # Display vulnerability breakdown
        if self.results:
            vuln_types = {}
            for result in self.results:
                vuln_type = result.get('type', 'Unknown')
                vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
                
            vuln_table = Table(title="Vulnerability Types")
            vuln_table.add_column("Type", style="cyan")
            vuln_table.add_column("Count", style="white")
            
            for vuln_type, count in sorted(vuln_types.items()):
                vuln_table.add_row(vuln_type, str(count))
                
            self.console.print()
            self.console.print(vuln_table)
            
    def generate_report(self):
        """Generate HTML and text reports"""
        if not self.report_generator:
            self.report_generator = ReportGenerator("./reports")
            
        try:
            html_file, txt_file = self.report_generator.generate_reports(
                self.results,
                scan_info={
                    'tool_name': 'ShadowX',
                    'version': '1.0',
                    'author': 'adce626',
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                }
            )
            
            self.console.print(f"\n[green]✓ HTML Report: {html_file}[/green]")
            self.console.print(f"[green]✓ Text Report: {txt_file}[/green]")
            
        except Exception as e:
            self.console.print(f"[red]Error generating reports: {e}[/red]")
            
def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="ShadowX - Advanced XSS Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --url https://example.com
  python main.py --url-file urls.txt --payloads custom_payloads.txt
  python main.py --url https://example.com --blind --webhook-url https://webhook.site/unique-id
  python main.py --url https://example.com --threads 10 --timeout 30
        """
    )
    
    # Target options
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('--url', help='Single URL to scan')
    target_group.add_argument('--url-file', help='File containing URLs to scan (one per line)')
    
    # Payload options
    parser.add_argument('--payloads', help='Custom payload file (default: assets/payloads.txt)')
    
    # Blind XSS options
    parser.add_argument('--blind', action='store_true', help='Enable blind XSS detection')
    parser.add_argument('--webhook-url', help='Webhook URL for blind XSS (required if --blind is used)')
    parser.add_argument('--blind-timeout', type=int, default=60, help='Blind XSS interaction timeout (seconds)')
    
    # Scan options
    parser.add_argument('--threads', type=int, default=5, help='Number of threads (default: 5)')
    parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds (default: 30)')
    parser.add_argument('--gui', action='store_true', help='Show browser GUI (not headless)')
    parser.add_argument('--output-dir', default='./output', help='Output directory for reports and screenshots')
    
    # Report options
    parser.add_argument('--report-only', action='store_true', help='Generate report only (skip scanning)')
    
    # Modes
    parser.add_argument('--mode', choices=['scan', 'manual', 'report-only', 'interactive'], default='scan',
                       help='Operation mode (default: scan)')
    parser.add_argument('--interactive', action='store_true',
                       help='Run in LOXS-style interactive mode with real-time payload testing')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.blind and not args.webhook_url:
        parser.error("--webhook-url is required when --blind is enabled")
        
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Initialize ShadowX
    shadowx = ShadowX()
    shadowx.setup_signal_handlers()
    
    # Display banner
    shadowx.display_banner()
    
    # Run based on mode
    if args.mode == 'interactive' or args.interactive:
        # Run interactive mode like LOXS
        if not args.url:
            shadowx.console.print("[red]Interactive mode requires --url parameter[/red]")
            sys.exit(1)
        
        interactive_scanner = InteractiveXSSScanner()
        interactive_scanner.run_interactive_scan(args.url)
        
    elif args.mode == 'scan' or not args.report_only:
        shadowx.run_scan(args)
    elif args.mode == 'report-only':
        shadowx.generate_report()
    elif args.mode == 'manual':
        shadowx.console.print("[yellow]Manual mode not implemented yet[/yellow]")
        
if __name__ == "__main__":
    main()
