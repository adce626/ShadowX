#!/usr/bin/env python3
"""
ShadowX Interactive CLI - Realistic XSS Scanner Experience
Created by: adce626
"""

import os
import sys
import time
import random
import threading
from urllib.parse import urlparse, parse_qs
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.text import Text
from rich import print as rprint
from colorama import init, Fore, Back, Style
import requests
from requests.exceptions import RequestException

# Initialize colorama
init(autoreset=True)

class InteractiveShadowX:
    def __init__(self):
        self.console = Console()
        self.target_url = None
        self.scan_mode = None
        self.thread_count = 5
        self.payloads_loaded = 0
        self.vulnerabilities_found = []
        self.scan_stats = {
            'urls_tested': 0,
            'payloads_sent': 0,
            'waf_blocks': 0,
            'timeouts': 0,
            'alerts_triggered': 0,
            'dom_mutations': 0
        }
        
        # Simulated payload database
        self.payload_contexts = {
            'script_tag': [
                '";alert("XSS-DETECTED");var x="',
                '</script><script>alert("XSS-DETECTED")</script>',
                'prompt("XSS-DETECTED")',
                '/**/confirm("XSS-DETECTED")/**/'
            ],
            'html_attribute': [
                '"><script>alert("XSS-DETECTED")</script>',
                '" onmouseover="alert(\\"XSS-DETECTED\\")"',
                '"><img src=x onerror=alert("XSS-DETECTED")>',
                '\' onfocus=\'alert("XSS-DETECTED")\' autofocus=\''
            ],
            'html_body': [
                '<script>alert("XSS-DETECTED")</script>',
                '<img src=x onerror=alert("XSS-DETECTED")>',
                '<svg onload=alert("XSS-DETECTED")>',
                '<iframe src=javascript:alert("XSS-DETECTED")>'
            ],
            'waf_bypass': [
                '<ScRiPt>alert("XSS-DETECTED")</ScRiPt>',
                '<img src=x onerror=eval(alert("XSS-DETECTED"))>',
                '<svg><animate onbegin=alert("XSS-DETECTED")>',
                'javascript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert("XSS-DETECTED") )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert("XSS-DETECTED")//'
            ]
        }
        
    def display_banner(self):
        """Display the ShadowX interactive banner"""
        banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║   ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗██╗  ██╗  ║
    ║   ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║╚██╗██╔╝  ║
    ║   ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║ ╚███╔╝   ║
    ║   ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║ ██╔██╗   ║
    ║   ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝██╔╝ ██╗  ║
    ║   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝  ║
    ╠═══════════════════════════════════════════════════════════════╣
    ║             🎯 INTERACTIVE XSS VULNERABILITY SCANNER          ║
    ║                     Created by: adce626                      ║
    ║               Realistic Red Team Lab Experience              ║
    ╚═══════════════════════════════════════════════════════════════╝
        """
        
        panel = Panel(
            banner,
            style="bold red",
            border_style="cyan",
            title="[bold yellow]ShadowX Interactive Mode[/bold yellow]",
            subtitle="[italic green]Professional XSS Assessment Suite[/italic green]"
        )
        self.console.print(panel)
        self.console.print()
        
    def setup_scan_configuration(self):
        """Interactive setup for scan configuration"""
        self.console.print("[bold cyan]═══ SCAN CONFIGURATION ═══[/bold cyan]")
        self.console.print()
        
        # Target URL input
        while True:
            self.target_url = Prompt.ask(
                "[bold green]Enter target URL",
                default="https://example.com/search?q=test"
            )
            
            if self.validate_url(self.target_url):
                self.console.print(f"[green]✓[/green] Target validated: {self.target_url}")
                break
            else:
                self.console.print("[red]✗ Invalid URL format. Please try again.[/red]")
        
        self.console.print()
        
        # Scan mode selection
        self.console.print("[bold cyan]Select Scan Mode:[/bold cyan]")
        scan_modes = Table()
        scan_modes.add_column("Option", style="cyan", no_wrap=True)
        scan_modes.add_column("Mode", style="white")
        scan_modes.add_column("Description", style="dim")
        
        scan_modes.add_row("1", "Quick Scan", "Basic payloads, fast execution")
        scan_modes.add_row("2", "Full Scan", "Comprehensive payload set")
        scan_modes.add_row("3", "WAF Bypass", "Advanced evasion techniques")
        scan_modes.add_row("4", "Stealth Mode", "Slow, low-profile scanning")
        
        self.console.print(scan_modes)
        self.console.print()
        
        mode_choice = IntPrompt.ask(
            "[bold yellow]Choose scan mode",
            choices=["1", "2", "3", "4"],
            default=2
        )
        
        mode_names = {1: "Quick Scan", 2: "Full Scan", 3: "WAF Bypass", 4: "Stealth Mode"}
        self.scan_mode = mode_names[mode_choice]
        
        # Thread count
        self.thread_count = IntPrompt.ask(
            "[bold yellow]Thread count (1-20)",
            default=5,
            choices=[str(i) for i in range(1, 21)]
        )
        
        self.console.print()
        self.console.print("[bold green]✓ Configuration complete![/bold green]")
        self.console.print()
        
        # Display configuration summary
        config_table = Table(title="Scan Configuration")
        config_table.add_column("Parameter", style="cyan")
        config_table.add_column("Value", style="white")
        
        config_table.add_row("Target URL", self.target_url)
        config_table.add_row("Scan Mode", self.scan_mode)
        config_table.add_row("Threads", str(self.thread_count))
        config_table.add_row("Payloads", str(self.get_payload_count()))
        
        self.console.print(config_table)
        self.console.print()
        
        return Confirm.ask("[bold yellow]Start scan with this configuration?[/bold yellow]", default=True)
        
    def validate_url(self, url):
        """Validate URL format"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
            
    def get_payload_count(self):
        """Get payload count based on scan mode"""
        counts = {
            "Quick Scan": 25,
            "Full Scan": 150,
            "WAF Bypass": 75,
            "Stealth Mode": 50
        }
        return counts.get(self.scan_mode or "Quick Scan", 50)
        
    def simulate_initialization(self):
        """Simulate scanner initialization"""
        self.console.print("[bold cyan]═══ INITIALIZING SHADOWX ═══[/bold cyan]")
        self.console.print()
        
        init_steps = [
            ("Loading payload database", 1.5),
            ("Initializing Chrome WebDriver", 2.0),
            ("Setting up proxy chains", 1.0),
            ("Configuring WAF detection", 1.5),
            ("Starting thread pool", 0.8),
            ("Validating target connectivity", 2.2)
        ]
        
        for step, duration in init_steps:
            self.console.print(f"[yellow]●[/yellow] {step}...", end="")
            time.sleep(duration)
            self.console.print(f" [green]✓[/green]")
            
        self.console.print()
        self.console.print("[bold green]✓ ShadowX initialized successfully![/bold green]")
        self.console.print()
        
        input("[dim]Press [ENTER] to begin reconnaissance...[/dim]")
        self.console.print()
        
    def perform_reconnaissance(self):
        """Simulate target reconnaissance"""
        self.console.print("[bold cyan]═══ TARGET RECONNAISSANCE ═══[/bold cyan]")
        self.console.print()
        
        # Simulate URL analysis
        self.console.print(f"[yellow]●[/yellow] Analyzing target: {self.target_url}")
        time.sleep(1.5)
        
        parsed_url = urlparse(self.target_url)
        params = parse_qs(parsed_url.query or "")
        
        recon_table = Table(title="Target Analysis")
        recon_table.add_column("Component", style="cyan")
        recon_table.add_column("Value", style="white")
        recon_table.add_column("Injectable", style="green")
        
        recon_table.add_row("Domain", parsed_url.netloc or "N/A", "N/A")
        recon_table.add_row("Path", parsed_url.path or "/", "Yes" if parsed_url.path else "No")
        
        if params:
            for param, values in params.items():
                recon_table.add_row(f"Parameter: {param}", str(values[0]), "Yes")
        
        self.console.print(recon_table)
        self.console.print()
        
        # Simulate WAF detection
        self.console.print("[yellow]●[/yellow] Detecting Web Application Firewall...")
        time.sleep(2.0)
        
        waf_detected = random.choice([True, False])
        if waf_detected:
            waf_name = random.choice(["Cloudflare", "AWS WAF", "ModSecurity", "Akamai"])
            self.console.print(f"[red]⚠[/red] WAF Detected: {waf_name}")
            self.console.print("[yellow]●[/yellow] Enabling evasion techniques...")
            time.sleep(1.0)
        else:
            self.console.print("[green]✓[/green] No WAF detected")
            
        self.console.print()
        
    def execute_scan(self):
        """Execute the main XSS scan with realistic simulation"""
        self.console.print("[bold cyan]═══ EXECUTING XSS SCAN ═══[/bold cyan]")
        self.console.print()
        
        payload_count = self.get_payload_count()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=self.console
        ) as progress:
            
            scan_task = progress.add_task("Scanning for XSS vulnerabilities", total=payload_count)
            
            for i in range(payload_count):
                # Select context and payload
                context = random.choice(list(self.payload_contexts.keys()))
                payload = random.choice(self.payload_contexts[context])
                
                # Simulate payload injection
                self.simulate_payload_test(context, payload, i + 1, payload_count)
                
                progress.advance(scan_task, 1)
                
                # Random delays for realism
                time.sleep(random.uniform(0.2, 0.8))
                
                # Simulate user interruption possibility
                if i == 15:
                    self.console.print()
                    if not Confirm.ask("[yellow]Scan in progress. Continue?[/yellow]", default=True):
                        break
                    self.console.print()
                    
        self.console.print()
        
    def simulate_payload_test(self, context, payload, current, total):
        """Simulate individual payload testing"""
        # Simulate different outcomes
        outcome = random.choices(
            ['success', 'blocked', 'timeout', 'failed', 'waf_detected'],
            weights=[5, 15, 8, 65, 7]
        )[0]
        
        self.scan_stats['payloads_sent'] += 1
        
        if outcome == 'success':
            self.handle_successful_xss(context, payload, current)
        elif outcome == 'blocked':
            self.handle_waf_block(context, payload, current)
        elif outcome == 'timeout':
            self.handle_timeout(context, payload, current)
        elif outcome == 'waf_detected':
            self.handle_waf_detection(context, payload, current)
        else:
            # Silent failure - most common in real scans
            pass
            
    def handle_successful_xss(self, context, payload, payload_num):
        """Handle successful XSS detection"""
        self.console.print()
        self.console.print(f"[bold green]🎯 XSS VULNERABILITY DETECTED! #{len(self.vulnerabilities_found) + 1}[/bold green]")
        
        vuln_info = Table()
        vuln_info.add_column("Property", style="cyan")
        vuln_info.add_column("Value", style="white")
        
        vuln_info.add_row("Payload #", str(payload_num))
        vuln_info.add_row("Context", context.replace('_', ' ').title())
        vuln_info.add_row("Payload", payload[:60] + "..." if len(payload) > 60 else payload)
        vuln_info.add_row("Method", random.choice(["Alert Triggered", "DOM Mutation", "Console Log"]))
        vuln_info.add_row("Severity", random.choice(["High", "Medium"]))
        
        self.console.print(vuln_info)
        
        # Simulate screenshot capture
        self.console.print("[yellow]●[/yellow] Capturing screenshot...", end="")
        time.sleep(1.5)
        self.console.print(" [green]✓[/green]")
        
        self.vulnerabilities_found.append({
            'context': context,
            'payload': payload,
            'method': 'alert_triggered'
        })
        
        self.scan_stats['alerts_triggered'] += 1
        self.console.print()
        
    def handle_waf_block(self, context, payload, payload_num):
        """Handle WAF blocking"""
        self.console.print(f"[red]🛡[/red] Payload #{payload_num} blocked by WAF")
        self.scan_stats['waf_blocks'] += 1
        
        if random.random() < 0.3:  # 30% chance to show bypass attempt
            self.console.print("[yellow]●[/yellow] Attempting WAF bypass...", end="")
            time.sleep(1.0)
            if random.random() < 0.4:  # 40% success rate for bypass
                self.console.print(" [green]✓ Bypass successful[/green]")
                self.handle_successful_xss(context, payload + " [BYPASSED]", payload_num)
            else:
                self.console.print(" [red]✗ Bypass failed[/red]")
                
    def handle_timeout(self, context, payload, payload_num):
        """Handle request timeout"""
        self.console.print(f"[yellow]⏱[/yellow] Payload #{payload_num} timed out")
        self.scan_stats['timeouts'] += 1
        
    def handle_waf_detection(self, context, payload, payload_num):
        """Handle WAF detection during scan"""
        self.console.print(f"[red]🚨[/red] WAF signature detected - Payload #{payload_num}")
        self.console.print("[yellow]●[/yellow] Switching to stealth mode...")
        time.sleep(2.0)
        
    def display_scan_results(self):
        """Display comprehensive scan results"""
        self.console.print("[bold cyan]═══ SCAN RESULTS ═══[/bold cyan]")
        self.console.print()
        
        # Statistics table
        stats_table = Table(title="Scan Statistics")
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Count", style="white")
        
        stats_table.add_row("Payloads Sent", str(self.scan_stats['payloads_sent']))
        stats_table.add_row("Vulnerabilities Found", f"[bold green]{len(self.vulnerabilities_found)}[/bold green]")
        stats_table.add_row("WAF Blocks", f"[red]{self.scan_stats['waf_blocks']}[/red]")
        stats_table.add_row("Timeouts", f"[yellow]{self.scan_stats['timeouts']}[/yellow]")
        stats_table.add_row("Alerts Triggered", f"[green]{self.scan_stats['alerts_triggered']}[/green]")
        
        self.console.print(stats_table)
        self.console.print()
        
        # Vulnerabilities found
        if self.vulnerabilities_found:
            self.console.print("[bold green]🎯 VULNERABILITIES DETECTED:[/bold green]")
            
            for i, vuln in enumerate(self.vulnerabilities_found, 1):
                vuln_panel = Panel(
                    f"[bold]Context:[/bold] {vuln['context'].replace('_', ' ').title()}\n"
                    f"[bold]Payload:[/bold] {vuln['payload'][:80]}{'...' if len(vuln['payload']) > 80 else ''}\n"
                    f"[bold]Evidence:[/bold] JavaScript execution confirmed",
                    title=f"[bold red]Vulnerability #{i}[/bold red]",
                    border_style="red"
                )
                self.console.print(vuln_panel)
                
        else:
            self.console.print("[yellow]No vulnerabilities detected in this scan.[/yellow]")
            
        self.console.print()
        
    def post_scan_options(self):
        """Handle post-scan user interactions"""
        self.console.print("[bold cyan]═══ POST-SCAN OPTIONS ═══[/bold cyan]")
        self.console.print()
        
        options = Table()
        options.add_column("Option", style="cyan", no_wrap=True)
        options.add_column("Action", style="white")
        
        options.add_row("1", "Generate HTML report")
        options.add_row("2", "Retry failed payloads")
        options.add_row("3", "Run deeper analysis")
        options.add_row("4", "Export findings")
        options.add_row("5", "Exit")
        
        self.console.print(options)
        self.console.print()
        
        while True:
            choice = IntPrompt.ask(
                "[bold yellow]Select an option",
                choices=["1", "2", "3", "4", "5"],
                default=1
            )
            
            if choice == 1:
                self.generate_report()
            elif choice == 2:
                self.retry_failed_payloads()
            elif choice == 3:
                self.deep_analysis()
            elif choice == 4:
                self.export_findings()
            elif choice == 5:
                self.console.print("[bold green]Thanks for using ShadowX! Happy hunting! 🎯[/bold green]")
                break
                
            if choice != 5:
                self.console.print()
                continue_prompt = Confirm.ask("[yellow]Perform another action?[/yellow]", default=True)
                if not continue_prompt:
                    break
                self.console.print()
                
    def generate_report(self):
        """Simulate report generation"""
        self.console.print("[yellow]●[/yellow] Generating HTML report...")
        time.sleep(2.0)
        self.console.print("[green]✓[/green] Report saved: shadowx_report_20241124_143022.html")
        
    def retry_failed_payloads(self):
        """Simulate retrying failed payloads"""
        if self.scan_stats['waf_blocks'] == 0:
            self.console.print("[dim]No failed payloads to retry.[/dim]")
            return
            
        self.console.print(f"[yellow]●[/yellow] Retrying {self.scan_stats['waf_blocks']} blocked payloads with enhanced evasion...")
        time.sleep(3.0)
        
        if random.random() < 0.6:  # 60% chance of finding something
            self.console.print("[green]✓[/green] Additional vulnerability found through evasion!")
            self.vulnerabilities_found.append({
                'context': 'waf_bypass',
                'payload': '<ScRiPt>alert("BYPASSED")</ScRiPt>',
                'method': 'waf_bypass'
            })
        else:
            self.console.print("[yellow]No additional vulnerabilities found.[/yellow]")
            
    def deep_analysis(self):
        """Simulate deep analysis"""
        self.console.print("[yellow]●[/yellow] Performing deep DOM analysis...")
        time.sleep(2.5)
        self.console.print("[yellow]●[/yellow] Testing advanced XSS vectors...")
        time.sleep(2.0)
        self.console.print("[green]✓[/green] Deep analysis complete. Results integrated into findings.")
        
    def export_findings(self):
        """Simulate exporting findings"""
        self.console.print("[yellow]●[/yellow] Exporting findings to JSON...")
        time.sleep(1.5)
        self.console.print("[green]✓[/green] Findings exported: shadowx_findings.json")
        
    def run_interactive_session(self):
        """Run the complete interactive session"""
        try:
            self.display_banner()
            
            # Configuration phase
            if not self.setup_scan_configuration():
                self.console.print("[yellow]Scan cancelled by user.[/yellow]")
                return
                
            # Initialization phase
            self.simulate_initialization()
            
            # Reconnaissance phase
            self.perform_reconnaissance()
            
            # Main scan phase
            self.execute_scan()
            
            # Results phase
            self.display_scan_results()
            
            # Post-scan interactions
            self.post_scan_options()
            
        except KeyboardInterrupt:
            self.console.print("\n[red]Scan interrupted by user.[/red]")
            if self.vulnerabilities_found:
                self.console.print("[yellow]Partial results available.[/yellow]")
                self.display_scan_results()
        except Exception as e:
            self.console.print(f"\n[red]Error during scan: {e}[/red]")

def main():
    """Main entry point"""
    scanner = InteractiveShadowX()
    scanner.run_interactive_session()

if __name__ == "__main__":
    main()