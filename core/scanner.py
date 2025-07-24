"""
ShadowX Scanner Core
Advanced XSS vulnerability detection with Selenium automation
"""

import os
import time
import base64
import hashlib
import threading
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote, unquote
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import (
    TimeoutException, UnexpectedAlertPresentException, 
    WebDriverException, NoSuchElementException
)
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import logging
from threading import Lock
import json
import re

from .context_engine import ContextEngine

class XSSScanner:
    def __init__(self, headless=True, timeout=30, threads=5, screenshot_dir="./screenshots"):
        self.headless = headless
        self.timeout = timeout
        self.threads = threads
        self.screenshot_dir = screenshot_dir
        self.context_engine = ContextEngine()
        self.lock = Lock()
        self.session = self._create_session()
        
        # Create screenshot directory
        os.makedirs(screenshot_dir, exist_ok=True)
        
        # Setup logging
        logging.getLogger('selenium').setLevel(logging.WARNING)
        logging.getLogger('urllib3').setLevel(logging.WARNING)
        
    def _create_session(self):
        """Create requests session with retries"""
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session
        
    def _get_chrome_driver(self):
        """Initialize Chrome driver with options"""
        chrome_options = Options()
        
        # Basic options
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--disable-extensions')
        chrome_options.add_argument('--disable-plugins')
        chrome_options.add_argument('--disable-images')
        chrome_options.add_argument('--disable-javascript-harmony-shipping')
        chrome_options.add_argument('--disable-background-timer-throttling')
        chrome_options.add_argument('--disable-renderer-backgrounding')
        chrome_options.add_argument('--disable-backgrounding-occluded-windows')
        chrome_options.add_argument('--disable-client-side-phishing-detection')
        chrome_options.add_argument('--disable-sync')
        chrome_options.add_argument('--disable-default-apps')
        chrome_options.add_argument('--disable-web-security')
        chrome_options.add_argument('--allow-running-insecure-content')
        
        # User agent
        chrome_options.add_argument('--user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.198 Safari/537.36')
        
        if self.headless:
            chrome_options.add_argument('--headless')
            
        # Window size
        chrome_options.add_argument('--window-size=1920,1080')
        
        # Enable logging for JavaScript errors
        chrome_options.add_argument('--enable-logging')
        chrome_options.add_argument('--log-level=0')
        chrome_options.add_experimental_option('useAutomationExtension', False)
        chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
        
        # Prefs for better compatibility
        prefs = {
            "profile.default_content_setting_values": {
                "notifications": 2,
                "media_stream": 2,
            }
        }
        chrome_options.add_experimental_option("prefs", prefs)
        
        try:
            # Use webdriver-manager to handle ChromeDriver
            service = ChromeService(ChromeDriverManager(version="114.0.5735.198").install())
            driver = webdriver.Chrome(service=service, options=chrome_options)
            driver.set_page_load_timeout(self.timeout)
            driver.implicitly_wait(10)
            return driver
        except Exception as e:
            raise Exception(f"Failed to initialize Chrome driver: {str(e)}")
            
    def _take_screenshot(self, driver, url, payload_type, vulnerability_id):
        """Take screenshot of the vulnerability"""
        try:
            timestamp = int(time.time())
            filename = f"xss_{vulnerability_id}_{payload_type}_{timestamp}.png"
            filepath = os.path.join(self.screenshot_dir, filename)
            
            driver.save_screenshot(filepath)
            return filepath
        except Exception as e:
            print(f"Failed to take screenshot: {e}")
            return None
            
    def _generate_unique_marker(self):
        """Generate unique marker for payload tracking"""
        timestamp = str(int(time.time() * 1000))
        random_str = base64.b64encode(os.urandom(8)).decode('ascii').rstrip('=')
        return f"shadowx_{timestamp}_{random_str}"
        
    def _check_reflection(self, response_text, marker):
        """Check if the marker is reflected in the response"""
        return marker in response_text
        
    def _analyze_dom_changes(self, driver, original_dom, marker):
        """Analyze DOM changes after payload injection"""
        try:
            # Wait a bit for potential DOM changes
            time.sleep(2)
            
            # Get new DOM
            new_dom = driver.page_source
            
            # Check if marker exists in new DOM
            if marker in new_dom:
                # Check for script tags containing our marker
                soup = BeautifulSoup(new_dom, 'html.parser')
                scripts = soup.find_all('script')
                
                for script in scripts:
                    if script.string and marker in script.string:
                        return True, "Script tag injection detected"
                        
                # Check for event handlers
                for tag in soup.find_all(attrs={"onclick": True}):
                    if marker in tag.get('onclick', ''):
                        return True, "Event handler injection detected"
                        
                for tag in soup.find_all(attrs={"onload": True}):
                    if marker in tag.get('onload', ''):
                        return True, "Event handler injection detected"
                        
                # Check for other potential injection points
                for tag in soup.find_all(attrs={"href": True}):
                    if marker in tag.get('href', ''):
                        return True, "Href attribute injection detected"
                        
            return False, "No significant DOM changes detected"
            
        except Exception as e:
            return False, f"DOM analysis error: {str(e)}"
            
    def _check_javascript_execution(self, driver, marker):
        """Check if JavaScript was executed"""
        try:
            # Check for alerts
            try:
                alert = driver.switch_to.alert
                alert_text = alert.text
                alert.accept()
                if marker in alert_text:
                    return True, "Alert executed with marker"
                return True, "Alert executed (generic)"
            except:
                pass
                
            # Check console logs
            logs = driver.get_log('browser')
            for log in logs:
                if marker in log['message']:
                    return True, f"Console log: {log['message']}"
                    
            # Check for JavaScript errors related to our payload
            for log in logs:
                if 'error' in log['level'].lower() and marker in log['message']:
                    return True, f"JavaScript error: {log['message']}"
                    
            # Execute JavaScript to check for global variables or function calls
            try:
                result = driver.execute_script(f"""
                    // Check if our marker created any global variables
                    if (window['{marker}']) return 'Global variable found';
                    
                    // Check document modifications
                    var elements = document.querySelectorAll('*');
                    for (var i = 0; i < elements.length; i++) {{
                        if (elements[i].innerHTML && elements[i].innerHTML.includes('{marker}')) {{
                            return 'DOM modification detected';
                        }}
                    }}
                    
                    return null;
                """)
                
                if result:
                    return True, result
                    
            except Exception as js_error:
                if marker in str(js_error):
                    return True, f"JavaScript execution detected: {str(js_error)}"
                    
            return False, "No JavaScript execution detected"
            
        except Exception as e:
            return False, f"JavaScript check error: {str(e)}"
            
    def _test_payload(self, driver, url, payload, injection_point, param_name=None):
        """Test a single payload against a URL"""
        marker = self._generate_unique_marker()
        marked_payload = payload.replace('{{MARKER}}', marker)
        
        try:
            # Get original DOM for comparison
            driver.get(url)
            original_dom = driver.page_source
            
            # Inject payload based on injection point
            if injection_point == 'query_param' and param_name:
                parsed_url = urlparse(url)
                params = parse_qs(parsed_url.query, keep_blank_values=True)
                params[param_name] = [marked_payload]
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse((
                    parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                    parsed_url.params, new_query, parsed_url.fragment
                ))
                
                # Navigate to URL with payload
                driver.get(test_url)
                
            elif injection_point == 'form_field':
                # Find and fill forms
                forms = driver.find_elements(By.TAG_NAME, 'form')
                for form in forms:
                    inputs = form.find_elements(By.TAG_NAME, 'input')
                    textareas = form.find_elements(By.TAG_NAME, 'textarea')
                    
                    # Fill text inputs and textareas
                    for element in inputs + textareas:
                        try:
                            if element.get_attribute('type') not in ['submit', 'button', 'hidden']:
                                element.clear()
                                element.send_keys(marked_payload)
                        except:
                            pass
                            
                    # Submit form
                    try:
                        submit_btn = form.find_element(By.XPATH, './/input[@type="submit"] | .//button[@type="submit"] | .//button[not(@type)]')
                        submit_btn.click()
                        break
                    except:
                        try:
                            form.submit()
                            break
                        except:
                            pass
                            
            elif injection_point == 'fragment':
                test_url = f"{url}#{marked_payload}"
                driver.get(test_url)
                
            elif injection_point == 'path':
                parsed_url = urlparse(url)
                new_path = f"{parsed_url.path}/{marked_payload}"
                test_url = urlunparse((
                    parsed_url.scheme, parsed_url.netloc, new_path,
                    parsed_url.params, parsed_url.query, parsed_url.fragment
                ))
                driver.get(test_url)
                
            # Wait for page to load and JavaScript to execute
            time.sleep(3)
            
            # Check for JavaScript execution (alerts, console logs, etc.)
            js_executed, js_evidence = self._check_javascript_execution(driver, marker)
            
            # Check for DOM changes
            dom_changed, dom_evidence = self._analyze_dom_changes(driver, original_dom, marker)
            
            # Get response content for reflection check
            page_source = driver.page_source
            reflected = self._check_reflection(page_source, marker)
            
            # Determine if this is a valid XSS
            if js_executed or (reflected and dom_changed):
                vulnerability_id = hashlib.md5(f"{url}_{payload}_{time.time()}".encode()).hexdigest()[:8]
                
                # Take screenshot
                screenshot_path = self._take_screenshot(driver, url, 'reflected', vulnerability_id)
                
                # Determine XSS type
                xss_type = "Reflected XSS"
                if injection_point == 'fragment':
                    xss_type = "DOM-based XSS"
                elif injection_point == 'form_field' and not reflected:
                    xss_type = "Stored XSS"
                    
                return {
                    'id': vulnerability_id,
                    'url': url,
                    'type': xss_type,
                    'payload': marked_payload,
                    'injection_point': injection_point,
                    'parameter': param_name,
                    'reflected': reflected,
                    'javascript_executed': js_executed,
                    'dom_modified': dom_changed,
                    'evidence': {
                        'javascript': js_evidence if js_executed else None,
                        'dom': dom_evidence if dom_changed else None
                    },
                    'screenshot': screenshot_path,
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'context': self.context_engine.analyze_context(page_source, marker)
                }
                
            return None
            
        except TimeoutException:
            return None
        except UnexpectedAlertPresentException:
            try:
                alert = driver.switch_to.alert
                alert_text = alert.text
                alert.accept()
                
                # This is likely a successful XSS
                vulnerability_id = hashlib.md5(f"{url}_{payload}_{time.time()}".encode()).hexdigest()[:8]
                screenshot_path = self._take_screenshot(driver, url, 'alert', vulnerability_id)
                
                return {
                    'id': vulnerability_id,
                    'url': url,
                    'type': 'Reflected XSS',
                    'payload': marked_payload,
                    'injection_point': injection_point,
                    'parameter': param_name,
                    'reflected': True,
                    'javascript_executed': True,
                    'dom_modified': False,
                    'evidence': {
                        'javascript': f'Alert executed: {alert_text}',
                        'dom': None
                    },
                    'screenshot': screenshot_path,
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'context': 'Alert popup'
                }
                
            except Exception as e:
                return None
                
        except Exception as e:
            return None
            
    def _scan_url_for_injection_points(self, url):
        """Identify potential injection points in a URL"""
        injection_points = []
        
        try:
            # Parse URL for query parameters
            parsed_url = urlparse(url)
            if parsed_url.query:
                params = parse_qs(parsed_url.query, keep_blank_values=True)
                for param_name in params.keys():
                    injection_points.append(('query_param', param_name))
                    
            # Always test fragment injection
            injection_points.append(('fragment', None))
            
            # Always test path injection
            injection_points.append(('path', None))
            
            # Check for forms by making a request
            try:
                response = self.session.get(url, timeout=self.timeout)
                soup = BeautifulSoup(response.text, 'html.parser')
                forms = soup.find_all('form')
                
                if forms:
                    injection_points.append(('form_field', None))
                    
            except Exception:
                pass
                
        except Exception:
            # Fallback to basic injection points
            injection_points = [('query_param', 'q'), ('fragment', None), ('form_field', None)]
            
        return injection_points if injection_points else [('query_param', 'test')]
        
    def scan_url(self, url, payloads, blind_manager=None):
        """Scan a single URL for XSS vulnerabilities"""
        vulnerabilities = []
        driver = None
        
        try:
            # Initialize Chrome driver
            driver = self._get_chrome_driver()
            
            # Get injection points
            injection_points = self._scan_url_for_injection_points(url)
            
            # Test each payload at each injection point
            for injection_point, param_name in injection_points:
                for payload in payloads:
                    try:
                        # Test the payload
                        result = self._test_payload(driver, url, payload, injection_point, param_name)
                        
                        if result:
                            vulnerabilities.append(result)
                            
                        # Brief delay between tests
                        time.sleep(1)
                        
                    except Exception as e:
                        continue
                        
            # Test blind XSS if manager is provided
            if blind_manager:
                blind_results = blind_manager.test_blind_xss(driver, url, injection_points)
                if blind_results:
                    vulnerabilities.extend(blind_results)
                    
        except Exception as e:
            print(f"Error scanning {url}: {str(e)}")
            
        finally:
            if driver:
                try:
                    driver.quit()
                except:
                    pass
                    
        return vulnerabilities
        
    def cleanup(self):
        """Cleanup resources"""
        if hasattr(self, 'session'):
            self.session.close()
