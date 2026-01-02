#!/usr/bin/env python3
"""
Cross-Site Scripting (XSS) vulnerability detection module
"""
import logging
from typing import List, Dict
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
from .http_utils import HTTPClient

logger = logging.getLogger(__name__)


class XSSScanner:
    """Scanner for detecting XSS vulnerabilities"""
    
    # Configuration constants
    MAX_PAYLOADS_PER_PARAM = 10  # Maximum payloads to test per parameter
    MAX_FORMS_TO_TEST = 5  # Maximum forms to test per page
    MAX_INPUTS_PER_FORM = 3  # Maximum inputs to test per form
    
    # XSS test payloads
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src=javascript:alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<select onfocus=alert('XSS') autofocus>",
        "<textarea onfocus=alert('XSS') autofocus>",
        "<marquee onstart=alert('XSS')>",
        "<details open ontoggle=alert('XSS')>",
        "'-alert('XSS')-'",
        "\"><script>alert('XSS')</script>",
        "'><script>alert('XSS')</script>",
        "<ScRiPt>alert('XSS')</ScRiPt>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<img src=\"x\" onerror=\"alert('XSS')\">",
        "<svg><script>alert('XSS')</script></svg>",
        "<object data=\"javascript:alert('XSS')\">",
        "<embed src=\"javascript:alert('XSS')\">",
    ]
    
    # Simple XSS patterns to check in response
    XSS_PATTERNS = [
        "<script>alert('XSS')</script>",
        "alert('XSS')",
        "onerror=alert('XSS')",
        "onload=alert('XSS')",
        "javascript:alert('XSS')",
        "onfocus=alert('XSS')",
        "ontoggle=alert('XSS')",
        "onstart=alert('XSS')",
    ]
    
    def __init__(self, http_client: HTTPClient):
        """
        Initialize XSS scanner
        
        Args:
            http_client: HTTP client for making requests
        """
        self.http_client = http_client
        self.vulnerabilities = []
    
    def scan(self, url: str) -> List[Dict]:
        """
        Scan URL for XSS vulnerabilities
        
        Args:
            url: Target URL to scan
            
        Returns:
            List of vulnerabilities found
        """
        self.vulnerabilities = []
        logger.info(f"Starting XSS scan for: {url}")
        
        # Test URL parameters
        self._test_url_parameters(url)
        
        # Test forms
        self._test_forms(url)
        
        logger.info(f"XSS scan completed. Found {len(self.vulnerabilities)} vulnerabilities")
        return self.vulnerabilities
    
    def _test_url_parameters(self, url: str):
        """
        Test URL parameters for XSS
        
        Args:
            url: Target URL
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            # If no parameters, try adding a test parameter
            test_url = f"{url}{'&' if '?' in url else '?'}q=test"
            self._test_parameter(test_url, 'q')
            return
        
        # Test each parameter
        for param_name in params:
            for payload in self.XSS_PAYLOADS[:self.MAX_PAYLOADS_PER_PARAM]:
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                # Reconstruct URL with test payload
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment
                ))
                
                if self._check_xss_reflection(test_url, param_name, payload):
                    break  # Found vulnerability, move to next parameter
    
    def _test_parameter(self, url: str, param_name: str):
        """
        Test a specific parameter for XSS
        
        Args:
            url: URL with parameter
            param_name: Parameter name being tested
        """
        for payload in self.XSS_PAYLOADS[:self.MAX_PAYLOADS_PER_PARAM]:
            # Replace parameter value with payload
            if '=' in url:
                base_url, query = url.split('?', 1)
                params = parse_qs(query)
                params[param_name] = [payload]
                new_query = urlencode(params, doseq=True)
                test_url = f"{base_url}?{new_query}"
            else:
                test_url = f"{url}?{param_name}={payload}"
            
            if self._check_xss_reflection(test_url, param_name, payload):
                break
    
    def _test_forms(self, url: str):
        """
        Test forms for XSS vulnerabilities
        
        Args:
            url: Target URL
        """
        # Get the page and find forms
        response = self.http_client.get(url)
        if not response:
            return
        
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms[:self.MAX_FORMS_TO_TEST]:
                self._test_form(url, form)
        except Exception as e:
            logger.error(f"Error parsing forms: {e}")
    
    def _test_form(self, base_url: str, form):
        """
        Test a specific form for XSS
        
        Args:
            base_url: Base URL of the page
            form: BeautifulSoup form element
        """
        try:
            # Get form action and method
            action = form.get('action', '')
            method = form.get('method', 'get').upper()
            
            # Build full form URL
            from .http_utils import normalize_url
            form_url = normalize_url(base_url, action)
            
            # Find input fields
            inputs = form.find_all(['input', 'textarea'])
            
            # Test each input with XSS payloads
            for input_field in inputs[:self.MAX_INPUTS_PER_FORM]:
                input_name = input_field.get('name')
                input_type = input_field.get('type', 'text')
                
                # Skip non-text inputs
                if input_type in ['submit', 'button', 'reset', 'file', 'hidden']:
                    continue
                
                if not input_name:
                    continue
                
                # Test with XSS payloads
                for payload in self.XSS_PAYLOADS[:self.MAX_PAYLOADS_PER_PARAM]:
                    data = {input_name: payload}
                    
                    if method == 'POST':
                        response = self.http_client.post(form_url, data=data)
                    else:
                        response = self.http_client.get(form_url, params=data)
                    
                    if response and self._payload_reflected(response.text, payload):
                        self.vulnerabilities.append({
                            'type': 'Cross-Site Scripting (XSS)',
                            'severity': 'High',
                            'url': form_url,
                            'parameter': input_name,
                            'method': method,
                            'payload': payload,
                            'description': f'XSS vulnerability detected in form input "{input_name}"',
                            'evidence': f'Payload reflected in response without proper sanitization'
                        })
                        break  # Found vulnerability in this input
        except Exception as e:
            logger.error(f"Error testing form: {e}")
    
    def _check_xss_reflection(self, url: str, param_name: str, payload: str) -> bool:
        """
        Check if XSS payload is reflected in response
        
        Args:
            url: Test URL
            param_name: Parameter name
            payload: XSS payload used
            
        Returns:
            True if XSS vulnerability detected
        """
        response = self.http_client.get(url)
        
        if response and self._payload_reflected(response.text, payload):
            self.vulnerabilities.append({
                'type': 'Cross-Site Scripting (XSS)',
                'severity': 'High',
                'url': url,
                'parameter': param_name,
                'method': 'GET',
                'payload': payload,
                'description': f'XSS vulnerability detected in parameter "{param_name}"',
                'evidence': f'Payload reflected in response without proper sanitization'
            })
            return True
        
        return False
    
    def _payload_reflected(self, response_text: str, payload: str) -> bool:
        """
        Check if payload is reflected in response
        
        Args:
            response_text: HTTP response text
            payload: XSS payload
            
        Returns:
            True if payload is reflected unsafely
        """
        # Check for exact payload match (unescaped)
        if payload in response_text:
            return True
        
        # Check for common XSS patterns in response
        response_lower = response_text.lower()
        payload_lower = payload.lower()
        
        # Check if key parts of payload are present
        for pattern in self.XSS_PATTERNS:
            if pattern.lower() in payload_lower and pattern.lower() in response_lower:
                return True
        
        # Check for script tags or event handlers
        dangerous_patterns = ['<script', 'onerror=', 'onload=', 'javascript:', 'onfocus=']
        for pattern in dangerous_patterns:
            if pattern.lower() in payload_lower and pattern.lower() in response_lower:
                return True
        
        return False
