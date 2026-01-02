#!/usr/bin/env python3
"""
Security headers analysis module
"""
import logging
from typing import List, Dict, Optional
from .http_utils import HTTPClient

logger = logging.getLogger(__name__)


class SecurityHeadersAnalyzer:
    """Analyzer for security-related HTTP headers"""
    
    # Security headers to check with their descriptions and recommendations
    SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'description': 'Enforces secure HTTPS connections',
            'recommendation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains',
            'severity': 'Medium'
        },
        'X-Frame-Options': {
            'description': 'Prevents clickjacking attacks',
            'recommendation': 'Add: X-Frame-Options: DENY or SAMEORIGIN',
            'severity': 'Medium'
        },
        'X-Content-Type-Options': {
            'description': 'Prevents MIME-sniffing',
            'recommendation': 'Add: X-Content-Type-Options: nosniff',
            'severity': 'Low'
        },
        'Content-Security-Policy': {
            'description': 'Controls resources the browser can load',
            'recommendation': "Add: Content-Security-Policy: default-src 'self'",
            'severity': 'High'
        },
        'X-XSS-Protection': {
            'description': 'Enables browser XSS filtering',
            'recommendation': 'Add: X-XSS-Protection: 1; mode=block',
            'severity': 'Low'
        },
        'Referrer-Policy': {
            'description': 'Controls referrer information',
            'recommendation': 'Add: Referrer-Policy: no-referrer or strict-origin-when-cross-origin',
            'severity': 'Low'
        },
        'Permissions-Policy': {
            'description': 'Controls browser features and APIs',
            'recommendation': 'Add: Permissions-Policy: geolocation=(), microphone=(), camera=()',
            'severity': 'Low'
        }
    }
    
    # Insecure header values to flag
    INSECURE_VALUES = {
        'X-Powered-By': {
            'description': 'Reveals technology stack information',
            'recommendation': 'Remove this header to avoid information disclosure',
            'severity': 'Low'
        },
        'Server': {
            'description': 'May reveal server software version',
            'recommendation': 'Remove or obfuscate server version information',
            'severity': 'Low'
        }
    }
    
    def __init__(self, http_client: HTTPClient):
        """
        Initialize security headers analyzer
        
        Args:
            http_client: HTTP client for making requests
        """
        self.http_client = http_client
        self.findings = []
    
    def analyze(self, url: str) -> List[Dict]:
        """
        Analyze security headers for a URL
        
        Args:
            url: Target URL to analyze
            
        Returns:
            List of security findings
        """
        self.findings = []
        logger.info(f"Starting security headers analysis for: {url}")
        
        response = self.http_client.get(url)
        if not response:
            logger.error(f"Failed to fetch URL: {url}")
            return self.findings
        
        headers = response.headers
        
        # Check for missing security headers
        self._check_missing_headers(url, headers)
        
        # Check for insecure headers
        self._check_insecure_headers(url, headers)
        
        # Check header values
        self._check_header_values(url, headers)
        
        logger.info(f"Security headers analysis completed. Found {len(self.findings)} issues")
        return self.findings
    
    def _check_missing_headers(self, url: str, headers: Dict):
        """
        Check for missing security headers
        
        Args:
            url: Target URL
            headers: Response headers
        """
        for header_name, header_info in self.SECURITY_HEADERS.items():
            if header_name not in headers:
                self.findings.append({
                    'type': 'Missing Security Header',
                    'severity': header_info['severity'],
                    'url': url,
                    'header': header_name,
                    'description': f'Missing {header_name} header: {header_info["description"]}',
                    'recommendation': header_info['recommendation']
                })
    
    def _check_insecure_headers(self, url: str, headers: Dict):
        """
        Check for headers that disclose sensitive information
        
        Args:
            url: Target URL
            headers: Response headers
        """
        for header_name, header_info in self.INSECURE_VALUES.items():
            if header_name in headers:
                self.findings.append({
                    'type': 'Insecure Header',
                    'severity': header_info['severity'],
                    'url': url,
                    'header': header_name,
                    'value': headers[header_name],
                    'description': f'{header_name} header present: {header_info["description"]}',
                    'recommendation': header_info['recommendation']
                })
    
    def _check_header_values(self, url: str, headers: Dict):
        """
        Validate security header values
        
        Args:
            url: Target URL
            headers: Response headers
        """
        # Check X-Frame-Options value
        if 'X-Frame-Options' in headers:
            value = headers['X-Frame-Options'].upper()
            if value not in ['DENY', 'SAMEORIGIN']:
                self.findings.append({
                    'type': 'Weak Security Header',
                    'severity': 'Medium',
                    'url': url,
                    'header': 'X-Frame-Options',
                    'value': headers['X-Frame-Options'],
                    'description': 'X-Frame-Options has weak or invalid value',
                    'recommendation': 'Use X-Frame-Options: DENY or SAMEORIGIN'
                })
        
        # Check Strict-Transport-Security value
        if 'Strict-Transport-Security' in headers:
            hsts = headers['Strict-Transport-Security'].lower()
            if 'max-age' not in hsts:
                self.findings.append({
                    'type': 'Weak Security Header',
                    'severity': 'Medium',
                    'url': url,
                    'header': 'Strict-Transport-Security',
                    'value': headers['Strict-Transport-Security'],
                    'description': 'HSTS header missing max-age directive',
                    'recommendation': 'Add max-age directive: Strict-Transport-Security: max-age=31536000'
                })
            elif 'max-age' in hsts:
                # Extract max-age value with robust error handling
                try:
                    max_age_parts = [p for p in hsts.split(';') if 'max-age' in p]
                    if max_age_parts:
                        max_age_str = max_age_parts[0].split('=')[1].strip()
                        max_age = int(max_age_str)
                        if max_age < 31536000:  # Less than 1 year
                            self.findings.append({
                                'type': 'Weak Security Header',
                                'severity': 'Low',
                                'url': url,
                                'header': 'Strict-Transport-Security',
                                'value': headers['Strict-Transport-Security'],
                                'description': 'HSTS max-age is less than recommended 1 year',
                                'recommendation': 'Increase max-age to at least 31536000 (1 year)'
                            })
                except (IndexError, ValueError, AttributeError) as e:
                    # Log parsing error but don't crash
                    logger.debug(f"Failed to parse HSTS max-age value: {e}")
        
        # Check Content-Security-Policy
        if 'Content-Security-Policy' in headers:
            csp = headers['Content-Security-Policy'].lower()
            if 'unsafe-inline' in csp:
                self.findings.append({
                    'type': 'Weak Security Header',
                    'severity': 'Medium',
                    'url': url,
                    'header': 'Content-Security-Policy',
                    'value': headers['Content-Security-Policy'],
                    'description': 'CSP contains unsafe-inline which weakens XSS protection',
                    'recommendation': 'Remove unsafe-inline and use nonces or hashes instead'
                })
            if 'unsafe-eval' in csp:
                self.findings.append({
                    'type': 'Weak Security Header',
                    'severity': 'Medium',
                    'url': url,
                    'header': 'Content-Security-Policy',
                    'value': headers['Content-Security-Policy'],
                    'description': 'CSP contains unsafe-eval which weakens security',
                    'recommendation': 'Remove unsafe-eval from CSP'
                })
