#!/usr/bin/env python3
"""
SQL Injection vulnerability detection module
"""
import logging
from typing import List, Dict, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .http_utils import HTTPClient

logger = logging.getLogger(__name__)


class SQLInjectionScanner:
    """Scanner for detecting SQL injection vulnerabilities"""
    
    # Configuration constants
    MAX_PAYLOADS_PER_PARAM = 10  # Maximum payloads to test per parameter
    MAX_POST_PARAMS = 5  # Maximum POST parameters to test
    
    # SQL injection payloads for testing
    SQL_PAYLOADS = [
        "'",
        "\"",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin' --",
        "admin' #",
        "admin'/*",
        "' or 1=1--",
        "' or 1=1#",
        "' or 1=1/*",
        "') or '1'='1--",
        "') or ('1'='1--",
        "1' AND '1' = '1",
        "1' AND '1' = '2",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' AND 1=1--",
        "' AND 1=2--",
    ]
    
    # SQL error signatures
    SQL_ERRORS = [
        "SQL syntax",
        "mysql_fetch",
        "mysql_num_rows",
        "mysqli",
        "ORA-01",
        "PostgreSQL",
        "pg_query",
        "SQLite",
        "ODBC Driver",
        "Microsoft SQL",
        "Unclosed quotation mark",
        "quoted string not properly terminated",
        "SQL command not properly ended",
        "syntax error",
        "unexpected end of SQL command",
        "Warning: mysql",
        "valid MySQL result",
        "MySqlClient",
        "com.mysql.jdbc",
        "org.postgresql",
        "Incorrect syntax near",
    ]
    
    def __init__(self, http_client: HTTPClient):
        """
        Initialize SQL injection scanner
        
        Args:
            http_client: HTTP client for making requests
        """
        self.http_client = http_client
        self.vulnerabilities = []
    
    def scan(self, url: str) -> List[Dict]:
        """
        Scan URL for SQL injection vulnerabilities
        
        Args:
            url: Target URL to scan
            
        Returns:
            List of vulnerabilities found
        """
        self.vulnerabilities = []
        logger.info(f"Starting SQL injection scan for: {url}")
        
        # Test URL parameters
        self._test_url_parameters(url)
        
        # Test POST forms (basic implementation)
        self._test_post_forms(url)
        
        logger.info(f"SQL injection scan completed. Found {len(self.vulnerabilities)} vulnerabilities")
        return self.vulnerabilities
    
    def _test_url_parameters(self, url: str):
        """
        Test URL parameters for SQL injection
        
        Args:
            url: Target URL
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            # If no parameters, try adding a test parameter
            test_url = f"{url}{'&' if '?' in url else '?'}id=1"
            self._test_parameter(test_url, 'id')
            return
        
        # Test each parameter
        for param_name in params:
            for payload in self.SQL_PAYLOADS[:self.MAX_PAYLOADS_PER_PARAM]:
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
                
                if self._check_sql_error(test_url, param_name, payload):
                    break  # Found vulnerability, move to next parameter
    
    def _test_parameter(self, url: str, param_name: str):
        """
        Test a specific parameter for SQL injection
        
        Args:
            url: URL with parameter
            param_name: Parameter name being tested
        """
        for payload in self.SQL_PAYLOADS[:self.MAX_PAYLOADS_PER_PARAM]:
            # Replace parameter value with payload
            if '=' in url:
                base_url, query = url.split('?', 1)
                params = parse_qs(query)
                params[param_name] = [payload]
                new_query = urlencode(params, doseq=True)
                test_url = f"{base_url}?{new_query}"
            else:
                test_url = f"{url}?{param_name}={payload}"
            
            if self._check_sql_error(test_url, param_name, payload):
                break
    
    def _test_post_forms(self, url: str):
        """
        Test POST forms for SQL injection
        
        Args:
            url: Target URL
        """
        # Basic POST parameter testing
        common_params = ['username', 'password', 'email', 'id', 'search', 'query']
        
        for param in common_params[:self.MAX_POST_PARAMS]:
            for payload in self.SQL_PAYLOADS[:self.MAX_PAYLOADS_PER_PARAM]:
                data = {param: payload}
                response = self.http_client.post(url, data=data)
                
                if response and self._contains_sql_error(response.text):
                    self.vulnerabilities.append({
                        'type': 'SQL Injection',
                        'severity': 'High',
                        'url': url,
                        'parameter': param,
                        'method': 'POST',
                        'payload': payload,
                        'description': f'SQL injection vulnerability detected in POST parameter "{param}"',
                        'evidence': self._extract_error_snippet(response.text)
                    })
                    break  # Found vulnerability, move to next parameter
    
    def _check_sql_error(self, url: str, param_name: str, payload: str) -> bool:
        """
        Check if response contains SQL errors
        
        Args:
            url: Test URL
            param_name: Parameter name
            payload: SQL payload used
            
        Returns:
            True if SQL error detected
        """
        response = self.http_client.get(url)
        
        if response and self._contains_sql_error(response.text):
            self.vulnerabilities.append({
                'type': 'SQL Injection',
                'severity': 'High',
                'url': url,
                'parameter': param_name,
                'method': 'GET',
                'payload': payload,
                'description': f'SQL injection vulnerability detected in parameter "{param_name}"',
                'evidence': self._extract_error_snippet(response.text)
            })
            return True
        
        return False
    
    def _contains_sql_error(self, text: str) -> bool:
        """
        Check if text contains SQL error messages
        
        Args:
            text: Response text to check
            
        Returns:
            True if SQL error found
        """
        text_lower = text.lower()
        return any(error.lower() in text_lower for error in self.SQL_ERRORS)
    
    def _extract_error_snippet(self, text: str, max_length: int = 200) -> str:
        """
        Extract a snippet of the SQL error from response
        
        Args:
            text: Response text
            max_length: Maximum length of snippet
            
        Returns:
            Error snippet
        """
        text_lower = text.lower()
        for error in self.SQL_ERRORS:
            error_lower = error.lower()
            if error_lower in text_lower:
                idx = text_lower.index(error_lower)
                start = max(0, idx - 50)
                end = min(len(text), idx + max_length)
                snippet = text[start:end].strip()
                return snippet[:max_length] + "..." if len(snippet) > max_length else snippet
        
        return "SQL error detected in response"
