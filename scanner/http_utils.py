#!/usr/bin/env python3
"""
HTTP utility functions for making requests and handling responses
"""
import requests
import logging
from typing import Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse

# Disable SSL warnings for testing purposes
requests.packages.urllib3.disable_warnings()

logger = logging.getLogger(__name__)


class HTTPClient:
    """HTTP client for making secure requests"""
    
    def __init__(self, timeout: int = 10, verify_ssl: bool = False):
        """
        Initialize HTTP client
        
        Args:
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Web-Security-Analyzer/1.0'
        })
    
    def get(self, url: str, params: Optional[Dict] = None) -> Optional[requests.Response]:
        """
        Make a GET request
        
        Args:
            url: Target URL
            params: Query parameters
            
        Returns:
            Response object or None on error
        """
        try:
            response = self.session.get(
                url,
                params=params,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True
            )
            return response
        except requests.exceptions.RequestException as e:
            logger.error(f"GET request failed for {url}: {e}")
            return None
    
    def post(self, url: str, data: Optional[Dict] = None) -> Optional[requests.Response]:
        """
        Make a POST request
        
        Args:
            url: Target URL
            data: POST data
            
        Returns:
            Response object or None on error
        """
        try:
            response = self.session.post(
                url,
                data=data,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True
            )
            return response
        except requests.exceptions.RequestException as e:
            logger.error(f"POST request failed for {url}: {e}")
            return None
    
    def close(self):
        """Close the session"""
        self.session.close()


def is_valid_url(url: str) -> bool:
    """
    Check if a URL is valid
    
    Args:
        url: URL to validate
        
    Returns:
        True if valid, False otherwise
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def normalize_url(base_url: str, path: str = "") -> str:
    """
    Normalize and join URL paths
    
    Args:
        base_url: Base URL
        path: Path to join
        
    Returns:
        Normalized URL
    """
    return urljoin(base_url, path)
