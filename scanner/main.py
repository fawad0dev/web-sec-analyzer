#!/usr/bin/env python3
"""
Main scanner application with CLI interface
"""
import sys
import argparse
import logging
import time
from pathlib import Path
from datetime import datetime
from colorama import init, Fore, Style

from .http_utils import HTTPClient, is_valid_url
from .sql_injection import SQLInjectionScanner
from .xss_scanner import XSSScanner
from .security_headers import SecurityHeadersAnalyzer
from .report_generator import ReportGenerator

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


class WebSecurityScanner:
    """Main web security scanner orchestrator"""
    
    def __init__(self, target_url: str, timeout: int = 10):
        """
        Initialize web security scanner
        
        Args:
            target_url: Target URL to scan
            timeout: Request timeout in seconds
        """
        self.target_url = target_url
        self.timeout = timeout
        self.http_client = HTTPClient(timeout=timeout)
        self.sql_scanner = SQLInjectionScanner(self.http_client)
        self.xss_scanner = XSSScanner(self.http_client)
        self.headers_analyzer = SecurityHeadersAnalyzer(self.http_client)
        self.report_generator = ReportGenerator()
        
        self.results = {
            'sql_injection': [],
            'xss': [],
            'security_headers': []
        }
    
    def scan(self, scan_types: list = None) -> dict:
        """
        Run security scans
        
        Args:
            scan_types: List of scan types to run (sql, xss, headers). None = all
            
        Returns:
            Scan results dictionary
        """
        if scan_types is None:
            scan_types = ['sql', 'xss', 'headers']
        
        start_time = time.time()
        
        self._print_banner()
        self._print_scan_info()
        
        # Run SQL injection scan
        if 'sql' in scan_types:
            self._print_section_header("SQL Injection Detection")
            try:
                self.results['sql_injection'] = self.sql_scanner.scan(self.target_url)
                self._print_results('SQL Injection', self.results['sql_injection'])
            except Exception as e:
                logger.error(f"SQL injection scan failed: {e}")
        
        # Run XSS scan
        if 'xss' in scan_types:
            self._print_section_header("Cross-Site Scripting (XSS) Detection")
            try:
                self.results['xss'] = self.xss_scanner.scan(self.target_url)
                self._print_results('XSS', self.results['xss'])
            except Exception as e:
                logger.error(f"XSS scan failed: {e}")
        
        # Run security headers analysis
        if 'headers' in scan_types:
            self._print_section_header("Security Headers Analysis")
            try:
                self.results['security_headers'] = self.headers_analyzer.analyze(self.target_url)
                self._print_results('Security Headers', self.results['security_headers'])
            except Exception as e:
                logger.error(f"Security headers analysis failed: {e}")
        
        end_time = time.time()
        duration = end_time - start_time
        
        self._print_summary(duration)
        
        return self.results
    
    def generate_report(self, output_path: str = None) -> str:
        """
        Generate HTML report
        
        Args:
            output_path: Output file path
            
        Returns:
            Path to generated report
        """
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"security_report_{timestamp}.html"
        
        # Calculate scan duration
        scan_duration = "N/A"
        
        report_path = self.report_generator.generate_report(
            target_url=self.target_url,
            sql_vulnerabilities=self.results['sql_injection'],
            xss_vulnerabilities=self.results['xss'],
            security_headers_findings=self.results['security_headers'],
            scan_duration=scan_duration,
            output_path=output_path
        )
        
        return report_path
    
    def close(self):
        """Clean up resources"""
        self.http_client.close()
    
    def _print_banner(self):
        """Print application banner"""
        banner = f"""
{Fore.CYAN}{'=' * 70}
{Fore.CYAN}            Web Security Analyzer v1.0.0                            
{Fore.CYAN}       Comprehensive Web Vulnerability Scanner                      
{Fore.CYAN}{'=' * 70}
{Style.RESET_ALL}"""
        print(banner)
    
    def _print_scan_info(self):
        """Print scan information"""
        print(f"\n{Fore.YELLOW}[*] Target URL:{Style.RESET_ALL} {self.target_url}")
        print(f"{Fore.YELLOW}[*] Scan started:{Style.RESET_ALL} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
    
    def _print_section_header(self, title: str):
        """Print section header"""
        print(f"\n{Fore.MAGENTA}{'=' * 70}")
        print(f"{Fore.MAGENTA}  {title}")
        print(f"{Fore.MAGENTA}{'=' * 70}{Style.RESET_ALL}\n")
    
    def _print_results(self, scan_type: str, results: list):
        """Print scan results"""
        if not results:
            print(f"{Fore.GREEN}[✓] No {scan_type} vulnerabilities detected.{Style.RESET_ALL}\n")
            return
        
        print(f"{Fore.RED}[!] Found {len(results)} {scan_type} issue(s):{Style.RESET_ALL}\n")
        
        for idx, result in enumerate(results, 1):
            severity = result.get('severity', 'Unknown')
            severity_color = self._get_severity_color(severity)
            
            print(f"{severity_color}[{idx}] {result.get('type', 'Unknown')}")
            print(f"    Severity: {severity}")
            print(f"    Description: {result.get('description', 'N/A')}")
            
            if 'url' in result:
                print(f"    URL: {result['url']}")
            if 'parameter' in result:
                print(f"    Parameter: {result['parameter']}")
            if 'method' in result:
                print(f"    Method: {result['method']}")
            if 'header' in result:
                print(f"    Header: {result['header']}")
            
            print(f"{Style.RESET_ALL}")
    
    def _print_summary(self, duration: float):
        """Print scan summary"""
        total_issues = (
            len(self.results['sql_injection']) +
            len(self.results['xss']) +
            len(self.results['security_headers'])
        )
        
        # Count by severity
        high_count = 0
        medium_count = 0
        low_count = 0
        
        all_findings = (
            self.results['sql_injection'] +
            self.results['xss'] +
            self.results['security_headers']
        )
        
        for finding in all_findings:
            severity = finding.get('severity', '').lower()
            if severity == 'high':
                high_count += 1
            elif severity == 'medium':
                medium_count += 1
            elif severity == 'low':
                low_count += 1
        
        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}  SCAN SUMMARY")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}[*] Scan Duration:{Style.RESET_ALL} {duration:.2f} seconds")
        print(f"{Fore.YELLOW}[*] Total Issues Found:{Style.RESET_ALL} {total_issues}")
        print(f"    {Fore.RED}High Severity:{Style.RESET_ALL} {high_count}")
        print(f"    {Fore.YELLOW}Medium Severity:{Style.RESET_ALL} {medium_count}")
        print(f"    {Fore.BLUE}Low Severity:{Style.RESET_ALL} {low_count}")
        print()
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color for severity level"""
        severity_lower = severity.lower()
        if severity_lower == 'high':
            return Fore.RED
        elif severity_lower == 'medium':
            return Fore.YELLOW
        elif severity_lower == 'low':
            return Fore.BLUE
        else:
            return Fore.WHITE


def main():
    """Main entry point for CLI"""
    parser = argparse.ArgumentParser(
        description='Web Security Analyzer - Comprehensive Web Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a website for all vulnerabilities
  %(prog)s https://example.com
  
  # Scan only for SQL injection
  %(prog)s https://example.com --scan-type sql
  
  # Scan with custom timeout and output file
  %(prog)s https://example.com --timeout 20 --output report.html
  
  # Scan for specific vulnerability types
  %(prog)s https://example.com --scan-type sql xss
        """
    )
    
    parser.add_argument(
        'url',
        help='Target URL to scan (e.g., https://example.com)'
    )
    
    parser.add_argument(
        '-t', '--scan-type',
        nargs='+',
        choices=['sql', 'xss', 'headers', 'all'],
        default=['all'],
        help='Types of scans to perform (default: all)'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output HTML report file path (default: security_report_TIMESTAMP.html)'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=10,
        help='Request timeout in seconds (default: 10)'
    )
    
    parser.add_argument(
        '--no-report',
        action='store_true',
        help='Skip HTML report generation'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validate URL
    if not is_valid_url(args.url):
        print(f"{Fore.RED}[!] Error: Invalid URL format. Please provide a valid URL (e.g., https://example.com){Style.RESET_ALL}")
        sys.exit(1)
    
    # Determine scan types
    scan_types = args.scan_type
    if 'all' in scan_types:
        scan_types = ['sql', 'xss', 'headers']
    
    # Create scanner instance
    scanner = WebSecurityScanner(args.url, timeout=args.timeout)
    
    try:
        # Run scans
        scanner.scan(scan_types=scan_types)
        
        # Generate report
        if not args.no_report:
            print(f"\n{Fore.CYAN}[*] Generating HTML report...{Style.RESET_ALL}")
            report_path = scanner.generate_report(output_path=args.output)
            print(f"{Fore.GREEN}[✓] Report generated: {report_path}{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}[✓] Scan completed successfully!{Style.RESET_ALL}\n")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user.{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    finally:
        scanner.close()


if __name__ == '__main__':
    main()
