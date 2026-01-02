#!/usr/bin/env python3
"""
Example usage of Web Security Analyzer as a Python module
"""
from scanner.main import WebSecurityScanner


def example_full_scan():
    """Example: Full vulnerability scan"""
    print("=" * 70)
    print("Example 1: Full Vulnerability Scan")
    print("=" * 70)
    
    # Create scanner instance
    scanner = WebSecurityScanner("https://httpbin.org", timeout=15)
    
    try:
        # Run all scans
        results = scanner.scan()
        
        # Generate report
        report_path = scanner.generate_report("example_full_report.html")
        print(f"\nReport generated: {report_path}")
        
        # Access results programmatically
        print(f"\nSQL Injection vulnerabilities: {len(results['sql_injection'])}")
        print(f"XSS vulnerabilities: {len(results['xss'])}")
        print(f"Security header issues: {len(results['security_headers'])}")
        
    finally:
        scanner.close()


def example_specific_scan():
    """Example: Scan for specific vulnerability types"""
    print("\n" + "=" * 70)
    print("Example 2: Specific Vulnerability Scan (Headers Only)")
    print("=" * 70)
    
    scanner = WebSecurityScanner("https://httpbin.org")
    
    try:
        # Only scan security headers
        results = scanner.scan(scan_types=['headers'])
        
        # Print header issues
        for issue in results['security_headers']:
            print(f"\n{issue['type']}: {issue['header']}")
            print(f"  Severity: {issue['severity']}")
            print(f"  Recommendation: {issue['recommendation']}")
        
    finally:
        scanner.close()


def example_custom_client():
    """Example: Using HTTP client directly"""
    print("\n" + "=" * 70)
    print("Example 3: Direct HTTP Client Usage")
    print("=" * 70)
    
    from scanner.http_utils import HTTPClient
    from scanner.security_headers import SecurityHeadersAnalyzer
    
    # Create HTTP client with custom settings
    http_client = HTTPClient(timeout=20, verify_ssl=False)
    
    try:
        # Use specific analyzer
        analyzer = SecurityHeadersAnalyzer(http_client)
        findings = analyzer.analyze("https://httpbin.org")
        
        print(f"\nFound {len(findings)} security header issues")
        
    finally:
        http_client.close()


def main():
    """Run all examples"""
    print("\n🔒 Web Security Analyzer - Usage Examples\n")
    
    try:
        # Example 1: Full scan
        example_full_scan()
        
        # Example 2: Specific scan types
        example_specific_scan()
        
        # Example 3: Custom HTTP client
        example_custom_client()
        
        print("\n" + "=" * 70)
        print("✓ All examples completed successfully!")
        print("=" * 70 + "\n")
        
    except Exception as e:
        print(f"\n❌ Error running examples: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
