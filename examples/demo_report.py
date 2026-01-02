#!/usr/bin/env python3
"""
Demonstration script showing Web Security Analyzer capabilities
This script demonstrates the scanner with mock/simulated responses
"""
from scanner.report_generator import ReportGenerator


def create_demo_report():
    """Create a comprehensive demo report showcasing all features"""
    
    print("=" * 70)
    print("Web Security Analyzer - Demo Report Generation")
    print("=" * 70)
    print()
    
    # Simulate comprehensive scan results
    sql_vulnerabilities = [
        {
            'type': 'SQL Injection',
            'severity': 'High',
            'url': 'https://example.com/products?id=123',
            'parameter': 'id',
            'method': 'GET',
            'payload': "' OR '1'='1",
            'description': 'SQL injection vulnerability detected in parameter "id"',
            'evidence': "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version..."
        },
        {
            'type': 'SQL Injection',
            'severity': 'High',
            'url': 'https://example.com/login',
            'parameter': 'username',
            'method': 'POST',
            'payload': "admin' --",
            'description': 'SQL injection vulnerability detected in POST parameter "username"',
            'evidence': "Warning: mysql_fetch_array() expects parameter 1 to be resource..."
        },
        {
            'type': 'SQL Injection',
            'severity': 'High',
            'url': 'https://example.com/search?q=test',
            'parameter': 'q',
            'method': 'GET',
            'payload': "' UNION SELECT NULL--",
            'description': 'SQL injection vulnerability detected in parameter "q"',
            'evidence': "Microsoft OLE DB Provider for SQL Server error '80040e14'..."
        }
    ]
    
    xss_vulnerabilities = [
        {
            'type': 'Cross-Site Scripting (XSS)',
            'severity': 'High',
            'url': 'https://example.com/search?query=test',
            'parameter': 'query',
            'method': 'GET',
            'payload': "<script>alert('XSS')</script>",
            'description': 'XSS vulnerability detected in parameter "query"',
            'evidence': 'Payload reflected in response without proper sanitization'
        },
        {
            'type': 'Cross-Site Scripting (XSS)',
            'severity': 'High',
            'url': 'https://example.com/comment',
            'parameter': 'comment',
            'method': 'POST',
            'payload': "<img src=x onerror=alert('XSS')>",
            'description': 'XSS vulnerability detected in form input "comment"',
            'evidence': 'Payload reflected in response without proper sanitization'
        },
        {
            'type': 'Cross-Site Scripting (XSS)',
            'severity': 'High',
            'url': 'https://example.com/profile?name=user',
            'parameter': 'name',
            'method': 'GET',
            'payload': "<svg/onload=alert('XSS')>",
            'description': 'XSS vulnerability detected in parameter "name"',
            'evidence': 'Payload reflected in response without proper sanitization'
        }
    ]
    
    security_headers = [
        {
            'type': 'Missing Security Header',
            'severity': 'High',
            'url': 'https://example.com',
            'header': 'Content-Security-Policy',
            'description': 'Missing Content-Security-Policy header: Controls resources the browser can load',
            'recommendation': "Add: Content-Security-Policy: default-src 'self'"
        },
        {
            'type': 'Missing Security Header',
            'severity': 'Medium',
            'url': 'https://example.com',
            'header': 'Strict-Transport-Security',
            'description': 'Missing Strict-Transport-Security header: Enforces secure HTTPS connections',
            'recommendation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains'
        },
        {
            'type': 'Missing Security Header',
            'severity': 'Medium',
            'url': 'https://example.com',
            'header': 'X-Frame-Options',
            'description': 'Missing X-Frame-Options header: Prevents clickjacking attacks',
            'recommendation': 'Add: X-Frame-Options: DENY or SAMEORIGIN'
        },
        {
            'type': 'Missing Security Header',
            'severity': 'Low',
            'url': 'https://example.com',
            'header': 'X-Content-Type-Options',
            'description': 'Missing X-Content-Type-Options header: Prevents MIME-sniffing',
            'recommendation': 'Add: X-Content-Type-Options: nosniff'
        },
        {
            'type': 'Insecure Header',
            'severity': 'Low',
            'url': 'https://example.com',
            'header': 'X-Powered-By',
            'value': 'PHP/7.4.3',
            'description': 'X-Powered-By header present: Reveals technology stack information',
            'recommendation': 'Remove this header to avoid information disclosure'
        },
        {
            'type': 'Insecure Header',
            'severity': 'Low',
            'url': 'https://example.com',
            'header': 'Server',
            'value': 'Apache/2.4.41 (Ubuntu)',
            'description': 'Server header present: May reveal server software version',
            'recommendation': 'Remove or obfuscate server version information'
        }
    ]
    
    # Generate the report
    print("Generating comprehensive demo report...")
    print()
    
    generator = ReportGenerator()
    report_path = generator.generate_report(
        target_url="https://example.com",
        sql_vulnerabilities=sql_vulnerabilities,
        xss_vulnerabilities=xss_vulnerabilities,
        security_headers_findings=security_headers,
        scan_duration="15.3 seconds",
        output_path="demo_security_report.html"
    )
    
    # Print summary
    print("✅ Demo Report Generated Successfully!")
    print()
    print(f"📄 Report Location: {report_path}")
    print()
    print("📊 Scan Summary:")
    print(f"   • Total Issues Found: {len(sql_vulnerabilities) + len(xss_vulnerabilities) + len(security_headers)}")
    print(f"   • SQL Injection: {len(sql_vulnerabilities)} vulnerabilities")
    print(f"   • XSS: {len(xss_vulnerabilities)} vulnerabilities")
    print(f"   • Security Headers: {len(security_headers)} issues")
    print()
    print("🔍 Severity Breakdown:")
    
    # Count by severity
    high = sum(1 for v in sql_vulnerabilities + xss_vulnerabilities + security_headers if v['severity'] == 'High')
    medium = sum(1 for v in sql_vulnerabilities + xss_vulnerabilities + security_headers if v['severity'] == 'Medium')
    low = sum(1 for v in sql_vulnerabilities + xss_vulnerabilities + security_headers if v['severity'] == 'Low')
    
    print(f"   • High Severity: {high}")
    print(f"   • Medium Severity: {medium}")
    print(f"   • Low Severity: {low}")
    print()
    print("=" * 70)
    print()
    print("💡 This is a DEMO report with simulated data.")
    print("   To scan real websites, use:")
    print("   python -m scanner.main <URL>")
    print()
    print("⚠️  Remember: Only scan websites you own or have permission to test!")
    print()


if __name__ == "__main__":
    create_demo_report()
