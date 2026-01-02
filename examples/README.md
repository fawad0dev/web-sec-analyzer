# Web Security Analyzer - Examples

This directory contains example scripts demonstrating how to use the Web Security Analyzer.

## Available Examples

### usage_examples.py

Demonstrates various ways to use the scanner:

1. **Full Vulnerability Scan**: Complete scan of all vulnerability types
2. **Specific Scan Types**: Scanning for specific vulnerabilities only
3. **Direct HTTP Client Usage**: Using individual scanner components

## Running Examples

```bash
# Run the usage examples
cd examples
python usage_examples.py
```

## Example: Basic Scan

```python
from scanner.main import WebSecurityScanner

# Create scanner
scanner = WebSecurityScanner("https://example.com")

# Run scan
results = scanner.scan()

# Generate report
report_path = scanner.generate_report()

# Clean up
scanner.close()
```

## Example: Specific Vulnerability Types

```python
from scanner.main import WebSecurityScanner

scanner = WebSecurityScanner("https://example.com")

# Only scan for SQL injection and XSS
results = scanner.scan(scan_types=['sql', 'xss'])

scanner.close()
```

## Example: Custom Configuration

```python
from scanner.main import WebSecurityScanner

# Scanner with custom timeout
scanner = WebSecurityScanner(
    "https://example.com",
    timeout=30
)

results = scanner.scan()

# Generate report to specific location
scanner.generate_report("custom_report.html")

scanner.close()
```

## Example: Analyzing Results

```python
from scanner.main import WebSecurityScanner

scanner = WebSecurityScanner("https://example.com")
results = scanner.scan()

# Access SQL injection vulnerabilities
for vuln in results['sql_injection']:
    print(f"Found {vuln['type']} in {vuln['parameter']}")
    print(f"Severity: {vuln['severity']}")
    print(f"Payload: {vuln['payload']}")

# Access XSS vulnerabilities
for vuln in results['xss']:
    print(f"XSS in {vuln['parameter']}: {vuln['description']}")

# Access security header issues
for issue in results['security_headers']:
    print(f"Header issue: {issue['header']}")
    print(f"Recommendation: {issue['recommendation']}")

scanner.close()
```

## Testing Targets

### Safe Testing Environments

For testing the scanner, use these safe and legal targets:

1. **Your Own Applications**: Always test your own web applications
2. **Local Test Servers**: Set up vulnerable applications locally
3. **Authorized Penetration Testing Sites**:
   - http://testphp.vulnweb.com/ (Acunetix test site)
   - http://demo.testfire.net/ (IBM test site)
   - https://httpbin.org/ (HTTP testing service)

### IMPORTANT: Legal Notice

**Never scan websites without permission!** Only use this tool on:
- Websites you own
- Applications you have explicit written permission to test
- Designated testing environments

Unauthorized testing may be illegal and unethical.

## Sample Output

When running the examples, you'll see:

1. **Console Output**: Color-coded scan progress and results
2. **HTML Reports**: Professional reports in the current directory
3. **Programmatic Access**: Direct access to vulnerability data

## Advanced Usage

### Using Individual Scanners

```python
from scanner.http_utils import HTTPClient
from scanner.sql_injection import SQLInjectionScanner

# Create HTTP client
client = HTTPClient(timeout=10)

# Use SQL injection scanner directly
sql_scanner = SQLInjectionScanner(client)
vulnerabilities = sql_scanner.scan("https://example.com")

# Process results
for vuln in vulnerabilities:
    print(vuln)

client.close()
```

### Custom Report Generation

```python
from scanner.report_generator import ReportGenerator

generator = ReportGenerator()

# Generate report with custom data
report_path = generator.generate_report(
    target_url="https://example.com",
    sql_vulnerabilities=[...],
    xss_vulnerabilities=[...],
    security_headers_findings=[...],
    scan_duration="45.2 seconds",
    output_path="my_report.html"
)
```

## Tips

1. Start with security headers analysis (fastest)
2. Use verbose mode (`--verbose`) for debugging
3. Increase timeout for slow servers
4. Review HTML reports for detailed evidence
5. Always verify findings manually

## Troubleshooting

**Connection Errors**: Increase timeout or check network connectivity
**SSL Errors**: The scanner disables SSL verification by default for testing
**No Vulnerabilities Found**: Good! Or try testing against known vulnerable apps
**Import Errors**: Ensure all dependencies are installed: `pip install -r requirements.txt`
