# Web Security Analyzer - Quick Reference Guide

## 🚀 Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run a basic scan
python -m scanner.main https://example.com

# Scan for specific vulnerabilities
python -m scanner.main https://example.com --scan-type sql xss

# Generate report with custom name
python -m scanner.main https://example.com --output my_report.html
```

## 📖 Common Commands

### Full Scan (All Vulnerabilities)
```bash
python -m scanner.main https://target-site.com
```

### SQL Injection Only
```bash
python -m scanner.main https://target-site.com --scan-type sql
```

### XSS Only
```bash
python -m scanner.main https://target-site.com --scan-type xss
```

### Security Headers Only
```bash
python -m scanner.main https://target-site.com --scan-type headers
```

### Multiple Scan Types
```bash
python -m scanner.main https://target-site.com --scan-type sql xss
```

### With Custom Settings
```bash
python -m scanner.main https://target-site.com \
    --timeout 30 \
    --output custom_report.html \
    --verbose
```

### Skip Report Generation
```bash
python -m scanner.main https://target-site.com --no-report
```

## 🔧 As a Python Module

### Basic Usage
```python
from scanner.main import WebSecurityScanner

# Create scanner
scanner = WebSecurityScanner("https://example.com", timeout=15)

# Run scan
results = scanner.scan()

# Generate report
report_path = scanner.generate_report("report.html")

# Clean up
scanner.close()
```

### Specific Scan Types
```python
# Scan only for SQL injection and XSS
results = scanner.scan(scan_types=['sql', 'xss'])

# Scan only security headers
results = scanner.scan(scan_types=['headers'])
```

### Access Results Programmatically
```python
# Get SQL injection vulnerabilities
sql_vulns = results['sql_injection']
for vuln in sql_vulns:
    print(f"Found {vuln['type']} in {vuln['parameter']}")

# Get XSS vulnerabilities
xss_vulns = results['xss']

# Get security header issues
header_issues = results['security_headers']
```

### Using Individual Scanners
```python
from scanner.http_utils import HTTPClient
from scanner.sql_injection import SQLInjectionScanner

# Create HTTP client
client = HTTPClient(timeout=10)

# Use SQL injection scanner
sql_scanner = SQLInjectionScanner(client)
vulnerabilities = sql_scanner.scan("https://example.com")

# Process results
for vuln in vulnerabilities:
    print(f"Severity: {vuln['severity']}")
    print(f"Description: {vuln['description']}")

# Clean up
client.close()
```

## 📊 Understanding Results

### Severity Levels

- **High**: Critical security issues requiring immediate attention
  - SQL Injection vulnerabilities
  - XSS vulnerabilities
  - Missing critical security headers

- **Medium**: Important security issues
  - Missing HSTS header
  - Missing X-Frame-Options
  - Weak CSP configurations

- **Low**: Best practice violations
  - Missing X-Content-Type-Options
  - Information disclosure headers
  - Suboptimal security configurations

### Result Structure

Each vulnerability contains:
```python
{
    'type': 'SQL Injection',
    'severity': 'High',
    'url': 'https://example.com/page?id=1',
    'parameter': 'id',
    'method': 'GET',
    'payload': "' OR '1'='1",
    'description': 'SQL injection vulnerability detected',
    'evidence': 'SQL error message detected'
}
```

## 🛠️ Troubleshooting

### Import Errors
```bash
# Install all dependencies
pip install -r requirements.txt
```

### Connection Timeouts
```bash
# Increase timeout
python -m scanner.main https://slow-site.com --timeout 60
```

### SSL Certificate Errors
The scanner disables SSL verification by default for testing purposes.
To enable it, modify the HTTPClient initialization in your code.

### No Vulnerabilities Found
This could mean:
- The site is secure (good!)
- The scanner couldn't detect the vulnerabilities
- The site has WAF/protection mechanisms
- Network connectivity issues

## 📝 Report Location

By default, reports are saved as:
- `security_report_YYYYMMDD_HHMMSS.html` in the current directory

Custom location:
```bash
python -m scanner.main https://example.com --output /path/to/report.html
```

## ⚠️ Legal & Ethical Use

**ALWAYS:**
- Get written permission before scanning
- Only scan systems you own
- Follow responsible disclosure practices

**NEVER:**
- Scan without authorization
- Use for malicious purposes
- Exploit vulnerabilities you find

## 🔍 Safe Testing Targets

For learning and testing:
- Your own web applications
- Local test environments
- Authorized penetration testing sites:
  - http://testphp.vulnweb.com/
  - http://demo.testfire.net/
  - https://httpbin.org/

## 💡 Tips

1. **Start with headers** - fastest scan, good overview
2. **Use verbose mode** - helps debugging: `--verbose`
3. **Review HTML reports** - more detailed than console output
4. **Verify findings** - always manually confirm vulnerabilities
5. **Test responsibly** - limit scan intensity on production systems

## 🎯 Scan Strategy

### Quick Assessment
```bash
# Fast security posture check
python -m scanner.main https://example.com --scan-type headers
```

### Full Security Audit
```bash
# Comprehensive scan
python -m scanner.main https://example.com --timeout 30 --verbose
```

### Targeted Testing
```bash
# Test specific vulnerability
python -m scanner.main https://example.com/page?id=1 --scan-type sql
```

## 📚 Further Reading

- Review the main README.md for detailed documentation
- Check examples/ directory for code samples
- See CONTRIBUTING.md for development guidelines
- Read SECURITY.md for security best practices

## 🆘 Getting Help

- Check documentation in README.md
- Review examples in examples/ directory
- Open an issue on GitHub
- Review the source code (it's well documented!)

---

**Remember**: With great power comes great responsibility. Use this tool ethically and legally!
