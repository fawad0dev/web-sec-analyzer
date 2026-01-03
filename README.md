# 🔒 Web Security Analyzer

<div align="center">
  <img src="Resources/main.png" alt="Web Security Analyzer Logo" width="600">
</div>

A comprehensive Python-based web vulnerability scanner designed to identify security issues in web applications. This tool provides professional security testing capabilities with detailed HTML reporting.

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## ✨ Features

### Vulnerability Detection
- **SQL Injection Detection**: Identifies SQL injection vulnerabilities in URL parameters and form inputs
- **Cross-Site Scripting (XSS)**: Detects reflected XSS vulnerabilities
- **Security Headers Analysis**: Analyzes HTTP security headers and provides recommendations

### Professional Reporting
- **HTML Report Generation**: Creates beautiful, detailed HTML reports
- **Severity Classification**: Issues categorized by severity (High, Medium, Low)
- **Detailed Evidence**: Includes payloads, affected parameters, and evidence
- **Actionable Recommendations**: Provides security remediation guidance

### Additional Features
- **Clean Architecture**: Modular design with separation of concerns
- **Color-coded CLI Output**: Easy-to-read terminal output with color coding
- **Configurable Scanning**: Choose specific vulnerability types to scan
- **Timeout Configuration**: Adjustable request timeouts
- **Progress Indicators**: Real-time scan progress and status updates

## 📋 Requirements

- Python 3.7 or higher
- pip (Python package installer)

## 🚀 Installation

### Method 1: Clone and Install

```bash
# Clone the repository
git clone https://github.com/fawad0dev/web-sec-analyzer.git
cd web-sec-analyzer

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

### Method 2: Install Dependencies Only

```bash
pip install requests beautifulsoup4 lxml colorama jinja2 urllib3
```

## 💻 Usage

### Basic Usage

Scan a website for all vulnerabilities:

```bash
python -m scanner.main https://example.com
```

Or if installed as a package:

```bash
web-sec-analyzer https://example.com
```

### Advanced Usage

**Scan for specific vulnerability types:**

```bash
# Scan only for SQL injection
python -m scanner.main https://example.com --scan-type sql

# Scan for SQL injection and XSS
python -m scanner.main https://example.com --scan-type sql xss

# Analyze only security headers
python -m scanner.main https://example.com --scan-type headers
```

**Custom output and timeout:**

```bash
# Specify custom output file
python -m scanner.main https://example.com --output my_report.html

# Increase timeout for slow servers
python -m scanner.main https://example.com --timeout 30

# Skip HTML report generation
python -m scanner.main https://example.com --no-report
```

**Verbose output:**

```bash
python -m scanner.main https://example.com --verbose
```

### Command-Line Options

```
usage: main.py [-h] [-t {sql,xss,headers,all} [{sql,xss,headers,all} ...]]
               [-o OUTPUT] [--timeout TIMEOUT] [--no-report] [-v]
               url

positional arguments:
  url                   Target URL to scan (e.g., https://example.com)

optional arguments:
  -h, --help            show this help message and exit
  -t, --scan-type {sql,xss,headers,all}
                        Types of scans to perform (default: all)
  -o, --output OUTPUT   Output HTML report file path
  --timeout TIMEOUT     Request timeout in seconds (default: 10)
  --no-report           Skip HTML report generation
  -v, --verbose         Enable verbose output
```

## 📊 Report Example

The scanner generates professional HTML reports with:

- **Executive Summary**: Overview of findings by severity
- **Vulnerability Details**: Detailed information for each issue
  - Type and severity
  - Affected URL and parameters
  - Payload used for detection
  - Evidence and description
  - Remediation recommendations
- **Security Headers Analysis**: Missing or misconfigured headers
- **Visual Design**: Clean, professional layout with color coding

## 🏗️ Architecture

```
web-sec-analyzer/
├── scanner/
│   ├── __init__.py           # Package initialization
│   ├── main.py               # CLI interface and main orchestrator
│   ├── http_utils.py         # HTTP client and utilities
│   ├── sql_injection.py      # SQL injection detection
│   ├── xss_scanner.py        # XSS vulnerability detection
│   ├── security_headers.py   # Security headers analysis
│   └── report_generator.py   # HTML report generation
├── requirements.txt          # Python dependencies
├── setup.py                  # Package setup configuration
├── .gitignore               # Git ignore rules
└── README.md                # Documentation
```

## 🔍 Vulnerability Detection Details

### SQL Injection Detection

The scanner tests for SQL injection vulnerabilities by:
- Injecting common SQL payloads into URL parameters
- Testing POST form inputs
- Analyzing responses for SQL error messages
- Detecting database-specific error patterns (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)

**Example payloads tested:**
- `' OR '1'='1`
- `admin' --`
- `' UNION SELECT NULL--`
- And 15+ more variations

### XSS Detection

The scanner identifies XSS vulnerabilities through:
- Injecting JavaScript payloads into parameters
- Testing HTML form inputs
- Detecting reflected payloads in responses
- Checking for unsafe script execution contexts

**Example payloads tested:**
- `<script>alert('XSS')</script>`
- `<img src=x onerror=alert('XSS')>`
- `<svg/onload=alert('XSS')>`
- And 15+ more variations

### Security Headers Analysis

Checks for presence and correct configuration of:
- **Strict-Transport-Security**: HTTPS enforcement
- **X-Frame-Options**: Clickjacking protection
- **X-Content-Type-Options**: MIME-sniffing prevention
- **Content-Security-Policy**: Resource loading control
- **X-XSS-Protection**: XSS filtering
- **Referrer-Policy**: Referrer information control
- **Permissions-Policy**: Browser feature control

Also flags information disclosure headers:
- **X-Powered-By**: Technology stack exposure
- **Server**: Server version exposure

## 🛡️ Security Best Practices

This tool follows security best practices:
- **Read-only Operations**: Only performs GET/POST requests for detection
- **No Exploitation**: Detects but does not exploit vulnerabilities
- **Sanitized Output**: All report output is properly escaped
- **Controlled Payloads**: Uses safe, non-destructive test payloads
- **Timeout Protection**: Prevents hanging on unresponsive servers

## ⚠️ Legal Disclaimer

**IMPORTANT**: This tool is intended for:
- Security testing of systems you own or have explicit permission to test
- Educational purposes to understand web vulnerabilities
- Security research in authorized environments

**DO NOT** use this tool to:
- Test systems without authorization
- Perform malicious activities
- Violate any laws or regulations

Unauthorized security testing may be illegal. Always obtain proper authorization before scanning any web application.

## 🎓 Educational Value

This project demonstrates:
- **Security Fundamentals**: Understanding of common web vulnerabilities
- **Python Best Practices**: Clean code, modularity, type hints
- **HTTP Protocol**: Request/response handling, headers, methods
- **HTML/CSS**: Professional report generation
- **CLI Development**: Argument parsing, user interaction
- **Error Handling**: Robust exception management
- **Logging**: Comprehensive logging for debugging
- **Package Structure**: Professional Python project organization

## 🤝 Contributing

Contributions are welcome! To contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👤 Author

**Muhammad Fawad**

- GitHub: [@fawad0dev](https://github.com/fawad0dev)

## 🙏 Acknowledgments

- OWASP for security testing guidelines
- Security research community for vulnerability patterns
- Python community for excellent libraries

## 📚 Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [Security Headers Reference](https://securityheaders.com/)

---

**⚡ Made with security in mind | Built for learning and professional security testing**
