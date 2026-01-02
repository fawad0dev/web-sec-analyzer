# Contributing to Web Security Analyzer

First off, thank you for considering contributing to Web Security Analyzer! It's people like you that make this tool better for everyone.

## Code of Conduct

This project and everyone participating in it is governed by respect and professionalism. By participating, you are expected to uphold this code.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the existing issues to avoid duplicates. When you create a bug report, include as many details as possible:

* **Use a clear and descriptive title**
* **Describe the exact steps to reproduce the problem**
* **Provide specific examples** (URLs, payloads, configurations)
* **Describe the behavior you observed** and what you expected
* **Include screenshots** if applicable
* **Specify your environment** (Python version, OS, etc.)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, include:

* **Use a clear and descriptive title**
* **Provide a step-by-step description** of the suggested enhancement
* **Provide specific examples** to demonstrate the feature
* **Explain why this enhancement would be useful**

### Pull Requests

* Fill in the required template
* Follow the Python style guide (PEP 8)
* Include comments in your code where necessary
* Update documentation for any changed functionality
* Add tests if applicable
* Ensure all tests pass

## Development Setup

1. **Fork and clone the repository**

```bash
git clone https://github.com/YOUR_USERNAME/web-sec-analyzer.git
cd web-sec-analyzer
```

2. **Create a virtual environment**

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**

```bash
pip install -r requirements.txt
```

4. **Create a branch**

```bash
git checkout -b feature/your-feature-name
```

## Style Guidelines

### Python Style Guide

* Follow PEP 8
* Use type hints where appropriate
* Write docstrings for all functions and classes
* Keep functions focused and concise
* Use meaningful variable names

### Git Commit Messages

* Use the present tense ("Add feature" not "Added feature")
* Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
* Limit the first line to 72 characters or less
* Reference issues and pull requests liberally

### Code Example

```python
def scan_for_vulnerability(url: str, payload: str) -> bool:
    """
    Scan a URL for a specific vulnerability using a payload.
    
    Args:
        url: Target URL to scan
        payload: Test payload to inject
        
    Returns:
        True if vulnerability detected, False otherwise
    """
    # Implementation here
    pass
```

## Testing

Before submitting a pull request:

1. Test your changes manually
2. Ensure no existing functionality is broken
3. Test with various URLs and payloads
4. Verify HTML reports generate correctly

## Adding New Features

### Adding a New Vulnerability Scanner

1. Create a new file in `scanner/` directory
2. Implement the scanner class with a `scan()` method
3. Follow the pattern of existing scanners
4. Update `main.py` to integrate the new scanner
5. Update documentation

Example structure:

```python
class NewVulnerabilityScanner:
    """Scanner for detecting XYZ vulnerabilities"""
    
    def __init__(self, http_client: HTTPClient):
        self.http_client = http_client
        self.vulnerabilities = []
    
    def scan(self, url: str) -> List[Dict]:
        """
        Scan URL for vulnerabilities
        
        Args:
            url: Target URL
            
        Returns:
            List of vulnerabilities found
        """
        # Implementation
        return self.vulnerabilities
```

### Adding New Report Formats

1. Create a new generator class in `report_generator.py` or a new file
2. Implement the generation logic
3. Update CLI to support the new format
4. Update documentation

## Documentation

* Update README.md for new features
* Add docstrings to all new functions and classes
* Update examples if needed
* Keep documentation clear and concise

## Security Considerations

When contributing:

* **Never commit sensitive data** (credentials, tokens, etc.)
* **Test responsibly** - only on authorized targets
* **Consider security implications** of new features
* **Report security issues privately** to maintainers first

## Questions?

Feel free to open an issue for any questions about contributing!

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
