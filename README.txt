# SQLInjector-CLI

Advanced SQL Injection Scanner Tool for penetration testing and security assessments.

## Features

- Multiple SQL injection techniques detection
- Support for GET/POST requests
- Custom headers and cookies
- Proxy support
- Multi-threading
- WAF detection and evasion
- Custom payload support
- Tamper scripts for obfuscation
- Database fingerprinting
- Data extraction capabilities
- Multiple output formats

## Installation

```bash
git clone https://github.com/yourusername/SQLInjector-CLI.git
cd SQLInjector-CLI
pip install -r requirements.txt
chmod +x main.py


# Basic scan
python main.py -u "http://example.com/page.php?id=1"

# POST request scan
python main.py -u "http://example.com/login.php" --data "username=admin&password=test"

# With cookies and headers
python main.py -u "http://example.com/profile.php" --cookie "PHPSESSID=abc123" --header "User-Agent: SQLInjector"

# Specific technique
python main.py -u "http://example.com/page.php?id=1" --technique time-based

# Batch scan
python main.py -l targets.txt

# Save results
python main.py -u "http://example.com/page.php?id=1" -o results.json --format json
