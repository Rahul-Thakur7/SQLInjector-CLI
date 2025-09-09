import requests
import random
import string
import logging
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def colorize(text, color):
    """Colorize text output"""
    colors = {
        'red': Fore.RED,
        'green': Fore.GREEN,
        'yellow': Fore.YELLOW,
        'blue': Fore.BLUE,
        'magenta': Fore.MAGENTA,
        'cyan': Fore.CYAN,
        'white': Fore.WHITE
    }
    return f"{colors.get(color, Fore.WHITE)}{text}{Style.RESET_ALL}"

def print_banner():
    """Print tool banner"""
    banner = f"""
{colorize('╔══════════════════════════════════════════════════════════╗', 'cyan')}
{colorize('║                 SQLInjector-CLI v1.0                    ║', 'cyan')}
{colorize('║          Advanced SQL Injection Scanner Tool            ║', 'cyan')}
{colorize('║                 For Educational Purposes               ║', 'cyan')}
{colorize('╚══════════════════════════════════════════════════════════╝', 'cyan')}
"""
    print(banner)

def setup_logging(level=logging.WARNING):
    """Setup logging configuration"""
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

def generate_random_string(length=8):
    """Generate random string for payloads"""
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def check_waf(url, session):
    """Check if WAF is present"""
    try:
        # Test with common WAF detection payloads
        test_payloads = [
            "../../../etc/passwd",
            "<script>alert('test')</script>",
            "' OR '1'='1",
            "UNION SELECT"
        ]
        
        for payload in test_payloads:
            test_url = f"{url}?test={payload}"
            response = session.get(test_url, timeout=10)
            
            waf_indicators = [
                'cloudflare', 'akamai', 'imperva', 'barracuda',
                'fortinet', 'f5', 'waf', 'security', 'blocked',
                'forbidden', 'access denied'
            ]
            
            if any(indicator in response.text.lower() for indicator in waf_indicators):
                return True
                
    except Exception as e:
        logging.error(f"WAF check failed: {e}")
    
    return False

def tamper_payload(payload, tamper_script=None):
    """Obfuscate payload using various techniques"""
    if tamper_script == 'base64':
        import base64
        return base64.b64encode(payload.encode()).decode()
    
    elif tamper_script == 'urlencode':
        import urllib.parse
        return urllib.parse.quote(payload)
    
    elif tamper_script == 'doubleurlencode':
        import urllib.parse
        return urllib.parse.quote(urllib.parse.quote(payload))
    
    elif tamper_script == 'unicode':
        return ''.join([f'%u{ord(c):04x}' for c in payload])
    
    elif tamper_script == 'hex':
        return ''.join([f'%{ord(c):02x}' for c in payload])
    
    elif tamper_script == 'randomcase':
        return ''.join(random.choice([c.upper(), c.lower()]) for c in payload)
    
    else:
        # Default: URL encoding
        import urllib.parse
        return urllib.parse.quote(payload)
