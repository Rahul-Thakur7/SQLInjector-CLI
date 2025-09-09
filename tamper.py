import random
import string
import base64
import urllib.parse

class Tamper:
    @staticmethod
    def base64_encode(payload):
        return base64.b64encode(payload.encode()).decode()

    @staticmethod
    def url_encode(payload):
        return urllib.parse.quote(payload)

    @staticmethod
    def double_url_encode(payload):
        return urllib.parse.quote(urllib.parse.quote(payload))

    @staticmethod
    def unicode_encode(payload):
        return ''.join([f'%u{ord(c):04x}' for c in payload])

    @staticmethod
    def hex_encode(payload):
        return ''.join([f'%{ord(c):02x}' for c in payload])

    @staticmethod
    def random_case(payload):
        return ''.join(random.choice([c.upper(), c.lower()]) for c in payload)

    @staticmethod
    def comment_obfuscate(payload):
        """Add random comments to obfuscate"""
        parts = payload.split()
        obfuscated = []
        for part in parts:
            if random.random() > 0.5:
                obfuscated.append(f"{part}/*{generate_random_string(3)}*/")
            else:
                obfuscated.append(part)
        return ' '.join(obfuscated)

    @staticmethod
    def whitespace_obfuscate(payload):
        """Add random whitespace"""
        return payload.replace(' ', random.choice(['   ', '\t', '\n', '\r']))

def generate_random_string(length=6):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

# Available tamper scripts
TAMPER_SCRIPTS = {
    'base64': Tamper.base64_encode,
    'urlencode': Tamper.url_encode,
    'doubleurlencode': Tamper.double_url_encode,
    'unicode': Tamper.unicode_encode,
    'hex': Tamper.hex_encode,
    'randomcase': Tamper.random_case,
    'comment': Tamper.comment_obfuscate,
    'whitespace': Tamper.whitespace_obfuscate
}
