import requests
import time
import threading
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from payloads import PAYLOADS
from utils import colorize, generate_random_string, check_waf, tamper_payload
import logging

class SQLInjectorScanner:
    def __init__(self, **kwargs):
        self.url = kwargs.get('url')
        self.target_file = kwargs.get('target_file')
        self.technique = kwargs.get('technique', 'all')
        self.dbms = kwargs.get('dbms', 'all')
        self.level = kwargs.get('level', 'medium')
        self.delay = kwargs.get('delay', 0)
        self.timeout = kwargs.get('timeout', 30)
        self.retries = kwargs.get('retries', 3)
        self.threads = kwargs.get('threads', 10)
        self.post_data = kwargs.get('post_data')
        self.cookies = kwargs.get('cookies')
        self.headers = self._parse_headers(kwargs.get('headers', []))
        self.proxy = kwargs.get('proxy')
        self.payload_file = kwargs.get('payload_file')
        self.tamper_script = kwargs.get('tamper_script')
        self.extract_data = kwargs.get('extract_data', False)
        self.fingerprint = kwargs.get('fingerprint', False)
        self.waf_evasion = kwargs.get('waf_evasion', False)
        
        self.session = requests.Session()
        self.results = []
        self.lock = threading.Lock()
        
        # Setup session
        if self.proxy:
            self.session.proxies = {'http': self.proxy, 'https': self.proxy}
        if self.cookies:
            self.session.headers.update({'Cookie': self.cookies})
        if self.headers:
            self.session.headers.update(self.headers)
        
        # Load custom payloads if specified
        self.payloads = self._load_payloads()
        
        logging.info(f"Scanner initialized with {self.threads} threads")

    def _parse_headers(self, headers_list):
        headers = {}
        if headers_list:
            for header in headers_list:
                if ':' in header:
                    key, value = header.split(':', 1)
                    headers[key.strip()] = value.strip()
        return headers

    def _load_payloads(self):
        if self.payload_file:
            try:
                with open(self.payload_file, 'r') as f:
                    return [line.strip() for line in f if line.strip()]
            except Exception as e:
                logging.error(f"Error loading payload file: {e}")
                return self._get_default_payloads()
        return self._get_default_payloads()

    def _get_default_payloads(self):
        all_payloads = []
        techniques = ['all'] if self.technique == 'all' else [self.technique]
        dbms_list = ['all'] if self.dbms == 'all' else [self.dbms]
        
        for tech in techniques:
            for db in dbms_list:
                if tech in PAYLOADS and db in PAYLOADS[tech]:
                    all_payloads.extend(PAYLOADS[tech][db])
        
        # Apply level filter
        if self.level == 'low':
            all_payloads = all_payloads[:len(all_payloads)//3]
        elif self.level == 'medium':
            all_payloads = all_payloads[:len(all_payloads)*2//3]
        
        return all_payloads

    def run_scan(self):
        targets = self._get_targets()
        
        if not targets:
            print(colorize("[-] No valid targets found", "red"))
            return []
        
        print(colorize(f"[+] Starting scan with {len(targets)} targets and {len(self.payloads)} payloads", "green"))
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for target in targets:
                futures.append(executor.submit(self.scan_target, target))
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logging.error(f"Error in scan thread: {e}")
        
        return self.results

    def _get_targets(self):
        targets = []
        if self.url:
            targets.append(self.url)
        if self.target_file:
            try:
                with open(self.target_file, 'r') as f:
                    targets.extend([line.strip() for line in f if line.strip()])
            except Exception as e:
                logging.error(f"Error reading target file: {e}")
        return targets

    def scan_target(self, url):
        logging.info(f"Scanning target: {url}")
        
        # Check for WAF
        if self.waf_evasion and check_waf(url, self.session):
            print(colorize(f"[!] WAF detected on {url}", "yellow"))
        
        # Extract parameters
        params = self._extract_parameters(url)
        
        for param_name, param_value in params.items():
            for payload in self.payloads:
                if self.delay > 0:
                    time.sleep(self.delay)
                
                # Tamper payload if specified
                final_payload = tamper_payload(payload, self.tamper_script) if self.tamper_script else payload
                
                # Test the payload
                vulnerable = self.test_payload(url, param_name, param_value, final_payload)
                
                if vulnerable:
                    with self.lock:
                        result = {
                            'url': url,
                            'vulnerability': 'SQL Injection',
                            'technique': self._detect_technique(payload),
                            'parameter': param_name,
                            'payload': final_payload,
                            'confidence': 'High'
                        }
                        self.results.append(result)
                        print(colorize(f"[+] Vulnerable: {url} - Parameter: {param_name}", "green"))
                    break

    def _extract_parameters(self, url):
        params = {}
        try:
            # GET parameters
            parsed_url = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            for key, values in query_params.items():
                params[key] = values[0]
            
            # POST parameters
            if self.post_data:
                post_params = urllib.parse.parse_qs(self.post_data)
                for key, values in post_params.items():
                    params[key] = values[0]
        except Exception as e:
            logging.error(f"Error extracting parameters: {e}")
        
        return params

    def test_payload(self, url, param_name, original_value, payload):
        techniques = {
            'error_based': self.test_error_based,
            'time_based': self.test_time_based,
            'boolean_based': self.test_boolean_based,
            'union_based': self.test_union_based
        }
        
        for technique_name, technique_func in techniques.items():
            if technique_func(url, param_name, original_value, payload):
                return True
        
        return False

    def test_error_based(self, url, param_name, original_value, payload):
        try:
            modified_value = original_value + payload
            response = self._send_request(url, param_name, modified_value)
            
            error_indicators = [
                'sql', 'syntax', 'mysql', 'postgresql', 'oracle', 'mssql',
                'odbc', 'driver', 'database', 'query', 'statement'
            ]
            
            if response and any(indicator in response.text.lower() for indicator in error_indicators):
                return True
        except Exception as e:
            logging.error(f"Error in error-based test: {e}")
        
        return False

    def test_time_based(self, url, param_name, original_value, payload):
        try:
            if 'sleep' in payload.lower() or 'waitfor' in payload.lower():
                start_time = time.time()
                self._send_request(url, param_name, original_value + payload)
                end_time = time.time()
                
                if end_time - start_time > 5:  # 5 seconds delay indicates vulnerability
                    return True
        except Exception as e:
            logging.error(f"Error in time-based test: {e}")
        
        return False

    def test_boolean_based(self, url, param_name, original_value, payload):
        try:
            # Get original response
            original_response = self._send_request(url, param_name, original_value)
            if not original_response:
                return False
            
            # Test true condition
            true_payload = payload.replace('{true}', '1=1')
            true_response = self._send_request(url, param_name, original_value + true_payload)
            
            # Test false condition
            false_payload = payload.replace('{false}', '1=0')
            false_response = self._send_request(url, param_name, original_value + false_payload)
            
            if (true_response and false_response and 
                true_response.text != false_response.text and
                original_response.text != true_response.text):
                return True
        except Exception as e:
            logging.error(f"Error in boolean-based test: {e}")
        
        return False

    def test_union_based(self, url, param_name, original_value, payload):
        try:
            if 'union' in payload.lower():
                response = self._send_request(url, param_name, original_value + payload)
                
                union_indicators = [
                    'different number of columns', 'union', 'select',
                    'concatenation', 'multiple results'
                ]
                
                if response and any(indicator in response.text.lower() for indicator in union_indicators):
                    return True
        except Exception as e:
            logging.error(f"Error in union-based test: {e}")
        
        return False

    def _send_request(self, url, param_name, value):
        for attempt in range(self.retries):
            try:
                parsed_url = urllib.parse.urlparse(url)
                query_params = urllib.parse.parse_qs(parsed_url.query)
                
                if param_name in query_params:
                    query_params[param_name] = [value]
                    new_query = urllib.parse.urlencode(query_params, doseq=True)
                    target_url = urllib.parse.urlunparse((
                        parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                        parsed_url.params, new_query, parsed_url.fragment
                    ))
                    
                    if self.post_data:
                        # Handle POST request
                        post_params = urllib.parse.parse_qs(self.post_data)
                        if param_name in post_params:
                            post_params[param_name] = [value]
                            data = urllib.parse.urlencode(post_params, doseq=True)
                            response = self.session.post(url, data=data, timeout=self.timeout)
                        else:
                            response = self.session.get(target_url, timeout=self.timeout)
                    else:
                        # Handle GET request
                        response = self.session.get(target_url, timeout=self.timeout)
                    
                    return response
                
            except requests.RequestException as e:
                logging.warning(f"Request failed (attempt {attempt + 1}): {e}")
                time.sleep(1)
            except Exception as e:
                logging.error(f"Unexpected error in request: {e}")
                break
        
        return None

    def _detect_technique(self, payload):
        payload_lower = payload.lower()
        if 'sleep' in payload_lower or 'waitfor' in payload_lower:
            return 'time-based'
        elif 'union' in payload_lower:
            return 'union-based'
        elif '1=1' in payload_lower or '1=0' in payload_lower:
            return 'boolean-based'
        else:
            return 'error-based'
