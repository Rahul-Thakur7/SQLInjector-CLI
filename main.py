#!/usr/bin/env python3
import argparse
import sys
import os
import json
import csv
from datetime import datetime
from scanner import SQLInjectorScanner
from utils import colorize, print_banner, setup_logging
import logging

def parse_arguments():
    parser = argparse.ArgumentParser(description="SQLInjector-CLI - Advanced SQL Injection Scanner")
    
    # Target options
    target_group = parser.add_argument_group('Target')
    target_group.add_argument("-u", "--url", help="Target URL")
    target_group.add_argument("-l", "--list", help="File containing list of target URLs")
    target_group.add_argument("--data", help="POST data")
    target_group.add_argument("--cookie", help="Cookie header")
    target_group.add_argument("--header", action='append', help="Custom headers (e.g., 'User-Agent: SQLInjector')")
    target_group.add_argument("--proxy", help="Proxy server (e.g., http://127.0.0.1:8080)")
    
    # Scan options
    scan_group = parser.add_argument_group('Scan')
    scan_group.add_argument("-t", "--technique", choices=['all', 'error-based', 'time-based', 'boolean-based', 'union-based'], 
                          default='all', help="SQL injection technique")
    scan_group.add_argument("--dbms", choices=['all', 'mysql', 'postgresql', 'mssql', 'oracle'], 
                          default='all', help="Target DBMS")
    scan_group.add_argument("--level", choices=['low', 'medium', 'high'], default='medium', 
                          help="Scan intensity level")
    scan_group.add_argument("--delay", type=float, default=0, help="Delay between requests (seconds)")
    scan_group.add_argument("--timeout", type=int, default=30, help="Request timeout")
    scan_group.add_argument("--retries", type=int, default=3, help="Number of retries")
    scan_group.add_argument("--threads", type=int, default=10, help="Number of threads")
    
    # Payload options
    payload_group = parser.add_argument_group('Payload')
    payload_group.add_argument("--payload-file", help="File containing custom payloads")
    payload_group.add_argument("--tamper", help="Tamper script for payload obfuscation")
    
    # Output options
    output_group = parser.add_argument_group('Output')
    output_group.add_argument("-o", "--output", help="Output file")
    output_group.add_argument("--format", choices=['json', 'csv', 'txt'], default='txt', 
                            help="Output format")
    output_group.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    output_group.add_argument("-d", "--debug", action="store_true", help="Debug mode")
    
    # Advanced options
    advanced_group = parser.add_argument_group('Advanced')
    advanced_group.add_argument("--extract-data", action="store_true", help="Attempt data extraction")
    advanced_group.add_argument("--fingerprint", action="store_true", help="Database fingerprinting")
    advanced_group.add_argument("--waf-evasion", action="store_true", help="Enable WAF evasion techniques")
    
    return parser.parse_args()

def main():
    print_banner()
    
    args = parse_arguments()
    
    # Setup logging
    log_level = logging.DEBUG if args.debug else (logging.INFO if args.verbose else logging.WARNING)
    setup_logging(log_level)
    
    # Validate arguments
    if not args.url and not args.list:
        print(colorize("[-] Error: Either --url or --list must be specified", "red"))
        sys.exit(1)
    
    # Initialize scanner
    try:
        scanner = SQLInjectorScanner(
            url=args.url,
            target_file=args.list,
            technique=args.technique,
            dbms=args.dbms,
            level=args.level,
            delay=args.delay,
            timeout=args.timeout,
            retries=args.retries,
            threads=args.threads,
            post_data=args.data,
            cookies=args.cookie,
            headers=args.header,
            proxy=args.proxy,
            payload_file=args.payload_file,
            tamper_script=args.tamper,
            extract_data=args.extract_data,
            fingerprint=args.fingerprint,
            waf_evasion=args.waf_evasion
        )
    except Exception as e:
        print(colorize(f"[-] Error initializing scanner: {e}", "red"))
        sys.exit(1)
    
    # Run scan
    try:
        results = scanner.run_scan()
        
        # Output results
        if results and args.output:
            save_results(results, args.output, args.format)
            
    except KeyboardInterrupt:
        print(colorize("\n[!] Scan interrupted by user", "yellow"))
    except Exception as e:
        print(colorize(f"[-] Error during scan: {e}", "red"))
        if args.debug:
            import traceback
            traceback.print_exc()

def save_results(results, output_file, format):
    """Save scan results to file"""
    try:
        with open(output_file, 'w') as f:
            if format == 'json':
                json.dump(results, f, indent=2)
            elif format == 'csv':
                writer = csv.writer(f)
                writer.writerow(['URL', 'Vulnerability', 'Technique', 'Parameter', 'Payload', 'Confidence'])
                for result in results:
                    writer.writerow([
                        result['url'],
                        result['vulnerability'],
                        result['technique'],
                        result['parameter'],
                        result['payload'],
                        result['confidence']
                    ])
            else:  # txt
                for result in results:
                    f.write(f"URL: {result['url']}\n")
                    f.write(f"Vulnerability: {result['vulnerability']}\n")
                    f.write(f"Technique: {result['technique']}\n")
                    f.write(f"Parameter: {result['parameter']}\n")
                    f.write(f"Payload: {result['payload']}\n")
                    f.write(f"Confidence: {result['confidence']}\n")
                    f.write("-" * 50 + "\n")
        
        print(colorize(f"[+] Results saved to {output_file}", "green"))
    except Exception as e:
        print(colorize(f"[-] Error saving results: {e}", "red"))

if __name__ == "__main__":
    main()
