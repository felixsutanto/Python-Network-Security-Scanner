#!/usr/bin/env python3
"""
Python Network Security Scanner
===============================

A production-ready network security scanner that performs:
- Multi-threaded TCP port scanning
- Service enumeration through banner grabbing
- Basic HTTP security header analysis
- Comprehensive error handling and logging

Usage: python scanner.py <target> <port_range>
Example: python scanner.py scanme.nmap.org 1-100
"""

import socket
import threading
import argparse
import sys
import time
import re
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ANSI color codes for terminal output formatting
class Colors:
    """ANSI color codes for enhanced terminal output readability"""
    GREEN = '\033[92m'    # Success/Open ports
    RED = '\033[91m'      # Errors/Missing headers
    YELLOW = '\033[93m'   # Warnings/Info
    BLUE = '\033[94m'     # Headers/Titles
    CYAN = '\033[96m'     # Highlights
    WHITE = '\033[97m'    # Normal text
    RESET = '\033[0m'     # Reset to default color
    BOLD = '\033[1m'      # Bold text

class NetworkSecurityScanner:
    """
    A comprehensive network security scanner class that performs:
    - Multi-threaded port scanning
    - Service banner grabbing
    - HTTP security header analysis
    """
    
    def __init__(self, target, port_range, max_threads=50):
        """
        Initialize the scanner with target and configuration
        
        Args:
            target (str): Target hostname or IP address
            port_range (str): Port range in format "start-end" or single port
            max_threads (int): Maximum number of concurrent threads
        """
        self.target = target
        self.port_range = port_range
        self.max_threads = max_threads
        self.open_ports = []  # List to store discovered open ports
        self.results_lock = threading.Lock()  # Thread-safe access to results
        self.scan_results = {}  # Dictionary to store detailed scan results
        
        # Connection timeout settings
        self.connection_timeout = 3  # seconds for initial connection
        self.banner_timeout = 2      # seconds for banner grabbing
        
    def resolve_target(self):
        """
        Resolve the target hostname to IP address
        
        Returns:
            str: IP address of the target
            
        Raises:
            socket.gaierror: If hostname cannot be resolved
        """
        try:
            # Attempt to resolve hostname to IP address
            ip_address = socket.gethostbyname(self.target)
            print(f"{Colors.CYAN}[INFO]{Colors.RESET} Target {Colors.BOLD}{self.target}{Colors.RESET} resolved to {Colors.YELLOW}{ip_address}{Colors.RESET}")
            return ip_address
        except socket.gaierror as e:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Failed to resolve hostname '{self.target}': {e}")
            raise
    
    def parse_port_range(self):
        """
        Parse the port range string into a list of ports to scan
        
        Returns:
            list: List of integer port numbers
            
        Raises:
            ValueError: If port range format is invalid
        """
        try:
            if '-' in self.port_range:
                # Handle range format (e.g., "1-100")
                start, end = map(int, self.port_range.split('-'))
                if start > end or start < 1 or end > 65535:
                    raise ValueError("Invalid port range")
                return list(range(start, end + 1))
            else:
                # Handle single port
                port = int(self.port_range)
                if port < 1 or port > 65535:
                    raise ValueError("Port must be between 1 and 65535")
                return [port]
        except ValueError as e:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Invalid port range '{self.port_range}': {e}")
            raise
    
    def scan_port(self, ip_address, port):
        """
        Scan a single port to check if it's open
        
        Args:
            ip_address (str): Target IP address
            port (int): Port number to scan
            
        Returns:
            bool: True if port is open, False otherwise
        """
        try:
            # Create a socket object for TCP connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.connection_timeout)
            
            # Attempt to connect to the target port
            result = sock.connect_ex((ip_address, port))
            sock.close()
            
            # connect_ex returns 0 if connection successful
            return result == 0
            
        except socket.error:
            # Handle any socket-related errors
            return False
    
    def grab_banner(self, ip_address, port):
        """
        Attempt to grab service banner from an open port
        
        Args:
            ip_address (str): Target IP address
            port (int): Open port number
            
        Returns:
            str: Service banner or error message
        """
        banner = "No banner received"
        
        try:
            # Create socket connection for banner grabbing
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.banner_timeout)
            sock.connect((ip_address, port))
            
            # Send a generic HTTP request for web services
            if port in [80, 443, 8080, 8443]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + self.target.encode() + b"\r\n\r\n")
            else:
                # For other services, just try to receive data
                pass
            
            # Attempt to receive banner data
            banner_data = sock.recv(1024)
            if banner_data:
                # Decode and clean the banner
                banner = banner_data.decode('utf-8', errors='ignore').strip()
                # Take only the first line for cleaner output
                banner = banner.split('\n')[0][:100]  # Limit length
            
            sock.close()
            
        except socket.timeout:
            banner = "Timeout during banner grab"
        except socket.error as e:
            banner = f"Error grabbing banner: {str(e)[:50]}"
        except UnicodeDecodeError:
            banner = "Binary data received (non-text service)"
        
        return banner
    
    def check_http_security_headers(self, ip_address, port):
        """
        Check for common HTTP security headers
        
        Args:
            ip_address (str): Target IP address
            port (int): HTTP port number
            
        Returns:
            dict: Dictionary of security header status
        """
        # Define critical security headers to check
        security_headers = {
            'Strict-Transport-Security': False,
            'X-Content-Type-Options': False,
            'X-Frame-Options': False,
            'X-XSS-Protection': False,
            'Content-Security-Policy': False
        }
        
        try:
            # Determine protocol (HTTP/HTTPS)
            protocol = 'https' if port == 443 else 'http'
            url = f"{protocol}://{ip_address}:{port}/"
            
            # Create HTTP request with proper headers
            request = urllib.request.Request(url)
            request.add_header('User-Agent', 'Security-Scanner/1.0')
            
            # Send request and analyze response headers
            with urllib.request.urlopen(request, timeout=5) as response:
                headers = response.headers
                
                # Check each security header
                for header in security_headers:
                    if header.lower() in [h.lower() for h in headers.keys()]:
                        security_headers[header] = True
                        
        except urllib.error.URLError:
            # Handle connection errors (server might not be HTTP)
            pass
        except Exception:
            # Handle any other unexpected errors
            pass
        
        return security_headers
    
    def worker_thread(self, ip_address, ports_chunk):
        """
        Worker function for thread pool to scan multiple ports
        
        Args:
            ip_address (str): Target IP address
            ports_chunk (list): List of ports for this thread to scan
        """
        local_results = {}
        
        for port in ports_chunk:
            try:
                # Scan the port
                if self.scan_port(ip_address, port):
                    print(f"{Colors.GREEN}[OPEN]{Colors.RESET} Port {Colors.BOLD}{port}{Colors.RESET} is open")
                    
                    # Grab banner for open port
                    banner = self.grab_banner(ip_address, port)
                    
                    # Store results locally first
                    local_results[port] = {
                        'status': 'open',
                        'banner': banner,
                        'security_headers': None
                    }
                    
                    # Check HTTP security headers for web ports
                    if port in [80, 443, 8080, 8443]:
                        headers = self.check_http_security_headers(ip_address, port)
                        local_results[port]['security_headers'] = headers
                
            except Exception as e:
                print(f"{Colors.RED}[ERROR]{Colors.RESET} Error scanning port {port}: {e}")
        
        # Thread-safe update of shared results
        with self.results_lock:
            self.scan_results.update(local_results)
            self.open_ports.extend(local_results.keys())
    
    def display_banner(self):
        """Display the scanner banner and information"""
        print(f"\n{Colors.BLUE}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}    Python Network Security Scanner v1.0{Colors.RESET}")
        print(f"{Colors.BLUE}{'='*60}{Colors.RESET}")
        print(f"{Colors.YELLOW}Target:{Colors.RESET} {Colors.BOLD}{self.target}{Colors.RESET}")
        print(f"{Colors.YELLOW}Port Range:{Colors.RESET} {Colors.BOLD}{self.port_range}{Colors.RESET}")
        print(f"{Colors.YELLOW}Max Threads:{Colors.RESET} {Colors.BOLD}{self.max_threads}{Colors.RESET}")
        print(f"{Colors.YELLOW}Scan Time:{Colors.RESET} {Colors.BOLD}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
        print(f"{Colors.BLUE}{'='*60}{Colors.RESET}\n")
    
    def display_results(self):
        """Display comprehensive scan results"""
        print(f"\n{Colors.BLUE}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}           SCAN RESULTS SUMMARY{Colors.RESET}")
        print(f"{Colors.BLUE}{'='*60}{Colors.RESET}")
        
        if not self.open_ports:
            print(f"{Colors.YELLOW}[INFO]{Colors.RESET} No open ports found in the specified range.")
            return
        
        print(f"{Colors.GREEN}[SUCCESS]{Colors.RESET} Found {Colors.BOLD}{len(self.open_ports)}{Colors.RESET} open ports:")
        print()
        
        # Sort ports for organized display
        for port in sorted(self.open_ports):
            result = self.scan_results[port]
            print(f"{Colors.GREEN}Port {Colors.BOLD}{port}{Colors.RESET}:")
            print(f"  {Colors.CYAN}Service Banner:{Colors.RESET} {result['banner']}")
            
            # Display HTTP security headers if available
            if result['security_headers']:
                print(f"  {Colors.CYAN}Security Headers Analysis:{Colors.RESET}")
                for header, present in result['security_headers'].items():
                    status_color = Colors.GREEN if present else Colors.RED
                    status_text = "PRESENT" if present else "MISSING"
                    print(f"    {status_color}{header}:{Colors.RESET} {status_text}")
            print()
        
        print(f"{Colors.BLUE}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
    
    def run_scan(self):
        """
        Main method to orchestrate the complete scanning process
        """
        try:
            # Display scanner information
            self.display_banner()
            
            # Resolve target to IP address
            ip_address = self.resolve_target()
            
            # Parse port range
            ports_to_scan = self.parse_port_range()
            total_ports = len(ports_to_scan)
            
            print(f"{Colors.CYAN}[INFO]{Colors.RESET} Scanning {Colors.BOLD}{total_ports}{Colors.RESET} ports...")
            print(f"{Colors.CYAN}[INFO]{Colors.RESET} Using {Colors.BOLD}{self.max_threads}{Colors.RESET} concurrent threads")
            print()
            
            # Record scan start time
            start_time = time.time()
            
            # Calculate optimal chunk size for thread distribution
            chunk_size = max(1, total_ports // self.max_threads)
            port_chunks = [ports_to_scan[i:i + chunk_size] 
                          for i in range(0, total_ports, chunk_size)]
            
            # Execute multi-threaded scanning
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                # Submit scanning tasks to thread pool
                futures = [executor.submit(self.worker_thread, ip_address, chunk) 
                          for chunk in port_chunks]
                
                # Wait for all scanning tasks to complete
                for future in as_completed(futures):
                    try:
                        future.result()  # This will raise any exceptions from threads
                    except Exception as e:
                        print(f"{Colors.RED}[ERROR]{Colors.RESET} Thread execution error: {e}")
            
            # Calculate and display scan duration
            scan_duration = time.time() - start_time
            print(f"\n{Colors.CYAN}[INFO]{Colors.RESET} Scan completed in {Colors.BOLD}{scan_duration:.2f}{Colors.RESET} seconds")
            
            # Display comprehensive results
            self.display_results()
            
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[INFO]{Colors.RESET} Scan interrupted by user (Ctrl+C)")
            sys.exit(1)
        except Exception as e:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Unexpected error during scan: {e}")
            sys.exit(1)

def validate_arguments(args):
    """
    Validate command-line arguments
    
    Args:
        args: Parsed arguments from argparse
        
    Returns:
        bool: True if arguments are valid
    """
    # Validate target format (basic check)
    if not args.target:
        print(f"{Colors.RED}[ERROR]{Colors.RESET} Target cannot be empty")
        return False
    
    # Validate port range format
    if args.ports:
        if '-' in args.ports:
            try:
                start, end = map(int, args.ports.split('-'))
                if start > end or start < 1 or end > 65535:
                    print(f"{Colors.RED}[ERROR]{Colors.RESET} Invalid port range. Use format: start-end (1-65535)")
                    return False
            except ValueError:
                print(f"{Colors.RED}[ERROR]{Colors.RESET} Invalid port range format. Use: start-end or single port")
                return False
        else:
            try:
                port = int(args.ports)
                if port < 1 or port > 65535:
                    print(f"{Colors.RED}[ERROR]{Colors.RESET} Port must be between 1 and 65535")
                    return False
            except ValueError:
                print(f"{Colors.RED}[ERROR]{Colors.RESET} Invalid port format")
                return False
    
    return True

def create_argument_parser():
    """
    Create and configure command-line argument parser
    
    Returns:
        argparse.ArgumentParser: Configured argument parser
    """
    parser = argparse.ArgumentParser(
        description="Python Network Security Scanner - A multi-threaded port scanner with service enumeration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py scanme.nmap.org 1-100        # Scan ports 1-100
  python scanner.py 192.168.1.1 22               # Scan single port
  python scanner.py example.com 80,443,8080      # Scan specific ports
  python scanner.py target.com 1-1000 -t 100     # Use 100 threads

Security Headers Checked (for HTTP services):
  - Strict-Transport-Security (HSTS)
  - X-Content-Type-Options
  - X-Frame-Options  
  - X-XSS-Protection
  - Content-Security-Policy

Note: This tool is for educational and authorized testing purposes only.
      Always ensure you have permission before scanning any network or system.
        """
    )
    
    # Required positional arguments
    parser.add_argument('target', 
                       help='Target hostname or IP address to scan')
    
    parser.add_argument('ports', 
                       help='Port range to scan (e.g., "1-100" or "80")')
    
    # Optional arguments
    parser.add_argument('-t', '--threads', 
                       type=int, 
                       default=50,
                       metavar='N',
                       help='Maximum number of concurrent threads (default: 50)')
    
    parser.add_argument('-v', '--version', 
                       action='version', 
                       version='Network Security Scanner v1.0')
    
    return parser

def main():
    """
    Main function - entry point of the application
    """
    # Display legal disclaimer
    print(f"{Colors.YELLOW}{'='*70}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.RED}                    LEGAL DISCLAIMER{Colors.RESET}")
    print(f"{Colors.YELLOW}{'='*70}{Colors.RESET}")
    print(f"{Colors.WHITE}This tool is for educational and authorized security testing only.")
    print(f"Unauthorized scanning of networks or systems may be illegal in your")
    print(f"jurisdiction. Always ensure you have explicit permission before")
    print(f"scanning any target that you do not own.{Colors.RESET}")
    print(f"{Colors.YELLOW}{'='*70}{Colors.RESET}\n")
    
    try:
        # Parse command-line arguments
        parser = create_argument_parser()
        args = parser.parse_args()
        
        # Validate arguments
        if not validate_arguments(args):
            sys.exit(1)
        
        # Validate thread count
        if args.threads < 1 or args.threads > 200:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Thread count must be between 1 and 200")
            sys.exit(1)
        
        # Create and run scanner instance
        scanner = NetworkSecurityScanner(
            target=args.target,
            port_range=args.ports,
            max_threads=args.threads
        )
        
        scanner.run_scan()
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[INFO]{Colors.RESET} Program interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}[FATAL]{Colors.RESET} Unexpected error: {e}")
        sys.exit(1)

# Entry point - only run if script is executed directly
if __name__ == "__main__":
    main()