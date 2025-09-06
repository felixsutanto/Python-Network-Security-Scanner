# Python Network Security Scanner

[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-educational%20use-yellow.svg)](#legal-disclaimer)

A high-performance, multi-threaded network security scanner built in Python. This tool performs comprehensive TCP port scanning, service enumeration through banner grabbing, and HTTP security header analysis.

## ✨ Features

### 🚀 **Core Functionality**
- **Multi-threaded Port Scanning**: Concurrent TCP port scanning for optimal performance
- **Service Enumeration**: Banner grabbing to identify running services
- **HTTP Security Analysis**: Automated security header assessment
- **Flexible Port Specification**: Support for ranges, single ports, and comma-separated lists
- **Real-time Results**: Live progress updates with color-coded output

### 🛡️ **Security Checks**
- **Banner Grabbing**: Identifies service versions and types
- **HTTP Security Headers**: Analyzes critical security headers:
  - Strict-Transport-Security (HSTS)
  - X-Content-Type-Options
  - X-Frame-Options
  - X-XSS-Protection
  - Content-Security-Policy

### ⚡ **Performance Features**
- **Thread Pool Management**: Efficient resource utilization
- **Dynamic Load Balancing**: Intelligent port distribution across threads
- **Configurable Concurrency**: Adjustable thread count (1-200)
- **Timeout Controls**: Separate timeouts for connections and banner grabbing

## 🔧 Installation

### Prerequisites
- Python 3.6 or higher
- No external dependencies (uses only standard library)

### Quick Setup
```bash
# Clone the repository
git clone https://github.com/felixsutanto/Python-Network-Security-Scanner.git
cd python-network-security-scanner

# Make the script executable (optional)
chmod +x scanner.py

# Run your first scan
python scanner.py scanme.nmap.org 1-100
```

## 📚 Usage

### Basic Syntax
```bash
python scanner.py <target> <ports> [options]
```

### Command Line Arguments
| Argument | Description | Example |
|----------|-------------|---------|
| `target` | Target hostname or IP address | `scanme.nmap.org` |
| `ports` | Port range or specific ports | `1-100`, `22`, `80,443,8080` |
| `-t, --threads` | Number of concurrent threads (1-200) | `-t 50` |
| `-v, --version` | Display version information | `-v` |
| `-h, --help` | Show help message | `-h` |

### 🎯 Usage Examples

#### Basic Port Range Scan
```bash
python scanner.py scanme.nmap.org 1-100
```

#### Single Port Scan
```bash
python scanner.py 192.168.1.1 22
```

#### Multiple Specific Ports
```bash
python scanner.py example.com 22,80,443,8080
```

#### High-Performance Scan
```bash
python scanner.py target.com 1-1000 -t 100
```

#### Quick Web Server Audit
```bash
python scanner.py mywebsite.com 80,443 -t 10
```

## 📊 Sample Output

```
==============================================================
    Python Network Security Scanner v1.0
==============================================================
Target: scanme.nmap.org
Port Range: 1-100
Max Threads: 50
Scan Time: 2024-01-15 14:30:22
==============================================================

[INFO] Target scanme.nmap.org resolved to 45.33.32.156
[INFO] Scanning 100 ports...
[INFO] Using 50 concurrent threads

[OPEN] Port 22 is open
[OPEN] Port 80 is open

[INFO] Scan completed in 3.45 seconds

==============================================================
           SCAN RESULTS SUMMARY
==============================================================
[SUCCESS] Found 2 open ports:

Port 22:
  Service Banner: SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13

Port 80:
  Service Banner: HTTP/1.1 200 OK Server: Apache/2.4.7
  Security Headers Analysis:
    Strict-Transport-Security: MISSING
    X-Content-Type-Options: PRESENT
    X-Frame-Options: MISSING
    X-XSS-Protection: MISSING
    Content-Security-Policy: MISSING

==============================================================
Scan completed at 2024-01-15 14:30:26
```

## 🏗️ Architecture & Design

### Class Structure
```python
NetworkSecurityScanner
├── __init__()              # Initialize scanner configuration
├── resolve_target()        # DNS resolution with error handling
├── parse_port_range()      # Flexible port range parsing
├── scan_port()            # Individual port scanning logic
├── grab_banner()          # Service enumeration
├── check_http_security_headers()  # HTTP security analysis
├── worker_thread()        # Multi-threading implementation
└── run_scan()            # Main orchestration method
```

### Key Design Patterns
- **Thread Pool Pattern**: Efficient concurrent execution
- **Producer-Consumer**: Thread-safe result aggregation
- **Strategy Pattern**: Modular scanning approaches
- **Template Method**: Consistent scan workflow

### Performance Optimization
- **Connection Pooling**: Reuse socket connections where possible
- **Timeout Management**: Prevent hanging connections
- **Memory Efficiency**: Streaming results processing
- **Load Balancing**: Dynamic thread work distribution

## 🧪 Technical Details

### Threading Implementation
```python
# Thread-safe result storage
self.results_lock = threading.Lock()
self.scan_results = {}

# Efficient thread pool management
with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
    futures = [executor.submit(self.worker_thread, ip_address, chunk) 
              for chunk in port_chunks]
```

### Error Handling Strategy
- **DNS Resolution**: Graceful hostname resolution failure handling
- **Network Timeouts**: Configurable timeout mechanisms
- **Connection Refused**: Proper closed port detection
- **Service Detection**: Robust banner parsing with encoding handling

### Security Considerations
- **Rate Limiting**: Prevents overwhelming target systems
- **Ethical Usage**: Built-in legal disclaimer and usage guidelines
- **Error Disclosure**: Minimal information leakage in error messages
- **Resource Management**: Proper cleanup of network connections

## 🎓 Educational Value

This project demonstrates proficiency in:

### Python Programming
- Object-oriented design principles
- Multi-threading and concurrency
- Exception handling and error management
- Standard library utilization
- Command-line interface development

### Network Security
- TCP/IP protocol understanding
- Port scanning methodologies
- Service enumeration techniques
- HTTP security best practices
- Vulnerability assessment basics

### Software Engineering
- Code organization and modularity
- Documentation and commenting
- Error handling strategies
- Performance optimization
- User experience design

## 🔒 Legal Disclaimer

**⚠️ IMPORTANT: This tool is for educational and authorized security testing purposes only.**

- Only scan systems you own or have explicit written permission to test
- Unauthorized port scanning may be illegal in your jurisdiction
- Users are responsible for compliance with local laws and regulations
- The authors assume no liability for misuse of this tool

### Ethical Usage Guidelines
1. **Always obtain proper authorization** before scanning any network
2. **Respect rate limits** to avoid overwhelming target systems
3. **Use responsibly** in production environments
4. **Report vulnerabilities** through proper disclosure channels

## 📋 Roadmap

### Planned Features
- [ ] UDP port scanning support
- [ ] XML/JSON output formats
- [ ] Configuration file support
- [ ] Advanced service version detection
- [ ] Integration with vulnerability databases
- [ ] Web-based dashboard interface

### Performance Enhancements
- [ ] Asynchronous I/O implementation
- [ ] Distributed scanning capabilities
- [ ] Advanced caching mechanisms
- [ ] Real-time progress indicators

## 🐛 Troubleshooting

### Common Issues

#### DNS Resolution Failures
```bash
[ERROR] Failed to resolve hostname 'invalid-host': [Errno -2] Name or service not known
```
**Solution**: Verify the target hostname is correct and reachable.

#### Permission Denied (Linux/Mac)
```bash
[ERROR] Permission denied when scanning privileged ports
```
**Solution**: Run with sudo for ports < 1024, or use non-privileged ports (1024+).

#### High Thread Count Issues
```bash
[ERROR] Too many open files
```
**Solution**: Reduce thread count using `-t` parameter or increase system limits.

## 📊 Performance Benchmarks

| Port Range | Threads | Time (seconds) | Ports/Second |
|------------|---------|----------------|--------------|
| 1-100      | 10      | 8.2           | 12.2         |
| 1-100      | 50      | 3.4           | 29.4         |
| 1-1000     | 50      | 28.7          | 34.8         |
| 1-1000     | 100     | 19.1          | 52.4         |

*Benchmarks performed on a modern laptop with gigabit internet connection.*

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **NMAP Project**: Inspiration for scanning methodologies
- **OWASP**: Security header recommendations
- **Python Community**: Standard library excellence
- **Security Researchers**: Vulnerability disclosure practices
