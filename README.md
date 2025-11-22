# Network Traffic Analyzer

A comprehensive network security tool built with Python that captures and analyzes network packets in real-time. Features include protocol analysis, traffic visualization, anomaly detection, and security threat identification. Utilizes Scapy for packet manipulation and provides detailed insights into network communications for security auditing purposes.

## Features

### 🔍 **Real-time Packet Capture**
- Capture network packets on any network interface
- Support for BPF (Berkeley Packet Filter) filtering
- Multi-threaded packet processing for high performance
- Configurable packet buffer size

### 📊 **Protocol Analysis**
- Layer 2: Ethernet, ARP
- Layer 3: IP, ICMP
- Layer 4: TCP, UDP
- Application Layer: HTTP, HTTPS, DNS, FTP, SSH, SMTP, and more
- Detailed TCP flag analysis
- Application protocol identification by port numbers

### 📈 **Traffic Statistics & Visualization**
- Real-time traffic statistics
- Protocol distribution analysis
- Top talkers identification
- Bandwidth usage metrics
- Port usage statistics
- Conversation tracking
- Data formatted in human-readable tables

### 🚨 **Anomaly Detection**
- **Port Scanning Detection**: Identifies hosts scanning multiple ports
- **SYN Flood Detection**: Detects potential SYN flood attacks
- **Connection Flooding**: Identifies excessive connection attempts
- **High Packet Rate Detection**: Flags unusually high packet rates
- **Insecure Protocol Detection**: Alerts on use of Telnet, FTP, etc.

### 🛡️ **Security Threat Identification**
- **SQL Injection Detection**: Identifies SQL injection patterns in HTTP requests
- **XSS Detection**: Detects cross-site scripting attempts
- **Command Injection**: Identifies command injection patterns
- **Path Traversal**: Detects directory traversal attempts
- **DNS Tunneling Detection**: Identifies potential DNS tunneling activity
- **Data Exfiltration Patterns**: Detects suspicious data transfer patterns
- **Malicious IP Tracking**: Maintains list of suspicious IPs

## Installation

### Prerequisites
- Python 3.7 or higher
- Root/Administrator privileges (required for packet capture)
- libpcap (Linux/macOS) or Npcap (Windows)

### Install from source

```bash
# Clone the repository
git clone https://github.com/katoki-dev/network-traffic-analyzer.git
cd network-traffic-analyzer

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

### Dependencies
- `scapy>=2.5.0` - Packet manipulation library
- `colorama>=0.4.6` - Colored terminal output
- `tabulate>=0.9.0` - Pretty-print tabular data

## Usage

### Command Line Interface

#### Basic Usage

```bash
# Run with default settings (requires sudo/admin privileges)
sudo network-analyzer

# Or using Python module
sudo python -m network_analyzer.cli
```

#### List Available Interfaces

```bash
sudo network-analyzer --list-interfaces
```

#### Capture on Specific Interface

```bash
sudo network-analyzer -i eth0
```

#### Capture Specific Number of Packets

```bash
# Capture 1000 packets
sudo network-analyzer -c 1000
```

#### Capture for Specific Duration

```bash
# Capture for 60 seconds
sudo network-analyzer -t 60
```

#### Apply BPF Filter

```bash
# Capture only HTTP traffic
sudo network-analyzer -f "tcp port 80"

# Capture only DNS traffic
sudo network-analyzer -f "udp port 53"

# Capture traffic to/from specific IP
sudo network-analyzer -f "host 192.168.1.1"

# Capture TCP SYN packets
sudo network-analyzer -f "tcp[tcpflags] & tcp-syn != 0"
```

#### Combined Options

```bash
# Capture 5000 packets on eth0, filtering HTTP traffic
sudo network-analyzer -i eth0 -c 5000 -f "tcp port 80"
```

### Programmatic Usage

```python
from network_analyzer import (
    PacketCapture,
    ProtocolAnalyzer,
    TrafficStats,
    AnomalyDetector,
    ThreatDetector
)

# Initialize components
capture = PacketCapture(interface="eth0")
protocol_analyzer = ProtocolAnalyzer()
traffic_stats = TrafficStats()
anomaly_detector = AnomalyDetector()
threat_detector = ThreatDetector()

# Define packet processing callback
def process_packet(packet):
    # Analyze protocol
    packet_info = protocol_analyzer.analyze_packet(packet)
    
    # Update statistics
    traffic_stats.update(packet_info)
    
    # Check for anomalies
    anomaly = anomaly_detector.analyze_packet(packet_info)
    if anomaly:
        print(f"Anomaly detected: {anomaly}")
    
    # Check for threats
    threat = threat_detector.analyze_packet(packet_info)
    if threat:
        print(f"Threat detected: {threat}")

# Register callback
capture.add_packet_callback(process_packet)

# Start capture
capture.start_capture(count=100)

# Get statistics
stats = traffic_stats.get_summary()
print(f"Captured {stats['total_packets']} packets")
```

## Output Examples

### Traffic Summary
```
==============================================================
TRAFFIC SUMMARY
==============================================================
Total Packets: 1,523
Total Bytes: 1.45 MB
Duration: 60.12 seconds
Packets/sec: 25.33
Average Packet Size: 1002.31 bytes

Bandwidth: 0.19 Mbps
```

### Protocol Distribution
```
==============================================================
PROTOCOL DISTRIBUTION
==============================================================
+----------+---------+----------+------------+
| Protocol | Packets | Bytes    | Percentage |
+==========+=========+==========+============+
| TCP      | 892     | 1.02 MB  | 58.57%     |
| UDP      | 421     | 312.45 KB| 27.64%     |
| HTTP     | 156     | 189.23 KB| 10.24%     |
| DNS      | 54      | 42.12 KB | 3.55%      |
+----------+---------+----------+------------+
```

### Anomaly Alerts
```
[ANOMALY DETECTED]
  Type: PORT_SCAN
  Severity: HIGH
  Possible port scan detected from 192.168.1.105 (25 ports accessed)

[ANOMALY DETECTED]
  Type: SYN_FLOOD
  Severity: CRITICAL
  Possible SYN flood attack from 10.0.0.50 (150 SYN packets in 60s)
```

### Threat Alerts
```
[THREAT DETECTED]
  Type: SQL_INJECTION
  Severity: CRITICAL
  Possible SQL injection attempt detected in HTTP request

[THREAT DETECTED]
  Type: DNS_TUNNELING
  Severity: HIGH
  Possible DNS tunneling detected from 192.168.1.200
```

## Architecture

The Network Traffic Analyzer is built with a modular architecture:

```
network_analyzer/
├── __init__.py           # Package initialization
├── packet_capture.py     # Real-time packet capture using Scapy
├── protocol_analyzer.py  # Protocol analysis and packet parsing
├── traffic_stats.py      # Traffic statistics and visualization
├── anomaly_detector.py   # Anomaly detection algorithms
├── threat_detector.py    # Security threat identification
└── cli.py               # Command-line interface
```

### Components

1. **PacketCapture**: Handles real-time packet capture with threading support
2. **ProtocolAnalyzer**: Analyzes network protocols and extracts packet information
3. **TrafficStats**: Collects and visualizes traffic statistics
4. **AnomalyDetector**: Detects network anomalies using pattern matching
5. **ThreatDetector**: Identifies security threats using signature-based detection

## Security Considerations

⚠️ **Important Security Notes:**

- This tool requires elevated privileges to capture network packets
- Use responsibly and only on networks you own or have permission to monitor
- The tool captures potentially sensitive information - handle data appropriately
- Some detection patterns may produce false positives - always verify alerts
- Not intended as a replacement for professional IDS/IPS systems

## Use Cases

- **Network Security Auditing**: Identify security vulnerabilities in network traffic
- **Incident Response**: Analyze network activity during security incidents
- **Network Troubleshooting**: Debug network connectivity and protocol issues
- **Performance Monitoring**: Monitor bandwidth usage and identify bottlenecks
- **Educational Purposes**: Learn about network protocols and security

## Limitations

- Encrypted traffic (HTTPS, SSH, etc.) cannot be inspected beyond metadata
- High-speed networks may require optimization to capture all packets
- Some advanced threats may evade signature-based detection
- Requires root/admin privileges which may not be available in all environments

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License.

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. Users are responsible for complying with applicable laws and regulations. The authors assume no liability for misuse of this tool.

## Future Enhancements

- [ ] PCAP file import/export
- [ ] Machine learning-based anomaly detection
- [ ] Web-based dashboard
- [ ] Database backend for historical analysis
- [ ] Advanced traffic visualization (graphs, charts)
- [ ] Integration with threat intelligence feeds
- [ ] Support for additional protocols
- [ ] Packet payload analysis and reconstruction
- [ ] Alert notifications (email, webhook)
- [ ] Configuration file support
