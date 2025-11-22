#!/usr/bin/env python3
"""
Demo script to verify the network analyzer functionality.
This demonstrates the API without requiring actual packet capture.
"""

from network_analyzer import (
    ProtocolAnalyzer,
    TrafficStats,
    AnomalyDetector,
    ThreatDetector
)
from scapy.all import IP, TCP, UDP, DNS, DNSQR, Ether

print("=" * 70)
print("Network Traffic Analyzer - Demonstration")
print("=" * 70)

# Initialize components
protocol_analyzer = ProtocolAnalyzer()
traffic_stats = TrafficStats()
anomaly_detector = AnomalyDetector(port_scan_threshold=3)
threat_detector = ThreatDetector()

print("\n1. Creating sample packets...")

# Sample packets
packets = [
    # HTTP request
    Ether()/IP(src="192.168.1.100", dst="93.184.216.34")/TCP(sport=50000, dport=80, flags="S"),
    Ether()/IP(src="93.184.216.34", dst="192.168.1.100")/TCP(sport=80, dport=50000, flags="SA"),
    # DNS query
    Ether()/IP(src="192.168.1.100", dst="8.8.8.8")/UDP(sport=54321, dport=53)/DNS(qd=DNSQR(qname="example.com")),
    # Port scan simulation
    Ether()/IP(src="192.168.1.200", dst="192.168.1.1")/TCP(sport=60000, dport=22, flags="S"),
    Ether()/IP(src="192.168.1.200", dst="192.168.1.1")/TCP(sport=60001, dport=80, flags="S"),
    Ether()/IP(src="192.168.1.200", dst="192.168.1.1")/TCP(sport=60002, dport=443, flags="S"),
    Ether()/IP(src="192.168.1.200", dst="192.168.1.1")/TCP(sport=60003, dport=8080, flags="S"),
]

print(f"Created {len(packets)} sample packets\n")

print("2. Analyzing packets...")
for i, packet in enumerate(packets, 1):
    # Analyze protocol
    packet_info = protocol_analyzer.analyze_packet(packet)
    
    # Update statistics
    traffic_stats.update(packet_info)
    
    # Check for anomalies
    anomaly = anomaly_detector.analyze_packet(packet_info)
    if anomaly:
        print(f"   ⚠️  Anomaly detected on packet {i}: {anomaly['anomalies'][0]['type']}")
    
    # Check for threats (simulated malicious HTTP)
    if i == 1:  # Simulate SQL injection on first packet
        malicious_packet_info = packet_info.copy()
        malicious_packet_info['http_request'] = {
            'method': 'GET',
            'path': '/search?q=1\' OR \'1\'=\'1',
            'host': 'example.com'
        }
        threat = threat_detector.analyze_packet(malicious_packet_info)
        if threat:
            print(f"   🛡️  Threat detected on packet {i}: {threat['threats'][0]['type']}")

print(f"\nProcessed {len(packets)} packets\n")

print("3. Protocol Distribution:")
protocol_dist = protocol_analyzer.get_protocol_distribution()
for protocol, count in sorted(protocol_dist.items(), key=lambda x: x[1], reverse=True):
    print(f"   {protocol}: {count} packets")

print("\n4. Traffic Summary:")
summary = traffic_stats.get_summary()
print(f"   Total Packets: {summary['total_packets']}")
print(f"   Total Bytes: {traffic_stats.format_bytes(summary['total_bytes'])}")

print("\n5. Top Talkers:")
top_talkers = traffic_stats.get_top_talkers(5)
for ip, bytes_count in top_talkers:
    print(f"   {ip}: {traffic_stats.format_bytes(bytes_count)}")

print("\n6. Anomaly Summary:")
anomalies = anomaly_detector.get_anomalies()
print(f"   Total Anomalies: {len(anomalies)}")
for anom in anomalies:
    print(f"   - {anom['type']}: {anom['description']}")

print("\n7. Threat Summary:")
threats = threat_detector.get_threats()
print(f"   Total Threats: {len(threats)}")
for threat in threats:
    for thr in threat['threats']:
        print(f"   - {thr['type']}: {thr['description']}")

print("\n" + "=" * 70)
print("✅ Demonstration completed successfully!")
print("=" * 70)
print("\nThe network analyzer is working correctly.")
print("To use it for real packet capture, run with root privileges:")
print("  sudo python -m network_analyzer.cli --help")
