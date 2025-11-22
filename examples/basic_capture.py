#!/usr/bin/env python3
"""
Example: Basic packet capture and analysis

This example demonstrates how to use the Network Traffic Analyzer
to capture and analyze packets programmatically.
"""

from network_analyzer import (
    PacketCapture,
    ProtocolAnalyzer,
    TrafficStats,
    AnomalyDetector,
    ThreatDetector
)
import time


def main():
    print("Network Traffic Analyzer - Basic Example")
    print("=" * 60)
    print("This example will capture 50 packets and analyze them.")
    print("Press Ctrl+C to stop early.\n")
    
    # Initialize components
    capture = PacketCapture()
    protocol_analyzer = ProtocolAnalyzer()
    traffic_stats = TrafficStats()
    anomaly_detector = AnomalyDetector()
    threat_detector = ThreatDetector()
    
    # Counters
    packet_count = 0
    
    def process_packet(packet):
        """Process each captured packet."""
        nonlocal packet_count
        packet_count += 1
        
        # Analyze protocol
        packet_info = protocol_analyzer.analyze_packet(packet)
        
        # Update statistics
        traffic_stats.update(packet_info)
        
        # Check for anomalies
        anomaly = anomaly_detector.analyze_packet(packet_info)
        if anomaly:
            print(f"\n⚠️  Anomaly detected: {anomaly['anomalies'][0]['description']}")
        
        # Check for threats
        threat = threat_detector.analyze_packet(packet_info)
        if threat:
            print(f"\n🛡️  Threat detected: {threat['threats'][0]['description']}")
        
        # Print progress
        if packet_count % 10 == 0:
            print(f"Captured {packet_count} packets...")
    
    # Register callback
    capture.add_packet_callback(process_packet)
    
    # Start capture
    print("Starting packet capture...")
    try:
        capture.start_capture(count=50)
        
        # Wait for capture to complete
        while capture.is_capturing and packet_count < 50:
            time.sleep(0.5)
        
        # Wait a bit more to ensure all packets are processed
        time.sleep(1)
        
    except KeyboardInterrupt:
        print("\nStopping capture...")
        capture.stop_capture()
    
    # Print statistics
    print("\n" + "=" * 60)
    print("ANALYSIS RESULTS")
    print("=" * 60)
    
    traffic_stats.print_summary()
    
    # Print protocol distribution
    print("\nProtocol Distribution:")
    for protocol, count in protocol_analyzer.get_protocol_distribution().items():
        print(f"  {protocol}: {count}")
    
    # Print anomalies
    anomalies = anomaly_detector.get_anomalies()
    print(f"\nTotal Anomalies: {len(anomalies)}")
    
    # Print threats
    threats = threat_detector.get_threats()
    print(f"Total Threats: {len(threats)}")
    
    print("\n✅ Example completed!")


if __name__ == "__main__":
    import sys
    try:
        main()
    except PermissionError:
        print("❌ Error: Packet capture requires root/administrator privileges")
        print("Please run with: sudo python3 examples/basic_capture.py")
        sys.exit(1)
