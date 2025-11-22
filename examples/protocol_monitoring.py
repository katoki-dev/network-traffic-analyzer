#!/usr/bin/env python3
"""
Example: Monitoring specific protocols

This example shows how to monitor specific protocols (HTTP and DNS)
and analyze their characteristics.
"""

from network_analyzer import PacketCapture, ProtocolAnalyzer
import time


def main():
    print("Protocol-Specific Monitoring Example")
    print("=" * 60)
    print("Monitoring HTTP and DNS traffic for 30 seconds...")
    print()
    
    # Initialize
    capture = PacketCapture()
    protocol_analyzer = ProtocolAnalyzer()
    
    http_count = 0
    dns_count = 0
    
    def process_packet(packet):
        """Process packets and track specific protocols."""
        nonlocal http_count, dns_count
        
        packet_info = protocol_analyzer.analyze_packet(packet)
        protocols = packet_info.get('protocols', [])
        
        # Track HTTP requests
        if 'HTTP' in protocols:
            http_count += 1
            http_req = packet_info.get('http_request')
            if http_req:
                print(f"🌐 HTTP: {http_req.get('method', 'N/A')} "
                      f"{http_req.get('host', 'N/A')}{http_req.get('path', 'N/A')}")
        
        # Track DNS queries
        if 'DNS' in protocols:
            dns_count += 1
            dns_info = packet_info.get('dns_info', {})
            if dns_info.get('query'):
                for query in dns_info.get('queries', []):
                    print(f"🔍 DNS Query: {query.get('name', 'N/A')}")
    
    # Register callback and start capture
    capture.add_packet_callback(process_packet)
    
    # Apply filter for HTTP and DNS only
    filter_str = "tcp port 80 or udp port 53"
    
    try:
        print(f"Starting capture with filter: {filter_str}\n")
        capture.start_capture(timeout=30, filter_str=filter_str)
        
        # Wait for timeout
        time.sleep(31)
        
    except KeyboardInterrupt:
        print("\nStopping...")
        capture.stop_capture()
    
    # Print summary
    print("\n" + "=" * 60)
    print(f"HTTP Requests: {http_count}")
    print(f"DNS Queries: {dns_count}")
    
    # Print DNS queries summary
    dns_queries = protocol_analyzer.get_dns_queries()
    if dns_queries:
        print(f"\nUnique DNS Queries: {len(set(q['name'] for q in dns_queries))}")
    
    # Print HTTP requests summary
    http_requests = protocol_analyzer.get_http_requests()
    if http_requests:
        unique_hosts = set(r.get('host', '') for r in http_requests if r.get('host'))
        print(f"Unique HTTP Hosts: {len(unique_hosts)}")
        if unique_hosts:
            print("\nTop Hosts:")
            for host in list(unique_hosts)[:10]:
                print(f"  - {host}")


if __name__ == "__main__":
    import sys
    try:
        main()
    except PermissionError:
        print("❌ Error: Requires root/administrator privileges")
        print("Run with: sudo python3 examples/protocol_monitoring.py")
        sys.exit(1)
