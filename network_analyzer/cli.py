#!/usr/bin/env python3
"""
Network Traffic Analyzer - Main CLI Application

A comprehensive network security tool for packet capture and analysis.
"""

import argparse
import sys
import signal
import time
from colorama import Fore, Style, init

from network_analyzer import (
    PacketCapture,
    ProtocolAnalyzer,
    TrafficStats,
    AnomalyDetector,
    ThreatDetector
)

# Initialize colorama
init(autoreset=True)


class NetworkAnalyzer:
    """Main network analyzer application."""
    
    def __init__(self, interface=None, filter_str=None):
        """
        Initialize the network analyzer.
        
        Args:
            interface: Network interface to capture on
            filter_str: BPF filter string
        """
        self.interface = interface
        self.filter_str = filter_str
        
        # Initialize components
        self.capture = PacketCapture(interface=interface)
        self.protocol_analyzer = ProtocolAnalyzer()
        self.traffic_stats = TrafficStats()
        self.anomaly_detector = AnomalyDetector()
        self.threat_detector = ThreatDetector()
        
        # Register packet callback
        self.capture.add_packet_callback(self._process_packet)
        
        # Statistics
        self.packets_analyzed = 0
        self.anomalies_found = 0
        self.threats_found = 0
        
    def _process_packet(self, packet):
        """Process each captured packet."""
        try:
            # Analyze protocol
            packet_info = self.protocol_analyzer.analyze_packet(packet)
            
            # Update traffic statistics
            self.traffic_stats.update(packet_info)
            
            # Check for anomalies
            anomaly = self.anomaly_detector.analyze_packet(packet_info)
            if anomaly:
                self.anomalies_found += 1
                self._print_anomaly(anomaly)
            
            # Check for threats
            threat = self.threat_detector.analyze_packet(packet_info)
            if threat:
                self.threats_found += 1
                self._print_threat(threat)
            
            self.packets_analyzed += 1
            
            # Print progress every 100 packets
            if self.packets_analyzed % 100 == 0:
                self._print_progress()
                
        except Exception as e:
            print(f"{Fore.RED}Error processing packet: {e}{Style.RESET_ALL}")
    
    def _print_progress(self):
        """Print capture progress."""
        stats = self.capture.get_capture_stats()
        print(f"{Fore.CYAN}Captured: {stats['total_packets']} packets | "
              f"Analyzed: {self.packets_analyzed} | "
              f"Anomalies: {self.anomalies_found} | "
              f"Threats: {self.threats_found}{Style.RESET_ALL}")
    
    def _print_anomaly(self, anomaly):
        """Print anomaly detection alert."""
        for anom in anomaly['anomalies']:
            severity_color = {
                'LOW': Fore.YELLOW,
                'MEDIUM': Fore.YELLOW,
                'HIGH': Fore.RED,
                'CRITICAL': Fore.RED + Style.BRIGHT
            }.get(anom['severity'], Fore.WHITE)
            
            print(f"\n{severity_color}[ANOMALY DETECTED]{Style.RESET_ALL}")
            print(f"  Type: {anom['type']}")
            print(f"  Severity: {anom['severity']}")
            print(f"  {anom['description']}")
    
    def _print_threat(self, threat):
        """Print threat detection alert."""
        for thr in threat['threats']:
            severity_color = {
                'LOW': Fore.YELLOW,
                'MEDIUM': Fore.YELLOW,
                'HIGH': Fore.RED,
                'CRITICAL': Fore.RED + Style.BRIGHT
            }.get(thr['severity'], Fore.WHITE)
            
            print(f"\n{severity_color}[THREAT DETECTED]{Style.RESET_ALL}")
            print(f"  Type: {thr['type']}")
            print(f"  Severity: {thr['severity']}")
            print(f"  {thr['description']}")
    
    def start(self, count=0, timeout=None):
        """
        Start the network analyzer.
        
        Args:
            count: Number of packets to capture (0 for infinite)
            timeout: Capture timeout in seconds
        """
        print(f"{Fore.GREEN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Network Traffic Analyzer Started{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'='*70}{Style.RESET_ALL}")
        
        if self.interface:
            print(f"Interface: {self.interface}")
        else:
            print(f"Interface: default")
        
        if self.filter_str:
            print(f"Filter: {self.filter_str}")
        
        print(f"\nPress Ctrl+C to stop capture and view statistics\n")
        
        # Start capture
        self.capture.start_capture(count=count, timeout=timeout, filter_str=self.filter_str)
        
        # Wait for capture to complete or user interrupt
        try:
            if timeout:
                time.sleep(timeout + 1)
            else:
                while self.capture.is_capturing:
                    time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Stopping capture...{Style.RESET_ALL}")
            self.capture.stop_capture()
            time.sleep(1)
        
        # Print final statistics
        self._print_final_stats()
    
    def _print_final_stats(self):
        """Print final statistics and analysis."""
        print(f"\n{Fore.GREEN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Analysis Complete{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'='*70}{Style.RESET_ALL}\n")
        
        # Traffic statistics
        self.traffic_stats.print_summary()
        
        # Protocol distribution
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}PROTOCOL ANALYSIS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        
        protocol_dist = self.protocol_analyzer.get_protocol_distribution()
        if protocol_dist:
            for protocol, count in sorted(protocol_dist.items(), key=lambda x: x[1], reverse=True):
                print(f"  {protocol}: {count} packets")
        
        # Top conversations
        print(f"\n{Fore.CYAN}TOP CONVERSATIONS{Style.RESET_ALL}")
        top_convs = self.protocol_analyzer.get_top_conversations(5)
        for conv, count in top_convs:
            print(f"  {conv[0]} <-> {conv[1]}: {count} packets")
        
        # Anomaly summary
        print(f"\n{Fore.YELLOW}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}ANOMALY DETECTION SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*70}{Style.RESET_ALL}")
        print(f"Total anomalies detected: {len(self.anomaly_detector.get_anomalies())}")
        
        anomalies_by_type = {}
        for anomaly in self.anomaly_detector.get_anomalies():
            for anom in anomaly.get('anomalies', []):
                anom_type = anom['type']
                anomalies_by_type[anom_type] = anomalies_by_type.get(anom_type, 0) + 1
        
        if anomalies_by_type:
            for anom_type, count in sorted(anomalies_by_type.items(), key=lambda x: x[1], reverse=True):
                print(f"  {anom_type}: {count}")
        
        # Threat summary
        print(f"\n{Fore.RED}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.RED}THREAT DETECTION SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.RED}{'='*70}{Style.RESET_ALL}")
        
        threat_summary = self.threat_detector.get_threat_summary()
        print(f"Total threats detected: {threat_summary['total_threats']}")
        
        if threat_summary['by_type']:
            print("\nBy Type:")
            for threat_type, count in sorted(threat_summary['by_type'].items(), key=lambda x: x[1], reverse=True):
                print(f"  {threat_type}: {count}")
        
        if threat_summary['by_severity']:
            print("\nBy Severity:")
            for severity, count in sorted(threat_summary['by_severity'].items(), key=lambda x: x[1], reverse=True):
                print(f"  {severity}: {count}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Network Traffic Analyzer - Comprehensive network security analysis tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Capture on default interface
  %(prog)s
  
  # Capture on specific interface
  %(prog)s -i eth0
  
  # Capture 1000 packets
  %(prog)s -c 1000
  
  # Capture for 60 seconds
  %(prog)s -t 60
  
  # Filter HTTP traffic only
  %(prog)s -f "tcp port 80"
  
  # List available interfaces
  %(prog)s --list-interfaces
        """
    )
    
    parser.add_argument('-i', '--interface',
                       help='Network interface to capture on')
    
    parser.add_argument('-c', '--count',
                       type=int,
                       default=0,
                       help='Number of packets to capture (0 for infinite)')
    
    parser.add_argument('-t', '--timeout',
                       type=int,
                       help='Capture timeout in seconds')
    
    parser.add_argument('-f', '--filter',
                       help='BPF filter string (e.g., "tcp port 80")')
    
    parser.add_argument('--list-interfaces',
                       action='store_true',
                       help='List available network interfaces')
    
    args = parser.parse_args()
    
    # List interfaces if requested
    if args.list_interfaces:
        print("Available network interfaces:")
        for iface in PacketCapture.get_available_interfaces():
            print(f"  - {iface}")
        return
    
    # Create and start analyzer
    try:
        analyzer = NetworkAnalyzer(interface=args.interface, filter_str=args.filter)
        analyzer.start(count=args.count, timeout=args.timeout)
    except PermissionError:
        print(f"{Fore.RED}Error: Packet capture requires root/administrator privileges{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Please run with sudo/administrator rights{Style.RESET_ALL}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
        sys.exit(1)


if __name__ == '__main__':
    main()
