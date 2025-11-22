"""
Traffic Statistics Module

Collects and visualizes network traffic statistics.
"""

from collections import defaultdict, Counter
from typing import Dict, List, Optional
from datetime import datetime
import time


class TrafficStats:
    """Collects and analyzes network traffic statistics."""
    
    def __init__(self):
        """Initialize traffic statistics collector."""
        self.total_bytes = 0
        self.total_packets = 0
        self.bytes_by_protocol = defaultdict(int)
        self.packets_by_protocol = defaultdict(int)
        self.bytes_sent = defaultdict(int)  # by IP
        self.bytes_received = defaultdict(int)  # by IP
        self.port_usage = Counter()
        self.start_time = time.time()
        self.time_series = []  # List of (timestamp, packet_count, bytes)
        
    def update(self, packet_info: Dict):
        """
        Update statistics with new packet information.
        
        Args:
            packet_info: Dictionary containing packet analysis results
        """
        # Update total counters
        packet_size = packet_info.get('size', 0)
        self.total_bytes += packet_size
        self.total_packets += 1
        
        # Update protocol statistics
        protocols = packet_info.get('protocols', [])
        for protocol in protocols:
            self.packets_by_protocol[protocol] += 1
            self.bytes_by_protocol[protocol] += packet_size
        
        # Update IP statistics
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        
        if src_ip:
            self.bytes_sent[src_ip] += packet_size
        if dst_ip:
            self.bytes_received[dst_ip] += packet_size
        
        # Update port statistics
        src_port = packet_info.get('src_port')
        dst_port = packet_info.get('dst_port')
        
        if src_port:
            self.port_usage[src_port] += 1
        if dst_port:
            self.port_usage[dst_port] += 1
        
        # Update time series
        timestamp = packet_info.get('timestamp', time.time())
        self.time_series.append((timestamp, 1, packet_size))
    
    def get_summary(self) -> Dict:
        """Get a summary of traffic statistics."""
        elapsed_time = time.time() - self.start_time
        
        return {
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'duration_seconds': elapsed_time,
            'packets_per_second': self.total_packets / elapsed_time if elapsed_time > 0 else 0,
            'bytes_per_second': self.total_bytes / elapsed_time if elapsed_time > 0 else 0,
            'average_packet_size': self.total_bytes / self.total_packets if self.total_packets > 0 else 0
        }
    
    def get_protocol_stats(self) -> Dict[str, Dict]:
        """Get statistics by protocol."""
        stats = {}
        for protocol in self.packets_by_protocol:
            stats[protocol] = {
                'packets': self.packets_by_protocol[protocol],
                'bytes': self.bytes_by_protocol[protocol],
                'percentage': (self.packets_by_protocol[protocol] / self.total_packets * 100) 
                             if self.total_packets > 0 else 0
            }
        return stats
    
    def get_top_talkers(self, n: int = 10) -> List[tuple]:
        """
        Get top N hosts by total traffic (sent + received).
        
        Args:
            n: Number of top talkers to return
            
        Returns:
            List of tuples (IP, total_bytes)
        """
        traffic = defaultdict(int)
        
        for ip, bytes_sent in self.bytes_sent.items():
            traffic[ip] += bytes_sent
        
        for ip, bytes_received in self.bytes_received.items():
            traffic[ip] += bytes_received
        
        return sorted(traffic.items(), key=lambda x: x[1], reverse=True)[:n]
    
    def get_top_ports(self, n: int = 10) -> List[tuple]:
        """
        Get top N ports by usage.
        
        Args:
            n: Number of top ports to return
            
        Returns:
            List of tuples (port, count)
        """
        return self.port_usage.most_common(n)
    
    def get_bandwidth_usage(self) -> Dict:
        """Get bandwidth usage information."""
        elapsed_time = time.time() - self.start_time
        
        if elapsed_time == 0:
            return {
                'bytes_per_second': 0,
                'bits_per_second': 0,
                'megabits_per_second': 0
            }
        
        bytes_per_sec = self.total_bytes / elapsed_time
        bits_per_sec = bytes_per_sec * 8
        
        return {
            'bytes_per_second': bytes_per_sec,
            'bits_per_second': bits_per_sec,
            'kilobits_per_second': bits_per_sec / 1024,
            'megabits_per_second': bits_per_sec / (1024 * 1024)
        }
    
    def format_bytes(self, bytes_val: int) -> str:
        """Format bytes into human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.2f} PB"
    
    def print_summary(self):
        """Print a formatted summary of traffic statistics."""
        from tabulate import tabulate
        
        summary = self.get_summary()
        
        print("\n" + "="*60)
        print("TRAFFIC SUMMARY")
        print("="*60)
        print(f"Total Packets: {summary['total_packets']:,}")
        print(f"Total Bytes: {self.format_bytes(summary['total_bytes'])}")
        print(f"Duration: {summary['duration_seconds']:.2f} seconds")
        print(f"Packets/sec: {summary['packets_per_second']:.2f}")
        print(f"Average Packet Size: {summary['average_packet_size']:.2f} bytes")
        
        # Bandwidth
        bandwidth = self.get_bandwidth_usage()
        print(f"\nBandwidth: {bandwidth['megabits_per_second']:.2f} Mbps")
        
        # Protocol distribution
        print("\n" + "="*60)
        print("PROTOCOL DISTRIBUTION")
        print("="*60)
        
        protocol_stats = self.get_protocol_stats()
        if protocol_stats:
            protocol_table = []
            for protocol, stats in sorted(protocol_stats.items(), 
                                         key=lambda x: x[1]['packets'], 
                                         reverse=True):
                protocol_table.append([
                    protocol,
                    f"{stats['packets']:,}",
                    self.format_bytes(stats['bytes']),
                    f"{stats['percentage']:.2f}%"
                ])
            
            print(tabulate(protocol_table, 
                          headers=['Protocol', 'Packets', 'Bytes', 'Percentage'],
                          tablefmt='grid'))
        
        # Top talkers
        print("\n" + "="*60)
        print("TOP TALKERS")
        print("="*60)
        
        top_talkers = self.get_top_talkers(10)
        if top_talkers:
            talker_table = []
            for ip, bytes_count in top_talkers:
                talker_table.append([ip, self.format_bytes(bytes_count)])
            
            print(tabulate(talker_table, 
                          headers=['IP Address', 'Total Traffic'],
                          tablefmt='grid'))
        
        # Top ports
        print("\n" + "="*60)
        print("TOP PORTS")
        print("="*60)
        
        top_ports = self.get_top_ports(10)
        if top_ports:
            port_table = []
            for port, count in top_ports:
                port_table.append([port, f"{count:,}"])
            
            print(tabulate(port_table, 
                          headers=['Port', 'Packet Count'],
                          tablefmt='grid'))
        
        print()
    
    def reset(self):
        """Reset all statistics."""
        self.total_bytes = 0
        self.total_packets = 0
        self.bytes_by_protocol.clear()
        self.packets_by_protocol.clear()
        self.bytes_sent.clear()
        self.bytes_received.clear()
        self.port_usage.clear()
        self.start_time = time.time()
        self.time_series.clear()
