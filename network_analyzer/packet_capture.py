"""
Packet Capture Module

Handles real-time network packet capture using Scapy.
"""

from scapy.all import sniff, get_if_list
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS
import threading
from collections import deque
from typing import Callable, Optional, List
import time


class PacketCapture:
    """Captures and processes network packets in real-time."""
    
    def __init__(self, interface: Optional[str] = None, max_packets: int = 10000):
        """
        Initialize the packet capture.
        
        Args:
            interface: Network interface to capture on (None for default)
            max_packets: Maximum number of packets to store in memory
        """
        self.interface = interface
        self.max_packets = max_packets
        self.packets = deque(maxlen=max_packets)
        self.is_capturing = False
        self.capture_thread = None
        self.packet_callbacks = []
        self.total_packets = 0
        self.start_time = None
        
    @staticmethod
    def get_available_interfaces() -> List[str]:
        """Get list of available network interfaces."""
        return get_if_list()
    
    def add_packet_callback(self, callback: Callable):
        """
        Add a callback function to process each captured packet.
        
        Args:
            callback: Function that takes a packet as argument
        """
        self.packet_callbacks.append(callback)
    
    def _packet_handler(self, packet):
        """Internal packet handler."""
        self.packets.append(packet)
        self.total_packets += 1
        
        # Call all registered callbacks
        for callback in self.packet_callbacks:
            try:
                callback(packet)
            except Exception as e:
                print(f"Error in packet callback: {e}")
    
    def start_capture(self, count: int = 0, timeout: Optional[int] = None, 
                     filter_str: Optional[str] = None):
        """
        Start capturing packets.
        
        Args:
            count: Number of packets to capture (0 for infinite)
            timeout: Capture timeout in seconds
            filter_str: BPF filter string (e.g., 'tcp port 80')
        """
        if self.is_capturing:
            print("Capture already in progress")
            return
        
        self.is_capturing = True
        self.start_time = time.time()
        
        def capture():
            try:
                sniff(
                    iface=self.interface,
                    prn=self._packet_handler,
                    count=count,
                    timeout=timeout,
                    filter=filter_str,
                    store=False
                )
            except Exception as e:
                print(f"Capture error: {e}")
            finally:
                self.is_capturing = False
        
        self.capture_thread = threading.Thread(target=capture, daemon=True)
        self.capture_thread.start()
    
    def stop_capture(self):
        """Stop the packet capture."""
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
    
    def get_packets(self) -> List:
        """Get all captured packets."""
        return list(self.packets)
    
    def clear_packets(self):
        """Clear all captured packets."""
        self.packets.clear()
        self.total_packets = 0
    
    def get_capture_stats(self) -> dict:
        """Get capture statistics."""
        elapsed_time = time.time() - self.start_time if self.start_time else 0
        return {
            'total_packets': self.total_packets,
            'stored_packets': len(self.packets),
            'is_capturing': self.is_capturing,
            'elapsed_time': elapsed_time,
            'packets_per_second': self.total_packets / elapsed_time if elapsed_time > 0 else 0
        }
