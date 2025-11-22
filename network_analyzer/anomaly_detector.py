"""
Anomaly Detection Module

Detects suspicious network patterns and anomalies.
"""

from collections import defaultdict, deque
from typing import Dict, List, Set, Optional
import time
from datetime import datetime


class AnomalyDetector:
    """Detects network anomalies and suspicious patterns."""
    
    def __init__(self, 
                 port_scan_threshold: int = 20,
                 syn_flood_threshold: int = 100,
                 time_window: int = 60):
        """
        Initialize the anomaly detector.
        
        Args:
            port_scan_threshold: Number of ports accessed before flagging as port scan
            syn_flood_threshold: Number of SYN packets before flagging as SYN flood
            time_window: Time window in seconds for rate-based detection
        """
        self.port_scan_threshold = port_scan_threshold
        self.syn_flood_threshold = syn_flood_threshold
        self.time_window = time_window
        
        # Tracking structures
        self.ports_accessed = defaultdict(set)  # IP -> set of ports
        self.syn_packets = defaultdict(list)  # IP -> list of timestamps
        self.connection_attempts = defaultdict(list)  # IP -> list of timestamps
        self.failed_connections = defaultdict(int)  # IP -> count
        self.packet_rates = defaultdict(deque)  # IP -> deque of timestamps
        
        # Detected anomalies
        self.anomalies = []
        
    def analyze_packet(self, packet_info: Dict) -> Optional[Dict]:
        """
        Analyze a packet for anomalies.
        
        Args:
            packet_info: Dictionary containing packet analysis results
            
        Returns:
            Anomaly dictionary if detected, None otherwise
        """
        anomalies_detected = []
        
        # Check for port scanning
        port_scan = self._detect_port_scan(packet_info)
        if port_scan:
            anomalies_detected.append(port_scan)
        
        # Check for SYN flood
        syn_flood = self._detect_syn_flood(packet_info)
        if syn_flood:
            anomalies_detected.append(syn_flood)
        
        # Check for connection flood
        conn_flood = self._detect_connection_flood(packet_info)
        if conn_flood:
            anomalies_detected.append(conn_flood)
        
        # Check for unusual packet rates
        rate_anomaly = self._detect_high_packet_rate(packet_info)
        if rate_anomaly:
            anomalies_detected.append(rate_anomaly)
        
        # Check for unusual protocols
        protocol_anomaly = self._detect_unusual_protocol(packet_info)
        if protocol_anomaly:
            anomalies_detected.append(protocol_anomaly)
        
        if anomalies_detected:
            return {
                'timestamp': packet_info.get('timestamp', time.time()),
                'anomalies': anomalies_detected,
                'packet_info': packet_info
            }
        
        return None
    
    def _detect_port_scan(self, packet_info: Dict) -> Optional[Dict]:
        """Detect potential port scanning activity."""
        src_ip = packet_info.get('src_ip')
        dst_port = packet_info.get('dst_port')
        tcp_flags = packet_info.get('tcp_flags', [])
        
        if not src_ip or not dst_port:
            return None
        
        # Track ports accessed by this IP
        self.ports_accessed[src_ip].add(dst_port)
        
        # Check if threshold exceeded
        if len(self.ports_accessed[src_ip]) >= self.port_scan_threshold:
            anomaly = {
                'type': 'PORT_SCAN',
                'severity': 'HIGH',
                'source_ip': src_ip,
                'ports_accessed': len(self.ports_accessed[src_ip]),
                'description': f'Possible port scan detected from {src_ip} ({len(self.ports_accessed[src_ip])} ports accessed)'
            }
            self.anomalies.append(anomaly)
            # Reset to avoid repeated alerts
            self.ports_accessed[src_ip].clear()
            return anomaly
        
        return None
    
    def _detect_syn_flood(self, packet_info: Dict) -> Optional[Dict]:
        """Detect potential SYN flood attack."""
        src_ip = packet_info.get('src_ip')
        tcp_flags = packet_info.get('tcp_flags', [])
        timestamp = packet_info.get('timestamp', time.time())
        
        if not src_ip or 'SYN' not in tcp_flags or 'ACK' in tcp_flags:
            return None
        
        # Track SYN packets
        self.syn_packets[src_ip].append(timestamp)
        
        # Clean old entries outside time window
        cutoff_time = timestamp - self.time_window
        self.syn_packets[src_ip] = [t for t in self.syn_packets[src_ip] if t > cutoff_time]
        
        # Check if threshold exceeded
        if len(self.syn_packets[src_ip]) >= self.syn_flood_threshold:
            anomaly = {
                'type': 'SYN_FLOOD',
                'severity': 'CRITICAL',
                'source_ip': src_ip,
                'syn_count': len(self.syn_packets[src_ip]),
                'time_window': self.time_window,
                'description': f'Possible SYN flood attack from {src_ip} ({len(self.syn_packets[src_ip])} SYN packets in {self.time_window}s)'
            }
            self.anomalies.append(anomaly)
            self.syn_packets[src_ip].clear()
            return anomaly
        
        return None
    
    def _detect_connection_flood(self, packet_info: Dict) -> Optional[Dict]:
        """Detect connection flooding."""
        src_ip = packet_info.get('src_ip')
        timestamp = packet_info.get('timestamp', time.time())
        
        if not src_ip:
            return None
        
        # Track connection attempts
        self.connection_attempts[src_ip].append(timestamp)
        
        # Clean old entries
        cutoff_time = timestamp - self.time_window
        self.connection_attempts[src_ip] = [t for t in self.connection_attempts[src_ip] if t > cutoff_time]
        
        # Check for excessive connection attempts
        threshold = 200  # connections per time window
        if len(self.connection_attempts[src_ip]) >= threshold:
            anomaly = {
                'type': 'CONNECTION_FLOOD',
                'severity': 'HIGH',
                'source_ip': src_ip,
                'connection_count': len(self.connection_attempts[src_ip]),
                'time_window': self.time_window,
                'description': f'Connection flood detected from {src_ip} ({len(self.connection_attempts[src_ip])} connections in {self.time_window}s)'
            }
            self.anomalies.append(anomaly)
            self.connection_attempts[src_ip].clear()
            return anomaly
        
        return None
    
    def _detect_high_packet_rate(self, packet_info: Dict) -> Optional[Dict]:
        """Detect unusually high packet rates."""
        src_ip = packet_info.get('src_ip')
        timestamp = packet_info.get('timestamp', time.time())
        
        if not src_ip:
            return None
        
        # Track packet timestamps
        self.packet_rates[src_ip].append(timestamp)
        
        # Keep only recent packets
        cutoff_time = timestamp - 10  # 10 second window
        while self.packet_rates[src_ip] and self.packet_rates[src_ip][0] < cutoff_time:
            self.packet_rates[src_ip].popleft()
        
        # Check for high rate
        rate_threshold = 1000  # packets per 10 seconds
        if len(self.packet_rates[src_ip]) >= rate_threshold:
            anomaly = {
                'type': 'HIGH_PACKET_RATE',
                'severity': 'MEDIUM',
                'source_ip': src_ip,
                'packet_rate': len(self.packet_rates[src_ip]),
                'description': f'High packet rate from {src_ip} ({len(self.packet_rates[src_ip])} packets/10s)'
            }
            self.anomalies.append(anomaly)
            return anomaly
        
        return None
    
    def _detect_unusual_protocol(self, packet_info: Dict) -> Optional[Dict]:
        """Detect unusual or suspicious protocols."""
        protocols = packet_info.get('protocols', [])
        src_ip = packet_info.get('src_ip')
        
        # Check for Telnet (unencrypted, should use SSH)
        if 'Telnet' in protocols:
            return {
                'type': 'INSECURE_PROTOCOL',
                'severity': 'MEDIUM',
                'source_ip': src_ip,
                'protocol': 'Telnet',
                'description': f'Insecure protocol (Telnet) detected from {src_ip}'
            }
        
        # Check for FTP (unencrypted)
        if 'FTP' in protocols:
            return {
                'type': 'INSECURE_PROTOCOL',
                'severity': 'LOW',
                'source_ip': src_ip,
                'protocol': 'FTP',
                'description': f'Insecure protocol (FTP) detected from {src_ip}'
            }
        
        return None
    
    def get_anomalies(self) -> List[Dict]:
        """Get all detected anomalies."""
        return self.anomalies
    
    def get_anomalies_by_type(self, anomaly_type: str) -> List[Dict]:
        """Get anomalies of a specific type."""
        return [a for a in self.anomalies if a['type'] == anomaly_type]
    
    def get_anomalies_by_severity(self, severity: str) -> List[Dict]:
        """Get anomalies of a specific severity level."""
        return [a for a in self.anomalies if a['severity'] == severity]
    
    def clear_anomalies(self):
        """Clear all detected anomalies."""
        self.anomalies.clear()
    
    def reset(self):
        """Reset all tracking data."""
        self.ports_accessed.clear()
        self.syn_packets.clear()
        self.connection_attempts.clear()
        self.failed_connections.clear()
        self.packet_rates.clear()
        self.anomalies.clear()
