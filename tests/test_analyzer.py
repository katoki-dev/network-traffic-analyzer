"""
Unit Tests for Network Traffic Analyzer

Run with: python -m pytest tests/
"""

import unittest
from unittest.mock import Mock, MagicMock
from scapy.all import IP, TCP, UDP, DNS, DNSQR, Ether, ARP
from scapy.layers.http import HTTPRequest

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from network_analyzer import (
    PacketCapture,
    ProtocolAnalyzer,
    TrafficStats,
    AnomalyDetector,
    ThreatDetector
)


class TestProtocolAnalyzer(unittest.TestCase):
    """Test ProtocolAnalyzer class."""
    
    def setUp(self):
        self.analyzer = ProtocolAnalyzer()
    
    def test_analyze_tcp_packet(self):
        """Test TCP packet analysis."""
        packet = Ether()/IP(src="192.168.1.1", dst="192.168.1.2")/TCP(sport=12345, dport=80, flags="S")
        result = self.analyzer.analyze_packet(packet)
        
        self.assertIn('TCP', result['protocols'])
        self.assertIn('IP', result['protocols'])
        self.assertEqual(result['src_ip'], "192.168.1.1")
        self.assertEqual(result['dst_ip'], "192.168.1.2")
        self.assertEqual(result['src_port'], 12345)
        self.assertEqual(result['dst_port'], 80)
        self.assertIn('SYN', result['tcp_flags'])
    
    def test_analyze_udp_packet(self):
        """Test UDP packet analysis."""
        packet = Ether()/IP(src="10.0.0.1", dst="8.8.8.8")/UDP(sport=54321, dport=53)
        result = self.analyzer.analyze_packet(packet)
        
        self.assertIn('UDP', result['protocols'])
        self.assertIn('IP', result['protocols'])
        self.assertEqual(result['src_port'], 54321)
        self.assertEqual(result['dst_port'], 53)
    
    def test_analyze_dns_packet(self):
        """Test DNS packet analysis."""
        packet = Ether()/IP()/UDP()/DNS(qd=DNSQR(qname="example.com"))
        result = self.analyzer.analyze_packet(packet)
        
        self.assertIn('DNS', result['protocols'])
        self.assertIsNotNone(result.get('dns_info'))
        self.assertTrue(result['dns_info']['query'])
    
    def test_protocol_counts(self):
        """Test protocol counting."""
        packets = [
            Ether()/IP()/TCP(),
            Ether()/IP()/TCP(),
            Ether()/IP()/UDP(),
        ]
        
        for packet in packets:
            self.analyzer.analyze_packet(packet)
        
        dist = self.analyzer.get_protocol_distribution()
        self.assertEqual(dist['TCP'], 2)
        self.assertEqual(dist['UDP'], 1)
        self.assertEqual(dist['IP'], 3)
    
    def test_tcp_flags_extraction(self):
        """Test TCP flags extraction."""
        packet = Ether()/IP()/TCP(flags="SA")  # SYN-ACK
        result = self.analyzer.analyze_packet(packet)
        
        self.assertIn('SYN', result['tcp_flags'])
        self.assertIn('ACK', result['tcp_flags'])
    
    def test_app_protocol_identification(self):
        """Test application protocol identification by port."""
        test_cases = [
            (80, 'HTTP'),
            (443, 'HTTPS'),
            (53, 'DNS'),
            (22, 'SSH'),
            (21, 'FTP'),
        ]
        
        for port, expected_proto in test_cases:
            # Use fresh analyzer for each test to avoid port conflicts
            analyzer = ProtocolAnalyzer()
            # Specify sport to avoid Scapy's default of 20
            packet = Ether()/IP()/TCP(sport=50000, dport=port)
            result = analyzer.analyze_packet(packet)
            self.assertIn(expected_proto, result['protocols'])


class TestTrafficStats(unittest.TestCase):
    """Test TrafficStats class."""
    
    def setUp(self):
        self.stats = TrafficStats()
    
    def test_update_stats(self):
        """Test statistics update."""
        packet_info = {
            'size': 100,
            'protocols': ['IP', 'TCP'],
            'src_ip': '192.168.1.1',
            'dst_ip': '192.168.1.2',
            'src_port': 12345,
            'dst_port': 80,
            'timestamp': 1234567890.0
        }
        
        self.stats.update(packet_info)
        
        summary = self.stats.get_summary()
        self.assertEqual(summary['total_packets'], 1)
        self.assertEqual(summary['total_bytes'], 100)
    
    def test_protocol_statistics(self):
        """Test protocol statistics."""
        packets = [
            {'size': 100, 'protocols': ['TCP'], 'timestamp': 1.0},
            {'size': 200, 'protocols': ['TCP'], 'timestamp': 2.0},
            {'size': 150, 'protocols': ['UDP'], 'timestamp': 3.0},
        ]
        
        for p in packets:
            self.stats.update(p)
        
        proto_stats = self.stats.get_protocol_stats()
        self.assertEqual(proto_stats['TCP']['packets'], 2)
        self.assertEqual(proto_stats['TCP']['bytes'], 300)
        self.assertEqual(proto_stats['UDP']['packets'], 1)
        self.assertEqual(proto_stats['UDP']['bytes'], 150)
    
    def test_top_talkers(self):
        """Test top talkers tracking."""
        packets = [
            {'size': 1000, 'src_ip': '192.168.1.1', 'dst_ip': '192.168.1.2', 'protocols': [], 'timestamp': 1.0},
            {'size': 500, 'src_ip': '192.168.1.1', 'dst_ip': '192.168.1.3', 'protocols': [], 'timestamp': 2.0},
            {'size': 200, 'src_ip': '192.168.1.2', 'dst_ip': '192.168.1.1', 'protocols': [], 'timestamp': 3.0},
        ]
        
        for p in packets:
            self.stats.update(p)
        
        top_talkers = self.stats.get_top_talkers(5)
        self.assertTrue(len(top_talkers) > 0)
        # 192.168.1.1 sent 1500 bytes and received 200 = 1700 total
        top_ip = top_talkers[0][0]
        self.assertIn(top_ip, ['192.168.1.1', '192.168.1.2'])


class TestAnomalyDetector(unittest.TestCase):
    """Test AnomalyDetector class."""
    
    def setUp(self):
        self.detector = AnomalyDetector(
            port_scan_threshold=5,
            syn_flood_threshold=10,
            time_window=60
        )
    
    def test_port_scan_detection(self):
        """Test port scan detection."""
        # Simulate scanning multiple ports
        for port in range(1, 10):
            packet_info = {
                'src_ip': '192.168.1.100',
                'dst_port': port,
                'tcp_flags': ['SYN'],
                'protocols': ['TCP'],
                'timestamp': 1.0
            }
            result = self.detector.analyze_packet(packet_info)
            
            if port >= 5:
                # Should detect on 5th port
                self.assertIsNotNone(result)
                break
    
    def test_syn_flood_detection(self):
        """Test SYN flood detection."""
        import time
        current_time = time.time()
        
        detected = False
        # Send many SYN packets
        for i in range(15):
            packet_info = {
                'src_ip': '10.0.0.50',
                'tcp_flags': ['SYN'],
                'protocols': ['TCP'],
                'timestamp': current_time + i * 0.1
            }
            result = self.detector.analyze_packet(packet_info)
            
            if result is not None:
                # Should detect when threshold is reached
                detected = True
                self.assertIsNotNone(result)
                self.assertTrue(len(result['anomalies']) > 0)
                self.assertEqual(result['anomalies'][0]['type'], 'SYN_FLOOD')
                break
        
        self.assertTrue(detected, "SYN flood should have been detected")
    
    def test_insecure_protocol_detection(self):
        """Test detection of insecure protocols."""
        packet_info = {
            'src_ip': '192.168.1.50',
            'protocols': ['Telnet'],
            'timestamp': 1.0
        }
        
        result = self.detector.analyze_packet(packet_info)
        self.assertIsNotNone(result)
        self.assertEqual(result['anomalies'][0]['type'], 'INSECURE_PROTOCOL')


class TestThreatDetector(unittest.TestCase):
    """Test ThreatDetector class."""
    
    def setUp(self):
        self.detector = ThreatDetector()
    
    def test_sql_injection_detection(self):
        """Test SQL injection detection."""
        packet_info = {
            'src_ip': '192.168.1.100',
            'http_request': {
                'method': 'GET',
                'path': '/search?q=1\' OR \'1\'=\'1',
                'host': 'example.com'
            },
            'protocols': ['HTTP'],
            'timestamp': 1.0
        }
        
        result = self.detector.analyze_packet(packet_info)
        self.assertIsNotNone(result)
        self.assertEqual(result['threats'][0]['type'], 'SQL_INJECTION')
    
    def test_xss_detection(self):
        """Test XSS detection."""
        packet_info = {
            'src_ip': '192.168.1.100',
            'http_request': {
                'method': 'GET',
                'path': '/page?param=<script>alert(1)</script>',
                'host': 'example.com'
            },
            'protocols': ['HTTP'],
            'timestamp': 1.0
        }
        
        result = self.detector.analyze_packet(packet_info)
        self.assertIsNotNone(result)
        self.assertEqual(result['threats'][0]['type'], 'XSS_ATTEMPT')
    
    def test_path_traversal_detection(self):
        """Test path traversal detection."""
        packet_info = {
            'src_ip': '192.168.1.100',
            'http_request': {
                'method': 'GET',
                'path': '/file?path=../../etc/passwd',
                'host': 'example.com'
            },
            'protocols': ['HTTP'],
            'timestamp': 1.0
        }
        
        result = self.detector.analyze_packet(packet_info)
        self.assertIsNotNone(result)
        self.assertEqual(result['threats'][0]['type'], 'PATH_TRAVERSAL')
    
    def test_dns_tunneling_detection(self):
        """Test DNS tunneling detection."""
        # Long subdomain indicating potential tunneling
        long_domain = 'a' * 60 + '.example.com'
        
        # Need to send multiple long DNS queries to trigger detection
        for i in range(6):
            packet_info = {
                'src_ip': '192.168.1.100',
                'dns_info': {
                    'query': True,
                    'queries': [{'name': long_domain + str(i), 'type': 1}]
                },
                'protocols': ['DNS'],
                'timestamp': 1.0 + i
            }
            
            result = self.detector.analyze_packet(packet_info)
            if result is not None:
                # Should detect after multiple long queries
                self.assertEqual(result['threats'][0]['type'], 'DNS_TUNNELING')
                return
        
        # If we get here, check if we got at least one detection
        self.fail("DNS tunneling should have been detected after multiple long queries")


class TestPacketCapture(unittest.TestCase):
    """Test PacketCapture class."""
    
    def test_initialization(self):
        """Test PacketCapture initialization."""
        capture = PacketCapture(interface="eth0", max_packets=1000)
        self.assertEqual(capture.interface, "eth0")
        self.assertEqual(capture.max_packets, 1000)
        self.assertFalse(capture.is_capturing)
    
    def test_callback_registration(self):
        """Test callback registration."""
        capture = PacketCapture()
        callback = Mock()
        capture.add_packet_callback(callback)
        self.assertIn(callback, capture.packet_callbacks)
    
    def test_get_capture_stats(self):
        """Test capture statistics."""
        capture = PacketCapture()
        stats = capture.get_capture_stats()
        
        self.assertIn('total_packets', stats)
        self.assertIn('stored_packets', stats)
        self.assertIn('is_capturing', stats)
        self.assertEqual(stats['total_packets'], 0)


if __name__ == '__main__':
    unittest.main()
