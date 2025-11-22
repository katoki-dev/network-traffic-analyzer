"""
Protocol Analyzer Module

Analyzes network protocols and extracts detailed information from packets.
"""

from scapy.all import Packet
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.l2 import ARP, Ether
from typing import Dict, Optional, List
from collections import defaultdict


class ProtocolAnalyzer:
    """Analyzes network protocols in captured packets."""
    
    def __init__(self):
        """Initialize the protocol analyzer."""
        self.protocol_counts = defaultdict(int)
        self.conversations = defaultdict(int)
        self.dns_queries = []
        self.http_requests = []
        
    def analyze_packet(self, packet: Packet) -> Dict:
        """
        Analyze a single packet and extract protocol information.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            Dictionary containing protocol analysis results
        """
        analysis = {
            'timestamp': float(packet.time) if hasattr(packet, 'time') else 0,
            'size': len(packet),
            'protocols': [],
            'summary': packet.summary() if hasattr(packet, 'summary') else str(packet)
        }
        
        # Layer 2 - Ethernet
        if packet.haslayer(Ether):
            ether = packet[Ether]
            analysis['protocols'].append('Ethernet')
            analysis['src_mac'] = ether.src
            analysis['dst_mac'] = ether.dst
            self.protocol_counts['Ethernet'] += 1
        
        # ARP
        if packet.haslayer(ARP):
            arp = packet[ARP]
            analysis['protocols'].append('ARP')
            analysis['arp_op'] = 'request' if arp.op == 1 else 'reply'
            analysis['arp_src_ip'] = arp.psrc
            analysis['arp_dst_ip'] = arp.pdst
            self.protocol_counts['ARP'] += 1
        
        # Layer 3 - IP
        if packet.haslayer(IP):
            ip = packet[IP]
            analysis['protocols'].append('IP')
            analysis['src_ip'] = ip.src
            analysis['dst_ip'] = ip.dst
            analysis['ttl'] = ip.ttl
            analysis['ip_protocol'] = ip.proto
            self.protocol_counts['IP'] += 1
            
            # Track conversations
            conv_key = tuple(sorted([ip.src, ip.dst]))
            self.conversations[conv_key] += 1
        
        # Layer 4 - TCP
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            analysis['protocols'].append('TCP')
            analysis['src_port'] = tcp.sport
            analysis['dst_port'] = tcp.dport
            analysis['tcp_flags'] = self._get_tcp_flags(tcp)
            analysis['seq'] = tcp.seq
            analysis['ack'] = tcp.ack
            self.protocol_counts['TCP'] += 1
            
            # Identify application protocol by port
            app_protocol = self._identify_app_protocol(tcp.sport, tcp.dport)
            if app_protocol:
                analysis['protocols'].append(app_protocol)
                self.protocol_counts[app_protocol] += 1
        
        # Layer 4 - UDP
        if packet.haslayer(UDP):
            udp = packet[UDP]
            analysis['protocols'].append('UDP')
            analysis['src_port'] = udp.sport
            analysis['dst_port'] = udp.dport
            self.protocol_counts['UDP'] += 1
            
            # Identify application protocol by port
            app_protocol = self._identify_app_protocol(udp.sport, udp.dport)
            if app_protocol:
                analysis['protocols'].append(app_protocol)
                self.protocol_counts[app_protocol] += 1
        
        # ICMP
        if packet.haslayer(ICMP):
            icmp = packet[ICMP]
            analysis['protocols'].append('ICMP')
            analysis['icmp_type'] = icmp.type
            analysis['icmp_code'] = icmp.code
            self.protocol_counts['ICMP'] += 1
        
        # DNS
        if packet.haslayer(DNS):
            dns = packet[DNS]
            analysis['protocols'].append('DNS')
            analysis['dns_info'] = self._analyze_dns(dns)
            self.protocol_counts['DNS'] += 1
        
        # HTTP
        if packet.haslayer(HTTPRequest):
            http = packet[HTTPRequest]
            analysis['protocols'].append('HTTP')
            http_info = {
                'method': http.Method.decode() if http.Method else '',
                'host': http.Host.decode() if http.Host else '',
                'path': http.Path.decode() if http.Path else ''
            }
            analysis['http_request'] = http_info
            self.http_requests.append(http_info)
            self.protocol_counts['HTTP'] += 1
        
        return analysis
    
    def _get_tcp_flags(self, tcp) -> List[str]:
        """Extract TCP flags from a TCP packet."""
        flags = []
        if tcp.flags.F: flags.append('FIN')
        if tcp.flags.S: flags.append('SYN')
        if tcp.flags.R: flags.append('RST')
        if tcp.flags.P: flags.append('PSH')
        if tcp.flags.A: flags.append('ACK')
        if tcp.flags.U: flags.append('URG')
        return flags
    
    def _identify_app_protocol(self, sport: int, dport: int) -> Optional[str]:
        """Identify application protocol based on port numbers."""
        common_ports = {
            20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
            25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            445: 'SMB', 3389: 'RDP', 3306: 'MySQL', 5432: 'PostgreSQL',
            6379: 'Redis', 27017: 'MongoDB'
        }
        
        for port in [sport, dport]:
            if port in common_ports:
                return common_ports[port]
        return None
    
    def _analyze_dns(self, dns) -> Dict:
        """Analyze DNS packet."""
        info = {
            'query': dns.qd is not None,
            'response': dns.an is not None,
            'queries': [],
            'answers': []
        }
        
        # DNS Queries
        if dns.qd:
            query = {
                'name': dns.qd.qname.decode() if hasattr(dns.qd.qname, 'decode') else str(dns.qd.qname),
                'type': dns.qd.qtype
            }
            info['queries'].append(query)
            self.dns_queries.append(query)
        
        # DNS Answers
        if dns.an:
            try:
                answer = {
                    'name': dns.an.rrname.decode() if hasattr(dns.an.rrname, 'decode') else str(dns.an.rrname),
                    'data': dns.an.rdata
                }
                info['answers'].append(answer)
            except:
                pass
        
        return info
    
    def get_protocol_distribution(self) -> Dict[str, int]:
        """Get the distribution of protocols seen."""
        return dict(self.protocol_counts)
    
    def get_top_conversations(self, n: int = 10) -> List[tuple]:
        """Get top N conversations by packet count."""
        return sorted(self.conversations.items(), key=lambda x: x[1], reverse=True)[:n]
    
    def get_dns_queries(self) -> List[Dict]:
        """Get all DNS queries captured."""
        return self.dns_queries
    
    def get_http_requests(self) -> List[Dict]:
        """Get all HTTP requests captured."""
        return self.http_requests
    
    def reset_stats(self):
        """Reset all collected statistics."""
        self.protocol_counts.clear()
        self.conversations.clear()
        self.dns_queries.clear()
        self.http_requests.clear()
