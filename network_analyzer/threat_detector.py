"""
Threat Detection Module

Identifies security threats in network traffic.
"""

from typing import Dict, List, Optional, Set
from collections import defaultdict
import re


class ThreatDetector:
    """Detects security threats in network traffic."""
    
    def __init__(self):
        """Initialize the threat detector."""
        self.threats = []
        self.suspicious_ips = set()
        self.malicious_patterns = self._load_malicious_patterns()
        self.dns_tunneling_suspects = defaultdict(list)
        
    def _load_malicious_patterns(self) -> Dict[str, List[str]]:
        """Load patterns for detecting malicious activity."""
        return {
            'sql_injection': [
                r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
                r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
                r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
            ],
            'xss': [
                r"<script[^>]*>.*?</script>",
                r"javascript:",
                r"onerror\s*=",
                r"onload\s*=",
            ],
            'command_injection': [
                r";\s*cat\s+",
                r";\s*ls\s+",
                r"\|\s*nc\s+",
                r"&&\s*whoami",
            ],
            'path_traversal': [
                r"\.\./",
                r"\.\.\\",
                r"\%2e\%2e/",
                r"\%2e\%2e\\",
            ]
        }
    
    def analyze_packet(self, packet_info: Dict) -> Optional[Dict]:
        """
        Analyze a packet for security threats.
        
        Args:
            packet_info: Dictionary containing packet analysis results
            
        Returns:
            Threat dictionary if detected, None otherwise
        """
        threats_detected = []
        
        # Check for malicious payloads
        payload_threat = self._detect_malicious_payload(packet_info)
        if payload_threat:
            threats_detected.append(payload_threat)
        
        # Check for DNS tunneling
        dns_threat = self._detect_dns_tunneling(packet_info)
        if dns_threat:
            threats_detected.append(dns_threat)
        
        # Check for suspicious HTTP requests
        http_threat = self._detect_suspicious_http(packet_info)
        if http_threat:
            threats_detected.append(http_threat)
        
        # Check for known malicious IPs (would be from threat intelligence feed)
        ip_threat = self._detect_malicious_ip(packet_info)
        if ip_threat:
            threats_detected.append(ip_threat)
        
        # Check for data exfiltration patterns
        exfil_threat = self._detect_data_exfiltration(packet_info)
        if exfil_threat:
            threats_detected.append(exfil_threat)
        
        if threats_detected:
            threat_record = {
                'timestamp': packet_info.get('timestamp'),
                'threats': threats_detected,
                'packet_info': packet_info
            }
            self.threats.append(threat_record)
            return threat_record
        
        return None
    
    def _detect_malicious_payload(self, packet_info: Dict) -> Optional[Dict]:
        """Detect malicious payloads in packet data."""
        # Check HTTP requests for malicious patterns
        http_request = packet_info.get('http_request')
        if http_request:
            path = http_request.get('path', '')
            
            # Check for SQL injection
            for pattern in self.malicious_patterns['sql_injection']:
                if re.search(pattern, path, re.IGNORECASE):
                    return {
                        'type': 'SQL_INJECTION',
                        'severity': 'CRITICAL',
                        'source_ip': packet_info.get('src_ip'),
                        'description': f'Possible SQL injection attempt detected in HTTP request',
                        'details': {'path': path}
                    }
            
            # Check for XSS
            for pattern in self.malicious_patterns['xss']:
                if re.search(pattern, path, re.IGNORECASE):
                    return {
                        'type': 'XSS_ATTEMPT',
                        'severity': 'HIGH',
                        'source_ip': packet_info.get('src_ip'),
                        'description': f'Possible XSS attempt detected in HTTP request',
                        'details': {'path': path}
                    }
            
            # Check for command injection
            for pattern in self.malicious_patterns['command_injection']:
                if re.search(pattern, path, re.IGNORECASE):
                    return {
                        'type': 'COMMAND_INJECTION',
                        'severity': 'CRITICAL',
                        'source_ip': packet_info.get('src_ip'),
                        'description': f'Possible command injection attempt detected',
                        'details': {'path': path}
                    }
            
            # Check for path traversal
            for pattern in self.malicious_patterns['path_traversal']:
                if re.search(pattern, path, re.IGNORECASE):
                    return {
                        'type': 'PATH_TRAVERSAL',
                        'severity': 'HIGH',
                        'source_ip': packet_info.get('src_ip'),
                        'description': f'Possible path traversal attempt detected',
                        'details': {'path': path}
                    }
        
        return None
    
    def _detect_dns_tunneling(self, packet_info: Dict) -> Optional[Dict]:
        """Detect potential DNS tunneling."""
        dns_info = packet_info.get('dns_info')
        if not dns_info or not dns_info.get('query'):
            return None
        
        queries = dns_info.get('queries', [])
        for query in queries:
            domain = query.get('name', '')
            
            # Check for suspiciously long subdomain (common in DNS tunneling)
            if len(domain) > 50:
                src_ip = packet_info.get('src_ip')
                self.dns_tunneling_suspects[src_ip].append(domain)
                
                if len(self.dns_tunneling_suspects[src_ip]) >= 5:
                    return {
                        'type': 'DNS_TUNNELING',
                        'severity': 'HIGH',
                        'source_ip': src_ip,
                        'description': f'Possible DNS tunneling detected from {src_ip}',
                        'details': {'domain': domain, 'length': len(domain)}
                    }
            
            # Check for high entropy in domain name (random-looking)
            if self._has_high_entropy(domain):
                return {
                    'type': 'SUSPICIOUS_DNS',
                    'severity': 'MEDIUM',
                    'source_ip': packet_info.get('src_ip'),
                    'description': f'Suspicious DNS query with high entropy',
                    'details': {'domain': domain}
                }
        
        return None
    
    def _detect_suspicious_http(self, packet_info: Dict) -> Optional[Dict]:
        """Detect suspicious HTTP activity."""
        http_request = packet_info.get('http_request')
        if not http_request:
            return None
        
        method = http_request.get('method', '')
        path = http_request.get('path', '')
        
        # Check for suspicious methods
        suspicious_methods = ['TRACE', 'CONNECT', 'DELETE']
        if method in suspicious_methods:
            return {
                'type': 'SUSPICIOUS_HTTP_METHOD',
                'severity': 'MEDIUM',
                'source_ip': packet_info.get('src_ip'),
                'description': f'Suspicious HTTP method: {method}',
                'details': {'method': method, 'path': path}
            }
        
        # Check for sensitive file access attempts
        sensitive_paths = ['/etc/passwd', '/etc/shadow', '/.env', '/config', '/admin']
        for sensitive in sensitive_paths:
            if sensitive in path.lower():
                return {
                    'type': 'SENSITIVE_FILE_ACCESS',
                    'severity': 'HIGH',
                    'source_ip': packet_info.get('src_ip'),
                    'description': f'Attempt to access sensitive path',
                    'details': {'path': path}
                }
        
        return None
    
    def _detect_malicious_ip(self, packet_info: Dict) -> Optional[Dict]:
        """Check if IP is in known malicious IP list."""
        src_ip = packet_info.get('src_ip')
        
        # In a real implementation, this would check against threat intelligence feeds
        # For now, we'll just track IPs that have triggered other alerts
        if src_ip and src_ip in self.suspicious_ips:
            return {
                'type': 'KNOWN_MALICIOUS_IP',
                'severity': 'CRITICAL',
                'source_ip': src_ip,
                'description': f'Traffic from known malicious IP: {src_ip}',
                'details': {}
            }
        
        return None
    
    def _detect_data_exfiltration(self, packet_info: Dict) -> Optional[Dict]:
        """Detect potential data exfiltration."""
        # Check for large outbound transfers
        size = packet_info.get('size', 0)
        dst_port = packet_info.get('dst_port')
        src_ip = packet_info.get('src_ip')
        
        # Check for large DNS responses (possible data exfiltration via DNS)
        if 'DNS' in packet_info.get('protocols', []) and size > 512:
            return {
                'type': 'SUSPICIOUS_DNS_SIZE',
                'severity': 'MEDIUM',
                'source_ip': src_ip,
                'description': f'Unusually large DNS packet ({size} bytes)',
                'details': {'size': size}
            }
        
        # Check for traffic on uncommon ports
        if dst_port and dst_port > 49152:  # Dynamic/private port range
            common_high_ports = {51820}  # WireGuard, etc.
            if dst_port not in common_high_ports and size > 1000:
                return {
                    'type': 'UNCOMMON_PORT_USAGE',
                    'severity': 'LOW',
                    'source_ip': src_ip,
                    'description': f'Large data transfer on uncommon port {dst_port}',
                    'details': {'port': dst_port, 'size': size}
                }
        
        return None
    
    def _has_high_entropy(self, domain: str) -> bool:
        """Check if a domain name has high entropy (looks random)."""
        # Simple entropy check - in a real implementation, use Shannon entropy
        if len(domain) < 10:
            return False
        
        # Count unique characters
        unique_chars = len(set(domain.lower()))
        ratio = unique_chars / len(domain)
        
        # High ratio suggests randomness
        return ratio > 0.6
    
    def mark_ip_as_malicious(self, ip: str):
        """Mark an IP as malicious."""
        self.suspicious_ips.add(ip)
    
    def get_threats(self) -> List[Dict]:
        """Get all detected threats."""
        return self.threats
    
    def get_threats_by_type(self, threat_type: str) -> List[Dict]:
        """Get threats of a specific type."""
        result = []
        for threat in self.threats:
            for t in threat['threats']:
                if t['type'] == threat_type:
                    result.append(threat)
                    break
        return result
    
    def get_threats_by_severity(self, severity: str) -> List[Dict]:
        """Get threats of a specific severity level."""
        result = []
        for threat in self.threats:
            for t in threat['threats']:
                if t['severity'] == severity:
                    result.append(threat)
                    break
        return result
    
    def get_threat_summary(self) -> Dict:
        """Get a summary of detected threats."""
        summary = {
            'total_threats': len(self.threats),
            'by_type': defaultdict(int),
            'by_severity': defaultdict(int),
            'suspicious_ips': len(self.suspicious_ips)
        }
        
        for threat in self.threats:
            for t in threat['threats']:
                summary['by_type'][t['type']] += 1
                summary['by_severity'][t['severity']] += 1
        
        return dict(summary)
    
    def clear_threats(self):
        """Clear all detected threats."""
        self.threats.clear()
    
    def reset(self):
        """Reset all tracking data."""
        self.threats.clear()
        self.suspicious_ips.clear()
        self.dns_tunneling_suspects.clear()
