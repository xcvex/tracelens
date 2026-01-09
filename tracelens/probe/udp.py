"""
UDP probe implementation
"""

import socket
import struct
import time
import random
from ..models import ProbeResult
from .base import BaseProbe


class UDPProbe(BaseProbe):
    """
    UDP probe (Unix-style traceroute).
    
    Sends UDP packets to high ports with controlled TTL.
    Receives either:
    - ICMP Time Exceeded from intermediate routers
    - ICMP Port Unreachable from destination (indicates arrival)
    
    This is the classic Unix traceroute method.
    """
    
    ICMP_TIME_EXCEEDED = 11
    ICMP_DEST_UNREACHABLE = 3
    ICMP_PORT_UNREACHABLE = 3  # Code within DEST_UNREACHABLE
    
    def __init__(self, base_port: int = 33434, timeout: float = 2.0):
        super().__init__(timeout)
        self.base_port = base_port
        self.port_offset = 0
        self._udp_socket = None
        self._icmp_socket = None
        self._init_sockets()
    
    def _init_sockets(self):
        """Initialize sockets for UDP probing"""
        try:
            # UDP socket for sending
            self._udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Raw ICMP socket for receiving responses
            self._icmp_socket = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP
            )
            self._icmp_socket.settimeout(self.timeout)
            self._icmp_socket.bind(('', 0))
            
        except PermissionError:
            raise PermissionError(
                "Administrator privileges required for UDP probing. "
                "Please run as Administrator."
            )
    
    def probe(self, target_ip: str, ttl: int) -> ProbeResult:
        """Send UDP probe with given TTL"""
        # Set TTL on UDP socket
        self._udp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        
        # Calculate destination port
        dst_port = self.base_port + self.port_offset
        self.port_offset = (self.port_offset + 1) % 30
        
        # Payload with identifier
        payload = struct.pack('!HHI', 
            dst_port,  # Store port for identification
            ttl,       # Store TTL
            int(time.time()) & 0xFFFFFFFF
        )
        
        send_time = time.perf_counter()
        
        try:
            self._udp_socket.sendto(payload, (target_ip, dst_port))
        except Exception:
            return ProbeResult()
        
        # Wait for ICMP response
        while True:
            try:
                remaining = self.timeout - (time.perf_counter() - send_time)
                if remaining <= 0:
                    return ProbeResult()
                
                self._icmp_socket.settimeout(remaining)
                data, addr = self._icmp_socket.recvfrom(1024)
                recv_time = time.perf_counter()
                
                # Parse ICMP response
                ip_header_len = (data[0] & 0x0F) * 4
                icmp_data = data[ip_header_len:]
                
                if len(icmp_data) < 8:
                    continue
                
                icmp_type = icmp_data[0]
                icmp_code = icmp_data[1]
                
                if icmp_type == self.ICMP_TIME_EXCEEDED:
                    # Intermediate router
                    if self._verify_our_packet(icmp_data, target_ip, dst_port):
                        rtt_ms = (recv_time - send_time) * 1000
                        return ProbeResult(
                            responder_ip=addr[0],
                            rtt_ms=round(rtt_ms, 2),
                            reached_target=False
                        )
                        
                elif icmp_type == self.ICMP_DEST_UNREACHABLE:
                    # Port unreachable means we reached destination
                    if self._verify_our_packet(icmp_data, target_ip, dst_port):
                        rtt_ms = (recv_time - send_time) * 1000
                        reached = (icmp_code == self.ICMP_PORT_UNREACHABLE)
                        return ProbeResult(
                            responder_ip=addr[0],
                            rtt_ms=round(rtt_ms, 2),
                            reached_target=reached
                        )
                
            except socket.timeout:
                return ProbeResult()
            except Exception:
                continue
    
    def _verify_our_packet(self, icmp_data: bytes, target_ip: str, 
                           dst_port: int) -> bool:
        """Verify the embedded packet is ours"""
        if len(icmp_data) < 36:
            return False
        
        # ICMP header is 8 bytes, then original IP header
        inner_ip_start = 8
        inner_ip = icmp_data[inner_ip_start:inner_ip_start + 20]
        
        if len(inner_ip) < 20:
            return False
        
        # Check protocol is UDP
        inner_proto = inner_ip[9]
        if inner_proto != socket.IPPROTO_UDP:
            return False
        
        # Check destination IP
        inner_dst_ip = socket.inet_ntoa(inner_ip[16:20])
        if inner_dst_ip != target_ip:
            return False
        
        # Check UDP header for destination port
        inner_udp_start = inner_ip_start + 20
        if len(icmp_data) >= inner_udp_start + 4:
            inner_udp = icmp_data[inner_udp_start:inner_udp_start + 4]
            _, inner_dst_port = struct.unpack('!HH', inner_udp)
            
            # Port should be in our range
            if self.base_port <= inner_dst_port < self.base_port + 30:
                return True
        
        return False
    
    def close(self):
        """Close sockets"""
        for sock in (self._udp_socket, self._icmp_socket):
            if sock:
                try:
                    sock.close()
                except:
                    pass
