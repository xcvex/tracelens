"""
TCP SYN probe implementation
"""

import socket
import struct
import time
import os
import random
from ..models import ProbeResult
from .base import BaseProbe


class TCPProbe(BaseProbe):
    """
    TCP SYN probe.
    
    Sends TCP SYN packets with controlled TTL.
    Receives either:
    - ICMP Time Exceeded from intermediate routers
    - TCP SYN-ACK or RST from destination
    
    Useful when ICMP is filtered but TCP ports are open.
    Requires administrator privileges.
    """
    
    ICMP_TIME_EXCEEDED = 11
    ICMP_DEST_UNREACHABLE = 3
    
    def __init__(self, port: int = 80, timeout: float = 2.0):
        super().__init__(timeout)
        self.port = port
        self.src_port = random.randint(32768, 60999)
        self._tcp_socket = None
        self._icmp_socket = None
        self._init_sockets()
    
    def _init_sockets(self):
        """Initialize sockets for TCP probing"""
        try:
            # Raw socket for sending TCP
            self._tcp_socket = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP
            )
            self._tcp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            # Raw socket for receiving ICMP responses
            self._icmp_socket = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP
            )
            self._icmp_socket.settimeout(self.timeout)
            self._icmp_socket.bind(('', 0))
            
        except PermissionError:
            raise PermissionError(
                "Administrator privileges required for TCP probing. "
                "Please run as Administrator."
            )
    
    def _checksum(self, data: bytes) -> int:
        """Calculate checksum"""
        if len(data) % 2:
            data += b'\x00'
        
        s = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + data[i + 1]
            s += w
        
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return ~s & 0xFFFF
    
    def _get_local_ip(self, target_ip: str) -> str:
        """Get local IP for routing to target"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((target_ip, 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return '0.0.0.0'
    
    def _build_ip_header(self, src_ip: str, dst_ip: str, ttl: int, payload_len: int) -> bytes:
        """Build IP header"""
        version_ihl = (4 << 4) + 5  # IPv4, 5 * 4 = 20 bytes
        tos = 0
        total_len = 20 + payload_len
        identification = random.randint(0, 65535)
        flags_fragment = 0
        protocol = socket.IPPROTO_TCP
        checksum = 0  # Kernel fills this
        
        src_addr = socket.inet_aton(src_ip)
        dst_addr = socket.inet_aton(dst_ip)
        
        header = struct.pack(
            '!BBHHHBBH4s4s',
            version_ihl,
            tos,
            total_len,
            identification,
            flags_fragment,
            ttl,
            protocol,
            checksum,
            src_addr,
            dst_addr
        )
        
        return header
    
    def _build_tcp_header(self, src_ip: str, dst_ip: str, src_port: int, 
                          dst_port: int, seq: int) -> bytes:
        """Build TCP SYN header with checksum"""
        # TCP header fields
        ack = 0
        data_offset = 5 << 4  # 5 * 4 = 20 bytes, no options
        flags = 0x02  # SYN flag
        window = socket.htons(65535)
        checksum = 0
        urgent = 0
        
        # Build header without checksum
        tcp_header = struct.pack(
            '!HHLLBBHHH',
            src_port,
            dst_port,
            seq,
            ack,
            data_offset,
            flags,
            window,
            checksum,
            urgent
        )
        
        # Pseudo header for checksum
        src_addr = socket.inet_aton(src_ip)
        dst_addr = socket.inet_aton(dst_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_len = len(tcp_header)
        
        pseudo_header = struct.pack(
            '!4s4sBBH',
            src_addr,
            dst_addr,
            placeholder,
            protocol,
            tcp_len
        )
        
        # Calculate checksum
        checksum = self._checksum(pseudo_header + tcp_header)
        
        # Rebuild with checksum
        tcp_header = struct.pack(
            '!HHLLBBHHH',
            src_port,
            dst_port,
            seq,
            ack,
            data_offset,
            flags,
            window,
            checksum,
            urgent
        )
        
        return tcp_header
    
    def probe(self, target_ip: str, ttl: int) -> ProbeResult:
        """Send TCP SYN with given TTL"""
        src_ip = self._get_local_ip(target_ip)
        self.src_port = (self.src_port + 1) % 65536
        if self.src_port < 32768:
            self.src_port = 32768
        
        seq = random.randint(0, 0xFFFFFFFF)
        
        # Build packet
        tcp_header = self._build_tcp_header(
            src_ip, target_ip, self.src_port, self.port, seq
        )
        ip_header = self._build_ip_header(src_ip, target_ip, ttl, len(tcp_header))
        packet = ip_header + tcp_header
        
        send_time = time.perf_counter()
        
        try:
            self._tcp_socket.sendto(packet, (target_ip, self.port))
        except Exception:
            return ProbeResult()
        
        # Wait for ICMP or TCP response
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
                
                if icmp_type in (self.ICMP_TIME_EXCEEDED, self.ICMP_DEST_UNREACHABLE):
                    # Check if it's our packet
                    if len(icmp_data) >= 36:
                        inner_ip_start = 8
                        inner_ip = icmp_data[inner_ip_start:inner_ip_start + 20]
                        inner_proto = inner_ip[9]
                        
                        if inner_proto == socket.IPPROTO_TCP:
                            inner_tcp_start = inner_ip_start + 20
                            if len(icmp_data) >= inner_tcp_start + 8:
                                inner_tcp = icmp_data[inner_tcp_start:inner_tcp_start + 8]
                                inner_src_port, inner_dst_port = struct.unpack('!HH', inner_tcp[:4])
                                
                                if inner_dst_port == self.port:
                                    rtt_ms = (recv_time - send_time) * 1000
                                    reached = (addr[0] == target_ip)
                                    
                                    return ProbeResult(
                                        responder_ip=addr[0],
                                        rtt_ms=round(rtt_ms, 2),
                                        reached_target=reached
                                    )
                
            except socket.timeout:
                return ProbeResult()
            except Exception:
                continue
    
    def close(self):
        """Close sockets"""
        for sock in (self._tcp_socket, self._icmp_socket):
            if sock:
                try:
                    sock.close()
                except:
                    pass
