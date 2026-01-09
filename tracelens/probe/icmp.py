"""
Cross-platform ICMP probe implementation

- Windows: Uses IcmpSendEcho API (works correctly for TTL-based traceroute)
- Linux: Uses raw sockets (works correctly on Linux)
"""

import sys
import socket
import struct
import time
import os
from ..models import ProbeResult
from .base import BaseProbe


def create_icmp_probe(timeout: float = 2.0) -> BaseProbe:
    """Factory function to create the appropriate probe for the current OS"""
    if sys.platform == 'win32':
        return WindowsICMPProbe(timeout)
    else:
        return LinuxICMPProbe(timeout)


class WindowsICMPProbe(BaseProbe):
    """
    ICMP probe using Windows native IcmpSendEcho2 API.
    This properly receives ICMP Time Exceeded messages.
    """
    
    def __init__(self, timeout: float = 2.0):
        super().__init__(timeout)
        self._icmp = None
        self._icmp_dll = None
        self._load_api()
    
    def _load_api(self):
        """Load Windows ICMP API"""
        import ctypes
        import ctypes.wintypes as wintypes
        
        # IP_OPTION_INFORMATION structure
        class IP_OPTION_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("Ttl", ctypes.c_uint8),
                ("Tos", ctypes.c_uint8),
                ("Flags", ctypes.c_uint8),
                ("OptionsSize", ctypes.c_uint8),
                ("OptionsData", ctypes.c_void_p),
            ]
        
        # ICMP_ECHO_REPLY structure
        class ICMP_ECHO_REPLY(ctypes.Structure):
            _fields_ = [
                ("Address", ctypes.c_uint32),
                ("Status", ctypes.c_uint32),
                ("RoundTripTime", ctypes.c_uint32),
                ("DataSize", ctypes.c_uint16),
                ("Reserved", ctypes.c_uint16),
                ("Data", ctypes.c_void_p),
                ("Options", IP_OPTION_INFORMATION),
            ]
        
        self._IP_OPTION_INFORMATION = IP_OPTION_INFORMATION
        self._ICMP_ECHO_REPLY = ICMP_ECHO_REPLY
        
        try:
            self._icmp_dll = ctypes.windll.iphlpapi
            
            self._icmp_dll.IcmpCreateFile.restype = wintypes.HANDLE
            self._icmp_dll.IcmpCreateFile.argtypes = []
            
            self._icmp_dll.IcmpSendEcho.restype = wintypes.DWORD
            self._icmp_dll.IcmpSendEcho.argtypes = [
                wintypes.HANDLE,
                ctypes.c_uint32,
                ctypes.c_void_p,
                wintypes.WORD,
                ctypes.POINTER(IP_OPTION_INFORMATION),
                ctypes.c_void_p,
                wintypes.DWORD,
                wintypes.DWORD,
            ]
            
            self._icmp_dll.IcmpCloseHandle.restype = wintypes.BOOL
            self._icmp_dll.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
            
            self._icmp = self._icmp_dll.IcmpCreateFile()
            if self._icmp == -1 or self._icmp == 0xFFFFFFFF:
                raise OSError("Failed to create ICMP handle")
                
        except Exception as e:
            raise RuntimeError(f"Failed to load Windows ICMP API: {e}")
    
    def probe(self, target_ip: str, ttl: int) -> ProbeResult:
        """Send ICMP ping with specified TTL"""
        import ctypes
        
        if not self._icmp:
            return ProbeResult()
        
        # Status codes
        IP_SUCCESS = 0
        IP_TTL_EXPIRED_TRANSIT = 11013
        IP_REQ_TIMED_OUT = 11010
        
        try:
            # Convert IP to integer (little-endian for Windows)
            ip_parts = target_ip.split('.')
            ip_int = (int(ip_parts[0]) | 
                     (int(ip_parts[1]) << 8) | 
                     (int(ip_parts[2]) << 16) | 
                     (int(ip_parts[3]) << 24))
            
            request_data = b'TraceLens'
            request_size = len(request_data)
            request_buffer = ctypes.create_string_buffer(request_data)
            
            options = self._IP_OPTION_INFORMATION()
            options.Ttl = ttl
            options.Tos = 0
            options.Flags = 0
            options.OptionsSize = 0
            options.OptionsData = None
            
            reply_size = ctypes.sizeof(self._ICMP_ECHO_REPLY) + request_size + 8
            reply_buffer = ctypes.create_string_buffer(reply_size)
            
            timeout_ms = int(self.timeout * 1000)
            
            result = self._icmp_dll.IcmpSendEcho(
                self._icmp,
                ip_int,
                request_buffer,
                request_size,
                ctypes.byref(options),
                reply_buffer,
                reply_size,
                timeout_ms
            )
            
            if result == 0:
                return ProbeResult()
            
            reply = ctypes.cast(reply_buffer, ctypes.POINTER(self._ICMP_ECHO_REPLY)).contents
            
            addr_int = reply.Address
            responder_ip = f"{addr_int & 0xFF}.{(addr_int >> 8) & 0xFF}.{(addr_int >> 16) & 0xFF}.{(addr_int >> 24) & 0xFF}"
            
            status = reply.Status
            rtt = reply.RoundTripTime
            
            if status == IP_SUCCESS:
                return ProbeResult(
                    responder_ip=responder_ip,
                    rtt_ms=float(rtt),
                    reached_target=True
                )
            elif status == IP_TTL_EXPIRED_TRANSIT:
                return ProbeResult(
                    responder_ip=responder_ip,
                    rtt_ms=float(rtt),
                    reached_target=False
                )
            elif status == IP_REQ_TIMED_OUT:
                return ProbeResult()
            else:
                # Other status (unreachable, etc.)
                return ProbeResult(
                    responder_ip=responder_ip,
                    rtt_ms=float(rtt),
                    reached_target=True
                )
            
        except Exception:
            return ProbeResult()
    
    def close(self):
        """Close ICMP handle"""
        if self._icmp and self._icmp_dll:
            try:
                self._icmp_dll.IcmpCloseHandle(self._icmp)
            except:
                pass
            self._icmp = None


class LinuxICMPProbe(BaseProbe):
    """
    ICMP probe using raw sockets for Linux/macOS.
    Raw sockets work correctly on Linux for receiving ICMP Time Exceeded.
    """
    
    ICMP_ECHO_REQUEST = 8
    ICMP_ECHO_REPLY = 0
    ICMP_TIME_EXCEEDED = 11
    ICMP_DEST_UNREACHABLE = 3
    
    def __init__(self, timeout: float = 2.0):
        super().__init__(timeout)
        self.identifier = os.getpid() & 0xFFFF
        self.sequence = 0
    
    def _checksum(self, data: bytes) -> int:
        """Calculate ICMP checksum (RFC 1071)"""
        if len(data) % 2:
            data += b'\x00'
        
        s = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + data[i + 1]
            s += w
        
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return ~s & 0xFFFF
    
    def _build_packet(self) -> bytes:
        """Build ICMP Echo Request packet"""
        self.sequence = (self.sequence + 1) & 0xFFFF
        
        header = struct.pack(
            '!BBHHH',
            self.ICMP_ECHO_REQUEST,
            0,
            0,
            self.identifier,
            self.sequence
        )
        
        payload = struct.pack('!d', time.time())
        cs = self._checksum(header + payload)
        
        header = struct.pack(
            '!BBHHH',
            self.ICMP_ECHO_REQUEST,
            0,
            cs,
            self.identifier,
            self.sequence
        )
        
        return header + payload
    
    def probe(self, target_ip: str, ttl: int) -> ProbeResult:
        """Send ICMP Echo Request with given TTL"""
        sock = None
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            sock.settimeout(self.timeout)
            
            packet = self._build_packet()
            current_seq = self.sequence
            send_time = time.perf_counter()
            
            sock.sendto(packet, (target_ip, 0))
            
            deadline = send_time + self.timeout
            
            while True:
                remaining = deadline - time.perf_counter()
                if remaining <= 0:
                    return ProbeResult()
                
                sock.settimeout(remaining)
                
                try:
                    data, addr = sock.recvfrom(1024)
                    recv_time = time.perf_counter()
                except socket.timeout:
                    return ProbeResult()
                
                result = self._parse_response(
                    data, addr[0], target_ip,
                    send_time, recv_time, current_seq
                )
                if result is not None:
                    return result
            
        except PermissionError:
            raise PermissionError(
                "Root privileges required. Please run with sudo."
            )
        except socket.timeout:
            return ProbeResult()
        except Exception:
            return ProbeResult()
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
    
    def _parse_response(self, data: bytes, responder_ip: str, target_ip: str,
                        send_time: float, recv_time: float,
                        expected_seq: int) -> ProbeResult | None:
        """Parse ICMP response"""
        if len(data) < 20:
            return None
        
        ip_header_len = (data[0] & 0x0F) * 4
        
        if len(data) < ip_header_len + 8:
            return None
        
        icmp_data = data[ip_header_len:]
        icmp_type = icmp_data[0]
        
        rtt_ms = (recv_time - send_time) * 1000
        
        if icmp_type == self.ICMP_ECHO_REPLY:
            if len(icmp_data) >= 8:
                ident = struct.unpack('!H', icmp_data[4:6])[0]
                seq = struct.unpack('!H', icmp_data[6:8])[0]
                if ident == self.identifier and seq == expected_seq:
                    return ProbeResult(
                        responder_ip=responder_ip,
                        rtt_ms=round(rtt_ms, 2),
                        reached_target=True
                    )
            return None
        
        elif icmp_type == self.ICMP_TIME_EXCEEDED:
            if self._is_our_packet(icmp_data, expected_seq):
                return ProbeResult(
                    responder_ip=responder_ip,
                    rtt_ms=round(rtt_ms, 2),
                    reached_target=False
                )
            return None
        
        elif icmp_type == self.ICMP_DEST_UNREACHABLE:
            if self._is_our_packet(icmp_data, expected_seq):
                return ProbeResult(
                    responder_ip=responder_ip,
                    rtt_ms=round(rtt_ms, 2),
                    reached_target=True
                )
            return None
        
        return None
    
    def _is_our_packet(self, icmp_data: bytes, expected_seq: int) -> bool:
        """Check if embedded packet belongs to us"""
        if len(icmp_data) < 36:
            return False
        
        inner_ip_start = 8
        inner_ip_header_len = (icmp_data[inner_ip_start] & 0x0F) * 4
        inner_icmp_start = inner_ip_start + inner_ip_header_len
        
        if len(icmp_data) < inner_icmp_start + 8:
            return False
        
        inner_icmp = icmp_data[inner_icmp_start:inner_icmp_start + 8]
        inner_type = inner_icmp[0]
        inner_ident = struct.unpack('!H', inner_icmp[4:6])[0]
        inner_seq = struct.unpack('!H', inner_icmp[6:8])[0]
        
        return (inner_type == self.ICMP_ECHO_REQUEST and
                inner_ident == self.identifier and
                inner_seq == expected_seq)
    
    def close(self):
        """No persistent resources"""
        pass


# Alias for backward compatibility
class ICMPProbe(BaseProbe):
    """
    Cross-platform ICMP probe.
    Automatically selects the correct implementation based on OS.
    """
    
    def __init__(self, timeout: float = 2.0):
        super().__init__(timeout)
        self._impl = create_icmp_probe(timeout)
    
    def probe(self, target_ip: str, ttl: int) -> ProbeResult:
        return self._impl.probe(target_ip, ttl)
    
    def close(self):
        self._impl.close()
