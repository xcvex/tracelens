"""
Traceroute orchestrator
"""

import socket
from typing import Callable, Optional
from ..models import HopResult, ProbeResult
from .base import BaseProbe
from .icmp import ICMPProbe
from .tcp import TCPProbe
from .udp import UDPProbe


class Tracer:
    """
    Traceroute orchestrator.
    
    Manages probe execution across multiple hops with configurable
    protocol, hop count, and probe count.
    """
    
    PROTOCOLS = {
        'icmp': ICMPProbe,
        'tcp': TCPProbe,
        'udp': UDPProbe,
    }
    
    def __init__(
        self,
        target: str,
        protocol: str = 'icmp',
        max_hops: int = 30,
        probes_per_hop: int = 3,
        timeout: float = 2.0,
        port: int = 80
    ):
        self.target = target
        self.protocol = protocol.lower()
        self.max_hops = max_hops
        self.probes_per_hop = probes_per_hop
        self.timeout = timeout
        self.port = port
        self.target_ip: Optional[str] = None
        self._probe: Optional[BaseProbe] = None
    
    def resolve_target(self) -> str:
        """Resolve target hostname to IP"""
        try:
            self.target_ip = socket.gethostbyname(self.target)
            return self.target_ip
        except socket.gaierror as e:
            raise ValueError(f"Cannot resolve hostname '{self.target}': {e}")
    
    def _create_probe(self) -> BaseProbe:
        """Create probe instance based on protocol"""
        probe_class = self.PROTOCOLS.get(self.protocol)
        if not probe_class:
            raise ValueError(
                f"Unknown protocol '{self.protocol}'. "
                f"Supported: {', '.join(self.PROTOCOLS.keys())}"
            )
        
        if self.protocol == 'tcp':
            return probe_class(port=self.port, timeout=self.timeout)
        elif self.protocol == 'udp':
            return probe_class(timeout=self.timeout)
        else:
            return probe_class(timeout=self.timeout)
    
    def trace(
        self,
        on_hop: Optional[Callable[[HopResult], None]] = None
    ) -> list[HopResult]:
        """
        Execute traceroute.
        
        Args:
            on_hop: Optional callback for real-time hop updates
            
        Returns:
            List of HopResult for each hop
        """
        if not self.target_ip:
            self.resolve_target()
        
        hops: list[HopResult] = []
        
        with self._create_probe() as probe:
            for ttl in range(1, self.max_hops + 1):
                rtts: list[Optional[float]] = []
                hop_ip: Optional[str] = None
                reached = False
                
                for _ in range(self.probes_per_hop):
                    result = probe.probe(self.target_ip, ttl)
                    rtts.append(result.rtt_ms)
                    
                    if result.responder_ip:
                        hop_ip = result.responder_ip
                    
                    if result.reached_target:
                        reached = True
                
                hop = HopResult(
                    hop=ttl,
                    ip=hop_ip,
                    rtts=rtts,
                    reached_target=reached
                )
                hops.append(hop)
                
                if on_hop:
                    on_hop(hop)
                
                if reached:
                    break
        
        return hops
