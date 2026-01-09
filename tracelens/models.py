"""
Data models for TraceLens
"""

from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime


@dataclass
class ProbeResult:
    """Result of a single probe"""
    responder_ip: Optional[str] = None
    rtt_ms: Optional[float] = None
    reached_target: bool = False


@dataclass
class HopResult:
    """Result of probing a single hop (multiple probes)"""
    hop: int
    ip: Optional[str] = None
    rtts: list[Optional[float]] = field(default_factory=list)
    reached_target: bool = False
    
    @property
    def rtt_min(self) -> Optional[float]:
        valid = [r for r in self.rtts if r is not None]
        return min(valid) if valid else None
    
    @property
    def rtt_avg(self) -> Optional[float]:
        valid = [r for r in self.rtts if r is not None]
        return sum(valid) / len(valid) if valid else None
    
    @property
    def rtt_max(self) -> Optional[float]:
        valid = [r for r in self.rtts if r is not None]
        return max(valid) if valid else None
    
    @property
    def all_timeout(self) -> bool:
        return all(r is None for r in self.rtts)


@dataclass
class GeoInfo:
    """Geographic information"""
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None


@dataclass
class EnrichedHop:
    """Hop with enrichment data"""
    hop: int
    ip: Optional[str] = None
    rtts: list[Optional[float]] = field(default_factory=list)
    ptr: Optional[str] = None
    asn: Optional[str] = None
    org: Optional[str] = None
    geo: Optional[GeoInfo] = None
    ip_type: Optional[str] = None  # private, cgnat, public, etc.
    tags: list[str] = field(default_factory=list)
    reached_target: bool = False
    
    @property
    def rtt_min(self) -> Optional[float]:
        valid = [r for r in self.rtts if r is not None]
        return min(valid) if valid else None
    
    @property
    def rtt_avg(self) -> Optional[float]:
        valid = [r for r in self.rtts if r is not None]
        return sum(valid) / len(valid) if valid else None
    
    @property
    def rtt_max(self) -> Optional[float]:
        valid = [r for r in self.rtts if r is not None]
        return max(valid) if valid else None


@dataclass
class TraceResult:
    """Complete trace result"""
    target: str
    resolved_ip: str
    protocol: str
    port: Optional[int] = None
    timestamp: datetime = field(default_factory=datetime.now)
    hops: list[EnrichedHop] = field(default_factory=list)
    reachable: bool = False
    total_hops: int = 0
    
    @property
    def final_rtt(self) -> Optional[float]:
        if self.hops and self.hops[-1].rtt_avg:
            return self.hops[-1].rtt_avg
        return None


@dataclass 
class Diagnosis:
    """Diagnostic summary"""
    reachable: bool = False
    total_hops: int = 0
    avg_rtt: Optional[float] = None
    filtered_hops: list[int] = field(default_factory=list)
    latency_jumps: list[tuple[int, float]] = field(default_factory=list)  # (hop, delta_ms)
    egress_hop: Optional[int] = None
    issues: list[str] = field(default_factory=list)
