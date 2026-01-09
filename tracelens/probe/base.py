"""
Abstract base class for probe implementations
"""

from abc import ABC, abstractmethod
from ..models import ProbeResult


class BaseProbe(ABC):
    """Abstract base class for network probes"""
    
    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout
    
    @abstractmethod
    def probe(self, target_ip: str, ttl: int) -> ProbeResult:
        """
        Send a probe with given TTL and return result.
        
        Args:
            target_ip: Target IP address (already resolved)
            ttl: Time-to-live value
            
        Returns:
            ProbeResult with responder IP and RTT
        """
        pass
    
    @abstractmethod
    def close(self):
        """Clean up resources"""
        pass
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
