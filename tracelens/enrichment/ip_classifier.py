"""
IP address classifier
"""

import ipaddress
from enum import Enum
from typing import Optional


class IPType(Enum):
    """IP address classification types"""
    PRIVATE = "private"
    CGNAT = "cgnat"
    LOOPBACK = "loopback"
    LINKLOCAL = "linklocal"
    MULTICAST = "multicast"
    RESERVED = "reserved"
    PUBLIC = "public"
    UNKNOWN = "unknown"


class IPClassifier:
    """
    Classify IP addresses into categories.
    
    Categories:
    - private: RFC1918 (10/8, 172.16/12, 192.168/16)
    - cgnat: Carrier-grade NAT (100.64/10)
    - loopback: Localhost (127/8)
    - linklocal: Link-local (169.254/16)
    - multicast: Multicast (224/4)
    - reserved: Other reserved ranges
    - public: Globally routable
    """
    
    # Special ranges
    CGNAT_NETWORK = ipaddress.IPv4Network('100.64.0.0/10')
    
    @classmethod
    def classify(cls, ip: str) -> IPType:
        """
        Classify an IP address.
        
        Args:
            ip: IPv4 address string
            
        Returns:
            IPType enum value
        """
        if not ip:
            return IPType.UNKNOWN
        
        try:
            addr = ipaddress.IPv4Address(ip)
        except (ipaddress.AddressValueError, ValueError):
            return IPType.UNKNOWN
        
        # Check specific types
        if addr.is_loopback:
            return IPType.LOOPBACK
        
        if addr.is_link_local:
            return IPType.LINKLOCAL
        
        if addr.is_multicast:
            return IPType.MULTICAST
        
        if addr.is_private:
            return IPType.PRIVATE
        
        # CGNAT range (not covered by is_private)
        if addr in cls.CGNAT_NETWORK:
            return IPType.CGNAT
        
        if addr.is_reserved:
            return IPType.RESERVED
        
        if addr.is_global:
            return IPType.PUBLIC
        
        return IPType.UNKNOWN
    
    @classmethod
    def is_public(cls, ip: str) -> bool:
        """Check if IP is publicly routable"""
        return cls.classify(ip) == IPType.PUBLIC
    
    @classmethod
    def should_enrich(cls, ip: str) -> bool:
        """Check if IP should have ASN/Geo enrichment"""
        ip_type = cls.classify(ip)
        return ip_type == IPType.PUBLIC
    
    @classmethod
    def get_tag(cls, ip: str) -> Optional[str]:
        """Get tag for non-public IPs, None for public"""
        ip_type = cls.classify(ip)
        
        if ip_type == IPType.PRIVATE:
            return "private"
        elif ip_type == IPType.CGNAT:
            return "cgnat"
        elif ip_type == IPType.LOOPBACK:
            return "loopback"
        elif ip_type == IPType.LINKLOCAL:
            return "linklocal"
        elif ip_type == IPType.RESERVED:
            return "reserved"
        
        return None
