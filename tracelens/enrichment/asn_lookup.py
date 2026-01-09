"""
ASN lookup via Team Cymru DNS service
"""

import asyncio
import socket
from dataclasses import dataclass
from typing import Optional
from concurrent.futures import ThreadPoolExecutor
import dns.resolver
import dns.exception


@dataclass
class ASNInfo:
    """ASN information"""
    asn: str  # e.g., "AS15169"
    org: Optional[str] = None
    prefix: Optional[str] = None
    country: Optional[str] = None
    registry: Optional[str] = None


class ASNLookup:
    """
    ASN lookup via Team Cymru DNS service.
    
    Uses DNS TXT queries to:
    1. Get ASN from IP: <reversed-ip>.origin.asn.cymru.com
    2. Get org name: AS<asn>.asn.cymru.com
    
    Free, no API key required, reliable.
    """
    
    ORIGIN_SUFFIX = "origin.asn.cymru.com"
    ASN_SUFFIX = "asn.cymru.com"
    
    def __init__(self, timeout: float = 3.0, max_workers: int = 10):
        self.timeout = timeout
        self.max_workers = max_workers
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._resolver = dns.resolver.Resolver()
        self._resolver.timeout = timeout
        self._resolver.lifetime = timeout
    
    def _reverse_ip(self, ip: str) -> str:
        """Reverse IP octets for DNS query"""
        parts = ip.split('.')
        return '.'.join(reversed(parts))
    
    def _query_txt(self, domain: str) -> Optional[str]:
        """Query TXT record"""
        try:
            answers = self._resolver.resolve(domain, 'TXT')
            for rdata in answers:
                # TXT record content
                txt = str(rdata).strip('"')
                return txt
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, 
                dns.resolver.NoNameservers, dns.exception.Timeout):
            return None
        except Exception:
            return None
        return None
    
    def _parse_origin_response(self, txt: str) -> Optional[tuple[str, str, str]]:
        """
        Parse origin.asn.cymru.com response.
        Format: "ASN | Prefix | CC | Registry | Date"
        """
        if not txt:
            return None
        
        parts = [p.strip() for p in txt.split('|')]
        if len(parts) >= 3:
            asn = parts[0]
            prefix = parts[1]
            country = parts[2]
            return asn, prefix, country
        return None
    
    def _parse_asn_response(self, txt: str) -> Optional[str]:
        """
        Parse AS<num>.asn.cymru.com response.
        Format: "ASN | CC | Registry | Date | Description"
        """
        if not txt:
            return None
        
        parts = [p.strip() for p in txt.split('|')]
        if len(parts) >= 5:
            return parts[4]  # Description/Org
        return None
    
    def _lookup_sync(self, ip: str) -> Optional[ASNInfo]:
        """Synchronous ASN lookup"""
        # First query: get ASN from IP
        reversed_ip = self._reverse_ip(ip)
        origin_domain = f"{reversed_ip}.{self.ORIGIN_SUFFIX}"
        
        origin_txt = self._query_txt(origin_domain)
        parsed = self._parse_origin_response(origin_txt)
        
        if not parsed:
            return None
        
        asn_num, prefix, country = parsed
        
        # Second query: get org name from ASN
        asn_domain = f"AS{asn_num}.{self.ASN_SUFFIX}"
        asn_txt = self._query_txt(asn_domain)
        org = self._parse_asn_response(asn_txt)
        
        return ASNInfo(
            asn=f"AS{asn_num}",
            org=org,
            prefix=prefix,
            country=country
        )
    
    async def lookup(self, ip: str) -> Optional[ASNInfo]:
        """
        Async ASN lookup for single IP.
        
        Args:
            ip: IP address
            
        Returns:
            ASNInfo or None
        """
        if not ip:
            return None
        
        loop = asyncio.get_event_loop()
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(self._executor, self._lookup_sync, ip),
                timeout=self.timeout * 2  # Allow for two queries
            )
            return result
        except asyncio.TimeoutError:
            return None
        except Exception:
            return None
    
    async def lookup_many(self, ips: list[str]) -> dict[str, Optional[ASNInfo]]:
        """
        Async ASN lookup for multiple IPs in parallel.
        
        Args:
            ips: List of IP addresses
            
        Returns:
            Dict mapping IP -> ASNInfo (or None)
        """
        unique_ips = list(set(ip for ip in ips if ip))
        
        if not unique_ips:
            return {}
        
        tasks = [self.lookup(ip) for ip in unique_ips]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return {
            ip: (result if isinstance(result, ASNInfo) else None)
            for ip, result in zip(unique_ips, results)
        }
    
    def close(self):
        """Shutdown thread pool"""
        self._executor.shutdown(wait=False)
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
