"""
PTR (reverse DNS) resolver
"""

import asyncio
import socket
from typing import Optional
from concurrent.futures import ThreadPoolExecutor


class PTRResolver:
    """
    Async PTR record resolver.
    
    Performs reverse DNS lookups to get hostnames for IP addresses.
    Uses thread pool for parallel lookups.
    """
    
    def __init__(self, timeout: float = 2.0, max_workers: int = 10):
        self.timeout = timeout
        self.max_workers = max_workers
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
    
    def _resolve_sync(self, ip: str) -> Optional[str]:
        """Synchronous PTR lookup"""
        try:
            socket.setdefaulttimeout(self.timeout)
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror, socket.timeout, OSError):
            return None
    
    async def resolve(self, ip: str) -> Optional[str]:
        """
        Async PTR lookup for single IP.
        
        Args:
            ip: IP address to resolve
            
        Returns:
            Hostname or None if not found
        """
        if not ip:
            return None
        
        loop = asyncio.get_event_loop()
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(self._executor, self._resolve_sync, ip),
                timeout=self.timeout
            )
            return result
        except asyncio.TimeoutError:
            return None
        except Exception:
            return None
    
    async def resolve_many(self, ips: list[str]) -> dict[str, Optional[str]]:
        """
        Async PTR lookup for multiple IPs in parallel.
        
        Args:
            ips: List of IP addresses
            
        Returns:
            Dict mapping IP -> hostname (or None)
        """
        unique_ips = list(set(ip for ip in ips if ip))
        
        if not unique_ips:
            return {}
        
        tasks = [self.resolve(ip) for ip in unique_ips]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return {
            ip: (result if isinstance(result, str) else None)
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
