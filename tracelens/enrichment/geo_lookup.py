"""
Geographic IP lookup via ip-api.com
"""

import asyncio
from dataclasses import dataclass
from typing import Optional
import httpx

from ..models import GeoInfo


# Country code to flag emoji mapping
COUNTRY_FLAGS = {
    'CN': '🇨🇳', 'US': '🇺🇸', 'JP': '🇯🇵', 'KR': '🇰🇷', 'HK': '🇭🇰',
    'TW': '🇹🇼', 'SG': '🇸🇬', 'DE': '🇩🇪', 'GB': '🇬🇧', 'FR': '🇫🇷',
    'NL': '🇳🇱', 'RU': '🇷🇺', 'AU': '🇦🇺', 'CA': '🇨🇦', 'IN': '🇮🇳',
    'BR': '🇧🇷', 'IT': '🇮🇹', 'ES': '🇪🇸', 'SE': '🇸🇪', 'NO': '🇳🇴',
    'FI': '🇫🇮', 'DK': '🇩🇰', 'PL': '🇵🇱', 'CZ': '🇨🇿', 'AT': '🇦🇹',
    'CH': '🇨🇭', 'BE': '🇧🇪', 'IE': '🇮🇪', 'NZ': '🇳🇿', 'MX': '🇲🇽',
    'AR': '🇦🇷', 'CL': '🇨🇱', 'CO': '🇨🇴', 'ZA': '🇿🇦', 'EG': '🇪🇬',
    'AE': '🇦🇪', 'IL': '🇮🇱', 'TR': '🇹🇷', 'TH': '🇹🇭', 'VN': '🇻🇳',
    'ID': '🇮🇩', 'MY': '🇲🇾', 'PH': '🇵🇭', 'UA': '🇺🇦', 'RO': '🇷🇴',
    'GR': '🇬🇷', 'PT': '🇵🇹', 'HU': '🇭🇺', 'BG': '🇧🇬', 'SK': '🇸🇰',
}


def get_flag(country_code: str) -> str:
    """Get flag emoji for country code"""
    if not country_code:
        return ''
    return COUNTRY_FLAGS.get(country_code.upper(), '🌍')


class GeoLookup:
    """
    Geographic IP lookup via ip-api.com.
    
    Free tier: 45 requests/minute (sufficient for traceroute).
    No API key required.
    """
    
    API_URL = "http://ip-api.com/json/{ip}"
    BATCH_URL = "http://ip-api.com/batch"
    FIELDS = "status,country,countryCode,city,lat,lon"
    
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client"""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout)
        return self._client
    
    async def lookup(self, ip: str) -> Optional[GeoInfo]:
        """
        Lookup geo info for single IP.
        
        Args:
            ip: IP address
            
        Returns:
            GeoInfo or None
        """
        if not ip:
            return None
        
        try:
            client = await self._get_client()
            url = f"{self.API_URL.format(ip=ip)}?fields={self.FIELDS}"
            
            response = await client.get(url)
            
            if response.status_code != 200:
                return None
            
            data = response.json()
            
            if data.get('status') != 'success':
                return None
            
            return GeoInfo(
                country=data.get('country'),
                country_code=data.get('countryCode'),
                city=data.get('city'),
                lat=data.get('lat'),
                lon=data.get('lon')
            )
            
        except Exception:
            return None
    
    async def lookup_many(self, ips: list[str]) -> dict[str, Optional[GeoInfo]]:
        """
        Lookup geo info for multiple IPs using batch API.
        
        Args:
            ips: List of IP addresses
            
        Returns:
            Dict mapping IP -> GeoInfo (or None)
        """
        unique_ips = list(set(ip for ip in ips if ip))
        
        if not unique_ips:
            return {}
        
        # Batch API supports up to 100 IPs
        if len(unique_ips) <= 100:
            return await self._batch_lookup(unique_ips)
        
        # Split into chunks
        results = {}
        for i in range(0, len(unique_ips), 100):
            chunk = unique_ips[i:i + 100]
            chunk_results = await self._batch_lookup(chunk)
            results.update(chunk_results)
            
            # Rate limiting pause between chunks
            if i + 100 < len(unique_ips):
                await asyncio.sleep(1)
        
        return results
    
    async def _batch_lookup(self, ips: list[str]) -> dict[str, Optional[GeoInfo]]:
        """Batch lookup for up to 100 IPs"""
        try:
            client = await self._get_client()
            
            # Build query
            query = [{"query": ip, "fields": self.FIELDS} for ip in ips]
            
            response = await client.post(self.BATCH_URL, json=query)
            
            if response.status_code != 200:
                # Fallback to individual lookups
                return await self._individual_lookups(ips)
            
            data = response.json()
            results = {}
            
            for item in data:
                ip = item.get('query')
                if item.get('status') == 'success':
                    results[ip] = GeoInfo(
                        country=item.get('country'),
                        country_code=item.get('countryCode'),
                        city=item.get('city'),
                        lat=item.get('lat'),
                        lon=item.get('lon')
                    )
                else:
                    results[ip] = None
            
            return results
            
        except Exception:
            return await self._individual_lookups(ips)
    
    async def _individual_lookups(self, ips: list[str]) -> dict[str, Optional[GeoInfo]]:
        """Fallback to individual lookups"""
        tasks = [self.lookup(ip) for ip in ips]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return {
            ip: (result if isinstance(result, GeoInfo) else None)
            for ip, result in zip(ips, results)
        }
    
    async def close(self):
        """Close HTTP client"""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
        return False
