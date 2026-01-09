"""
Simple JSON file cache for enrichment data
"""

import json
import time
from pathlib import Path
from typing import Optional, Any
from dataclasses import asdict

from .models import GeoInfo
from .enrichment.asn_lookup import ASNInfo


class Cache:
    """
    Simple JSON file cache.
    
    Stores enrichment data in ~/.tracelens/cache.json with TTL support.
    No database required - just a JSON file.
    """
    
    DEFAULT_PATH = Path.home() / '.tracelens' / 'cache.json'
    DEFAULT_TTL = 7 * 24 * 3600  # 7 days in seconds
    
    def __init__(self, path: Optional[Path] = None, ttl: Optional[int] = None):
        self.path = path or self.DEFAULT_PATH
        self.ttl = ttl or self.DEFAULT_TTL
        self._data: dict[str, dict] = {}
        self._dirty = False
        self._load()
    
    def _load(self):
        """Load cache from file"""
        if self.path.exists():
            try:
                content = self.path.read_text(encoding='utf-8')
                self._data = json.loads(content)
                self._cleanup_expired()
            except (json.JSONDecodeError, IOError):
                self._data = {}
    
    def _save(self):
        """Save cache to file"""
        if not self._dirty:
            return
        
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            content = json.dumps(self._data, indent=2, ensure_ascii=False)
            self.path.write_text(content, encoding='utf-8')
            self._dirty = False
        except IOError:
            pass  # Silently fail - cache is not critical
    
    def _cleanup_expired(self):
        """Remove expired entries"""
        now = time.time()
        expired = [
            ip for ip, entry in self._data.items()
            if now - entry.get('_ts', 0) > self.ttl
        ]
        
        for ip in expired:
            del self._data[ip]
        
        if expired:
            self._dirty = True
    
    def _is_valid(self, entry: dict) -> bool:
        """Check if cache entry is still valid"""
        ts = entry.get('_ts', 0)
        return time.time() - ts < self.ttl
    
    def get(self, ip: str) -> Optional[dict]:
        """
        Get cached data for IP.
        
        Args:
            ip: IP address
            
        Returns:
            Cached data dict or None if not found/expired
        """
        entry = self._data.get(ip)
        if entry and self._is_valid(entry):
            return entry
        return None
    
    def get_asn(self, ip: str) -> Optional[ASNInfo]:
        """Get cached ASN info"""
        entry = self.get(ip)
        if entry and 'asn' in entry:
            return ASNInfo(
                asn=entry.get('asn'),
                org=entry.get('org'),
                prefix=entry.get('prefix'),
                country=entry.get('asn_country')
            )
        return None
    
    def get_geo(self, ip: str) -> Optional[GeoInfo]:
        """Get cached geo info"""
        entry = self.get(ip)
        if entry and 'geo_country' in entry:
            return GeoInfo(
                country=entry.get('geo_country'),
                country_code=entry.get('geo_country_code'),
                city=entry.get('geo_city'),
                lat=entry.get('geo_lat'),
                lon=entry.get('geo_lon')
            )
        return None
    
    def get_ptr(self, ip: str) -> Optional[str]:
        """Get cached PTR record"""
        entry = self.get(ip)
        if entry:
            return entry.get('ptr')
        return None
    
    def set(self, ip: str, 
            asn: Optional[ASNInfo] = None,
            geo: Optional[GeoInfo] = None,
            ptr: Optional[str] = None):
        """
        Set cache data for IP.
        
        Args:
            ip: IP address
            asn: ASN info
            geo: Geo info
            ptr: PTR hostname
        """
        entry = self._data.get(ip, {})
        entry['_ts'] = time.time()
        
        if asn:
            entry['asn'] = asn.asn
            entry['org'] = asn.org
            entry['prefix'] = asn.prefix
            entry['asn_country'] = asn.country
        
        if geo:
            entry['geo_country'] = geo.country
            entry['geo_country_code'] = geo.country_code
            entry['geo_city'] = geo.city
            entry['geo_lat'] = geo.lat
            entry['geo_lon'] = geo.lon
        
        if ptr is not None:
            entry['ptr'] = ptr
        
        self._data[ip] = entry
        self._dirty = True
    
    def has(self, ip: str) -> bool:
        """Check if IP is in cache and valid"""
        return self.get(ip) is not None
    
    def save(self):
        """Manually trigger save"""
        self._save()
    
    def clear(self):
        """Clear all cache entries"""
        self._data = {}
        self._dirty = True
        self._save()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self._save()
        return False
