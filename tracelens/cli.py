import asyncio
import sys
import os
from pathlib import Path
from typing import Optional
from datetime import datetime

import click
from rich.console import Console

from . import __version__
from .models import EnrichedHop, HopResult, TraceResult, Diagnosis, GeoInfo
from .probe import Tracer
from .enrichment import IPClassifier, PTRResolver, ASNLookup, GeoLookup
from .cache import Cache
from .diagnostics import Diagnostics
from .output import ConsoleOutput, JsonExporter


console = Console()


def is_admin() -> bool:
    """Check if running with elevated privileges (admin on Windows, root on Linux)"""
    if sys.platform == 'win32':
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:
        # Linux/macOS: check if running as root
        return os.geteuid() == 0


def enrich_hop_sync(hop: HopResult, cache: Cache, 
                    enable_ptr: bool = True, enable_geo: bool = True) -> EnrichedHop:
    """
    Synchronously enrich a single hop.
    Uses cache when available, with fallback to ASN country for geo.
    """
    from .models import GeoInfo
    
    enriched = EnrichedHop(
        hop=hop.hop,
        ip=hop.ip,
        rtts=hop.rtts,
        reached_target=hop.reached_target
    )
    
    if not hop.ip:
        return enriched
    
    # IP classification
    ip_type = IPClassifier.classify(hop.ip).value
    enriched.ip_type = ip_type
    
    # Add tag for non-public IPs
    tag = IPClassifier.get_tag(hop.ip)
    if tag:
        enriched.tags.append(tag)
    
    # Skip enrichment for non-public IPs
    if not IPClassifier.should_enrich(hop.ip):
        return enriched
    
    # Try cache first
    cached_asn = cache.get_asn(hop.ip)
    cached_geo = cache.get_geo(hop.ip) if enable_geo else None
    cached_ptr = cache.get_ptr(hop.ip) if enable_ptr else None
    
    asn_info = cached_asn  # Track ASN info for geo fallback
    
    if cached_asn:
        enriched.asn = cached_asn.asn
        enriched.org = cached_asn.org
    
    if cached_geo:
        enriched.geo = cached_geo
    
    if cached_ptr:
        enriched.ptr = cached_ptr
    
    # If we have all cached data, skip network lookup
    need_asn = not cached_asn
    need_geo = enable_geo and not cached_geo
    need_ptr = enable_ptr and not cached_ptr
    
    if not need_asn and not need_geo and not need_ptr:
        # Apply geo fallback from cached ASN if needed
        if not enriched.geo and asn_info and asn_info.country:
            enriched.geo = GeoInfo(
                country_code=asn_info.country,
                country=None, city=None, lat=None, lon=None
            )
        return enriched
    
    # Fetch fresh data
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        async def fetch_enrichment():
            results = {}
            
            # ASN lookup
            if need_asn:
                asn_lookup = ASNLookup(timeout=3.0)
                try:
                    results['asn'] = await asn_lookup.lookup(hop.ip)
                finally:
                    asn_lookup.close()
            
            # Geo lookup
            if need_geo:
                async with GeoLookup(timeout=3.0) as geo_lookup:
                    results['geo'] = await geo_lookup.lookup(hop.ip)
            
            # PTR lookup
            if need_ptr:
                resolver = PTRResolver(timeout=2.0)
                try:
                    results['ptr'] = await resolver.resolve(hop.ip)
                finally:
                    resolver.close()
            
            return results
        
        results = loop.run_until_complete(fetch_enrichment())
        loop.close()
        
        # Apply results
        if results.get('asn'):
            asn_info = results['asn']
            enriched.asn = asn_info.asn
            enriched.org = asn_info.org
            cache.set(hop.ip, asn=asn_info)
        
        if results.get('geo'):
            enriched.geo = results['geo']
            cache.set(hop.ip, geo=results['geo'])
        
        if results.get('ptr'):
            enriched.ptr = results['ptr']
            cache.set(hop.ip, ptr=results['ptr'])
        
    except Exception:
        pass
    
    # Fallback: use country from ASN data when GeoIP is missing
    if not enriched.geo and asn_info and asn_info.country:
        enriched.geo = GeoInfo(
            country_code=asn_info.country,
            country=None, city=None, lat=None, lon=None
        )
    
    return enriched


@click.command()
@click.argument('target')
@click.option('-p', '--protocol', default='icmp', 
              type=click.Choice(['icmp', 'tcp', 'udp'], case_sensitive=False),
              help='Probe protocol (default: icmp)')
@click.option('--port', default=80, type=int,
              help='Port for TCP/UDP probes (default: 80)')
@click.option('-m', '--max-hops', default=30, type=int,
              help='Maximum hops (default: 30)')
@click.option('-q', '--probes', default=3, type=int,
              help='Probes per hop (default: 3)')
@click.option('-w', '--timeout', default=2.0, type=float,
              help='Timeout per probe in seconds (default: 2)')
@click.option('--dns/--no-dns', default=True,
              help='Enable/disable PTR lookups (default: enabled)')
@click.option('--geo/--no-geo', default=True,
              help='Enable/disable geo lookups (default: enabled)')
@click.option('--json', 'json_path', type=click.Path(),
              help='Export results to JSON file')
@click.option('--no-cache', is_flag=True,
              help='Disable cache (always fetch fresh data)')
@click.version_option(version=__version__)
def main(target: str, protocol: str, port: int, max_hops: int,
         probes: int, timeout: float, dns: bool, geo: bool,
         json_path: Optional[str], no_cache: bool):
    """
    TraceLens - Enhanced traceroute with network intelligence.
    
    Trace route to TARGET (IP address or hostname) with automatic
    enrichment of ASN, organization, and geographic information.
    
    Examples:
    
        tracelens 8.8.8.8
        
        tracelens google.com -p tcp --port 443
        
        tracelens 1.1.1.1 --json output.json
    """
    # Check admin privileges
    if not is_admin():
        if sys.platform == 'win32':
            console.print(
                "[bold red]Error:[/] Administrator privileges required.\n"
                "[dim]Please run PowerShell as Administrator.[/]"
            )
        else:
            console.print(
                "[bold red]Error:[/] Root privileges required.\n"
                "[dim]Please run with sudo.[/]"
            )
        sys.exit(1)
    
    output = ConsoleOutput()
    cache = Cache() if not no_cache else Cache(ttl=0)
    enriched_hops: list[EnrichedHop] = []
    
    try:
        # Create tracer
        tracer = Tracer(
            target=target,
            protocol=protocol,
            max_hops=max_hops,
            probes_per_hop=probes,
            timeout=timeout,
            port=port
        )
        
        # Resolve target
        try:
            resolved_ip = tracer.resolve_target()
        except ValueError as e:
            output.print_error(str(e))
            sys.exit(1)
        
        # Print header
        output.print_header(
            target=target,
            resolved_ip=resolved_ip,
            protocol=protocol,
            max_hops=max_hops,
            probes=probes,
            port=port if protocol in ('tcp', 'udp') else None
        )
        
        # Real-time tracing with per-hop output
        def on_hop(hop: HopResult):
            # Enrich this hop immediately
            enriched = enrich_hop_sync(hop, cache, enable_ptr=dns, enable_geo=geo)
            enriched_hops.append(enriched)
            
            # Print immediately
            output.print_hop_realtime(enriched)
        
        # Execute trace
        hops = tracer.trace(on_hop=on_hop)
        
        # Print separator
        output.print_separator()
        
        # Save cache
        if not no_cache:
            cache.save()
        
        # Diagnostics
        diagnostics = Diagnostics()
        enriched_hops = diagnostics.add_tags(enriched_hops)
        diagnosis = diagnostics.analyze(enriched_hops)
        
        # Build result
        result = TraceResult(
            target=target,
            resolved_ip=resolved_ip,
            protocol=protocol,
            port=port if protocol in ('tcp', 'udp') else None,
            timestamp=datetime.now(),
            hops=enriched_hops,
            reachable=diagnosis.reachable,
            total_hops=len(enriched_hops)
        )
        
        # Print diagnosis summary
        output.print_diagnosis(diagnosis)
        
        # JSON export
        if json_path:
            exporter = JsonExporter()
            exporter.add_data_source("team_cymru")
            if geo:
                exporter.add_data_source("ip-api.com")
            
            json_file = Path(json_path)
            exporter.export(result, diagnosis, json_file)
            console.print(f"\n[dim]Results exported to:[/] {json_file.absolute()}")
        
    except PermissionError as e:
        output.print_error(str(e))
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted[/]")
        sys.exit(130)
    except Exception as e:
        output.print_error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
