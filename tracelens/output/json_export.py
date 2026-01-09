"""
JSON export for TraceLens
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from ..models import EnrichedHop, TraceResult, Diagnosis
from .. import __version__


class JsonExporter:
    """
    Export trace results to JSON format.
    
    Output format is designed to be both human-readable
    and machine-parseable.
    """
    
    def __init__(self):
        self.data_sources = []
    
    def add_data_source(self, source: str):
        """Record data source used"""
        if source not in self.data_sources:
            self.data_sources.append(source)
    
    def export(self, result: TraceResult, diagnosis: Diagnosis, 
               output_path: Optional[Path] = None) -> dict:
        """
        Export trace result to JSON.
        
        Args:
            result: Trace result
            diagnosis: Diagnostic analysis
            output_path: Optional file path to write
            
        Returns:
            JSON-serializable dict
        """
        data = {
            "meta": {
                "version": __version__,
                "generator": "TraceLens",
                "data_sources": self.data_sources or ["team_cymru", "ip-api.com"],
                "generated_at": datetime.now().isoformat()
            },
            "target": result.target,
            "resolved_ip": result.resolved_ip,
            "protocol": result.protocol,
            "port": result.port,
            "timestamp": result.timestamp.isoformat(),
            "hops": [self._serialize_hop(hop) for hop in result.hops],
            "diagnosis": {
                "reachable": diagnosis.reachable,
                "total_hops": diagnosis.total_hops,
                "avg_rtt_ms": round(diagnosis.avg_rtt, 2) if diagnosis.avg_rtt else None,
                "filtered_hops": diagnosis.filtered_hops,
                "latency_jumps": [
                    {"hop": hop, "delta_ms": delta}
                    for hop, delta in diagnosis.latency_jumps
                ],
                "egress_hop": diagnosis.egress_hop,
                "summary": diagnosis.issues
            }
        }
        
        if output_path:
            self._write_file(data, output_path)
        
        return data
    
    def _serialize_hop(self, hop: EnrichedHop) -> dict:
        """Serialize a single hop"""
        return {
            "hop": hop.hop,
            "ip": hop.ip,
            "probes": [
                round(r, 2) if r is not None else None 
                for r in hop.rtts
            ],
            "rtt_min": round(hop.rtt_min, 2) if hop.rtt_min else None,
            "rtt_avg": round(hop.rtt_avg, 2) if hop.rtt_avg else None,
            "rtt_max": round(hop.rtt_max, 2) if hop.rtt_max else None,
            "ptr": hop.ptr,
            "asn": hop.asn,
            "org": hop.org,
            "geo": self._serialize_geo(hop.geo) if hop.geo else None,
            "ip_type": hop.ip_type,
            "tags": hop.tags
        }
    
    def _serialize_geo(self, geo) -> dict:
        """Serialize geo info"""
        return {
            "country": geo.country,
            "country_code": geo.country_code,
            "city": geo.city,
            "lat": geo.lat,
            "lon": geo.lon
        }
    
    def _write_file(self, data: dict, path: Path):
        """Write JSON to file"""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)


def export_json(result: TraceResult, diagnosis: Diagnosis,
                output_path: Optional[Path] = None) -> dict:
    """Convenience function for JSON export"""
    exporter = JsonExporter()
    return exporter.export(result, diagnosis, output_path)
