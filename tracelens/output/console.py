"""
Rich console output for TraceLens - with real-time per-hop printing
"""

from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich import box

from ..models import EnrichedHop, TraceResult, Diagnosis, HopResult
from ..enrichment.geo_lookup import get_flag


# Tag styling
TAG_STYLES = {
    'private': ('🏠', 'dim'),
    'cgnat': ('🔒', 'yellow'),
    'loopback': ('🔄', 'dim'),
    'linklocal': ('🔗', 'dim'),
    'icmp_filtered': ('⚠️', 'yellow'),
    'unreachable': ('❌', 'red'),
    'latency_jump': ('🚀', 'cyan'),
    'international_egress': ('🌏', 'magenta'),
    'high_jitter': ('📈', 'yellow'),
    'spike': ('⚡', 'yellow'),
    'destination': ('✅', 'green'),
}


class ConsoleOutput:
    """
    Rich console output for traceroute results.
    
    Features:
    - Real-time per-hop output
    - Color-coded tags
    - Diagnostic summary panel
    """
    
    def __init__(self):
        self.console = Console()
        self._header_printed = False
        self._table_header_printed = False
    
    def print_header(self, target: str, resolved_ip: str, protocol: str,
                     max_hops: int, probes: int, port: Optional[int] = None):
        """Print trace header"""
        protocol_info = protocol.upper()
        if protocol in ('tcp', 'udp') and port:
            protocol_info += f":{port}"
        
        content = Text()
        content.append("🔍 TraceLens", style="bold cyan")
        content.append(" v1.0.0\n", style="dim")
        content.append("Target: ", style="dim")
        content.append(target, style="bold")
        if target != resolved_ip:
            content.append(f" ({resolved_ip})", style="dim")
        content.append("\n")
        content.append(f"Protocol: {protocol_info}", style="dim")
        content.append(f"  |  Probes: {probes} × {max_hops} hops", style="dim")
        
        panel = Panel(content, border_style="cyan", padding=(0, 1))
        self.console.print(panel)
        self.console.print()
        self._header_printed = True
    
    def print_table_header(self):
        """Print the table header row"""
        if self._table_header_printed:
            return
        
        # Column order: # | RTT | IP | Status | ASN | Location | Organization
        header = Text()
        header.append(f"{'#':>3}  ", style="bold magenta")
        header.append(f"{'RTT (ms)':^16}  ", style="bold magenta")
        header.append(f"{'IP':<16}  ", style="bold magenta")
        header.append(f"{'Status':<6}  ", style="bold magenta")
        header.append(f"{'ASN':<8}  ", style="bold magenta")
        header.append(f"{'Location':<14}  ", style="bold magenta")
        header.append(f"{'Organization':<30}", style="bold magenta")
        
        self.console.print("─" * 115)
        self.console.print(header)
        self.console.print("─" * 115)
        self._table_header_printed = True
    
    def print_hop_realtime(self, hop: 'EnrichedHop'):
        """Print a single hop result in real-time"""
        self.print_table_header()
        
        # Format fields
        rtt_str = self._format_rtt(hop.rtts)
        geo_str = self._format_geo(hop.geo)
        tags_str = self._format_tags(hop.tags)
        org_str = self._format_org(hop.org)
        
        # Build line: # | RTT | IP | Status | ASN | Location | Organization
        line = Text()
        line.append(f"{hop.hop:>3}  ", style="dim")
        line.append(f"{rtt_str:^16}  ")
        line.append(f"{(hop.ip or '-'):<16}  ")
        line.append(f"{tags_str:<6}  ")
        line.append(f"{(hop.asn or '-'):<8}  ")
        line.append(f"{geo_str:<14}  ")
        line.append(f"{org_str:<30}")
        
        self.console.print(line)
    
    def print_hop_basic(self, hop: HopResult):
        """Print a basic hop result (before enrichment) in real-time"""
        self.print_table_header()
        
        rtt_str = self._format_rtt(hop.rtts)
        
        # Determine basic tag
        from ..enrichment import IPClassifier
        tag = ""
        if hop.ip:
            ip_tag = IPClassifier.get_tag(hop.ip)
            if ip_tag:
                icon, _ = TAG_STYLES.get(ip_tag, ('', 'dim'))
                tag = icon
        
        if hop.all_timeout:
            tag = "⏳"
        
        # Build line: # | RTT | IP | Status | ASN | Location | Organization
        line = Text()
        line.append(f"{hop.hop:>3}  ", style="dim")
        line.append(f"{rtt_str:^16}  ")
        line.append(f"{(hop.ip or '*'):<16}  ", style="yellow" if hop.all_timeout else "")
        line.append(f"{tag:<6}  ")
        line.append(f"{'-':<8}  ", style="dim")
        line.append(f"{'-':<14}  ", style="dim")
        line.append(f"{'(enriching...)':<30}", style="dim italic")
        
        self.console.print(line)
    
    def print_separator(self):
        """Print table separator"""
        self.console.print("─" * 115)
    
    def create_progress(self, max_hops: int) -> tuple[Progress, int]:
        """Create progress bar for tracing"""
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]Tracing route..."),
            BarColumn(complete_style="cyan", finished_style="green"),
            TaskProgressColumn(),
            TextColumn("[dim]{task.fields[status]}"),
            console=self.console
        )
        task_id = progress.add_task("trace", total=max_hops, status="")
        return progress, task_id
    
    def print_results(self, hops: list[EnrichedHop], target: str):
        """Print results table (for non-realtime mode)"""
        table = Table(
            show_header=True,
            header_style="bold magenta",
            box=box.ROUNDED,
            border_style="dim",
            padding=(0, 1)
        )
        
        # Columns: # | RTT | IP | Status | ASN | Location | Organization
        table.add_column("#", style="dim", width=3, justify="right")
        table.add_column("RTT (min/avg/max)", width=16, justify="center")
        table.add_column("IP", width=16)
        table.add_column("Status", width=8)
        table.add_column("ASN", width=8)
        table.add_column("Location", width=14)
        table.add_column("Organization", width=30, overflow="ellipsis")
        
        for hop in hops:
            table.add_row(
                str(hop.hop),
                self._format_rtt(hop.rtts),
                hop.ip or "-",
                self._format_tags(hop.tags),
                hop.asn or "-",
                self._format_geo(hop.geo),
                self._format_org(hop.org)
            )
        
        # Panel header
        header = Text()
        header.append("📍 Route to ", style="dim")
        header.append(target, style="bold")
        
        panel = Panel(table, title=header, border_style="blue", padding=(0, 0))
        self.console.print(panel)
    
    def print_diagnosis(self, diagnosis: Diagnosis):
        """Print diagnostic summary panel"""
        content = Text()
        
        # Reachability
        if diagnosis.reachable:
            content.append("✅ ", style="green")
            content.append("Target Reachable: ", style="bold")
            content.append(f"{diagnosis.total_hops} hops", style="dim")
            if diagnosis.avg_rtt:
                content.append(f", {diagnosis.avg_rtt:.0f}ms avg", style="dim")
        else:
            content.append("❌ ", style="red")
            content.append("Target Unreachable", style="bold red")
        
        # Filtered hops
        if diagnosis.filtered_hops:
            content.append("\n")
            content.append("⚠️ ", style="yellow")
            content.append("ICMP Filtering: ", style="bold")
            hops_str = ", ".join(str(h) for h in diagnosis.filtered_hops[:5])
            if len(diagnosis.filtered_hops) > 5:
                hops_str += f" (+{len(diagnosis.filtered_hops) - 5})"
            content.append(f"hops {hops_str}", style="dim")
        
        # Latency jumps
        for hop, delta in diagnosis.latency_jumps:
            content.append("\n")
            if delta >= 120:
                content.append("🌏 ", style="magenta")
                content.append(f"Egress: ", style="bold")
                content.append(f"+{delta:.0f}ms at hop {hop} ", style="dim")
                content.append("(international transit)", style="dim italic")
            else:
                content.append("🚀 ", style="cyan")
                content.append(f"Latency Jump: ", style="bold")
                content.append(f"+{delta:.0f}ms at hop {hop}", style="dim")
        
        panel = Panel(
            content,
            title=Text("📊 Summary", style="bold"),
            border_style="green" if diagnosis.reachable else "red",
            padding=(0, 1)
        )
        self.console.print()
        self.console.print(panel)
    
    def print_error(self, message: str):
        """Print error message"""
        self.console.print(f"[bold red]Error:[/] {message}")
    
    def print_warning(self, message: str):
        """Print warning message"""
        self.console.print(f"[yellow]Warning:[/] {message}")
    
    def _format_rtt(self, rtts: list[Optional[float]]) -> str:
        """Format RTT values"""
        valid = [r for r in rtts if r is not None]
        
        if not valid:
            return "* / * / *"
        
        if len(valid) == len(rtts):
            # All probes succeeded
            rtt_min = min(valid)
            rtt_avg = sum(valid) / len(valid)
            rtt_max = max(valid)
            return f"{rtt_min:.0f} / {rtt_avg:.0f} / {rtt_max:.0f}"
        else:
            # Some timeouts - show individual results
            parts = []
            for r in rtts:
                parts.append(f"{r:.0f}" if r is not None else "*")
            return " / ".join(parts)
    
    def _format_org(self, org: Optional[str]) -> str:
        """Format organization name - extract key part, no truncation"""
        if not org:
            return "-"
        
        org = org.strip()
        
        # Remove common country suffixes
        for suffix in [', CN', ', US', ', JP', ', HK', ', SG', ', DE', ', GB', ', NL', ', TW', ', KR']:
            if org.endswith(suffix):
                org = org[:-len(suffix)]
        
        # If org contains comma, take first meaningful part
        if ',' in org:
            parts = org.split(',')
            # Take first part, but if it's just an AS name, take more
            org = parts[0].strip()
        
        # No truncation - show full org name
        return org
    
    def _format_geo(self, geo) -> str:
        """Format geo info with flag"""
        if not geo:
            return "-"
        
        parts = []
        
        if geo.country_code:
            flag = get_flag(geo.country_code)
            parts.append(flag)
        
        if geo.city:
            city = geo.city[:12] if len(geo.city) > 12 else geo.city
            parts.append(city)
        elif geo.country:
            country = geo.country[:12] if len(geo.country) > 12 else geo.country
            parts.append(country)
        elif geo.country_code:
            parts.append(geo.country_code)
        
        return " ".join(parts) if parts else "-"
    
    def _format_tags(self, tags: list[str]) -> str:
        """Format tags with icons and colors"""
        if not tags:
            return ""
        
        parts = []
        for tag in tags[:2]:  # Max 2 tags
            icon, style = TAG_STYLES.get(tag, ('•', 'dim'))
            parts.append(f"{icon}")
        
        return " ".join(parts)
    
    def _truncate(self, text: str, max_len: int) -> str:
        """Truncate text with ellipsis"""
        if not text:
            return "-"
        if len(text) <= max_len:
            return text
        return text[:max_len - 1] + "…"
