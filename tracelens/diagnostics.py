"""
Diagnostic analysis for traceroute results
"""

from dataclasses import dataclass, field
from typing import Optional
from .models import EnrichedHop, Diagnosis


# Configurable thresholds
LATENCY_JUMP_THRESHOLD = 80  # ms
INTERNATIONAL_EGRESS_THRESHOLD = 120  # ms
HIGH_JITTER_THRESHOLD = 100  # ms
SPIKE_MULTIPLIER = 2.0
SPIKE_ABSOLUTE_THRESHOLD = 300  # ms


class Diagnostics:
    """
    Analyze trace results and generate diagnostic tags.
    
    Detects:
    - ICMP filtering (middle timeout with later response)
    - Latency jumps (significant RTT increase)
    - International egress (large latency jump suggesting undersea cable)
    - High jitter (RTT variance within hop)
    - Spikes (single probe with extreme RTT)
    """
    
    def __init__(
        self,
        latency_jump_threshold: float = LATENCY_JUMP_THRESHOLD,
        egress_threshold: float = INTERNATIONAL_EGRESS_THRESHOLD,
        jitter_threshold: float = HIGH_JITTER_THRESHOLD,
        spike_multiplier: float = SPIKE_MULTIPLIER,
        spike_absolute: float = SPIKE_ABSOLUTE_THRESHOLD
    ):
        self.latency_jump_threshold = latency_jump_threshold
        self.egress_threshold = egress_threshold
        self.jitter_threshold = jitter_threshold
        self.spike_multiplier = spike_multiplier
        self.spike_absolute = spike_absolute
    
    def analyze(self, hops: list[EnrichedHop]) -> Diagnosis:
        """
        Analyze hops and return diagnosis.
        
        Args:
            hops: List of enriched hops
            
        Returns:
            Diagnosis with summary information
        """
        diagnosis = Diagnosis()
        
        if not hops:
            return diagnosis
        
        # Check reachability
        last_hop = hops[-1]
        diagnosis.reachable = last_hop.reached_target
        diagnosis.total_hops = len(hops)
        
        if last_hop.rtt_avg:
            diagnosis.avg_rtt = last_hop.rtt_avg
        
        # Detect ICMP filtering
        self._detect_filtering(hops, diagnosis)
        
        # Detect latency jumps
        self._detect_latency_jumps(hops, diagnosis)
        
        # Generate summary issues
        self._generate_issues(diagnosis)
        
        return diagnosis
    
    def add_tags(self, hops: list[EnrichedHop]) -> list[EnrichedHop]:
        """
        Add diagnostic tags to hops.
        
        Args:
            hops: List of enriched hops (modified in place)
            
        Returns:
            Same list with tags added
        """
        # First pass: detect ICMP filtering
        self._tag_filtering(hops)
        
        # Second pass: detect latency issues
        self._tag_latency(hops)
        
        # Third pass: detect jitter and spikes
        self._tag_jitter(hops)
        
        # Mark destination
        if hops and hops[-1].reached_target:
            if 'destination' not in hops[-1].tags:
                hops[-1].tags.append('destination')
        
        return hops
    
    def _tag_filtering(self, hops: list[EnrichedHop]):
        """Tag ICMP filtered hops"""
        # Find last responding hop
        last_response_idx = -1
        for i, hop in enumerate(hops):
            if hop.ip is not None:
                last_response_idx = i
        
        # Tag timeout hops before last response as filtered
        for i, hop in enumerate(hops):
            all_timeout = all(r is None for r in hop.rtts) if hop.rtts else True
            
            if all_timeout and hop.ip is None:
                if i < last_response_idx:
                    # Timeout followed by response = filtered
                    if 'icmp_filtered' not in hop.tags:
                        hop.tags.append('icmp_filtered')
                elif i == len(hops) - 1 and not hop.reached_target:
                    # Last hop timeout = unreachable
                    if 'unreachable' not in hop.tags:
                        hop.tags.append('unreachable')
    
    def _tag_latency(self, hops: list[EnrichedHop]):
        """Tag latency jumps and egress points"""
        prev_rtt: Optional[float] = None
        
        for i, hop in enumerate(hops):
            curr_rtt = hop.rtt_avg
            
            if curr_rtt is not None and prev_rtt is not None:
                delta = curr_rtt - prev_rtt
                
                if delta >= self.egress_threshold:
                    # Large jump - likely international
                    if 'latency_jump' not in hop.tags:
                        hop.tags.append('latency_jump')
                    if 'international_egress' not in hop.tags:
                        hop.tags.append('international_egress')
                        
                elif delta >= self.latency_jump_threshold:
                    # Moderate jump
                    if 'latency_jump' not in hop.tags:
                        hop.tags.append('latency_jump')
            
            if curr_rtt is not None:
                prev_rtt = curr_rtt
    
    def _tag_jitter(self, hops: list[EnrichedHop]):
        """Tag high jitter and spikes"""
        for hop in hops:
            valid_rtts = [r for r in hop.rtts if r is not None]
            
            if len(valid_rtts) < 2:
                continue
            
            rtt_min = min(valid_rtts)
            rtt_max = max(valid_rtts)
            rtt_avg = sum(valid_rtts) / len(valid_rtts)
            
            # High jitter
            if rtt_max - rtt_min > self.jitter_threshold:
                if 'high_jitter' not in hop.tags:
                    hop.tags.append('high_jitter')
            
            # Spike detection
            for rtt in valid_rtts:
                if rtt > rtt_avg * self.spike_multiplier and rtt > self.spike_absolute:
                    if 'spike' not in hop.tags:
                        hop.tags.append('spike')
                    break
    
    def _detect_filtering(self, hops: list[EnrichedHop], diagnosis: Diagnosis):
        """Detect filtered hops for diagnosis"""
        last_response_idx = -1
        for i, hop in enumerate(hops):
            if hop.ip is not None:
                last_response_idx = i
        
        for i, hop in enumerate(hops):
            all_timeout = all(r is None for r in hop.rtts) if hop.rtts else True
            if all_timeout and hop.ip is None and i < last_response_idx:
                diagnosis.filtered_hops.append(hop.hop)
    
    def _detect_latency_jumps(self, hops: list[EnrichedHop], diagnosis: Diagnosis):
        """Detect latency jumps for diagnosis"""
        prev_rtt: Optional[float] = None
        
        for hop in hops:
            curr_rtt = hop.rtt_avg
            
            if curr_rtt is not None and prev_rtt is not None:
                delta = curr_rtt - prev_rtt
                
                if delta >= self.latency_jump_threshold:
                    diagnosis.latency_jumps.append((hop.hop, round(delta, 1)))
                    
                    if delta >= self.egress_threshold and diagnosis.egress_hop is None:
                        diagnosis.egress_hop = hop.hop
            
            if curr_rtt is not None:
                prev_rtt = curr_rtt
    
    def _generate_issues(self, diagnosis: Diagnosis):
        """Generate human-readable issue list"""
        if not diagnosis.reachable:
            diagnosis.issues.append("Target unreachable")
        
        if diagnosis.filtered_hops:
            hops_str = ', '.join(str(h) for h in diagnosis.filtered_hops[:5])
            if len(diagnosis.filtered_hops) > 5:
                hops_str += f" (+{len(diagnosis.filtered_hops) - 5} more)"
            diagnosis.issues.append(f"ICMP filtering detected at hop(s): {hops_str}")
        
        for hop, delta in diagnosis.latency_jumps:
            if delta >= self.egress_threshold:
                diagnosis.issues.append(
                    f"Latency jump +{delta}ms at hop {hop} (likely international transit)"
                )
            else:
                diagnosis.issues.append(f"Latency jump +{delta}ms at hop {hop}")
