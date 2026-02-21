"""Deterministic IOC extraction from CloudTrail events using regex + field extraction.

This module provides reliable, auditable IOC extraction that doesn't depend on AI.
It extracts IPs, access key IDs, identities (ARNs, principal IDs, usernames), and
optionally domains from raw CloudTrail events.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

# =============================================================================
# Regex patterns
# =============================================================================

# IPv4 pattern (standard dotted decimal)
_IPV4_PATTERN = re.compile(
    r"\b((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\b"
)

# IPv6 pattern (simplified - catches most common formats)
_IPV6_PATTERN = re.compile(
    r"\b((?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,7}:|"
    r"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
    r"::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}|"
    r"[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4})\b"
)

# AWS Access Key ID pattern (AKIA for long-term, ASIA for temporary)
_ACCESS_KEY_PATTERN = re.compile(r"\b(A[KS]IA[A-Z0-9]{16,20})\b")

# AWS ARN pattern
_ARN_PATTERN = re.compile(
    r"\b(arn:aws(?:-[a-z]+)?:[a-z0-9-]+:[a-z0-9-]*:[0-9]*:[a-zA-Z0-9/_-]+)\b"
)

# Domain/hostname pattern (basic)
_DOMAIN_PATTERN = re.compile(
    r"\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*"
    r"\.[a-zA-Z]{2,})\b"
)

# =============================================================================
# Default configuration values
# =============================================================================

# Default IPs to skip (placeholders, localhost, etc.)
DEFAULT_SKIP_IPS: FrozenSet[str] = frozenset([
    "unknown",
    "-",
    "0.0.0.0",
    "127.0.0.1",
    "::1",
    "localhost",
])

# Default domains to skip (AWS internal, common CDNs, etc.)
DEFAULT_SKIP_DOMAIN_SUFFIXES: Tuple[str, ...] = (
    ".amazonaws.com",
    ".aws.amazon.com",
    ".cloudfront.net",
    ".googleapis.com",
    ".google.com",
    ".microsoft.com",
    ".azure.com",
    ".windows.net",
)

# Default display limits for human-readable output
DEFAULT_DISPLAY_LIMITS = {
    "ips": 100,
    "identities": 50,
    "domains": 30,
    "user_agents": 50,
    "copy_ips": 100,
}


@dataclass
class IndicatorConfig:
    """Configuration for IOC extraction and display.
    
    All fields have sensible defaults. Override as needed.
    """
    # Skip lists
    skip_ips: FrozenSet[str] = field(default_factory=lambda: DEFAULT_SKIP_IPS)
    skip_domain_suffixes: Tuple[str, ...] = DEFAULT_SKIP_DOMAIN_SUFFIXES
    
    # Display limits for human output
    max_ips_display: int = DEFAULT_DISPLAY_LIMITS["ips"]
    max_identities_display: int = DEFAULT_DISPLAY_LIMITS["identities"]
    max_domains_display: int = DEFAULT_DISPLAY_LIMITS["domains"]
    max_user_agents: int = DEFAULT_DISPLAY_LIMITS["user_agents"]
    max_copy_ips: int = DEFAULT_DISPLAY_LIMITS["copy_ips"]
    
    @classmethod
    def from_dict(cls, cfg: Dict[str, Any]) -> "IndicatorConfig":
        """Create config from a dictionary (e.g., from YAML config).
        
        Expected structure under ai.indicators:
            skip_ips: ["127.0.0.1", "0.0.0.0", ...]
            skip_domain_suffixes: [".amazonaws.com", ...]
            display_limits:
                ips: 100
                identities: 50
                domains: 30
                user_agents: 50
                copy_ips: 100
        """
        indicators_cfg = cfg.get("ai", {}).get("indicators", {})
        
        # Skip lists
        skip_ips = indicators_cfg.get("skip_ips")
        if skip_ips and isinstance(skip_ips, list):
            skip_ips = frozenset(skip_ips)
        else:
            skip_ips = DEFAULT_SKIP_IPS
        
        skip_domains = indicators_cfg.get("skip_domain_suffixes")
        if skip_domains and isinstance(skip_domains, list):
            skip_domains = tuple(skip_domains)
        else:
            skip_domains = DEFAULT_SKIP_DOMAIN_SUFFIXES
        
        # Display limits
        limits = indicators_cfg.get("display_limits", {})
        
        return cls(
            skip_ips=skip_ips,
            skip_domain_suffixes=skip_domains,
            max_ips_display=limits.get("ips", DEFAULT_DISPLAY_LIMITS["ips"]),
            max_identities_display=limits.get("identities", DEFAULT_DISPLAY_LIMITS["identities"]),
            max_domains_display=limits.get("domains", DEFAULT_DISPLAY_LIMITS["domains"]),
            max_user_agents=limits.get("user_agents", DEFAULT_DISPLAY_LIMITS["user_agents"]),
            max_copy_ips=limits.get("copy_ips", DEFAULT_DISPLAY_LIMITS["copy_ips"]),
        )


# Global default config instance
_default_config = IndicatorConfig()

# =============================================================================
# Helper functions
# =============================================================================


def _is_private_ip(ip: str) -> bool:
    """Check if an IP is in a private range."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def _mask_access_key(key_id: str) -> str:
    """Mask access key ID, showing only last 4 characters."""
    if not key_id or len(key_id) < 4:
        return "****"
    return "****" + key_id[-4:]


def _get_nested(data: Dict[str, Any], *keys: str) -> Any:
    """Safely get nested dictionary value."""
    current = data
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key)
        else:
            return None
    return current


def _extract_ips_from_string(
    text: str, 
    ips: Set[str], 
    skip_ips: FrozenSet[str] = DEFAULT_SKIP_IPS
) -> None:
    """Extract IPs from a string using regex."""
    if not text or not isinstance(text, str):
        return
    
    for match in _IPV4_PATTERN.findall(text):
        if match and match.lower() not in skip_ips:
            ips.add(match)
    
    for match in _IPV6_PATTERN.findall(text):
        if match and match.lower() not in skip_ips:
            ips.add(match)


def _extract_domains_from_string(
    text: str, 
    domains: Set[str],
    skip_suffixes: Tuple[str, ...] = DEFAULT_SKIP_DOMAIN_SUFFIXES
) -> None:
    """Extract domains from a string using regex."""
    if not text or not isinstance(text, str):
        return
    
    for match in _DOMAIN_PATTERN.findall(text):
        if match:
            lower = match.lower()
            # Skip if it's an IP-like string or in skip list
            if _IPV4_PATTERN.match(lower):
                continue
            if any(lower.endswith(suffix) for suffix in skip_suffixes):
                continue
            domains.add(lower)


# =============================================================================
# Main extraction functions
# =============================================================================


class ExtractedIndicators:
    """Container for extracted IOCs from CloudTrail events."""

    def __init__(self, config: Optional[IndicatorConfig] = None) -> None:
        self.ips: Set[str] = set()
        self.ips_private: Set[str] = set()  # Private IPs (separate for filtering)
        self.access_key_ids: Set[str] = set()
        self.identities: Set[str] = set()  # ARNs, usernames, principal IDs
        self.user_agents: Set[str] = set()
        self.domains: Set[str] = set()
        self.event_sources: Set[str] = set()
        self.regions: Set[str] = set()
        self.config = config or _default_config

    def to_dict(self, include_private_ips: bool = False, mask_keys: bool = True) -> Dict[str, List[str]]:
        """Convert to dictionary for JSON serialization."""
        ips = sorted(self.ips)
        if include_private_ips:
            ips = sorted(self.ips | self.ips_private)
        
        key_ids = sorted(self.access_key_ids)
        if mask_keys:
            key_ids = [_mask_access_key(k) for k in key_ids]
        
        # Cap user agents based on config
        max_ua = self.config.max_user_agents
        
        return {
            "ips": ips,
            "ips_count": len(ips),
            "access_key_ids": key_ids,
            "access_key_ids_count": len(self.access_key_ids),
            "identities": sorted(self.identities),
            "identities_count": len(self.identities),
            "user_agents": sorted(self.user_agents)[:max_ua],
            "user_agents_count": len(self.user_agents),
            "domains": sorted(self.domains),
            "domains_count": len(self.domains),
            "event_sources": sorted(self.event_sources),
            "regions": sorted(self.regions),
        }


def extract_indicators_from_event(
    event: Dict[str, Any], 
    indicators: ExtractedIndicators,
    config: Optional[IndicatorConfig] = None
) -> None:
    """Extract IOCs from a single CloudTrail event."""
    cfg = config or indicators.config
    skip_ips = cfg.skip_ips
    skip_domains = cfg.skip_domain_suffixes
    
    # --- IPs ---
    source_ip = event.get("sourceIPAddress")
    if source_ip and isinstance(source_ip, str):
        ip = source_ip.strip()
        if ip and ip.lower() not in skip_ips:
            if _is_private_ip(ip):
                indicators.ips_private.add(ip)
            else:
                indicators.ips.add(ip)
    
    # Also scan error messages and user agent for IPs (rare but possible)
    _extract_ips_from_string(event.get("errorMessage"), indicators.ips, skip_ips)
    
    # --- Access Key IDs ---
    user_identity = event.get("userIdentity") or {}
    
    access_key_id = user_identity.get("accessKeyId")
    if access_key_id and isinstance(access_key_id, str) and _ACCESS_KEY_PATTERN.match(access_key_id):
        indicators.access_key_ids.add(access_key_id.strip())
    
    # Also check session context
    session_context = user_identity.get("sessionContext") or {}
    session_issuer = session_context.get("sessionIssuer") or {}
    
    # --- Identities (ARNs, usernames, principal IDs) ---
    # ARN
    arn = user_identity.get("arn")
    if arn and isinstance(arn, str):
        indicators.identities.add(arn.strip())
    
    # Principal ID
    principal_id = user_identity.get("principalId")
    if principal_id and isinstance(principal_id, str):
        indicators.identities.add(principal_id.strip())
    
    # Username
    user_name = user_identity.get("userName")
    if user_name and isinstance(user_name, str):
        indicators.identities.add(f"user:{user_name.strip()}")
    
    # Session issuer ARN (for assumed roles)
    issuer_arn = session_issuer.get("arn")
    if issuer_arn and isinstance(issuer_arn, str):
        indicators.identities.add(issuer_arn.strip())
    
    # Session issuer username
    issuer_name = session_issuer.get("userName")
    if issuer_name and isinstance(issuer_name, str):
        indicators.identities.add(f"role:{issuer_name.strip()}")
    
    # --- User Agent ---
    user_agent = event.get("userAgent")
    if user_agent and isinstance(user_agent, str):
        ua = user_agent.strip()
        if ua and ua.lower() not in ("unknown", "-"):
            indicators.user_agents.add(ua)
        # Extract domains from user agent
        _extract_domains_from_string(ua, indicators.domains, skip_domains)
    
    # --- Event source and region ---
    event_source = event.get("eventSource")
    if event_source and isinstance(event_source, str):
        indicators.event_sources.add(event_source.strip())
    
    region = event.get("awsRegion")
    if region and isinstance(region, str):
        indicators.regions.add(region.strip())
    
    # --- Domains from error messages ---
    _extract_domains_from_string(event.get("errorMessage"), indicators.domains, skip_domains)


def extract_indicators_from_events(
    events: List[Dict[str, Any]],
    config: Optional[IndicatorConfig] = None
) -> ExtractedIndicators:
    """Extract IOCs from a list of CloudTrail events.
    
    Args:
        events: List of CloudTrail event dictionaries.
        config: Optional configuration for extraction. Uses defaults if not provided.
    
    Returns:
        ExtractedIndicators object with all found IOCs.
    """
    cfg = config or _default_config
    indicators = ExtractedIndicators(config=cfg)
    
    for event in events:
        if isinstance(event, dict):
            extract_indicators_from_event(event, indicators, cfg)
    
    return indicators


def render_indicators_human(
    indicators: ExtractedIndicators, 
    include_private_ips: bool = False,
    config: Optional[IndicatorConfig] = None
) -> str:
    """Render extracted indicators in human-readable format."""
    cfg = config or indicators.config
    max_ips = cfg.max_ips_display
    max_identities = cfg.max_identities_display
    max_domains = cfg.max_domains_display
    
    lines = []
    lines.append("=" * 60)
    lines.append("Extracted Indicators (IOCs)")
    lines.append("=" * 60)
    lines.append("")
    
    # IPs
    ips = sorted(indicators.ips)
    if include_private_ips:
        ips = sorted(indicators.ips | indicators.ips_private)
    
    lines.append(f"## IPs ({len(ips)} found)")
    if ips:
        for ip in ips[:max_ips]:
            lines.append(f"  {ip}")
        if len(ips) > max_ips:
            lines.append(f"  ... and {len(ips) - max_ips} more")
    else:
        lines.append("  (none)")
    lines.append("")
    
    # Access Key IDs
    lines.append(f"## Access Key IDs ({len(indicators.access_key_ids)} found)")
    if indicators.access_key_ids:
        for key_id in sorted(indicators.access_key_ids):
            lines.append(f"  {_mask_access_key(key_id)}")
    else:
        lines.append("  (none)")
    lines.append("")
    
    # Identities
    lines.append(f"## Identities ({len(indicators.identities)} found)")
    if indicators.identities:
        for identity in sorted(indicators.identities)[:max_identities]:
            lines.append(f"  {identity}")
        if len(indicators.identities) > max_identities:
            lines.append(f"  ... and {len(indicators.identities) - max_identities} more")
    else:
        lines.append("  (none)")
    lines.append("")
    
    # Domains (if any)
    if indicators.domains:
        lines.append(f"## Domains ({len(indicators.domains)} found)")
        for domain in sorted(indicators.domains)[:max_domains]:
            lines.append(f"  {domain}")
        if len(indicators.domains) > max_domains:
            lines.append(f"  ... and {len(indicators.domains) - max_domains} more")
        lines.append("")
    
    # Summary
    lines.append("## Summary")
    lines.append(f"  Regions: {', '.join(sorted(indicators.regions)) or '(none)'}")
    lines.append(f"  Event sources: {len(indicators.event_sources)}")
    lines.append(f"  Unique user agents: {len(indicators.user_agents)}")
    lines.append("")
    
    # Next steps hint
    lines.append("## Next Steps")
    lines.append("  - Copy IPs above to run through Threat Intel (batch lookup)")
    lines.append("  - For long-lived access keys and key age: run AWS scan")
    lines.append("    (cti-checkup cloud aws scan) and check IAM findings")
    lines.append("")
    
    lines.append("=" * 60)
    return "\n".join(lines)


def render_indicators_json(indicators: ExtractedIndicators, include_private_ips: bool = False) -> str:
    """Render extracted indicators as JSON."""
    import json
    return json.dumps(indicators.to_dict(include_private_ips=include_private_ips), indent=2)
