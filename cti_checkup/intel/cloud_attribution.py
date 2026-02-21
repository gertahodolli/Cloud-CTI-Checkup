"""Cloud attribution from ipinfo enrichment data (config-driven)."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from cti_checkup.core.config_utils import get_bool, get_int, get_list_int, get_list_str


_ASN_RE = re.compile(r"\bAS(\d+)\b", re.IGNORECASE)


def _parse_int(value: Any) -> Optional[int]:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        v = value.strip()
        if v.isdigit() or (v.startswith("-") and v[1:].isdigit()):
            return int(v)
    return None


def _extract_asn(ipinfo: Dict[str, Any]) -> Optional[int]:
    if not isinstance(ipinfo, dict):
        return None
    asn = ipinfo.get("asn")
    if isinstance(asn, dict):
        for key in ("asn", "id", "number"):
            if key in asn:
                parsed = _parse_int(asn.get(key))
                if parsed is not None:
                    return parsed
        if "asn" in asn and isinstance(asn.get("asn"), str):
            match = _ASN_RE.search(asn.get("asn", ""))
            if match:
                return _parse_int(match.group(1))
    if isinstance(asn, str):
        match = _ASN_RE.search(asn)
        if match:
            return _parse_int(match.group(1))
        return _parse_int(asn)
    org = ipinfo.get("org")
    if isinstance(org, str):
        match = _ASN_RE.search(org)
        if match:
            return _parse_int(match.group(1))
    return None


def _extract_org(ipinfo: Dict[str, Any]) -> Optional[str]:
    if not isinstance(ipinfo, dict):
        return None
    org = ipinfo.get("org")
    if isinstance(org, str) and org.strip():
        return org.strip()
    return None


def _extract_hostnames(ipinfo: Dict[str, Any]) -> List[str]:
    if not isinstance(ipinfo, dict):
        return []
    hostnames: List[str] = []
    raw = ipinfo.get("hostname")
    if isinstance(raw, str) and raw.strip():
        hostnames.append(raw.strip())
    elif isinstance(raw, list):
        for h in raw:
            if isinstance(h, str) and h.strip():
                hostnames.append(h.strip())
    raw = ipinfo.get("hostnames")
    if isinstance(raw, list):
        for h in raw:
            if isinstance(h, str) and h.strip():
                hostnames.append(h.strip())
    return hostnames


def _extract_privacy(ipinfo: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(ipinfo, dict):
        return {}
    privacy = ipinfo.get("privacy")
    if isinstance(privacy, dict):
        return privacy
    return {}


def _normalize_list(values: Optional[List[str]]) -> List[str]:
    if not values:
        return []
    out = []
    for v in values:
        if isinstance(v, str) and v.strip():
            out.append(v.strip())
    return out


def load_cloud_attribution_config(cfg: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    intel_cfg = cfg.get("intel") or {}
    cloud_cfg = intel_cfg.get("cloud_attribution")
    if cloud_cfg is None:
        return False, None, None
    if not isinstance(cloud_cfg, dict):
        return True, None, "intel.cloud_attribution must be a mapping."

    enabled = get_bool(cloud_cfg, ["enabled"])
    if enabled is None:
        return True, None, "Missing intel.cloud_attribution.enabled."
    if not enabled:
        return False, None, None

    providers_cfg = cloud_cfg.get("providers")
    if not isinstance(providers_cfg, dict) or not providers_cfg:
        return True, None, "Missing intel.cloud_attribution.providers (required when enabled)."

    weights_cfg = cloud_cfg.get("confidence_weights")
    if not isinstance(weights_cfg, dict):
        return True, None, "Missing intel.cloud_attribution.confidence_weights (required when enabled)."

    weights: Dict[str, int] = {}
    for key in ("asn_match", "org_match", "hostname_match", "privacy_hosting"):
        w = get_int(weights_cfg, [key])
        if w is None or w < 0:
            return True, None, f"Invalid intel.cloud_attribution.confidence_weights.{key} (required)."
        weights[key] = w

    providers: Dict[str, Dict[str, Any]] = {}
    for name, raw in providers_cfg.items():
        if not isinstance(name, str) or not name.strip():
            return True, None, "Invalid provider name in intel.cloud_attribution.providers."
        provider_name = name.strip()
        if provider_name not in ("aws", "azure", "gcp"):
            return True, None, f"Unsupported provider '{provider_name}' in intel.cloud_attribution.providers."
        if not isinstance(raw, dict):
            return True, None, f"Provider '{provider_name}' config must be a mapping."

        asn_present = "asn_numbers" in raw
        org_present = "org_contains" in raw
        host_present = "hostname_contains" in raw

        asn_numbers = get_list_int(raw, ["asn_numbers"])
        org_contains = get_list_str(raw, ["org_contains"])
        hostname_contains = get_list_str(raw, ["hostname_contains"])

        if asn_present and not asn_numbers:
            return True, None, f"Provider '{provider_name}' has invalid asn_numbers."
        if org_present and not org_contains:
            return True, None, f"Provider '{provider_name}' has invalid org_contains."
        if host_present and not hostname_contains:
            return True, None, f"Provider '{provider_name}' has invalid hostname_contains."

        if not asn_numbers and not org_contains and not hostname_contains:
            return True, None, f"Provider '{provider_name}' has no match criteria."

        providers[provider_name] = {
            "asn_numbers": asn_numbers or [],
            "org_contains": _normalize_list(org_contains),
            "hostname_contains": _normalize_list(hostname_contains),
        }

    return True, {"providers": providers, "weights": weights}, None


def build_cloud_attribution(
    ipinfo: Optional[Dict[str, Any]], cfg: Dict[str, Any]
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    enabled, config, error = load_cloud_attribution_config(cfg)
    if not enabled:
        return None, None
    if error:
        return None, error
    return compute_cloud_attribution(ipinfo or {}, config or {}), None


def compute_cloud_attribution(ipinfo: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    providers = config.get("providers") or {}
    weights = config.get("weights") or {}

    asn = _extract_asn(ipinfo)
    org = _extract_org(ipinfo)
    hostnames = _extract_hostnames(ipinfo)
    privacy = _extract_privacy(ipinfo)

    org_lower = org.lower() if org else ""
    hostname_lower = [h.lower() for h in hostnames]

    best_provider = "unknown"
    best_score = 0
    best_hints: List[str] = []

    for provider_name, p_cfg in providers.items():
        score = 0
        hints: List[str] = []

        asn_numbers = p_cfg.get("asn_numbers") or []
        if asn is not None and asn_numbers and asn in asn_numbers:
            score += weights.get("asn_match", 0)

        org_contains = p_cfg.get("org_contains") or []
        if org_lower and org_contains:
            for needle in org_contains:
                if needle.lower() in org_lower:
                    score += weights.get("org_match", 0)
                    break

        hostname_contains = p_cfg.get("hostname_contains") or []
        if hostname_lower and hostname_contains:
            for needle in hostname_contains:
                n = needle.lower()
                if any(n in h for h in hostname_lower):
                    score += weights.get("hostname_match", 0)
                    hints.append(needle)
                    break

        if score > best_score:
            best_score = score
            best_provider = provider_name
            best_hints = hints

    hosting_val: Any = "unknown"
    privacy_hosting = privacy.get("hosting") if isinstance(privacy, dict) else None
    if isinstance(privacy_hosting, bool):
        hosting_val = privacy_hosting
    elif best_provider != "unknown":
        hosting_val = True

    confidence = best_score
    if isinstance(privacy_hosting, bool) and privacy_hosting:
        confidence += weights.get("privacy_hosting", 0)
    if confidence > 100:
        confidence = 100
    if confidence < 0:
        confidence = 0

    service_hints: List[str] = []
    service = privacy.get("service") if isinstance(privacy, dict) else None
    if isinstance(service, str) and service.strip():
        service_hints.append(service.strip())
    for hint in best_hints:
        if hint not in service_hints:
            service_hints.append(hint)

    return {
        "provider": best_provider,
        "asn": asn,
        "org": org,
        "hosting": hosting_val,
        "service_hints": service_hints,
        "confidence": int(confidence),
    }
