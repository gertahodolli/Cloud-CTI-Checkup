"""Intel configuration: secrets from env, base URLs and timeouts from config."""
from __future__ import annotations

import os
from typing import Any, Dict, Optional, Tuple

from cti_checkup.core.config_utils import get_int


def normalize_ipinfo_response(data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Flatten new IPinfo API (geo, as) shape so existing code works with legacy shape."""
    if not data or not isinstance(data, dict):
        return data or {}
    out = dict(data)
    if "geo" in out and isinstance(out.get("geo"), dict):
        out.setdefault("country", out["geo"].get("country"))
    if "as" in out and isinstance(out.get("as"), dict):
        out.setdefault("org", out["as"].get("name"))
        out.setdefault("asn", out["as"].get("asn"))
    return out


def get_abuseipdb_api_key() -> Optional[str]:
    v = os.environ.get("CTICHECKUP_ABUSEIPDB_API_KEY", "").strip()
    return v or None


def get_ipinfo_token() -> Optional[str]:
    v = os.environ.get("CTICHECKUP_IPINFO_TOKEN", "").strip()
    return v or None


def get_ipinfo_referrer(cfg: Dict[str, Any]) -> Optional[str]:
    """Referrer to send when IPinfo 'Limit Referring Domains' is enabled."""
    v = os.environ.get("CTICHECKUP_IPINFO_REFERRER", "").strip()
    if v:
        return v
    intel_cfg = (cfg.get("intel") or {}).get("ipinfo") or {}
    v = intel_cfg.get("referrer") or intel_cfg.get("referer")
    return (v or "").strip() or None


def get_abuseipdb_base_url(cfg: Dict[str, Any]) -> str:
    intel_cfg = (cfg.get("intel") or {}).get("abuseipdb") or {}
    url = intel_cfg.get("base_url") or intel_cfg.get("base_url_abuseipdb")
    if isinstance(url, str) and url.strip():
        return url.strip().rstrip("/")
    return "https://api.abuseipdb.com/api/v2"


def get_ipinfo_base_url(cfg: Dict[str, Any]) -> str:
    intel_cfg = (cfg.get("intel") or {}).get("ipinfo") or {}
    url = intel_cfg.get("base_url") or intel_cfg.get("base_url_ipinfo")
    if isinstance(url, str) and url.strip():
        return url.strip().rstrip("/")
    # Use new API (api.ipinfo.io); legacy ipinfo.io often returns 403 with token
    return "https://api.ipinfo.io"


def get_intel_timeout_seconds(cfg: Dict[str, Any]) -> Optional[int]:
    intel_cfg = cfg.get("intel") or {}
    sec = get_int(intel_cfg, ["timeout_seconds"])
    if sec is not None and sec > 0:
        return sec
    return None


def get_intel_retry_config(cfg: Dict[str, Any]) -> Optional[Tuple[int, int, int]]:
    """Returns (timeout_seconds, max_attempts, backoff_seconds) or None if any required is missing."""
    intel_cfg = cfg.get("intel") or {}
    timeout = get_int(intel_cfg, ["timeout_seconds"])
    retry_cfg = intel_cfg.get("retry") or {}
    max_attempts = get_int(retry_cfg, ["max_attempts"])
    backoff_seconds = get_int(retry_cfg, ["backoff_seconds"])
    if timeout is None or timeout <= 0 or max_attempts is None or max_attempts < 1 or backoff_seconds is None or backoff_seconds < 0:
        return None
    return (timeout, max_attempts, backoff_seconds)
