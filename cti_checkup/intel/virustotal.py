"""VirusTotal hash/URL lookup; uses Finding and ScanResult."""
from __future__ import annotations

import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional, Tuple

from cti_checkup.core.models import Finding, ScanResult, CheckRun
from cti_checkup.core.risk import compute_risk_score
from cti_checkup.core.finding_id import assign_finding_ids_and_dedup
from cti_checkup.intel.config import get_intel_retry_config


def get_virustotal_api_key() -> Optional[str]:
    """Get VirusTotal API key from environment."""
    v = os.environ.get("CTICHECKUP_VIRUSTOTAL_API_KEY", "").strip()
    return v or None


def get_virustotal_base_url(cfg: Dict[str, Any]) -> str:
    """Get VirusTotal API base URL from config or default."""
    intel_cfg = (cfg.get("intel") or {}).get("virustotal") or {}
    url = intel_cfg.get("base_url")
    if isinstance(url, str) and url.strip():
        return url.strip().rstrip("/")
    return "https://www.virustotal.com/api/v3"


def _fetch_virustotal(
    resource: str,
    resource_type: str,  # "files" for hash, "urls" for URL
    cfg: Dict[str, Any],
    timeout: int,
    max_attempts: int,
    backoff_seconds: int,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Fetch resource info from VirusTotal API v3."""
    api_key = get_virustotal_api_key()
    if not api_key:
        return None, "Missing CTICHECKUP_VIRUSTOTAL_API_KEY."
    
    base_url = get_virustotal_base_url(cfg)
    
    # For URLs, we need to encode the URL as base64url without padding
    if resource_type == "urls":
        import base64
        url_id = base64.urlsafe_b64encode(resource.encode()).decode().rstrip("=")
        url = f"{base_url}/urls/{url_id}"
    else:
        # For hashes (files), use the hash directly
        url = f"{base_url}/files/{urllib.parse.quote(resource, safe='')}"
    
    headers = {
        "Accept": "application/json",
        "x-apikey": api_key,
        "User-Agent": "CTI-Checkup/1.0 (https://github.com/cti-checkup)",
    }
    req = urllib.request.Request(url, headers=headers)
    ctx = ssl.create_default_context()
    
    last_error: Optional[Exception] = None
    for attempt in range(max_attempts):
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                data = json.loads(resp.read().decode())
                return data, None
        except urllib.error.HTTPError as e:
            last_error = e
            if e.code == 404:
                return None, f"Resource not found in VirusTotal: {resource}"
            if e.code == 429:
                # Rate limit - wait longer
                if attempt < max_attempts - 1:
                    time.sleep(backoff_seconds * (2 ** (attempt + 2)))
                    continue
            if e.code is not None and 500 <= e.code < 600 and attempt < max_attempts - 1:
                time.sleep(backoff_seconds * (2 ** attempt))
                continue
            return None, f"HTTP {e.code}: {e.reason}"
        except (OSError, TimeoutError) as e:
            last_error = e
            if attempt < max_attempts - 1:
                time.sleep(backoff_seconds * (2 ** attempt))
                continue
            return None, str(e)
        except Exception as e:
            last_error = e
            return None, str(e)
    
    if last_error is not None:
        return None, str(last_error)
    return None, "Unknown error"


def _parse_vt_stats(data: Dict[str, Any]) -> Dict[str, int]:
    """Extract detection stats from VirusTotal response."""
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "undetected": stats.get("undetected", 0),
        "harmless": stats.get("harmless", 0),
        "timeout": stats.get("timeout", 0),
    }


def _determine_severity(stats: Dict[str, int]) -> str:
    """Determine severity based on detection stats.
    
    Returns one of: 'critical', 'high', 'medium', 'low', 'info'.
    """
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    
    # Critical: 10+ malicious detections (widely detected malware)
    if malicious >= 10:
        return "critical"
    # High: 5-9 malicious detections
    elif malicious >= 5:
        return "high"
    # Medium: at least 1 malicious or several suspicious
    elif malicious >= 1 or suspicious >= 5:
        return "medium"
    # Low: only suspicious detections
    elif suspicious >= 1:
        return "low"
    # Info: clean or harmless
    return "info"


def run_intel_hash(hash_value: str, cfg: Dict[str, Any]) -> ScanResult:
    """Look up a file hash on VirusTotal.
    
    Args:
        hash_value: MD5, SHA1, or SHA256 hash.
        cfg: Full configuration dictionary.
    
    Returns:
        ScanResult with findings.
    """
    result = ScanResult(provider="virustotal")
    result.account_id = None
    result.regions = []
    
    # Validate hash format
    hash_value = hash_value.strip().lower()
    if len(hash_value) not in (32, 40, 64):  # MD5, SHA1, SHA256
        result.fatal_error = True
        result.checks.append(CheckRun(
            name="hash_lookup",
            status="error",
            message=f"Invalid hash length: {len(hash_value)}. Expected MD5 (32), SHA1 (40), or SHA256 (64)."
        ))
        return result
    
    # Get retry config
    retry_cfg = get_intel_retry_config(cfg)
    if retry_cfg is None:
        timeout, max_attempts, backoff = 30, 3, 2
    else:
        timeout, max_attempts, backoff = retry_cfg
    
    # Fetch from VirusTotal
    data, error = _fetch_virustotal(hash_value, "files", cfg, timeout, max_attempts, backoff)
    
    if error:
        if "not found" in error.lower():
            result.checks.append(CheckRun(name="hash_lookup", status="ok", message="Hash not found in VirusTotal"))
            result.findings.append(Finding(
                service="virustotal",
                resource_type="hash",
                resource_id=hash_value,
                issue="hash_not_found",
                severity="info",
                evidence={"hash": hash_value, "message": "Hash not found in VirusTotal database"},
            ))
        elif "Missing CTICHECKUP_VIRUSTOTAL_API_KEY" in error:
            result.fatal_error = True
            result.checks.append(CheckRun(name="hash_lookup", status="error", message=error))
        else:
            result.partial_failure = True
            result.checks.append(CheckRun(name="hash_lookup", status="error", message=error))
        
        result.findings = assign_finding_ids_and_dedup(result.provider, result.findings)
        _count_summary(result)
        result.risk_score, result.risk_score_explanation = compute_risk_score(result, cfg)
        return result
    
    # Parse response
    stats = _parse_vt_stats(data or {})
    severity = _determine_severity(stats)
    attrs = (data or {}).get("data", {}).get("attributes", {})
    
    # Build evidence
    evidence = {
        "hash": hash_value,
        "sha256": attrs.get("sha256"),
        "sha1": attrs.get("sha1"),
        "md5": attrs.get("md5"),
        "size": attrs.get("size"),
        "type": attrs.get("type_description") or attrs.get("type_tag"),
        "names": attrs.get("names", [])[:5],  # First 5 names
        "detection_stats": stats,
        "malicious_count": stats.get("malicious", 0),
        "suspicious_count": stats.get("suspicious", 0),
        "total_engines": sum(stats.values()),
        "reputation": attrs.get("reputation"),
        "last_analysis_date": attrs.get("last_analysis_date"),
    }
    
    # Determine issue
    if stats.get("malicious", 0) > 0:
        issue = "hash_malicious_detections"
    elif stats.get("suspicious", 0) > 0:
        issue = "hash_suspicious_detections"
    else:
        issue = "hash_clean"
    
    result.findings.append(Finding(
        service="virustotal",
        resource_type="hash",
        resource_id=hash_value,
        issue=issue,
        severity=severity,
        evidence=evidence,
    ))
    
    result.checks.append(CheckRun(name="hash_lookup", status="ok", message="VirusTotal lookup completed"))
    result.findings = assign_finding_ids_and_dedup(result.provider, result.findings)
    _count_summary(result)
    
    # Use VirusTotal-style score: detection ratio (malicious / total_engines)
    # This gives a 0-100 score that can reach 100 for widely detected malware
    malicious = stats.get("malicious", 0)
    total_engines = evidence.get("total_engines", 0)
    if total_engines > 0:
        vt_score = round(100 * malicious / total_engines)
    else:
        vt_score = 0
    
    result.risk_score = vt_score
    result.risk_score_explanation = {
        "formula": "VirusTotal detection ratio (malicious / total_engines × 100)",
        "malicious": malicious,
        "total_engines": total_engines,
        "cap": 100,
    }
    return result


def _count_summary(result: ScanResult) -> None:
    """Count findings by severity."""
    for f in result.findings:
        if f.status == "skipped":
            result.summary.skipped += 1
        elif f.status == "error":
            result.summary.errors += 1
        else:
            sev = (f.severity or "info").lower()
            if sev == "critical":
                result.summary.critical += 1
            elif sev == "high":
                result.summary.high += 1
            elif sev == "medium":
                result.summary.medium += 1
            elif sev == "low":
                result.summary.low += 1
            else:
                result.summary.info += 1
