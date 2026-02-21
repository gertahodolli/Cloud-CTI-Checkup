"""IP threat intelligence lookup (AbuseIPDB); uses Finding and ScanResult."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

from cti_checkup.core.models import Finding, ScanResult, CheckRun
from cti_checkup.core.risk import compute_risk_score
from cti_checkup.core.finding_id import assign_finding_ids_and_dedup
from cti_checkup.intel.cloud_attribution import (
    compute_cloud_attribution,
    load_cloud_attribution_config,
)
from cti_checkup.intel.config import (
    get_abuseipdb_api_key,
    get_abuseipdb_base_url,
    get_ipinfo_base_url,
    get_ipinfo_referrer,
    get_ipinfo_token,
    get_intel_retry_config,
    normalize_ipinfo_response,
)


def _fetch_ipinfo_enrichment(
    ip_address: str,
    cfg: Dict[str, Any],
    timeout: int,
    max_attempts: int,
    backoff_seconds: int,
) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
    token = get_ipinfo_token()
    if not token:
        return None, "Missing CTICHECKUP_IPINFO_TOKEN (required for cloud attribution)."

    base_url = get_ipinfo_base_url(cfg)
    # New API (api.ipinfo.io) requires /lite/ or /lookup/ path; legacy ipinfo.io uses bare path
    path = "/lite/" if "api.ipinfo.io" in base_url else "/"
    url = f"{base_url}{path}{urllib.parse.quote(ip_address, safe='')}?token={urllib.parse.quote(token, safe='')}"
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "CTI-Checkup/1.0 (https://github.com/cti-checkup)",
    }
    referrer = get_ipinfo_referrer(cfg)
    if referrer:
        headers["Referer"] = referrer
    req = urllib.request.Request(url, headers=headers)
    ctx = ssl.create_default_context()

    data = None
    last_error: Optional[Exception] = None
    for attempt in range(max_attempts):
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                data = normalize_ipinfo_response(json.loads(resp.read().decode()))
            return data, None
        except urllib.error.HTTPError as e:
            last_error = e
            if e.code is not None and 500 <= e.code < 600 and attempt < max_attempts - 1:
                time.sleep(backoff_seconds * (2 ** attempt))
                continue
            return None, str(e)
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
    return None, "Unknown error fetching ipinfo enrichment."


def run_intel_ip(ip_address: str, cfg: Dict[str, Any]) -> ScanResult:
    result = ScanResult(provider="intel")
    result.regions = []

    api_key = get_abuseipdb_api_key()
    if not api_key:
        result.fatal_error = True
        result.checks.append(
            CheckRun(
                name="intel_ip",
                status="error",
                message="Missing CTICHECKUP_ABUSEIPDB_API_KEY (required for IP lookup).",
            )
        )
        return result

    retry_config = get_intel_retry_config(cfg)
    if retry_config is None:
        result.partial_failure = True
        result.checks.append(
            CheckRun(
                name="intel_ip",
                status="error",
                message="Missing intel.timeout_seconds / intel.retry.max_attempts / intel.retry.backoff_seconds (required).",
            )
        )
        return result

    timeout, max_attempts, backoff_seconds = retry_config
    base_url = get_abuseipdb_base_url(cfg)
    url = f"{base_url}/check?ipAddress={urllib.parse.quote(ip_address, safe='')}"
    req = urllib.request.Request(url, headers={"Key": api_key, "Accept": "application/json"})
    ctx = ssl.create_default_context()

    data = None
    last_error = None
    for attempt in range(max_attempts):
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                data = json.loads(resp.read().decode())
            break
        except urllib.error.HTTPError as e:
            last_error = e
            if e.code is not None and 500 <= e.code < 600 and attempt < max_attempts - 1:
                time.sleep(backoff_seconds * (2 ** attempt))
                continue
            result.fatal_error = True
            result.checks.append(CheckRun(name="intel_ip", status="error", message=str(e)))
            result.findings.append(
                Finding(
                    service="intel",
                    resource_type="ip",
                    resource_id=ip_address,
                    issue="ip_lookup_failed",
                    severity="info",
                    status="error",
                    evidence={"error": str(e), "status_code": getattr(e, "code", None)},
                )
            )
            return result
        except (OSError, TimeoutError) as e:
            last_error = e
            if attempt < max_attempts - 1:
                time.sleep(backoff_seconds * (2 ** attempt))
                continue
            result.partial_failure = True
            result.checks.append(CheckRun(name="intel_ip", status="error", message=str(e)))
            result.findings.append(
                Finding(
                    service="intel",
                    resource_type="ip",
                    resource_id=ip_address,
                    issue="ip_lookup_failed",
                    severity="info",
                    status="error",
                    evidence={"error": str(e)},
                )
            )
            return result
        except Exception as e:
            last_error = e
            result.fatal_error = True
            result.checks.append(CheckRun(name="intel_ip", status="error", message=str(e)))
            result.findings.append(
                Finding(
                    service="intel",
                    resource_type="ip",
                    resource_id=ip_address,
                    issue="ip_lookup_failed",
                    severity="info",
                    status="error",
                    evidence={"error": str(e)},
                )
            )
            return result

    if data is None and last_error is not None:
        result.partial_failure = True
        result.checks.append(CheckRun(name="intel_ip", status="error", message=str(last_error)))
        result.findings.append(
            Finding(
                service="intel",
                resource_type="ip",
                resource_id=ip_address,
                issue="ip_lookup_failed",
                severity="info",
                status="error",
                evidence={"error": str(last_error)},
            )
        )
        return result

    cloud_attr: Optional[Dict[str, Any]] = None
    enabled, cloud_cfg, cloud_error = load_cloud_attribution_config(cfg)
    if enabled:
        if cloud_error:
            result.partial_failure = True
            result.checks.append(CheckRun(name="cloud_attribution", status="error", message=cloud_error))
        else:
            ipinfo_data, ipinfo_error = _fetch_ipinfo_enrichment(
                ip_address, cfg, timeout, max_attempts, backoff_seconds
            )
            if ipinfo_error:
                result.partial_failure = True
                result.checks.append(
                    CheckRun(name="cloud_attribution", status="error", message=ipinfo_error)
                )
            cloud_attr = compute_cloud_attribution(ipinfo_data or {}, cloud_cfg or {})

    abuse_score = data.get("data", {}).get("abuseConfidenceScore")
    if abuse_score is not None:
        result.findings.append(
            Finding(
                service="intel",
                resource_type="ip",
                resource_id=ip_address,
                issue="ip_abuse_confidence",
                severity="high" if (isinstance(abuse_score, (int, float)) and abuse_score >= 75) else "medium" if isinstance(abuse_score, (int, float)) and abuse_score >= 25 else "low",
                status="finding",
                evidence={
                    "abuse_confidence_score": abuse_score,
                    "ip": ip_address,
                    "country": data.get("data", {}).get("countryCode"),
                    "usage_type": data.get("data", {}).get("usageType"),
                    **({"cloud_attribution": cloud_attr} if cloud_attr else {}),
                },
                remediation="Review and block high-confidence abusive IPs as per policy.",
            )
        )

    result.checks.append(CheckRun(name="intel_ip", status="ok"))
    result.findings = assign_finding_ids_and_dedup(result.provider, result.findings)
    result.summary.high = sum(1 for f in result.findings if f.severity == "high")
    result.summary.medium = sum(1 for f in result.findings if f.severity == "medium")
    result.summary.low = sum(1 for f in result.findings if f.severity == "low")
    result.summary.info = sum(1 for f in result.findings if f.severity == "info")
    result.risk_score, result.risk_score_explanation = compute_risk_score(result, cfg)
    return result
