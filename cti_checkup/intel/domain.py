"""Domain threat intelligence lookup (IPInfo); uses Finding and ScanResult."""
from __future__ import annotations

import json
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional, Tuple

from cti_checkup.core.models import Finding, ScanResult, CheckRun
from cti_checkup.core.risk import compute_risk_score
from cti_checkup.core.finding_id import assign_finding_ids_and_dedup
from cti_checkup.intel.config import (
    get_ipinfo_token,
    get_ipinfo_base_url,
    get_ipinfo_referrer,
    get_intel_retry_config,
    normalize_ipinfo_response,
)
from cti_checkup.intel.cloud_attribution import build_cloud_attribution


def _resolve_domain_to_ip(domain: str, timeout: int = 10) -> Tuple[Optional[str], Optional[str]]:
    """Resolve domain to an IPv4 address. Returns (ip, error_message)."""
    try:
        # Prefer IPv4; getaddrinfo is more reliable than gethostbyname for timeouts
        infos = socket.getaddrinfo(domain, None, socket.AF_INET)
        if not infos:
            return None, "No IPv4 address found for domain"
        # Use first resolved address (family, type, proto, canonname, sockaddr)
        return infos[0][4][0], None
    except socket.gaierror as e:
        return None, f"Could not resolve domain: {e}"
    except OSError as e:
        return None, str(e)


def run_intel_domain(domain: str, cfg: Dict[str, Any]) -> ScanResult:
    result = ScanResult(provider="intel")
    result.regions = []

    token = get_ipinfo_token()
    if not token:
        result.fatal_error = True
        result.checks.append(
            CheckRun(
                name="intel_domain",
                status="error",
                message="Missing CTICHECKUP_IPINFO_TOKEN (required for domain lookup).",
            )
        )
        return result

    retry_config = get_intel_retry_config(cfg)
    if retry_config is None:
        result.partial_failure = True
        result.checks.append(
            CheckRun(
                name="intel_domain",
                status="error",
                message="Missing intel.timeout_seconds / intel.retry.max_attempts / intel.retry.backoff_seconds (required).",
            )
        )
        return result

    timeout, max_attempts, backoff_seconds = retry_config
    base_url = get_ipinfo_base_url(cfg)
    use_new_api = "api.ipinfo.io" in base_url
    resolved_ip, resolve_err = None, None
    # Build list of (base_url, path, lookup_target) to try; on 403 we fall back to legacy
    strategies = []
    if use_new_api:
        resolved_ip, resolve_err = _resolve_domain_to_ip(domain, timeout=timeout)
        if not resolve_err and resolved_ip:
            strategies.append(("https://api.ipinfo.io", "/lite/", resolved_ip))
        # Fallback for 403 or no resolution: legacy endpoint accepts domain in path
        strategies.append(("https://ipinfo.io", "/", domain))
    else:
        strategies.append((base_url, "/", domain))

    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "CTI-Checkup/1.0 (https://github.com/cti-checkup)",
    }
    referrer = get_ipinfo_referrer(cfg)
    if referrer:
        headers["Referer"] = referrer
    ctx = ssl.create_default_context()
    data = None
    last_error = None
    last_403 = False

    for base, path, target in strategies:
        if last_403 and base == "https://api.ipinfo.io":
            continue  # already tried new API and got 403
        url = f"{base}{path}{urllib.parse.quote(target, safe='')}?token={urllib.parse.quote(token, safe='')}"
        req = urllib.request.Request(url, headers=headers)
        for attempt in range(max_attempts):
            try:
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    data = normalize_ipinfo_response(json.loads(resp.read().decode()))
                last_error = None
                last_403 = False
                break
            except urllib.error.HTTPError as e:
                last_error = e
                if e.code == 403:
                    last_403 = True
                    break  # try next strategy
                if e.code is not None and 500 <= e.code < 600 and attempt < max_attempts - 1:
                    time.sleep(backoff_seconds * (2 ** attempt))
                    continue
                result.fatal_error = True
                result.checks.append(CheckRun(name="intel_domain", status="error", message=str(e)))
                result.findings.append(
                    Finding(
                        service="intel",
                        resource_type="domain",
                        resource_id=domain,
                        issue="domain_lookup_failed",
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
                result.checks.append(CheckRun(name="intel_domain", status="error", message=str(e)))
                result.findings.append(
                    Finding(
                        service="intel",
                        resource_type="domain",
                        resource_id=domain,
                        issue="domain_lookup_failed",
                        severity="info",
                        status="error",
                        evidence={"error": str(e)},
                    )
                )
                return result
            except Exception as e:
                last_error = e
                result.fatal_error = True
                result.checks.append(CheckRun(name="intel_domain", status="error", message=str(e)))
                result.findings.append(
                    Finding(
                        service="intel",
                        resource_type="domain",
                        resource_id=domain,
                        issue="domain_lookup_failed",
                        severity="info",
                        status="error",
                        evidence={"error": str(e)},
                    )
                )
                return result
        if data is not None:
            break

    if data is None and last_error is not None:
        result.partial_failure = True
        result.checks.append(CheckRun(name="intel_domain", status="error", message=str(last_error)))
        result.findings.append(
            Finding(
                service="intel",
                resource_type="domain",
                resource_id=domain,
                issue="domain_lookup_failed",
                severity="info",
                status="error",
                evidence={"error": str(last_error)},
            )
        )
        return result

    cloud_attr, cloud_attr_error = build_cloud_attribution(data, cfg)
    if cloud_attr_error:
        result.partial_failure = True
        result.checks.append(
            CheckRun(name="cloud_attribution", status="error", message=cloud_attr_error)
        )

    result.findings.append(
        Finding(
            service="intel",
            resource_type="domain",
            resource_id=domain,
            issue="domain_lookup_ok",
            severity="info",
            status="ok",
            evidence={
                "domain": domain,
                "ip": data.get("ip"),
                "hostname": data.get("hostname"),
                "org": data.get("org"),
                "country": data.get("country"),
                **({"cloud_attribution": cloud_attr} if cloud_attr else {}),
            },
        )
    )
    result.findings = assign_finding_ids_and_dedup(result.provider, result.findings)
    for f in result.findings:
        if f.severity == "info":
            result.summary.info += 1
    result.checks.append(CheckRun(name="intel_domain", status="ok"))
    result.risk_score, result.risk_score_explanation = compute_risk_score(result, cfg)
    return result
