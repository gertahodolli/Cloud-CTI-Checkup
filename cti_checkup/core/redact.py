"""Redaction: mask access key IDs (last 4 only); never expose intel tokens in output."""
from __future__ import annotations

import re
from typing import Any

from cti_checkup.core.models import Finding, ScanResult


# AWS access key ID pattern: 20 chars, alphanumeric, often starts with AKIA
_ACCESS_KEY_PATTERN = re.compile(r"\b(A[A-Z0-9]{19})\b")


def _mask_access_key_id(value: str) -> str:
    if not value or len(value) < 4:
        return "****"
    return "****" + value[-4:]


def _redact_value(v: Any) -> Any:
    if isinstance(v, dict):
        return {k: _redact_value(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_redact_value(x) for x in v]
    if isinstance(v, str) and _ACCESS_KEY_PATTERN.search(v):
        return _ACCESS_KEY_PATTERN.sub(lambda m: _mask_access_key_id(m.group(1)), v)
    return v


def _redact_finding(f: Finding) -> Finding:
    resource_id = f.resource_id
    if f.resource_type == "access_key":
        if ":" in resource_id:
            user, key_part = resource_id.rsplit(":", 1)
            resource_id = f"{user}:{_mask_access_key_id(key_part)}"
        else:
            resource_id = _mask_access_key_id(resource_id)
    evidence = _redact_value(f.evidence)
    return Finding(
        finding_id=f.finding_id,
        service=f.service,
        region=f.region,
        resource_type=f.resource_type,
        resource_id=resource_id,
        issue=f.issue,
        severity=f.severity,
        status=f.status,
        evidence=evidence,
        remediation=f.remediation,
    )


def redact_scan_result(result: ScanResult) -> ScanResult:
    """Return a copy of the scan result with access key IDs masked (last 4 only)."""
    redacted_findings = [_redact_finding(f) for f in result.findings]
    return ScanResult(
        provider=result.provider,
        account_id=result.account_id,
        regions=result.regions,
        scan_date=result.scan_date,
        checks=result.checks,
        findings=redacted_findings,
        summary=result.summary,
        partial_failure=result.partial_failure,
        fatal_error=result.fatal_error,
        risk_score=result.risk_score,
        risk_score_explanation=result.risk_score_explanation,
    )
