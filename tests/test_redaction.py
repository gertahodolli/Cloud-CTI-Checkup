"""Tests asserting access key IDs are redacted (last 4 only); raw secrets never in output."""
from __future__ import annotations

import json
from cti_checkup.core.models import Finding, ScanResult, Summary
from cti_checkup.core.redact import redact_scan_result


def test_access_key_resource_id_masked() -> None:
    result = ScanResult(
        provider="aws",
        findings=[
            Finding(
                service="iam",
                resource_type="access_key",
                resource_id="alice:AKIAIOSFODNN7EXAMPLE",
                issue="access_key_older_than_threshold",
                severity="medium",
                evidence={"age_days": 100},
            )
        ],
        summary=Summary(medium=1),
    )
    out = redact_scan_result(result)
    assert len(out.findings) == 1
    assert out.findings[0].resource_id == "alice:****MPLE"
    assert "AKIA" not in out.findings[0].resource_id


def test_evidence_access_key_masked() -> None:
    result = ScanResult(
        provider="aws",
        findings=[
            Finding(
                service="iam",
                resource_type="user",
                resource_id="alice",
                issue="policy_read_failed",
                severity="info",
                evidence={"policy_arn": "arn:aws:iam::123:policy/x", "access_key_id": "AKIAIOSFODNN7EXAMPLE"},
            )
        ],
        summary=Summary(info=1),
    )
    out = redact_scan_result(result)
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(out.model_dump())
    assert out.findings[0].evidence.get("access_key_id") == "****MPLE"


def test_no_intel_token_in_output() -> None:
    result = ScanResult(provider="intel", findings=[], summary=Summary())
    out = redact_scan_result(result)
    dumped = json.dumps(out.model_dump())
    assert "CTICHECKUP_ABUSEIPDB" not in dumped
    assert "CTICHECKUP_IPINFO" not in dumped
