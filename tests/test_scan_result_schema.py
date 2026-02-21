"""Validate ScanResult JSON output against schemas/scan_result.schema.json."""
from __future__ import annotations

import json
from pathlib import Path

from cti_checkup.core.models import Finding, ScanResult, CheckRun, Summary


def _load_schema():
    schema_path = Path(__file__).resolve().parent.parent / "schemas" / "scan_result.schema.json"
    return json.loads(schema_path.read_text())


def test_scan_result_json_validates_against_schema():
    try:
        import jsonschema
    except ImportError:
        return
    schema = _load_schema()
    result = ScanResult(
        provider="aws",
        account_id="123456789012",
        regions=["us-east-1"],
        checks=[CheckRun(name="s3_public", status="ok")],
        findings=[
            Finding(
                finding_id="sha256:abc123",
                service="s3",
                resource_type="bucket",
                resource_id="mybucket",
                issue="public_access_enabled",
                severity="high",
                status="finding",
                evidence={"block_public_access_all_true": False},
            )
        ],
        summary=Summary(high=1, medium=0, low=0, info=0, skipped=0, errors=0),
        partial_failure=False,
        fatal_error=False,
        risk_score=42,
        risk_score_explanation={
            "cap": 100,
            "weights": {"high": 10, "medium": 5, "low": 2, "info": 1},
            "counts": {"high": 1, "medium": 0, "low": 0, "info": 0},
            "contribution": {"high": 10, "medium": 0, "low": 0, "info": 0},
        },
    )
    data = result.model_dump()
    jsonschema.validate(instance=data, schema=schema)
