"""Unit test for finding_id stability and dedup."""
from __future__ import annotations

from cti_checkup.core.models import Finding
from cti_checkup.core.finding_id import compute_finding_id, assign_finding_ids_and_dedup


def test_finding_id_stable() -> None:
    fid1 = compute_finding_id("aws", "s3", "bucket", "b1", "public_access_enabled")
    fid2 = compute_finding_id("aws", "s3", "bucket", "b1", "public_access_enabled")
    assert fid1 == fid2
    assert fid1.startswith("sha256:")


def test_dedup_same_finding_once() -> None:
    findings = [
        Finding(service="s3", resource_type="bucket", resource_id="b1", issue="public_access_enabled", severity="high"),
        Finding(service="s3", resource_type="bucket", resource_id="b1", issue="public_access_enabled", severity="high"),
    ]
    out = assign_finding_ids_and_dedup("aws", findings)
    assert len(out) == 1
    assert out[0].finding_id is not None
    assert out[0].finding_id == compute_finding_id("aws", "s3", "bucket", "b1", "public_access_enabled")
