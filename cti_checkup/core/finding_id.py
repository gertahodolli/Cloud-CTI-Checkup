"""Stable finding_id and dedup by finding_id."""
from __future__ import annotations

import hashlib
from typing import List

from cti_checkup.core.models import Finding


def compute_finding_id(provider: str, service: str, resource_type: str, resource_id: str, issue: str) -> str:
    payload = f"{provider}|{service}|{resource_type}|{resource_id}|{issue}"
    digest = hashlib.sha256(payload.encode()).hexdigest()
    return f"sha256:{digest}"


def assign_finding_ids_and_dedup(provider: str, findings: List[Finding]) -> List[Finding]:
    seen: set[str] = set()
    out: List[Finding] = []
    for f in findings:
        fid = compute_finding_id(provider, f.service, f.resource_type, f.resource_id, f.issue)
        if fid in seen:
            continue
        seen.add(fid)
        f.finding_id = fid
        out.append(f)
    return out
