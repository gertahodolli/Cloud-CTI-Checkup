from __future__ import annotations

import json
from typing import Literal

from cti_checkup.core.models import ScanResult


def render_json(result: ScanResult) -> str:
    return json.dumps(result.model_dump(), indent=2, default=str)


def render_human(result: ScanResult, fmt: Literal["table", "text"] = "table") -> str:
    lines = []
    lines.append(f"{result.provider} scan | account={result.account_id or 'unknown'}")
    lines.append(f"Regions: {', '.join(result.regions) if result.regions else 'none'}")
    lines.append(
        f"Summary: high={result.summary.high} medium={result.summary.medium} low={result.summary.low} "
        f"info={result.summary.info} skipped={result.summary.skipped} errors={result.summary.errors}"
    )
    if result.risk_score is not None:
        lines.append(f"Risk score: {result.risk_score}")
    lines.append("")

    if fmt == "text":
        for f in result.findings:
            lines.append(f"[{f.severity.upper()}] {f.service} {f.resource_type}:{f.resource_id} {f.issue}")
        return "\n".join(lines)

    # basic table without external deps
    header = ["Service", "Region", "Resource", "Issue", "Severity"]
    rows = []
    for f in result.findings:
        rows.append([f.service, f.region or "-", f"{f.resource_type}:{f.resource_id}", f.issue, f.severity.upper()])

    if not rows:
        lines.append("No findings.")
        return "\n".join(lines)

    # column widths
    widths = [len(h) for h in header]
    for r in rows:
        widths = [max(widths[i], len(str(r[i]))) for i in range(len(header))]

    def fmt_row(r):
        return " | ".join(str(r[i]).ljust(widths[i]) for i in range(len(header)))

    lines.append(fmt_row(header))
    lines.append("-+-".join("-" * w for w in widths))
    for r in rows:
        lines.append(fmt_row(r))

    return "\n".join(lines)
