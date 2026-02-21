"""S3 bucket versioning check."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import botocore

from cti_checkup.core.models import Finding, CheckRun
from cti_checkup.core.config_utils import get_bool


def check_s3_versioning(
    session: Any,
    account_id: Optional[str],
    region: Optional[str],
    config_section: Dict[str, Any],
) -> Tuple[List[Finding], CheckRun]:
    enabled = get_bool(config_section, ["check_versioning"])

    if not enabled:
        return (
            [
                Finding(
                    service="s3",
                    region=None,
                    resource_type="check",
                    resource_id="s3_versioning",
                    issue="versioning_check_disabled",
                    severity="info",
                    status="skipped",
                    evidence={"reason": "check_disabled_by_config"},
                )
            ],
            CheckRun(name="s3_versioning", status="skipped", message="Check disabled by config."),
        )

    s3 = session.client("s3")
    findings: List[Finding] = []

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except Exception as e:
        return (
            [
                Finding(
                    service="s3",
                    resource_type="service",
                    resource_id="s3",
                    issue="list_buckets_failed",
                    severity="info",
                    status="error",
                    evidence={"error": str(e), "account_id": account_id or "unknown"},
                )
            ],
            CheckRun(name="s3_versioning", status="error", message=str(e)),
        )

    for b in buckets:
        name = b.get("Name", "unknown")
        try:
            ver = s3.get_bucket_versioning(Bucket=name)
            status = ver.get("Status") or ""
            if str(status).lower() != "enabled":
                findings.append(
                    Finding(
                        service="s3",
                        region=None,
                        resource_type="bucket",
                        resource_id=name,
                        issue="versioning_disabled",
                        severity="low",
                        status="finding",
                        evidence={
                            "bucket": name,
                            "status": status,
                            "account_id": account_id or "unknown",
                        },
                        remediation="Enable bucket versioning for data protection and recovery.",
                    )
                )
        except botocore.exceptions.ClientError as ce:
            findings.append(
                Finding(
                    service="s3",
                    region=None,
                    resource_type="bucket",
                    resource_id=name,
                    issue="versioning_check_failed",
                    severity="info",
                    status="error",
                    evidence={"error": str(ce), "bucket": name},
                )
            )
        except Exception as e:
            findings.append(
                Finding(
                    service="s3",
                    region=None,
                    resource_type="bucket",
                    resource_id=name,
                    issue="versioning_check_failed",
                    severity="info",
                    status="error",
                    evidence={"error": str(e), "bucket": name},
                )
            )

    return findings, CheckRun(name="s3_versioning", status="ok")
