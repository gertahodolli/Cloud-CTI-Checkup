from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from cti_checkup.core.models import Finding, CheckRun
from cti_checkup.core.config_utils import get_int


def check_unused_access_keys(
    session: Any,
    account_id: Optional[str],
    region: Optional[str],
    config_section: Dict[str, Any],
) -> Tuple[List[Finding], CheckRun]:
    max_unused_days = get_int(config_section, ["max_access_key_unused_days"])
    strict = config_section.get("_strict", False)

    if max_unused_days is None:
        msg = "Missing max_access_key_unused_days in config"
        if strict:
            return ([], CheckRun(name="iam_unused_access_keys", status="error", message=msg))
        return (
            [
                Finding(
                    service="iam",
                    region=None,
                    resource_type="check",
                    resource_id="unused_access_keys",
                    issue="missing_max_unused_days_config",
                    severity="info",
                    status="skipped",
                    evidence={"message": msg, "reason": "config_missing"},
                )
            ],
            CheckRun(name="iam_unused_access_keys", status="skipped", message=msg),
        )

    iam = session.client("iam")
    findings: List[Finding] = []
    now = datetime.now(timezone.utc)

    paginator = iam.get_paginator("list_users")
    users = []
    for page in paginator.paginate():
        users.extend(page.get("Users", []))

    for u in users:
        user_name = u.get("UserName", "unknown")
        keys = iam.list_access_keys(UserName=user_name).get("AccessKeyMetadata", [])
        for k in keys:
            key_id = k.get("AccessKeyId", "unknown")
            key_status = k.get("Status", "unknown")

            try:
                last_used = iam.get_access_key_last_used(AccessKeyId=key_id).get("AccessKeyLastUsed", {})
                last_used_date = last_used.get("LastUsedDate")
            except Exception as e:
                findings.append(
                    Finding(
                        service="iam",
                        region=None,
                        resource_type="access_key",
                        resource_id=f"{user_name}:{key_id}",
                        issue="access_key_last_used_lookup_failed",
                        severity="info",
                        status="error",
                        evidence={
                            "error": str(e),
                            "status": key_status,
                            "user_name": user_name,
                            "account_id": account_id or "unknown",
                        },
                    )
                )
                continue

            if last_used_date is None:
                findings.append(
                    Finding(
                        service="iam",
                        region=None,
                        resource_type="access_key",
                        resource_id=f"{user_name}:{key_id}",
                        issue="access_key_never_used",
                        severity="medium",
                        status="finding",
                        evidence={
                            "threshold_days": max_unused_days,
                            "status": key_status,
                            "user_name": user_name,
                            "account_id": account_id or "unknown",
                        },
                        remediation="Remove unused access keys or rotate them; prefer short-lived credentials.",
                    )
                )
                continue

            age_days = (now - last_used_date).days
            if age_days > max_unused_days:
                findings.append(
                    Finding(
                        service="iam",
                        region=None,
                        resource_type="access_key",
                        resource_id=f"{user_name}:{key_id}",
                        issue="access_key_unused_over_threshold",
                        severity="medium",
                        status="finding",
                        evidence={
                            "last_used_days_ago": age_days,
                            "threshold_days": max_unused_days,
                            "status": key_status,
                            "user_name": user_name,
                            "account_id": account_id or "unknown",
                        },
                        remediation="Disable/remove unused access keys; rotate credentials and enforce least privilege.",
                    )
                )

    return findings, CheckRun(name="iam_unused_access_keys", status="ok")
