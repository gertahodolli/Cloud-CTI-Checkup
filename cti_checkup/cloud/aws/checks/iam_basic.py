from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from cti_checkup.core.models import Finding, CheckRun
from cti_checkup.core.config_utils import get_int


def check_iam_mfa_and_old_keys(
    session: Any,
    account_id: Optional[str],
    region: Optional[str],
    config_section: Dict[str, Any],
) -> Tuple[List[Finding], CheckRun]:
    findings: List[Finding] = []
    iam = session.client("iam")
    max_age_days = get_int(config_section, ["max_access_key_age_days"])
    strict = config_section.get("_strict", False)

    try:
        paginator = iam.get_paginator("list_users")
        users = []
        for page in paginator.paginate():
            users.extend(page.get("Users", []))
    except Exception as e:
        return (
            [
                Finding(
                    service="iam",
                    resource_type="service",
                    resource_id="iam",
                    issue="list_users_failed",
                    severity="info",
                    status="error",
                    evidence={"error": str(e), "account_id": account_id or "unknown"},
                )
            ],
            CheckRun(name="iam_basic", status="error", message=str(e)),
        )

    now = datetime.now(timezone.utc)

    for u in users:
        user_name = u.get("UserName", "unknown")

        try:
            mfa = iam.list_mfa_devices(UserName=user_name).get("MFADevices", [])
            if len(mfa) == 0:
                findings.append(
                    Finding(
                        service="iam",
                        resource_type="user",
                        resource_id=user_name,
                        issue="mfa_not_enabled",
                        severity="high",
                        evidence={
                            "user_name": user_name,
                            "account_id": account_id or "unknown",
                        },
                        remediation="Enable MFA for the user or migrate to federated access with MFA.",
                    )
                )
        except Exception as e:
            findings.append(
                Finding(
                    service="iam",
                    resource_type="user",
                    resource_id=user_name,
                    issue="mfa_check_failed",
                    severity="info",
                    status="error",
                    evidence={"error": str(e), "user_name": user_name},
                )
            )

        if max_age_days is None:
            if strict:
                return (
                    [],
                    CheckRun(
                        name="iam_old_access_keys",
                        status="error",
                        message="Missing max_access_key_age_days (required in strict mode).",
                    ),
                )
            continue

        try:
            keys = iam.list_access_keys(UserName=user_name).get("AccessKeyMetadata", [])
            for k in keys:
                create_date = k.get("CreateDate")
                key_id = k.get("AccessKeyId", "unknown")
                key_status = k.get("Status", "unknown")
                if not create_date:
                    continue
                age_days = (now - create_date).days
                if age_days > max_age_days:
                    findings.append(
                        Finding(
                            service="iam",
                            resource_type="access_key",
                            resource_id=f"{user_name}:{key_id}",
                            issue="access_key_older_than_threshold",
                            severity="medium",
                            evidence={
                                "age_days": age_days,
                                "threshold_days": max_age_days,
                                "status": key_status,
                                "user_name": user_name,
                                "account_id": account_id or "unknown",
                            },
                            remediation="Rotate old access keys and remove unused keys.",
                        )
                    )
        except Exception as e:
            findings.append(
                Finding(
                    service="iam",
                    resource_type="user",
                    resource_id=user_name,
                    issue="access_key_check_failed",
                    severity="info",
                    status="error",
                    evidence={"error": str(e), "user_name": user_name},
                )
            )

    return findings, CheckRun(name="iam_basic", status="ok")
