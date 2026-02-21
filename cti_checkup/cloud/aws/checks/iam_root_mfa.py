from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from cti_checkup.core.models import Finding, CheckRun
from cti_checkup.core.config_utils import get_bool


def check_root_mfa(
    session: Any,
    account_id: Optional[str],
    region: Optional[str],
    config_section: Dict[str, Any],
) -> Tuple[List[Finding], CheckRun]:
    enabled = get_bool(config_section, ["check_root_mfa"])
    strict = config_section.get("_strict", False)

    if not enabled:
        return (
            [
                Finding(
                    service="iam",
                    region=None,
                    resource_type="check",
                    resource_id="root_mfa",
                    issue="root_mfa_check_disabled",
                    severity="info",
                    status="skipped",
                    evidence={"reason": "check_disabled_by_config"},
                )
            ],
            CheckRun(name="iam_root_mfa", status="skipped", message="Check disabled by config."),
        )

    iam = session.client("iam")

    try:
        summary = iam.get_account_summary().get("SummaryMap", {})
        root_mfa = int(summary.get("AccountMFAEnabled", 0))
    except Exception as e:
        if strict:
            return ([], CheckRun(name="iam_root_mfa", status="error", message=str(e)))
        return (
            [
                Finding(
                    service="iam",
                    region=None,
                    resource_type="account",
                    resource_id="root",
                    issue="root_mfa_check_failed",
                    severity="info",
                    status="error",
                    evidence={"error": str(e), "account_id": account_id or "unknown"},
                )
            ],
            CheckRun(name="iam_root_mfa", status="error", message=str(e)),
        )

    if root_mfa == 0:
        return (
            [
                Finding(
                    service="iam",
                    region=None,
                    resource_type="account",
                    resource_id="root",
                    issue="root_mfa_not_enabled",
                    severity="high",
                    status="finding",
                    evidence={
                        "account_mfa_enabled": root_mfa,
                        "account_id": account_id or "unknown",
                    },
                    remediation="Enable MFA on the AWS account root user and minimize root usage.",
                )
            ],
            CheckRun(name="iam_root_mfa", status="ok"),
        )

    return ([], CheckRun(name="iam_root_mfa", status="ok"))
