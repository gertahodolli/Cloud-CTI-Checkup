from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from cti_checkup.core.models import Finding, CheckRun
from cti_checkup.core.config_utils import get_bool


def _as_list(x: Any) -> List[Any]:
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]


def _statement_is_admin(stmt: Dict[str, Any]) -> bool:
    if str(stmt.get("Effect", "")).lower() != "allow":
        return False

    actions = _as_list(stmt.get("Action"))
    resources = _as_list(stmt.get("Resource"))

    action_admin = any(a == "*" for a in actions if isinstance(a, str))
    resource_admin = any(r == "*" for r in resources if isinstance(r, str))

    return action_admin and resource_admin


def _policy_doc_is_admin(policy_doc: Dict[str, Any]) -> bool:
    stmts = policy_doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    for st in stmts:
        if isinstance(st, dict) and _statement_is_admin(st):
            return True
    return False


def check_admin_policies(
    session: Any,
    account_id: Optional[str],
    region: Optional[str],
    config_section: Dict[str, Any],
) -> Tuple[List[Finding], CheckRun]:
    enabled = get_bool(config_section, ["detect_admin_policies"])

    if not enabled:
        return (
            [
                Finding(
                    service="iam",
                    region=None,
                    resource_type="check",
                    resource_id="admin_policies",
                    issue="admin_policy_check_disabled",
                    severity="info",
                    status="skipped",
                    evidence={"reason": "check_disabled_by_config"},
                )
            ],
            CheckRun(name="iam_admin_policies", status="skipped", message="Check disabled by config."),
        )

    iam = session.client("iam")
    findings: List[Finding] = []

    paginator = iam.get_paginator("list_users")
    users = []
    for page in paginator.paginate():
        users.extend(page.get("Users", []))

    for u in users:
        user_name = u.get("UserName", "unknown")

        attached = iam.list_attached_user_policies(UserName=user_name).get("AttachedPolicies", [])
        for ap in attached:
            pol_arn = ap.get("PolicyArn")
            pol_name = ap.get("PolicyName", "unknown")
            if not pol_arn:
                continue

            try:
                pol = iam.get_policy(PolicyArn=pol_arn).get("Policy", {})
                default_ver = pol.get("DefaultVersionId")
                ver = iam.get_policy_version(PolicyArn=pol_arn, VersionId=default_ver).get("PolicyVersion", {})
                doc = ver.get("Document", {})
            except Exception as e:
                findings.append(
                    Finding(
                        service="iam",
                        region=None,
                        resource_type="policy",
                        resource_id=f"{user_name}:{pol_name}",
                        issue="policy_read_failed",
                        severity="info",
                        status="error",
                        evidence={
                            "error": str(e),
                            "policy_arn": pol_arn,
                            "user_name": user_name,
                            "account_id": account_id or "unknown",
                        },
                    )
                )
                continue

            if isinstance(doc, dict) and _policy_doc_is_admin(doc):
                findings.append(
                    Finding(
                        service="iam",
                        region=None,
                        resource_type="policy",
                        resource_id=f"{user_name}:{pol_name}",
                        issue="admin_policy_wildcards_detected",
                        severity="high",
                        status="finding",
                        evidence={
                            "policy_arn": pol_arn,
                            "user_name": user_name,
                            "account_id": account_id or "unknown",
                        },
                        remediation="Remove or restrict wildcard admin policies; apply least privilege roles and scoped permissions.",
                    )
                )

        inline_names = iam.list_user_policies(UserName=user_name).get("PolicyNames", [])
        for pname in inline_names:
            try:
                pdoc = iam.get_user_policy(UserName=user_name, PolicyName=pname).get("PolicyDocument", {})
            except Exception as e:
                findings.append(
                    Finding(
                        service="iam",
                        region=None,
                        resource_type="policy",
                        resource_id=f"{user_name}:{pname}",
                        issue="inline_policy_read_failed",
                        severity="info",
                        status="error",
                        evidence={"error": str(e), "user_name": user_name},
                    )
                )
                continue

            if isinstance(pdoc, dict) and _policy_doc_is_admin(pdoc):
                findings.append(
                    Finding(
                        service="iam",
                        region=None,
                        resource_type="policy",
                        resource_id=f"{user_name}:{pname}",
                        issue="admin_policy_wildcards_detected",
                        severity="high",
                        status="finding",
                        evidence={
                            "inline": True,
                            "user_name": user_name,
                            "account_id": account_id or "unknown",
                        },
                        remediation="Remove or restrict wildcard admin policies; apply least privilege roles and scoped permissions.",
                    )
                )

    return findings, CheckRun(name="iam_admin_policies", status="ok")
