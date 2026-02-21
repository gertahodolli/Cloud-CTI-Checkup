"""IAM advanced risky policy patterns: NotAction, NotResource, privilege-escalation actions."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from cti_checkup.core.models import Finding, CheckRun
from cti_checkup.core.config_utils import get_bool, get_list_str


def _as_list(x: Any) -> List[Any]:
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]


def _normalize_action(a: str) -> str:
    return a.strip().lower()


def _statement_has_allow_not_action(stmt: Dict[str, Any]) -> bool:
    if str(stmt.get("Effect", "")).lower() != "allow":
        return False
    return "NotAction" in stmt and stmt.get("NotAction") is not None


def _statement_has_allow_not_resource(stmt: Dict[str, Any]) -> bool:
    if str(stmt.get("Effect", "")).lower() != "allow":
        return False
    return "NotResource" in stmt and stmt.get("NotResource") is not None


def _statement_has_privilege_escalation_actions(
    stmt: Dict[str, Any], escalation_actions: Set[str]
) -> Optional[List[str]]:
    if not escalation_actions or str(stmt.get("Effect", "")).lower() != "allow":
        return None
    actions = _as_list(stmt.get("Action"))
    hit: List[str] = []
    for a in actions:
        if isinstance(a, str):
            an = _normalize_action(a)
            if an in escalation_actions:
                hit.append(a)
            if "*" in escalation_actions and (an == "*" or an.endswith(":*")):
                hit.append(a)
    return hit if hit else None


def check_iam_risky_policies(
    session: Any,
    account_id: Optional[str],
    region: Optional[str],
    config_section: Dict[str, Any],
) -> Tuple[List[Finding], CheckRun]:
    enabled = get_bool(config_section, ["detect_risky_policies"])

    privilege_escalation_actions_raw = get_list_str(config_section, ["privilege_escalation_actions"])
    privilege_escalation_actions: Set[str] = set()
    if privilege_escalation_actions_raw:
        privilege_escalation_actions = {
            _normalize_action(a) for a in privilege_escalation_actions_raw
        }

    detect_not_action = get_bool(config_section, ["detect_allow_not_action"])
    if detect_not_action is None:
        detect_not_action = True
    detect_not_resource = get_bool(config_section, ["detect_allow_not_resource"])
    if detect_not_resource is None:
        detect_not_resource = True

    if not enabled:
        return (
            [
                Finding(
                    service="iam",
                    region=None,
                    resource_type="check",
                    resource_id="risky_policies",
                    issue="risky_policy_check_disabled",
                    severity="info",
                    status="skipped",
                    evidence={"reason": "check_disabled_by_config"},
                )
            ],
            CheckRun(name="iam_risky_policies", status="skipped", message="Check disabled by config."),
        )

    iam = session.client("iam")
    findings: List[Finding] = []

    paginator = iam.get_paginator("list_users")
    users = []
    for page in paginator.paginate():
        users.extend(page.get("Users", []))

    def _process_doc(
        doc: Dict[str, Any],
        resource_id: str,
        policy_arn: Optional[str],
        inline: bool,
    ) -> None:
        stmts = doc.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        for idx, st in enumerate(stmts):
            if not isinstance(st, dict):
                continue
            if detect_not_action and _statement_has_allow_not_action(st):
                findings.append(
                    Finding(
                        service="iam",
                        region=None,
                        resource_type="policy",
                        resource_id=resource_id,
                        issue="policy_allow_not_action",
                        severity="medium",
                        status="finding",
                        evidence={
                            "statement_index": idx,
                            "policy_arn": policy_arn,
                            "inline": inline,
                            "account_id": account_id or "unknown",
                        },
                        remediation="Avoid Effect Allow with NotAction; use explicit Action lists for least privilege.",
                    )
                )
            if detect_not_resource and _statement_has_allow_not_resource(st):
                findings.append(
                    Finding(
                        service="iam",
                        region=None,
                        resource_type="policy",
                        resource_id=resource_id,
                        issue="policy_allow_not_resource",
                        severity="medium",
                        status="finding",
                        evidence={
                            "statement_index": idx,
                            "policy_arn": policy_arn,
                            "inline": inline,
                            "account_id": account_id or "unknown",
                        },
                        remediation="Avoid Effect Allow with NotResource; use explicit Resource lists.",
                    )
                )
            if privilege_escalation_actions:
                hit = _statement_has_privilege_escalation_actions(st, privilege_escalation_actions)
                if hit:
                    findings.append(
                        Finding(
                            service="iam",
                            region=None,
                            resource_type="policy",
                            resource_id=resource_id,
                            issue="policy_privilege_escalation_action",
                            severity="high",
                            status="finding",
                            evidence={
                                "statement_index": idx,
                                "actions": hit,
                                "policy_arn": policy_arn,
                                "inline": inline,
                                "account_id": account_id or "unknown",
                            },
                            remediation="Remove or restrict privilege-escalation-sensitive actions; apply least privilege.",
                        )
                    )

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
            if isinstance(doc, dict):
                _process_doc(doc, f"{user_name}:{pol_name}", pol_arn, False)

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
            if isinstance(pdoc, dict):
                _process_doc(pdoc, f"{user_name}:{pname}", None, True)

    return findings, CheckRun(name="iam_risky_policies", status="ok")
