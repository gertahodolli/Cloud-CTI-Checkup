"""IAM identity risk profiles derived from existing IAM findings."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from cti_checkup.core.config_utils import get_bool, get_int
from cti_checkup.core.models import Finding
from cti_checkup.cloud.aws.runner import run_aws_scan


def _parse_int(value: Any) -> Optional[int]:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        v = value.strip()
        if v.isdigit() or (v.startswith("-") and v[1:].isdigit()):
            return int(v)
    return None


def _load_identity_profile_config(cfg: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    checks_cfg = cfg.get("checks") or {}
    iam_cfg = checks_cfg.get("iam") or {}
    profile_cfg = iam_cfg.get("identity_profile")
    if not isinstance(profile_cfg, dict):
        return False, None, "Missing checks.iam.identity_profile configuration."

    enabled = get_bool(profile_cfg, ["enabled"])
    if enabled is None:
        return False, None, "Missing checks.iam.identity_profile.enabled."
    if not enabled:
        return False, None, None

    scoring_cfg = profile_cfg.get("scoring")
    if not isinstance(scoring_cfg, dict):
        return True, None, "Missing checks.iam.identity_profile.scoring (required)."
    weights_cfg = scoring_cfg.get("weights")
    if not isinstance(weights_cfg, dict):
        return True, None, "Missing checks.iam.identity_profile.scoring.weights (required)."

    weights: Dict[str, int] = {}
    for key in ("no_mfa", "old_keys", "admin_policies", "risky_policies"):
        w = _parse_int(weights_cfg.get(key))
        if w is None:
            return True, None, f"Invalid checks.iam.identity_profile.scoring.weights.{key}."
        weights[key] = w

    include_users = get_bool(profile_cfg, ["include_users"])
    if include_users is None:
        return True, None, "Missing checks.iam.identity_profile.include_users."
    include_roles = get_bool(profile_cfg, ["include_roles"])
    if include_roles is None:
        return True, None, "Missing checks.iam.identity_profile.include_roles."

    top_n = get_int(profile_cfg, ["top_n"])
    if top_n is None or top_n < 1:
        return True, None, "Invalid checks.iam.identity_profile.top_n (required)."

    return True, {
        "weights": weights,
        "include_users": include_users,
        "include_roles": include_roles,
        "top_n": top_n,
    }, None


def _extract_identity(finding: Finding) -> Tuple[Optional[str], Optional[str]]:
    if finding.resource_type == "user":
        return finding.resource_id, "user"
    if finding.resource_type == "role":
        return finding.resource_id, "role"
    if finding.resource_type in ("access_key", "policy"):
        if ":" in finding.resource_id:
            return finding.resource_id.split(":", 1)[0], "user"
    evidence = finding.evidence or {}
    user_name = evidence.get("user_name")
    if isinstance(user_name, str) and user_name.strip():
        return user_name.strip(), "user"
    role_name = evidence.get("role_name")
    if isinstance(role_name, str) and role_name.strip():
        return role_name.strip(), "role"
    return None, None


def build_identity_profiles(
    findings: List[Finding], profile_cfg: Dict[str, Any]
) -> List[Dict[str, Any]]:
    weights = profile_cfg["weights"]
    include_users = profile_cfg["include_users"]
    include_roles = profile_cfg["include_roles"]

    profiles: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        if f.status != "finding":
            continue
        identity, identity_type = _extract_identity(f)
        if not identity or not identity_type:
            continue
        if identity_type == "user" and not include_users:
            continue
        if identity_type == "role" and not include_roles:
            continue

        key = f"{identity_type}:{identity}"
        if key not in profiles:
            profiles[key] = {
                "identity": identity,
                "type": identity_type,
                "counts": {
                    "no_mfa": 0,
                    "old_keys": 0,
                    "admin_policies": 0,
                    "risky_policies": 0,
                },
            }

        counts = profiles[key]["counts"]
        if f.issue == "mfa_not_enabled":
            counts["no_mfa"] += 1
        elif f.issue in (
            "access_key_older_than_threshold",
            "access_key_unused_over_threshold",
            "access_key_never_used",
        ):
            counts["old_keys"] += 1
        elif f.issue == "admin_policy_wildcards_detected":
            counts["admin_policies"] += 1
        elif f.issue in (
            "policy_allow_not_action",
            "policy_allow_not_resource",
            "policy_privilege_escalation_action",
        ):
            counts["risky_policies"] += 1

    result: List[Dict[str, Any]] = []
    for profile in profiles.values():
        counts = profile["counts"]
        score = (
            counts["no_mfa"] * weights["no_mfa"]
            + counts["old_keys"] * weights["old_keys"]
            + counts["admin_policies"] * weights["admin_policies"]
            + counts["risky_policies"] * weights["risky_policies"]
        )
        if score > 100:
            score = 100
        if score < 0:
            score = 0
        risk_factors = []
        for key in ("no_mfa", "old_keys", "admin_policies", "risky_policies"):
            if counts[key] > 0:
                risk_factors.append(key)
        result.append(
            {
                "identity": profile["identity"],
                "type": profile["type"],
                "risk_score": int(score),
                "risk_factors": risk_factors,
                "counts": counts,
            }
        )

    result.sort(key=lambda x: (-x.get("risk_score", 0), x.get("identity", "")))
    return result


def render_identity_profiles_human(result: Dict[str, Any], fmt: str = "table") -> str:
    profiles = result.get("identities", [])
    summary = result.get("summary", {})
    errors = result.get("errors") or []
    lines = []
    lines.append(
        f"iam identity profiles | identities={summary.get('total_identities', 0)}"
    )
    lines.append("")
    if errors:
        lines.append("Errors:")
        for err in errors:
            lines.append(f"- {err}")
        lines.append("")

    if fmt == "text":
        for p in profiles:
            lines.append(
                f"{p.get('identity')} type={p.get('type')} score={p.get('risk_score')}"
            )
        return "\n".join(lines)

    header = ["Identity", "Type", "Risk Score", "Top Factors"]
    rows = []
    for p in profiles:
        rows.append(
            [
                p.get("identity", ""),
                p.get("type", ""),
                str(p.get("risk_score", "")),
                ", ".join(p.get("risk_factors", []) or []) or "none",
            ]
        )

    if not rows:
        lines.append("No identities found.")
        return "\n".join(lines)

    widths = [len(h) for h in header]
    for r in rows:
        widths = [max(widths[i], len(str(r[i]))) for i in range(len(header))]

    def fmt_row(r: List[str]) -> str:
        return " | ".join(str(r[i]).ljust(widths[i]) for i in range(len(header)))

    lines.append(fmt_row(header))
    lines.append("-+-".join("-" * w for w in widths))
    for r in rows:
        lines.append(fmt_row(r))

    return "\n".join(lines)


def run_iam_identity_profiles(
    cfg: Dict[str, Any], profile: Optional[str], strict: bool
) -> Tuple[Dict[str, Any], bool, bool]:
    enabled, profile_cfg, config_error = _load_identity_profile_config(cfg)
    if config_error:
        return {
            "identities": [],
            "summary": {"total_identities": 0},
            "errors": [config_error],
        }, True, False
    if not enabled:
        return {
            "identities": [],
            "summary": {"total_identities": 0, "disabled": True},
        }, False, False

    assert profile_cfg is not None
    scan_result = run_aws_scan(cfg=cfg, profile=profile, regions=None, strict=strict, services=["iam"])
    all_profiles = build_identity_profiles(scan_result.findings, profile_cfg)

    top_n = profile_cfg["top_n"]
    profiles = all_profiles[:top_n]

    summary = {
        "total_identities": len(all_profiles),
        "top_n": top_n,
    }

    result = {
        "identities": profiles,
        "summary": summary,
    }
    partial = bool(scan_result.partial_failure)
    fatal = bool(scan_result.fatal_error)
    return result, partial, fatal
