"""EC2 unused security groups: SGs not attached to any ENI."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from cti_checkup.core.models import Finding, CheckRun
from cti_checkup.core.config_utils import get_bool


def check_ec2_unused_sg(
    session: Any,
    account_id: Optional[str],
    region: Optional[str],
    config_section: Dict[str, Any],
) -> Tuple[List[Finding], CheckRun]:
    enabled = get_bool(config_section, ["check_unused_security_groups"])

    if not enabled:
        return (
            [
                Finding(
                    service="ec2",
                    region=region or None,
                    resource_type="check",
                    resource_id="ec2_unused_sg",
                    issue="unused_sg_check_disabled",
                    severity="info",
                    status="skipped",
                    evidence={"reason": "check_disabled_by_config"},
                )
            ],
            CheckRun(name="ec2_unused_sg", status="skipped", message="Check disabled by config."),
        )

    if region is None:
        return ([], CheckRun(name="ec2_unused_sg", status="error", message="EC2 check requires a region."))

    ec2 = session.client("ec2", region_name=region)
    findings: List[Finding] = []

    try:
        sg_resp = ec2.describe_security_groups()
        all_sgs = sg_resp.get("SecurityGroups", [])
    except Exception as e:
        findings.append(
            Finding(
                service="ec2",
                region=region,
                resource_type="service",
                resource_id="ec2",
                issue="describe_security_groups_failed",
                severity="info",
                status="error",
                evidence={
                    "error": str(e),
                    "region": region,
                    "account_id": account_id or "unknown",
                },
            )
        )
        return findings, CheckRun(name="ec2_unused_sg", status="error", message=str(e))

    try:
        eni_resp = ec2.describe_network_interfaces()
        enis = eni_resp.get("NetworkInterfaces", [])
    except Exception as e:
        findings.append(
            Finding(
                service="ec2",
                region=region,
                resource_type="service",
                resource_id="ec2",
                issue="describe_network_interfaces_failed",
                severity="info",
                status="error",
                evidence={
                    "error": str(e),
                    "region": region,
                    "account_id": account_id or "unknown",
                },
            )
        )
        return findings, CheckRun(name="ec2_unused_sg", status="error", message=str(e))

    attached_sg_ids: Set[str] = set()
    for eni in enis:
        for grp in eni.get("Groups", []) or []:
            gid = grp.get("GroupId") if isinstance(grp, dict) else None
            if gid:
                attached_sg_ids.add(gid)

    for sg in all_sgs:
        if sg.get("GroupName") == "default":
            sg.get("VpcId")
            break

    for sg in all_sgs:
        sg_id = sg.get("GroupId", "unknown")
        sg_name = sg.get("GroupName", "unknown")
        vpc_id = sg.get("VpcId", "")
        if sg_id in attached_sg_ids:
            continue
        if sg_name == "default" and vpc_id:
            continue
        findings.append(
            Finding(
                service="ec2",
                region=region,
                resource_type="security_group",
                resource_id=f"{sg_id}({sg_name})",
                issue="security_group_unused",
                severity="low",
                status="finding",
                evidence={
                    "group_id": sg_id,
                    "group_name": sg_name,
                    "vpc_id": vpc_id,
                    "region": region,
                    "account_id": account_id or "unknown",
                },
                remediation="Remove unused security groups to reduce clutter and avoid misuse.",
            )
        )

    return findings, CheckRun(name="ec2_unused_sg", status="ok")
