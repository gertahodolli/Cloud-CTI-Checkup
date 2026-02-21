from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from cti_checkup.core.models import Finding, CheckRun
from cti_checkup.core.config_utils import get_list_int, get_list_str


def _cidr_is_disallowed(cidr: str, allowed_cidrs: Optional[List[str]]) -> bool:
    if not cidr or not cidr.strip():
        return False
    cidr = cidr.strip()
    if allowed_cidrs is None or len(allowed_cidrs) == 0:
        return cidr == "0.0.0.0/0" or cidr == "::/0"
    return cidr not in allowed_cidrs


def check_ec2_sg_exposure(
    session: Any,
    account_id: Optional[str],
    region: Optional[str],
    config_section: Dict[str, Any],
) -> Tuple[List[Finding], CheckRun]:
    ports = get_list_int(config_section, ["sensitive_ports"])
    allowed_cidrs = get_list_str(config_section, ["allowed_cidrs"])
    strict = config_section.get("_strict", False)

    if ports is None:
        if strict:
            return (
                [],
                CheckRun(
                    name="ec2_sg_exposure",
                    status="error",
                    message="Missing sensitive_ports (required in strict mode).",
                ),
            )
        return (
            [
                Finding(
                    service="ec2",
                    region=region or None,
                    resource_type="check",
                    resource_id="ec2_sg_exposure",
                    issue="missing_sensitive_ports_config",
                    severity="info",
                    status="skipped",
                    evidence={"reason": "config_missing"},
                )
            ],
            CheckRun(name="ec2_sg_exposure", status="skipped", message="No sensitive_ports configured."),
        )

    if region is None:
        return ([], CheckRun(name="ec2_sg_exposure", status="error", message="EC2 check requires a region."))

    findings: List[Finding] = []
    ec2 = session.client("ec2", region_name=region)

    try:
        resp = ec2.describe_security_groups()
        sgs = resp.get("SecurityGroups", [])
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
        return findings, CheckRun(name="ec2_sg_exposure", status="error", message=str(e))

    for sg in sgs:
        sg_id = sg.get("GroupId", "unknown")
        sg_name = sg.get("GroupName", "unknown")
        ingress = sg.get("IpPermissions", [])

        for perm in ingress:
            ip_proto = perm.get("IpProtocol")
            from_port = perm.get("FromPort")
            to_port = perm.get("ToPort")

            port_range_all = (from_port is None and to_port is None) or ip_proto == "-1"

            ranges_v4 = perm.get("IpRanges", [])
            ranges_v6 = perm.get("Ipv6Ranges", [])
            has_disallowed_v4 = any(
                _cidr_is_disallowed(r.get("CidrIp", ""), allowed_cidrs) for r in ranges_v4
            )
            has_disallowed_v6 = any(
                _cidr_is_disallowed(r.get("CidrIpv6", ""), allowed_cidrs) for r in ranges_v6
            )
            if not (has_disallowed_v4 or has_disallowed_v6):
                continue

            if port_range_all:
                findings.append(
                    Finding(
                        service="ec2",
                        region=region,
                        resource_type="security_group",
                        resource_id=f"{sg_id}({sg_name})",
                        issue="security_group_all_ports_open_to_world",
                        severity="critical",
                        evidence={
                            "ip_protocol": ip_proto,
                            "from_port": from_port,
                            "to_port": to_port,
                            "region": region,
                            "account_id": account_id or "unknown",
                        },
                        remediation="Restrict inbound rules to specific CIDRs and required ports only.",
                    )
                )
                continue

            try:
                fp = int(from_port)
                tp = int(to_port)
            except (TypeError, ValueError):
                continue

            hit_ports = [p for p in ports if fp <= p <= tp]
            if hit_ports:
                findings.append(
                    Finding(
                        service="ec2",
                        region=region,
                        resource_type="security_group",
                        resource_id=f"{sg_id}({sg_name})",
                        issue="security_group_sensitive_port_open_to_world",
                        severity="high",
                        evidence={
                            "open_range": f"{fp}-{tp}",
                            "sensitive_ports": hit_ports,
                            "region": region,
                            "account_id": account_id or "unknown",
                        },
                        remediation="Restrict inbound rules; avoid exposing sensitive management ports to the internet.",
                    )
                )

    return findings, CheckRun(name="ec2_sg_exposure", status="ok")
