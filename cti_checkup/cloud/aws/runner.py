from __future__ import annotations

from typing import Any, Dict, List, Optional

from cti_checkup.core.models import ScanResult, CheckRun
from cti_checkup.core.config_utils import get_list_str
from cti_checkup.core.risk import compute_risk_score
from cti_checkup.core.finding_id import assign_finding_ids_and_dedup
from cti_checkup.cloud.aws.session import make_boto_session
from cti_checkup.cloud.aws.identity import get_account_id_from_session
from cti_checkup.cloud.aws.regions import discover_regions_from_session

from cti_checkup.cloud.aws.checks.s3_public import check_s3_public
from cti_checkup.cloud.aws.checks.s3_encryption import check_s3_default_encryption
from cti_checkup.cloud.aws.checks.s3_versioning import check_s3_versioning
from cti_checkup.cloud.aws.checks.s3_logging import check_s3_logging

from cti_checkup.cloud.aws.checks.iam_basic import check_iam_mfa_and_old_keys
from cti_checkup.cloud.aws.checks.iam_root_mfa import check_root_mfa
from cti_checkup.cloud.aws.checks.iam_unused_keys import check_unused_access_keys
from cti_checkup.cloud.aws.checks.iam_admin_policies import check_admin_policies
from cti_checkup.cloud.aws.checks.iam_risky_policies import check_iam_risky_policies

from cti_checkup.cloud.aws.checks.ec2_sg_exposure import check_ec2_sg_exposure
from cti_checkup.cloud.aws.checks.ec2_unused_sg import check_ec2_unused_sg


def _count_summary(result: ScanResult) -> None:
    for f in result.findings:
        if f.status == "skipped":
            result.summary.skipped += 1
        elif f.status == "error":
            result.summary.errors += 1
        else:
            if f.severity == "critical":
                result.summary.critical += 1
            elif f.severity == "high":
                result.summary.high += 1
            elif f.severity == "medium":
                result.summary.medium += 1
            elif f.severity == "low":
                result.summary.low += 1
            else:
                result.summary.info += 1


def _services_enabled(cfg: Dict[str, Any]) -> List[str]:
    aws_cfg = cfg.get("aws") or {}
    raw = get_list_str(aws_cfg, ["enabled_services"])
    if raw is not None:
        return [s.strip().lower() for s in raw if s.strip() in ("s3", "iam", "ec2")]
    return ["s3", "iam", "ec2"]


def run_aws_scan(
    cfg: Dict[str, Any],
    profile: Optional[str],
    regions: Optional[List[str]],
    strict: bool,
    services: Optional[List[str]] = None,
) -> ScanResult:
    result = ScanResult(provider="aws")
    session = make_boto_session(profile)

    try:
        result.account_id = get_account_id_from_session(session)
    except Exception as e:
        result.fatal_error = True
        result.checks.append(CheckRun(name="aws_identity", status="error", message=str(e)))
        return result

    if services is None:
        services = _services_enabled(cfg)

    try:
        if any(s in services for s in ["s3", "ec2"]):
            if regions is None or len(regions) == 0:
                regions = discover_regions_from_session(session)
            result.regions = regions or []
        else:
            result.regions = []
    except Exception as e:
        if strict:
            result.fatal_error = True
            result.checks.append(CheckRun(name="region_discovery", status="error", message=str(e)))
            return result
        result.partial_failure = True
        result.checks.append(CheckRun(name="region_discovery", status="error", message=str(e)))
        regions = []
        result.regions = []

    checks_cfg = cfg.get("checks") or {}
    s3_cfg = {**(checks_cfg.get("s3") or {}), "_strict": strict}
    iam_cfg = {**(checks_cfg.get("iam") or {}), "_strict": strict}
    ec2_cfg = {**(checks_cfg.get("ec2") or {}), "_strict": strict}

    try:
        if "s3" in services:
            findings, checkrun = check_s3_public(session, result.account_id, None, s3_cfg)
            result.findings.extend(findings)
            result.checks.append(checkrun)

            findings, checkrun = check_s3_default_encryption(session, result.account_id, None, s3_cfg)
            result.findings.extend(findings)
            result.checks.append(checkrun)

            findings, checkrun = check_s3_versioning(session, result.account_id, None, s3_cfg)
            result.findings.extend(findings)
            result.checks.append(checkrun)

            findings, checkrun = check_s3_logging(session, result.account_id, None, s3_cfg)
            result.findings.extend(findings)
            result.checks.append(checkrun)

        if "iam" in services:
            findings, checkrun = check_iam_mfa_and_old_keys(session, result.account_id, None, iam_cfg)
            result.findings.extend(findings)
            result.checks.append(checkrun)

            findings, checkrun = check_root_mfa(session, result.account_id, None, iam_cfg)
            result.findings.extend(findings)
            result.checks.append(checkrun)

            findings, checkrun = check_unused_access_keys(session, result.account_id, None, iam_cfg)
            result.findings.extend(findings)
            result.checks.append(checkrun)

            findings, checkrun = check_admin_policies(session, result.account_id, None, iam_cfg)
            result.findings.extend(findings)
            result.checks.append(checkrun)

            findings, checkrun = check_iam_risky_policies(session, result.account_id, None, iam_cfg)
            result.findings.extend(findings)
            result.checks.append(checkrun)

        if "ec2" in services:
            reg_list = regions or []
            if not reg_list:
                result.checks.append(
                    CheckRun(name="ec2_sg_exposure", status="error", message="No regions provided for EC2 scan.")
                )
            else:
                for r in reg_list:
                    findings, checkrun = check_ec2_sg_exposure(session, result.account_id, r, ec2_cfg)
                    result.findings.extend(findings)
                    result.checks.append(checkrun)
                    findings, checkrun = check_ec2_unused_sg(session, result.account_id, r, ec2_cfg)
                    result.findings.extend(findings)
                    result.checks.append(checkrun)

    except Exception as e:
        result.partial_failure = True
        result.checks.append(CheckRun(name="scan", status="error", message=str(e)))

    result.findings = assign_finding_ids_and_dedup(result.provider, result.findings)
    _count_summary(result)
    result.risk_score, result.risk_score_explanation = compute_risk_score(result, cfg)
    return result
