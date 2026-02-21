from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import botocore

from cti_checkup.core.models import Finding, CheckRun
from cti_checkup.core.config_utils import get_bool, get_list_str


def check_s3_default_encryption(
    session: Any,
    account_id: Optional[str],
    region: Optional[str],
    config_section: Dict[str, Any],
) -> Tuple[List[Finding], CheckRun]:
    require_enc = get_bool(config_section, ["require_default_encryption"])
    allowed = get_list_str(config_section, ["allowed_sse_algorithms"])

    if not require_enc:
        return (
            [
                Finding(
                    service="s3",
                    region=None,
                    resource_type="check",
                    resource_id="s3_default_encryption",
                    issue="default_encryption_check_disabled",
                    severity="info",
                    status="skipped",
                    evidence={"reason": "check_disabled_by_config"},
                )
            ],
            CheckRun(name="s3_default_encryption", status="skipped", message="Check disabled by config."),
        )

    if allowed is None:
        msg = "Missing allowed_sse_algorithms in config"
        strict = config_section.get("_strict", False)
        if strict:
            return ([], CheckRun(name="s3_default_encryption", status="error", message=msg))
        return (
            [
                Finding(
                    service="s3",
                    region=None,
                    resource_type="check",
                    resource_id="s3_default_encryption",
                    issue="missing_allowed_sse_algorithms_config",
                    severity="info",
                    status="skipped",
                    evidence={"message": msg, "reason": "config_missing"},
                )
            ],
            CheckRun(name="s3_default_encryption", status="skipped", message=msg),
        )

    s3 = session.client("s3")

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except Exception as e:
        return (
            [
                Finding(
                    service="s3",
                    region=None,
                    resource_type="service",
                    resource_id="s3",
                    issue="list_buckets_failed",
                    severity="info",
                    status="error",
                    evidence={"error": str(e), "account_id": account_id or "unknown"},
                )
            ],
            CheckRun(name="s3_default_encryption", status="error", message=str(e)),
        )

    findings: List[Finding] = []
    for b in buckets:
        name = b.get("Name", "unknown")

        try:
            enc = s3.get_bucket_encryption(Bucket=name)
            rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            algo = None
            kms_key = None
            if rules:
                default = rules[0].get("ApplyServerSideEncryptionByDefault", {})
                algo = default.get("SSEAlgorithm")
                kms_key = default.get("KMSMasterKeyID")
        except botocore.exceptions.ClientError as ce:
            findings.append(
                Finding(
                    service="s3",
                    region=None,
                    resource_type="bucket",
                    resource_id=name,
                    issue="default_encryption_not_configured",
                    severity="medium",
                    status="finding",
                    evidence={"error": str(ce), "bucket": name, "account_id": account_id or "unknown"},
                    remediation="Enable default server-side encryption for the bucket (AES256 or aws:kms).",
                )
            )
            continue
        except Exception as e:
            findings.append(
                Finding(
                    service="s3",
                    region=None,
                    resource_type="bucket",
                    resource_id=name,
                    issue="default_encryption_check_failed",
                    severity="info",
                    status="error",
                    evidence={"error": str(e), "bucket": name},
                )
            )
            continue

        if not algo or algo not in allowed:
            findings.append(
                Finding(
                    service="s3",
                    region=None,
                    resource_type="bucket",
                    resource_id=name,
                    issue="default_encryption_algorithm_not_allowed",
                    severity="medium",
                    status="finding",
                    evidence={
                        "sse_algorithm": algo,
                        "kms_key_id": kms_key,
                        "allowed": allowed,
                        "bucket": name,
                        "account_id": account_id or "unknown",
                    },
                    remediation="Set bucket default encryption to an allowed algorithm (per your policy).",
                )
            )

    return findings, CheckRun(name="s3_default_encryption", status="ok")
