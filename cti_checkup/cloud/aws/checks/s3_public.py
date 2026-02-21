from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

import botocore

from cti_checkup.core.models import Finding, CheckRun


def _policy_allows_public(policy_doc: Dict[str, Any]) -> bool:
    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for st in statements:
        if str(st.get("Effect", "")).lower() != "allow":
            continue
        principal = st.get("Principal")
        if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
            return True
    return False


def check_s3_public(
    session: Any,
    account_id: Optional[str],
    region: Optional[str],
    config_section: Dict[str, Any],
) -> Tuple[List[Finding], CheckRun]:
    findings: List[Finding] = []
    s3 = session.client("s3")

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except Exception as e:
        return (
            [
                Finding(
                    service="s3",
                    resource_type="service",
                    resource_id="s3",
                    issue="list_buckets_failed",
                    severity="info",
                    status="error",
                    evidence={"error": str(e), "account_id": account_id or "unknown"},
                )
            ],
            CheckRun(name="s3_public", status="error", message=str(e)),
        )

    for b in buckets:
        name = b.get("Name", "unknown")

        bpa = None
        bpa_error = None
        try:
            bpa = s3.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration")
        except botocore.exceptions.ClientError as ce:
            bpa_error = str(ce)

        block_public = False
        if isinstance(bpa, dict):
            vals = [
                bool(bpa.get("BlockPublicAcls")),
                bool(bpa.get("IgnorePublicAcls")),
                bool(bpa.get("BlockPublicPolicy")),
                bool(bpa.get("RestrictPublicBuckets")),
            ]
            block_public = all(vals)

        policy_public = False
        policy_error = None
        try:
            pol = s3.get_bucket_policy(Bucket=name).get("Policy")
            policy_doc = json.loads(pol) if pol else None
            if policy_doc:
                policy_public = _policy_allows_public(policy_doc)
        except botocore.exceptions.ClientError as ce:
            policy_error = str(ce)

        acl_public = False
        acl_error = None
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []):
                gr = grant.get("Grantee", {})
                uri = gr.get("URI", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    acl_public = True
                    break
        except Exception as e:
            acl_error = str(e)

        if not block_public and (policy_public or acl_public):
            findings.append(
                Finding(
                    service="s3",
                    region=None,
                    resource_type="bucket",
                    resource_id=name,
                    issue="public_access_enabled",
                    severity="high",
                    status="finding",
                    evidence={
                        "block_public_access_all_true": block_public,
                        "policy_allows_public": policy_public,
                        "acl_allows_public": acl_public,
                        "policy_error": policy_error,
                        "bpa_error": bpa_error,
                        "acl_error": acl_error,
                        "account_id": account_id or "unknown",
                    },
                    remediation="Enable S3 Block Public Access and remove public bucket policy/ACL grants.",
                )
            )

    return findings, CheckRun(name="s3_public", status="ok")
