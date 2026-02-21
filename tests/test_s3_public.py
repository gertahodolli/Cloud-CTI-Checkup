"""Unit test for S3 public access check; mocks boto3."""
from __future__ import annotations

from unittest.mock import MagicMock

import botocore.exceptions

from cti_checkup.cloud.aws.checks.s3_public import check_s3_public


def test_s3_public_no_buckets() -> None:
    session = MagicMock()
    s3 = MagicMock()
    s3.list_buckets.return_value = {"Buckets": []}
    session.client.return_value = s3

    findings, checkrun = check_s3_public(session, "123456789012", None, {})

    assert len(findings) == 0
    assert checkrun.name == "s3_public"
    assert checkrun.status == "ok"


def test_s3_public_list_buckets_fails() -> None:
    session = MagicMock()
    s3 = MagicMock()
    s3.list_buckets.side_effect = Exception("AccessDenied")
    session.client.return_value = s3

    findings, checkrun = check_s3_public(session, "123456789012", None, {})

    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert findings[0].issue == "list_buckets_failed"
    assert "error" in findings[0].evidence
    assert "account_id" in findings[0].evidence
    assert checkrun.status == "error"


def test_s3_public_bucket_public_finding() -> None:
    session = MagicMock()
    s3 = MagicMock()
    s3.list_buckets.return_value = {"Buckets": [{"Name": "mybucket"}]}
    s3.get_public_access_block.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchPublicAccessBlockConfiguration", "Message": "none"}}, "GetPublicAccessBlock"
    )
    s3.get_bucket_policy.return_value = {
        "Policy": '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject"}]}'
    }
    s3.get_bucket_acl.return_value = {"Grants": []}
    session.client.return_value = s3

    findings, checkrun = check_s3_public(session, "123456789012", None, {})

    assert len(findings) >= 1
    f = next(x for x in findings if x.issue == "public_access_enabled")
    assert f.severity == "high"
    assert "block_public_access_all_true" in f.evidence
    assert "policy_allows_public" in f.evidence
    assert "account_id" in f.evidence
