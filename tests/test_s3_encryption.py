"""Unit test for S3 default encryption check; mocks boto3."""
from __future__ import annotations

from unittest.mock import MagicMock

import botocore.exceptions

from cti_checkup.cloud.aws.checks.s3_encryption import check_s3_default_encryption


def test_s3_encryption_check_disabled() -> None:
    session = MagicMock()
    findings, checkrun = check_s3_default_encryption(
        session, "123456789012", None, {"require_default_encryption": False}
    )

    assert len(findings) == 1
    assert findings[0].status == "skipped"
    assert "reason" in findings[0].evidence
    assert checkrun.status == "skipped"


def test_s3_encryption_bucket_unencrypted() -> None:
    session = MagicMock()
    s3 = MagicMock()
    s3.list_buckets.return_value = {"Buckets": [{"Name": "b1"}]}
    s3.get_bucket_encryption.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError", "Message": "none"}},
        "GetBucketEncryption",
    )
    session.client.return_value = s3

    findings, checkrun = check_s3_default_encryption(
        session,
        "123456789012",
        None,
        {"require_default_encryption": True, "allowed_sse_algorithms": ["AES256", "aws:kms"]},
    )

    assert len(findings) >= 1
    f = next(x for x in findings if x.issue == "default_encryption_not_configured")
    assert f.severity == "medium"
    assert "bucket" in f.evidence
    assert "account_id" in f.evidence
