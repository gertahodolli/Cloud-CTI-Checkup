"""Unit test for IAM MFA and old keys check; mocks boto3."""
from __future__ import annotations

from unittest.mock import MagicMock

from cti_checkup.cloud.aws.checks.iam_basic import check_iam_mfa_and_old_keys


def test_iam_basic_no_users() -> None:
    session = MagicMock()
    iam = MagicMock()
    iam.get_paginator.return_value.paginate.return_value = [{"Users": []}]
    session.client.return_value = iam

    findings, checkrun = check_iam_mfa_and_old_keys(
        session, "123456789012", None, {"max_access_key_age_days": 90}
    )

    assert len(findings) == 0
    assert checkrun.name == "iam_basic"
    assert checkrun.status == "ok"


def test_iam_basic_mfa_not_enabled() -> None:
    session = MagicMock()
    iam = MagicMock()
    iam.get_paginator.return_value.paginate.return_value = [{"Users": [{"UserName": "alice"}]}]
    iam.list_mfa_devices.return_value = {"MFADevices": []}
    iam.list_access_keys.return_value = {"AccessKeyMetadata": []}
    session.client.return_value = iam

    findings, checkrun = check_iam_mfa_and_old_keys(session, "123456789012", None, {})

    assert len(findings) >= 1
    f = next(x for x in findings if x.issue == "mfa_not_enabled")
    assert f.severity == "high"
    assert "user_name" in f.evidence
    assert "account_id" in f.evidence


def test_iam_basic_list_users_fails() -> None:
    session = MagicMock()
    iam = MagicMock()
    iam.get_paginator.return_value.paginate.side_effect = Exception("AccessDenied")
    session.client.return_value = iam

    findings, checkrun = check_iam_mfa_and_old_keys(session, "123456789012", None, {})

    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert findings[0].issue == "list_users_failed"
    assert "error" in findings[0].evidence
    assert checkrun.status == "error"
