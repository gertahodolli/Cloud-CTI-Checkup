"""Unit tests for IAM admin policies check (wildcard admin detection)."""
from __future__ import annotations

from unittest.mock import MagicMock

from cti_checkup.cloud.aws.checks.iam_admin_policies import (
    check_admin_policies,
    _statement_is_admin,
    _policy_doc_is_admin,
)


class TestStatementIsAdmin:
    """Tests for _statement_is_admin helper."""

    def test_allow_wildcard_action_and_resource(self) -> None:
        stmt = {"Effect": "Allow", "Action": "*", "Resource": "*"}
        assert _statement_is_admin(stmt) is True

    def test_allow_list_wildcard(self) -> None:
        stmt = {"Effect": "Allow", "Action": ["s3:GetObject", "*"], "Resource": ["*"]}
        assert _statement_is_admin(stmt) is True

    def test_deny_not_admin(self) -> None:
        stmt = {"Effect": "Deny", "Action": "*", "Resource": "*"}
        assert _statement_is_admin(stmt) is False

    def test_allow_without_wildcard_not_admin(self) -> None:
        stmt = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*"}
        assert _statement_is_admin(stmt) is False

    def test_missing_effect_default_false(self) -> None:
        stmt = {"Action": "*", "Resource": "*"}
        assert _statement_is_admin(stmt) is False


class TestPolicyDocIsAdmin:
    """Tests for _policy_doc_is_admin helper."""

    def test_statement_list_with_admin(self) -> None:
        doc = {
            "Statement": [
                {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"},
                {"Effect": "Allow", "Action": "*", "Resource": "*"},
            ]
        }
        assert _policy_doc_is_admin(doc) is True

    def test_statement_list_no_admin(self) -> None:
        doc = {
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::mybucket/*"},
            ]
        }
        assert _policy_doc_is_admin(doc) is False

    def test_statement_single_dict(self) -> None:
        doc = {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}
        assert _policy_doc_is_admin(doc) is True

    def test_empty_statement(self) -> None:
        assert _policy_doc_is_admin({"Statement": []}) is False


class TestCheckAdminPolicies:
    """Tests for check_admin_policies with mocked boto3."""

    def test_check_disabled(self) -> None:
        session = MagicMock()
        findings, checkrun = check_admin_policies(
            session, "123456789012", "us-east-1", {"detect_admin_policies": False}
        )
        assert len(findings) == 1
        assert findings[0].issue == "admin_policy_check_disabled"
        assert findings[0].status == "skipped"
        assert checkrun.status == "skipped"
        session.client.assert_not_called()

    def test_check_enabled_no_users(self) -> None:
        session = MagicMock()
        iam = MagicMock()
        iam.get_paginator.return_value.paginate.return_value = [{"Users": []}]
        session.client.return_value = iam

        findings, checkrun = check_admin_policies(
            session, "123456789012", None, {"detect_admin_policies": True}
        )
        assert len(findings) == 0
        assert checkrun.name == "iam_admin_policies"
        assert checkrun.status == "ok"

    def test_check_enabled_user_with_non_admin_policy(self) -> None:
        session = MagicMock()
        iam = MagicMock()
        iam.get_paginator.return_value.paginate.return_value = [
            {"Users": [{"UserName": "alice"}]}
        ]
        iam.list_attached_user_policies.return_value = {"AttachedPolicies": []}
        iam.list_user_policies.return_value = {"PolicyNames": []}
        session.client.return_value = iam

        findings, checkrun = check_admin_policies(
            session, "123456789012", None, {"detect_admin_policies": True}
        )
        assert len(findings) == 0
        assert checkrun.status == "ok"

    def test_check_enabled_detects_attached_admin_policy(self) -> None:
        session = MagicMock()
        iam = MagicMock()
        iam.get_paginator.return_value.paginate.return_value = [
            {"Users": [{"UserName": "adminuser"}]}
        ]
        iam.list_attached_user_policies.return_value = {
            "AttachedPolicies": [{"PolicyArn": "arn:aws:iam::123:policy/Admin", "PolicyName": "Admin"}]
        }
        iam.list_user_policies.return_value = {"PolicyNames": []}
        iam.get_policy.return_value = {"Policy": {"DefaultVersionId": "v1"}}
        iam.get_policy_version.return_value = {
            "PolicyVersion": {
                "Document": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
            }
        }
        session.client.return_value = iam

        findings, checkrun = check_admin_policies(
            session, "123456789012", None, {"detect_admin_policies": True}
        )
        assert len(findings) == 1
        assert findings[0].issue == "admin_policy_wildcards_detected"
        assert findings[0].severity == "high"
        assert "adminuser" in findings[0].resource_id
        assert checkrun.status == "ok"

    def test_check_enabled_detects_inline_admin_policy(self) -> None:
        session = MagicMock()
        iam = MagicMock()
        iam.get_paginator.return_value.paginate.return_value = [
            {"Users": [{"UserName": "inlineadmin"}]}
        ]
        iam.list_attached_user_policies.return_value = {"AttachedPolicies": []}
        iam.list_user_policies.return_value = {"PolicyNames": ["InlineAdmin"]}
        iam.get_user_policy.return_value = {
            "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        }
        session.client.return_value = iam

        findings, checkrun = check_admin_policies(
            session, "123456789012", None, {"detect_admin_policies": True}
        )
        assert len(findings) == 1
        assert findings[0].issue == "admin_policy_wildcards_detected"
        assert findings[0].evidence.get("inline") is True
        assert checkrun.status == "ok"
