"""Tests for IAM identity profiles."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from cti_checkup.aws.iam_identity_profile import build_identity_profiles, run_iam_identity_profiles
from cti_checkup.core.models import Finding


def test_identity_profile_scoring_unit() -> None:
    findings = [
        Finding(
            service="iam",
            resource_type="user",
            resource_id="alice",
            issue="mfa_not_enabled",
            severity="high",
            status="finding",
            evidence={},
        ),
        Finding(
            service="iam",
            resource_type="access_key",
            resource_id="alice:AKIA1234567890123456",
            issue="access_key_older_than_threshold",
            severity="medium",
            status="finding",
            evidence={},
        ),
        Finding(
            service="iam",
            resource_type="policy",
            resource_id="alice:Admin",
            issue="admin_policy_wildcards_detected",
            severity="high",
            status="finding",
            evidence={},
        ),
        Finding(
            service="iam",
            resource_type="policy",
            resource_id="bob:Policy",
            issue="policy_allow_not_action",
            severity="medium",
            status="finding",
            evidence={},
        ),
    ]
    profile_cfg = {
        "weights": {
            "no_mfa": 50,
            "old_keys": 20,
            "admin_policies": 30,
            "risky_policies": 10,
        },
        "include_users": True,
        "include_roles": False,
        "top_n": 10,
    }

    profiles = build_identity_profiles(findings, profile_cfg)

    assert len(profiles) == 2
    assert profiles[0]["identity"] == "alice"
    assert profiles[0]["risk_score"] == 100
    assert "no_mfa" in profiles[0]["risk_factors"]
    assert "admin_policies" in profiles[0]["risk_factors"]
    assert profiles[1]["identity"] == "bob"
    assert profiles[1]["risk_score"] == 10


def test_identity_profile_integration(monkeypatch) -> None:
    now = datetime.now(timezone.utc)
    iam = MagicMock()
    iam.get_paginator.return_value.paginate.return_value = [{"Users": [{"UserName": "alice"}]}]
    iam.list_mfa_devices.return_value = {"MFADevices": []}
    iam.list_access_keys.return_value = {
        "AccessKeyMetadata": [
            {
                "AccessKeyId": "AKIA1234567890123456",
                "CreateDate": now - timedelta(days=100),
                "Status": "Active",
            }
        ]
    }
    iam.get_access_key_last_used.return_value = {
        "AccessKeyLastUsed": {"LastUsedDate": now - timedelta(days=200)}
    }

    session = MagicMock()

    def _client(name: str):
        if name == "iam":
            return iam
        if name == "sts":
            sts = MagicMock()
            sts.get_caller_identity.return_value = {"Account": "123456789012"}
            return sts
        return MagicMock()

    session.client.side_effect = _client

    monkeypatch.setattr(
        "cti_checkup.cloud.aws.runner.make_boto_session", lambda profile: session
    )
    monkeypatch.setattr(
        "cti_checkup.cloud.aws.runner.get_account_id_from_session",
        lambda sess: "123456789012",
    )

    cfg = {
        "checks": {
            "iam": {
                "max_access_key_age_days": 90,
                "max_access_key_unused_days": 30,
                "check_root_mfa": False,
                "detect_admin_policies": False,
                "detect_risky_policies": False,
                "identity_profile": {
                    "enabled": True,
                    "scoring": {
                        "weights": {
                            "no_mfa": 50,
                            "old_keys": 20,
                            "admin_policies": 30,
                            "risky_policies": 10,
                        }
                    },
                    "include_users": True,
                    "include_roles": False,
                    "top_n": 10,
                },
            }
        }
    }

    result, partial, fatal = run_iam_identity_profiles(cfg, profile=None, strict=False)

    assert fatal is False
    assert partial is False
    assert result["summary"]["total_identities"] == 1
    profile = result["identities"][0]
    assert profile["identity"] == "alice"
    assert profile["counts"]["no_mfa"] == 1
    assert profile["counts"]["old_keys"] == 2
    assert profile["risk_score"] == 90
