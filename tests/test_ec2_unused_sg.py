"""Unit tests for EC2 unused security groups check."""
from __future__ import annotations

from unittest.mock import MagicMock

from cti_checkup.cloud.aws.checks.ec2_unused_sg import check_ec2_unused_sg


def test_ec2_unused_sg_check_disabled() -> None:
    session = MagicMock()
    findings, checkrun = check_ec2_unused_sg(
        session, "123456789012", "us-east-1", {"check_unused_security_groups": False}
    )
    assert len(findings) == 1
    assert findings[0].issue == "unused_sg_check_disabled"
    assert findings[0].status == "skipped"
    assert checkrun.status == "skipped"
    session.client.assert_not_called()


def test_ec2_unused_sg_requires_region() -> None:
    session = MagicMock()
    findings, checkrun = check_ec2_unused_sg(
        session, "123456789012", None, {"check_unused_security_groups": True}
    )
    assert len(findings) == 0
    assert checkrun.status == "error"
    assert "region" in checkrun.message.lower()
    session.client.assert_not_called()


def test_ec2_unused_sg_all_attached_no_findings() -> None:
    session = MagicMock()
    ec2 = MagicMock()
    ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {"GroupId": "sg-111", "GroupName": "web", "VpcId": "vpc-aaa"},
            {"GroupId": "sg-222", "GroupName": "db", "VpcId": "vpc-aaa"},
        ]
    }
    ec2.describe_network_interfaces.return_value = {
        "NetworkInterfaces": [
            {"Groups": [{"GroupId": "sg-111"}]},
            {"Groups": [{"GroupId": "sg-222"}]},
        ]
    }
    session.client.return_value = ec2

    findings, checkrun = check_ec2_unused_sg(
        session, "123456789012", "us-east-1", {"check_unused_security_groups": True}
    )
    assert len(findings) == 0
    assert checkrun.status == "ok"


def test_ec2_unused_sg_finds_unused() -> None:
    session = MagicMock()
    ec2 = MagicMock()
    ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {"GroupId": "sg-attached", "GroupName": "used", "VpcId": "vpc-aaa"},
            {"GroupId": "sg-unused", "GroupName": "orphan", "VpcId": "vpc-aaa"},
        ]
    }
    ec2.describe_network_interfaces.return_value = {
        "NetworkInterfaces": [
            {"Groups": [{"GroupId": "sg-attached"}]},
        ]
    }
    session.client.return_value = ec2

    findings, checkrun = check_ec2_unused_sg(
        session, "123456789012", "us-east-1", {"check_unused_security_groups": True}
    )
    assert len(findings) == 1
    assert findings[0].issue == "security_group_unused"
    assert findings[0].severity == "low"
    assert "sg-unused" in findings[0].resource_id
    assert "orphan" in findings[0].resource_id
    assert checkrun.status == "ok"


def test_ec2_unused_sg_skips_default_sg_with_vpc() -> None:
    session = MagicMock()
    ec2 = MagicMock()
    ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {"GroupId": "sg-default", "GroupName": "default", "VpcId": "vpc-aaa"},
        ]
    }
    ec2.describe_network_interfaces.return_value = {"NetworkInterfaces": []}
    session.client.return_value = ec2

    findings, checkrun = check_ec2_unused_sg(
        session, "123456789012", "us-east-1", {"check_unused_security_groups": True}
    )
    assert len(findings) == 0
    assert checkrun.status == "ok"


def test_ec2_unused_sg_describe_sg_fails() -> None:
    session = MagicMock()
    ec2 = MagicMock()
    ec2.describe_security_groups.side_effect = Exception("AccessDenied")
    session.client.return_value = ec2

    findings, checkrun = check_ec2_unused_sg(
        session, "123456789012", "us-east-1", {"check_unused_security_groups": True}
    )
    assert len(findings) == 1
    assert findings[0].issue == "describe_security_groups_failed"
    assert checkrun.status == "error"
