"""Unit test for EC2 security group exposure check; mocks boto3."""
from __future__ import annotations

from unittest.mock import MagicMock

from cti_checkup.cloud.aws.checks.ec2_sg_exposure import check_ec2_sg_exposure


def test_ec2_sg_exposure_no_sensitive_ports_skipped() -> None:
    session = MagicMock()
    findings, checkrun = check_ec2_sg_exposure(
        session, "123456789012", "us-east-1", {"_strict": False}
    )

    assert len(findings) == 1
    assert findings[0].status == "skipped"
    assert "reason" in findings[0].evidence
    assert checkrun.status == "skipped"


def test_ec2_sg_exposure_no_exposed_ports() -> None:
    session = MagicMock()
    ec2 = MagicMock()
    ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {"GroupId": "sg-123", "GroupName": "my-sg", "IpPermissions": []}
        ]
    }
    session.client.return_value = ec2

    findings, checkrun = check_ec2_sg_exposure(
        session, "123456789012", "us-east-1", {"sensitive_ports": [22, 3389], "_strict": True}
    )

    assert len(findings) == 0
    assert checkrun.name == "ec2_sg_exposure"
    assert checkrun.status == "ok"


def test_ec2_sg_exposure_sensitive_port_open() -> None:
    session = MagicMock()
    ec2 = MagicMock()
    ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-123",
                "GroupName": "bad-sg",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        "Ipv6Ranges": [],
                    }
                ],
            }
        ]
    }
    session.client.return_value = ec2

    findings, checkrun = check_ec2_sg_exposure(
        session, "123456789012", "us-east-1", {"sensitive_ports": [22, 3389], "_strict": True}
    )

    assert len(findings) >= 1
    f = next(x for x in findings if x.issue == "security_group_sensitive_port_open_to_world")
    assert f.severity == "high"
    assert "sensitive_ports" in f.evidence
    assert "open_range" in f.evidence
    assert "account_id" in f.evidence
