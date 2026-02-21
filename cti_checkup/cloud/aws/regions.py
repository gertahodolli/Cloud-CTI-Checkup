from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional

from cti_checkup.cloud.aws.session import make_boto_session

if TYPE_CHECKING:
    import boto3


def discover_regions(profile: Optional[str]) -> List[str]:
    sess = make_boto_session(profile)
    return discover_regions_from_session(sess)


def discover_regions_from_session(session: "boto3.Session") -> List[str]:
    ec2 = session.client("ec2")
    resp = ec2.describe_regions(AllRegions=False)
    return sorted([r["RegionName"] for r in resp.get("Regions", [])])
