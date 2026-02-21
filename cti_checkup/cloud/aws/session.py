from __future__ import annotations

from typing import Optional

import boto3


def make_boto_session(profile: Optional[str]) -> boto3.Session:
    # No hardcoded region/endpoints/timeouts. Region is set per-client call.
    if profile:
        return boto3.Session(profile_name=profile)
    return boto3.Session()
