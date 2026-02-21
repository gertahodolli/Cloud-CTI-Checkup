from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from cti_checkup.cloud.aws.session import make_boto_session

if TYPE_CHECKING:
    import boto3


def get_account_id(profile: Optional[str]) -> Optional[str]:
    sess = make_boto_session(profile)
    return get_account_id_from_session(sess)


def get_account_id_from_session(session: "boto3.Session") -> Optional[str]:
    sts = session.client("sts")
    return sts.get_caller_identity().get("Account")
