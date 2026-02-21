"""Tests for CloudTrail correlation (JSON array and JSONL)."""
from __future__ import annotations

import json
from pathlib import Path

from cti_checkup.intel.correlation.cloudtrail import correlate_cloudtrail


def _config() -> dict:
    return {
        "intel": {
            "correlation": {
                "cloudtrail": {
                    "enabled": True,
                    "ip_field": "sourceIPAddress",
                    "ua_field": "userAgent",
                    "identity_field": "userIdentity.arn",
                    "event_name_field": "eventName",
                    "max_events": 100,
                    "max_indicators": 10,
                    "scoring": {
                        "weights": {
                            "event_count": 2,
                            "abuse_confidence": 1,
                        },
                        "rules": [
                            {
                                "field": "event_name",
                                "match": "contains",
                                "value": "Delete",
                                "score": 5,
                                "per_event": True,
                            }
                        ],
                    },
                }
            }
        }
    }


def _intel_stub(ip: str, cfg: dict) -> tuple[dict, bool]:
    if ip == "1.2.3.4":
        return (
            {
                "abuse_confidence": 80,
                "cloud_attribution": {"provider": "aws", "hosting": True},
            },
            False,
        )
    return (
        {
            "abuse_confidence": 10,
            "cloud_attribution": {"provider": "unknown", "hosting": "unknown"},
        },
        False,
    )


def test_cloudtrail_json_array(tmp_path: Path) -> None:
    events = [
        {
            "sourceIPAddress": "1.2.3.4",
            "userAgent": "aws-cli/2.0",
            "userIdentity": {"arn": "arn:aws:iam::123:user/alice"},
            "eventName": "DeleteBucket",
            "eventTime": "2024-01-01T00:00:00Z",
        },
        {
            "sourceIPAddress": "1.2.3.4",
            "userAgent": "aws-cli/2.0",
            "userIdentity": {"arn": "arn:aws:iam::123:user/alice"},
            "eventName": "ListBuckets",
            "eventTime": "2024-01-01T00:01:00Z",
        },
        {
            "sourceIPAddress": "5.6.7.8",
            "userAgent": "console",
            "userIdentity": {"arn": "arn:aws:iam::123:user/bob"},
            "eventName": "DeleteBucket",
            "eventTime": "2024-01-01T00:02:00Z",
        },
    ]

    path = tmp_path / "events.json"
    path.write_text(json.dumps(events), encoding="utf-8")

    result, partial, fatal, _ = correlate_cloudtrail(path, _config(), intel_lookup=_intel_stub)

    assert fatal is False
    assert partial is False
    assert result["input"]["processed_events"] == 3
    assert len(result["actors"]) == 2
    assert result["actors"][0]["ip"] == "1.2.3.4"
    assert result["actors"][0]["score"] == 89
    assert result["actors"][0]["event_stats"]["event_count"] == 2
    assert result["actors"][0]["event_stats"]["top_events"][0]["name"] == "DeleteBucket"


def test_cloudtrail_jsonl(tmp_path: Path) -> None:
    lines = [
        json.dumps(
            {
                "sourceIPAddress": "9.9.9.9",
                "userAgent": "aws-cli/2.0",
                "userIdentity": {"arn": "arn:aws:iam::123:user/alice"},
                "eventName": "DeleteBucket",
                "eventTime": "2024-01-01T00:00:00Z",
            }
        ),
        json.dumps(
            {
                "sourceIPAddress": "9.9.9.9",
                "userAgent": "aws-cli/2.0",
                "userIdentity": {"arn": "arn:aws:iam::123:user/alice"},
                "eventName": "DeleteBucket",
                "eventTime": "2024-01-01T00:01:00Z",
            }
        ),
    ]
    path = tmp_path / "events.jsonl"
    path.write_text("\n".join(lines), encoding="utf-8")

    result, partial, fatal, _ = correlate_cloudtrail(path, _config(), intel_lookup=_intel_stub)

    assert fatal is False
    assert partial is False
    assert result["input"]["processed_events"] == 2
    assert len(result["actors"]) == 1
    assert result["actors"][0]["event_stats"]["event_count"] == 2
