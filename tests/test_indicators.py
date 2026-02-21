"""Tests for AI indicators extraction from CloudTrail events."""
from __future__ import annotations

from cti_checkup.ai.indicators import (
    IndicatorConfig,
    ExtractedIndicators,
    extract_indicators_from_events,
    render_indicators_human,
    render_indicators_json,
    DEFAULT_SKIP_IPS,
)


def test_extract_indicators_empty_events() -> None:
    indicators = extract_indicators_from_events([])
    assert len(indicators.ips) == 0
    assert len(indicators.identities) == 0
    assert len(indicators.access_key_ids) == 0
    assert len(indicators.domains) == 0
    assert len(indicators.regions) == 0


def test_extract_indicators_source_ip_and_region() -> None:
    # Use a clearly public IP (e.g. 8.8.8.8) so it is not classified as private
    events = [
        {
            "sourceIPAddress": "8.8.8.8",
            "awsRegion": "us-east-1",
            "eventSource": "ec2.amazonaws.com",
            "userIdentity": {"type": "IAMUser", "userName": "alice"},
        }
    ]
    indicators = extract_indicators_from_events(events)
    assert "8.8.8.8" in indicators.ips
    assert "us-east-1" in indicators.regions
    assert "ec2.amazonaws.com" in indicators.event_sources
    assert "user:alice" in indicators.identities


def test_extract_indicators_skips_internal_ips() -> None:
    for ip in ("127.0.0.1", "0.0.0.0"):
        events = [{"sourceIPAddress": ip, "userIdentity": {}}]
        indicators = extract_indicators_from_events(events)
        assert ip not in indicators.ips


def test_extract_indicators_access_key_id() -> None:
    events = [
        {
            "sourceIPAddress": "10.0.0.1",
            "userIdentity": {
                "type": "IAMUser",
                "userName": "bob",
                "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
            },
        }
    ]
    indicators = extract_indicators_from_events(events)
    assert "AKIAIOSFODNN7EXAMPLE" in indicators.access_key_ids
    assert "user:bob" in indicators.identities
    assert "10.0.0.1" in indicators.ips_private


def test_extract_indicators_arn_and_principal_id() -> None:
    events = [
        {
            "userIdentity": {
                "type": "AssumedRole",
                "arn": "arn:aws:sts::123456789012:assumed-role/Admin/role-session",
                "principalId": "AROAEXAMPLE:session",
                "sessionContext": {
                    "sessionIssuer": {
                        "arn": "arn:aws:iam::123456789012:role/Admin",
                        "userName": "Admin",
                    }
                },
            }
        }
    ]
    indicators = extract_indicators_from_events(events)
    assert "arn:aws:sts::123456789012:assumed-role/Admin/role-session" in indicators.identities
    assert "AROAEXAMPLE:session" in indicators.identities
    assert "arn:aws:iam::123456789012:role/Admin" in indicators.identities
    assert "role:Admin" in indicators.identities


def test_extract_indicators_user_agent() -> None:
    events = [
        {
            "userIdentity": {},
            "userAgent": "custom-client/1.0",
        }
    ]
    indicators = extract_indicators_from_events(events)
    assert "custom-client/1.0" in indicators.user_agents


def test_extract_indicators_from_string_ips_in_error_message() -> None:
    events = [
        {
            "userIdentity": {},
            "errorMessage": "Connection refused from 198.51.100.5",
        }
    ]
    indicators = extract_indicators_from_events(events)
    assert "198.51.100.5" in indicators.ips


def test_indicator_config_defaults() -> None:
    cfg = IndicatorConfig()
    assert cfg.max_ips_display > 0
    assert "127.0.0.1" in cfg.skip_ips or "127.0.0.1" in DEFAULT_SKIP_IPS
    assert ".amazonaws.com" in cfg.skip_domain_suffixes


def test_extracted_indicators_to_dict() -> None:
    indicators = ExtractedIndicators()
    indicators.ips.add("8.8.8.8")
    indicators.identities.add("user:alice")
    indicators.access_key_ids.add("AKIAEXAMPLE")
    d = indicators.to_dict(mask_keys=True)
    assert d["ips"] == ["8.8.8.8"]
    assert d["identities"] == ["user:alice"]
    assert "****" in str(d["access_key_ids"])
    assert d["ips_count"] == 1
    assert d["identities_count"] == 1


def test_render_indicators_human_empty() -> None:
    indicators = ExtractedIndicators()
    out = render_indicators_human(indicators)
    assert "Extracted Indicators" in out
    assert "IPs (0 found)" in out
    assert "(none)" in out
    assert "Regions:" in out


def test_render_indicators_human_with_data() -> None:
    indicators = ExtractedIndicators()
    indicators.ips.add("8.8.8.8")
    indicators.identities.add("user:alice")
    indicators.regions.add("us-east-1")
    out = render_indicators_human(indicators)
    assert "8.8.8.8" in out
    assert "user:alice" in out
    assert "us-east-1" in out


def test_render_indicators_json() -> None:
    indicators = ExtractedIndicators()
    indicators.ips.add("8.8.8.8")
    out = render_indicators_json(indicators)
    assert "8.8.8.8" in out
    assert "ips" in out
    assert "identities" in out


def test_extract_indicators_non_dict_events_skipped() -> None:
    events = [
        {"sourceIPAddress": "1.2.3.4", "userIdentity": {}},
        None,
        "not-a-dict",
        [],
    ]
    indicators = extract_indicators_from_events(events)
    assert "1.2.3.4" in indicators.ips
    assert len(indicators.ips) == 1
