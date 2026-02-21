"""Unit tests for cloud attribution using fake ipinfo data."""
from __future__ import annotations

from cti_checkup.intel.cloud_attribution import build_cloud_attribution


def test_cloud_attribution_matches_provider() -> None:
    cfg = {
        "intel": {
            "cloud_attribution": {
                "enabled": True,
                "providers": {
                    "aws": {
                        "asn_numbers": [12345],
                        "org_contains": ["Amazon"],
                        "hostname_contains": ["compute.amazonaws.com"],
                    },
                    "gcp": {
                        "asn_numbers": [15169],
                        "org_contains": ["Google"],
                        "hostname_contains": ["googleusercontent.com"],
                    },
                },
                "confidence_weights": {
                    "asn_match": 60,
                    "org_match": 25,
                    "hostname_match": 15,
                    "privacy_hosting": 10,
                },
            }
        }
    }
    ipinfo = {
        "org": "AS12345 Amazon Data Services",
        "hostname": "ec2-1-2-3-4.compute.amazonaws.com",
        "privacy": {"hosting": True},
    }

    cloud_attr, error = build_cloud_attribution(ipinfo, cfg)

    assert error is None
    assert cloud_attr is not None
    assert cloud_attr["provider"] == "aws"
    assert cloud_attr["asn"] == 12345
    assert cloud_attr["hosting"] is True
    assert "compute.amazonaws.com" in cloud_attr["service_hints"]
    assert cloud_attr["confidence"] == 100


def test_cloud_attribution_missing_config_errors() -> None:
    cfg = {"intel": {"cloud_attribution": {"enabled": True}}}
    cloud_attr, error = build_cloud_attribution({"org": "AS1 Example"}, cfg)

    assert cloud_attr is None
    assert error is not None
