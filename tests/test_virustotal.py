"""Tests for VirusTotal intel (hash lookup, config, severity)."""
from __future__ import annotations

import os
from unittest.mock import patch

from cti_checkup.intel.virustotal import (
    get_virustotal_api_key,
    get_virustotal_base_url,
    _parse_vt_stats,
    _determine_severity,
    run_intel_hash,
)


class TestVirusTotalConfig:
    """Tests for API key and base URL config."""

    def test_get_virustotal_api_key_missing(self) -> None:
        with patch.dict(os.environ, {"CTICHECKUP_VIRUSTOTAL_API_KEY": ""}, clear=False):
            assert get_virustotal_api_key() is None

    def test_get_virustotal_api_key_empty_string(self) -> None:
        with patch.dict(os.environ, {"CTICHECKUP_VIRUSTOTAL_API_KEY": ""}):
            assert get_virustotal_api_key() is None

    def test_get_virustotal_api_key_whitespace_only(self) -> None:
        with patch.dict(os.environ, {"CTICHECKUP_VIRUSTOTAL_API_KEY": "  \t  "}):
            assert get_virustotal_api_key() is None

    def test_get_virustotal_api_key_present(self) -> None:
        with patch.dict(os.environ, {"CTICHECKUP_VIRUSTOTAL_API_KEY": "test-key-123"}):
            assert get_virustotal_api_key() == "test-key-123"

    def test_get_virustotal_base_url_default(self) -> None:
        assert get_virustotal_base_url({}) == "https://www.virustotal.com/api/v3"
        assert get_virustotal_base_url({"intel": {}}) == "https://www.virustotal.com/api/v3"
        assert get_virustotal_base_url({"intel": {"virustotal": {}}}) == "https://www.virustotal.com/api/v3"

    def test_get_virustotal_base_url_from_config(self) -> None:
        cfg = {"intel": {"virustotal": {"base_url": "https://custom.vt.example.com"}}}
        assert get_virustotal_base_url(cfg) == "https://custom.vt.example.com"

    def test_get_virustotal_base_url_strips_trailing_slash(self) -> None:
        cfg = {"intel": {"virustotal": {"base_url": "https://www.virustotal.com/api/v3/"}}}
        assert get_virustotal_base_url(cfg) == "https://www.virustotal.com/api/v3"


class TestParseVtStats:
    """Tests for _parse_vt_stats."""

    def test_parse_vt_stats_empty(self) -> None:
        assert _parse_vt_stats({}) == {
            "malicious": 0,
            "suspicious": 0,
            "undetected": 0,
            "harmless": 0,
            "timeout": 0,
        }

    def test_parse_vt_stats_nested(self) -> None:
        data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "suspicious": 2,
                        "undetected": 60,
                        "harmless": 3,
                        "timeout": 1,
                    }
                }
            }
        }
        assert _parse_vt_stats(data) == {
            "malicious": 5,
            "suspicious": 2,
            "undetected": 60,
            "harmless": 3,
            "timeout": 1,
        }

    def test_parse_vt_stats_missing_keys_default_zero(self) -> None:
        data = {"data": {"attributes": {"last_analysis_stats": {}}}}
        assert _parse_vt_stats(data) == {
            "malicious": 0,
            "suspicious": 0,
            "undetected": 0,
            "harmless": 0,
            "timeout": 0,
        }


class TestDetermineSeverity:
    """Tests for _determine_severity."""

    def test_severity_critical(self) -> None:
        assert _determine_severity({"malicious": 10, "suspicious": 0}) == "critical"
        assert _determine_severity({"malicious": 15, "suspicious": 5}) == "critical"

    def test_severity_high(self) -> None:
        assert _determine_severity({"malicious": 5, "suspicious": 0}) == "high"
        assert _determine_severity({"malicious": 9, "suspicious": 0}) == "high"

    def test_severity_medium(self) -> None:
        assert _determine_severity({"malicious": 1, "suspicious": 0}) == "medium"
        assert _determine_severity({"malicious": 0, "suspicious": 5}) == "medium"

    def test_severity_low(self) -> None:
        assert _determine_severity({"malicious": 0, "suspicious": 1}) == "low"
        assert _determine_severity({"malicious": 0, "suspicious": 4}) == "low"

    def test_severity_info(self) -> None:
        assert _determine_severity({"malicious": 0, "suspicious": 0}) == "info"
        assert _determine_severity({}) == "info"


class TestRunIntelHash:
    """Tests for run_intel_hash (with mocked fetch)."""

    def test_run_intel_hash_invalid_length(self) -> None:
        result = run_intel_hash("short", {})
        assert result.provider == "virustotal"
        assert result.fatal_error is True
        assert len(result.checks) == 1
        assert "Invalid hash length" in result.checks[0].message

    def test_run_intel_hash_invalid_length_sha1(self) -> None:
        result = run_intel_hash("a" * 39, {})
        assert result.fatal_error is True
        assert "Invalid hash length" in result.checks[0].message

    def test_run_intel_hash_missing_api_key(self) -> None:
        with patch("cti_checkup.intel.virustotal.get_virustotal_api_key", return_value=None):
            result = run_intel_hash("d41d8cd98f00b204e9800998ecf8427e", {})
        assert result.fatal_error is True
        assert any("VIRUSTOTAL_API_KEY" in c.message for c in result.checks)

    def test_run_intel_hash_success_clean(self) -> None:
        vt_response = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "undetected": 70,
                        "harmless": 0,
                        "timeout": 0,
                    },
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                    "md5": "d41d8cd98f00b204e9800998ecf8427e",
                }
            }
        }

        with patch("cti_checkup.intel.virustotal.get_virustotal_api_key", return_value="test-key"):
            with patch("cti_checkup.intel.virustotal._fetch_virustotal", return_value=(vt_response, None)):
                result = run_intel_hash("d41d8cd98f00b204e9800998ecf8427e", {})

        assert result.provider == "virustotal"
        assert result.fatal_error is False
        assert len(result.findings) == 1
        assert result.findings[0].issue == "hash_clean"
        assert result.findings[0].severity == "info"
        assert result.risk_score == 0

    def test_run_intel_hash_success_malicious(self) -> None:
        vt_response = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 10,
                        "suspicious": 2,
                        "undetected": 58,
                        "harmless": 0,
                        "timeout": 0,
                    },
                }
            }
        }

        with patch("cti_checkup.intel.virustotal.get_virustotal_api_key", return_value="test-key"):
            with patch("cti_checkup.intel.virustotal._fetch_virustotal", return_value=(vt_response, None)):
                result = run_intel_hash("a" * 64, {})

        assert result.provider == "virustotal"
        assert len(result.findings) == 1
        assert result.findings[0].issue == "hash_malicious_detections"
        assert result.findings[0].severity == "critical"
        assert result.risk_score > 0

    def test_run_intel_hash_not_found(self) -> None:
        with patch("cti_checkup.intel.virustotal.get_virustotal_api_key", return_value="test-key"):
            with patch(
                "cti_checkup.intel.virustotal._fetch_virustotal",
                return_value=(None, "Resource not found in VirusTotal: abc"),
            ):
                result = run_intel_hash("a" * 32, {})

        assert result.fatal_error is False
        assert len(result.findings) == 1
        assert result.findings[0].issue == "hash_not_found"
        assert result.findings[0].severity == "info"
