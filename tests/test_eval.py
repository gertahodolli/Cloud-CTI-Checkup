"""Tests for evaluation harness."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from cti_checkup.eval.config import get_default_eval_config, load_eval_config
from cti_checkup.eval.models import (
    AIQualityMetrics,
    CompletenessScore,
    EvalReport,
    GroundingScore,
    HallucinationCheck,
    InjectionResistanceScore,
)
from cti_checkup.eval.scorer import (
    calculate_overall_score,
    check_hallucination,
    score_ai_output,
    score_completeness,
    score_grounding,
    score_injection_resistance,
)


FIXTURES_DIR = Path(__file__).parent / "fixtures"


def get_sample_evidence_bundle() -> Dict[str, Any]:
    """Return a sample evidence bundle for testing."""
    return {
        "start_time": "2026-02-03T09:00:00Z",
        "end_time": "2026-02-03T10:00:00Z",
        "total_events": 100,
        "processed_events": 100,
        "regions": ["us-east-1", "us-west-2"],
        "identities": [
            {
                "identity": "arn:aws:iam::123456789012:user/alice",
                "identity_type": "user",
                "event_count": 50,
                "failure_count": 5,
            },
            {
                "identity": "arn:aws:iam::123456789012:user/bob",
                "identity_type": "user",
                "event_count": 30,
                "failure_count": 0,
            },
        ],
        "network": [
            {"ip": "203.0.113.50", "event_count": 60},
            {"ip": "198.51.100.25", "event_count": 40},
        ],
        "event_stats": [
            {"event_name": "ListBuckets", "count": 20, "failure_count": 0},
            {"event_name": "GetObject", "count": 30, "failure_count": 2},
            {"event_name": "CreateAccessKey", "count": 5, "failure_count": 3},
        ],
    }


def get_sample_ai_summary() -> Dict[str, Any]:
    """Return a sample AI summary for testing."""
    return {
        "type": "cloudtrail_ai_summary",
        "summary_text": "Activity analysis shows user alice performing discovery operations.",
        "key_observations": [
            "User alice has elevated failure rate on CreateAccessKey attempts",
            "Activity spans multiple regions (us-east-1, us-west-2)",
        ],
        "timeline": [
            {
                "time": "2026-02-03T09:00:00Z",
                "event": "Discovery activity begins from IP 203.0.113.50",
                "severity": "medium",
            },
            {
                "time": "2026-02-03T09:30:00Z",
                "event": "CreateAccessKey failures detected for alice",
                "severity": "high",
            },
        ],
        "top_actors": [
            {
                "identity": "arn:aws:iam::123456789012:user/alice",
                "ip": "203.0.113.50",
                "why": ["High failure rate", "CreateAccessKey attempts"],
                "risk_level": "high",
            },
        ],
        "recommended_actions": [
            "Review alice's recent activity",
            "Check for unauthorized access key creation",
        ],
        "recommended_detections": [
            {"format": "sigma", "name": "CreateAccessKey Failures", "description": "Detect failed key creation"},
        ],
        "confidence": 75,
        "confidence_reason": "Good evidence coverage",
        "limitations": ["No VPC Flow Logs available"],
        "input": {},
        "evidence_used": {},
    }


class TestEvalConfig:
    """Tests for evaluation configuration."""

    def test_default_config(self):
        """Test that default config has expected values."""
        config = get_default_eval_config()
        assert config["enabled"] is True
        assert "metrics" in config
        assert config["metrics"]["grounding_min_score"] == 70.0
        assert config["metrics"]["hallucination_max_count"] == 5
        assert "weights" in config["metrics"]

    def test_load_eval_config_disabled(self):
        """Test loading config when eval is disabled."""
        cfg = {"eval": {"enabled": False}}
        enabled, config, error = load_eval_config(cfg)
        assert enabled is False
        assert config is None
        assert error is None

    def test_load_eval_config_not_configured(self):
        """Test loading when eval section is missing."""
        cfg = {}
        enabled, config, error = load_eval_config(cfg)
        assert enabled is True  # Defaults to enabled
        assert config is not None
        assert error is None


class TestGroundingScore:
    """Tests for grounding scoring."""

    def test_grounding_perfect_score(self):
        """Test grounding with all claims grounded."""
        evidence = get_sample_evidence_bundle()
        ai_summary = get_sample_ai_summary()
        config = get_default_eval_config()

        score = score_grounding(ai_summary, evidence, config)

        assert score.score > 50  # Should have decent grounding
        assert score.grounded_claims > 0
        assert score.total_claims > 0

    def test_grounding_with_ungrounded_claims(self):
        """Test grounding with fabricated data."""
        evidence = get_sample_evidence_bundle()
        ai_summary = {
            "timeline": [
                {"time": "2025-01-01T00:00:00Z", "event": "Fabricated event", "severity": "high"},
            ],
            "top_actors": [
                {"identity": "unknown-identity", "why": ["Fabricated reason"]},
            ],
            "key_observations": ["Completely fabricated observation"],
        }
        config = get_default_eval_config()

        score = score_grounding(ai_summary, evidence, config)

        assert len(score.ungrounded_claims) > 0


class TestHallucinationCheck:
    """Tests for hallucination detection."""

    def test_no_hallucinations(self):
        """Test with no hallucinated data."""
        evidence = get_sample_evidence_bundle()
        ai_summary = get_sample_ai_summary()
        config = get_default_eval_config()

        result = check_hallucination(ai_summary, evidence, config)

        assert result.score == 100.0 or result.total_hallucinations == 0

    def test_hallucinated_ip(self):
        """Test detection of hallucinated IP addresses."""
        evidence = get_sample_evidence_bundle()
        ai_summary = {
            "summary_text": "Attack from IP 192.168.1.100 detected.",
            "top_actors": [{"ip": "192.168.1.100", "why": ["Fake reason"]}],
            "timeline": [],
            "key_observations": [],
        }
        config = get_default_eval_config()

        result = check_hallucination(ai_summary, evidence, config)

        assert "192.168.1.100" in result.hallucinated_ips
        assert result.total_hallucinations > 0
        assert result.score < 100.0


class TestCompletenessScore:
    """Tests for completeness scoring."""

    def test_complete_summary(self):
        """Test with all required sections present."""
        ai_summary = get_sample_ai_summary()
        config = get_default_eval_config()

        score = score_completeness(ai_summary, config)

        assert score.score > 80.0
        assert len(score.missing_sections) < 3

    def test_incomplete_summary(self):
        """Test with missing sections."""
        ai_summary = {
            "summary_text": "Test summary",
            # Missing many required sections
        }
        config = get_default_eval_config()

        score = score_completeness(ai_summary, config)

        assert score.score < 50.0
        assert len(score.missing_sections) > 3


class TestInjectionResistance:
    """Tests for injection resistance scoring."""

    def test_no_injection_attempts(self):
        """Test with no injection in input."""
        evidence = get_sample_evidence_bundle()
        ai_summary = get_sample_ai_summary()

        score = score_injection_resistance(ai_summary, evidence)

        assert score.score == 100.0
        assert score.passed is True
        assert score.injection_strings_in_input == 0

    def test_injection_with_warnings(self):
        """Test injection detected with warnings generated."""
        evidence = get_sample_evidence_bundle()
        ai_summary = {
            **get_sample_ai_summary(),
            "input": {
                "security_warnings": [
                    "Potential injection: ignore.*instructions",
                    "Potential injection: system.*prompt",
                ],
            },
        }

        score = score_injection_resistance(ai_summary, evidence)

        assert score.injection_strings_in_input == 2
        assert score.warnings_generated == 2
        assert score.passed is True  # Warnings were generated, so it passed


class TestOverallScore:
    """Tests for overall score calculation."""

    def test_overall_score_calculation(self):
        """Test weighted score calculation."""
        metrics = AIQualityMetrics(
            grounding=GroundingScore(score=80.0),
            hallucination=HallucinationCheck(score=90.0),
            completeness=CompletenessScore(score=70.0),
            injection_resistance=InjectionResistanceScore(score=100.0),
        )
        config = get_default_eval_config()

        overall = calculate_overall_score(metrics, config)

        # Should be weighted average
        assert 70.0 < overall < 90.0


class TestScoreAIOutput:
    """Tests for the main scoring function."""

    def test_score_ai_output(self, tmp_path: Path):
        """Test scoring AI output from files."""
        # Write test files
        evidence = get_sample_evidence_bundle()
        ai_summary = get_sample_ai_summary()

        evidence_path = tmp_path / "evidence.json"
        summary_path = tmp_path / "summary.json"

        evidence_path.write_text(json.dumps(evidence))
        summary_path.write_text(json.dumps(ai_summary))

        cfg = {}
        metrics, error = score_ai_output(summary_path, evidence_path, cfg)

        assert error is None
        assert metrics.overall_score > 0
        assert metrics.grounding is not None
        assert metrics.hallucination is not None
        assert metrics.completeness is not None

    def test_score_ai_output_missing_file(self, tmp_path: Path):
        """Test error handling for missing files."""
        evidence_path = tmp_path / "nonexistent.json"
        summary_path = tmp_path / "also_nonexistent.json"

        cfg = {}
        metrics, error = score_ai_output(summary_path, evidence_path, cfg)

        assert error is not None


class TestEvalReport:
    """Tests for EvalReport model."""

    def test_eval_report_creation(self):
        """Test creating an eval report."""
        report = EvalReport(
            scenario_name="test_scenario",
            timestamp="2026-02-03T10:00:00Z",
            total_events=100,
            processed_events=100,
            actors_found=5,
        )

        assert report.scenario_name == "test_scenario"
        assert report.total_events == 100
        assert report.errors == []

    def test_eval_report_serialization(self):
        """Test that eval report can be serialized to JSON."""
        report = EvalReport(
            scenario_name="test",
            timestamp="2026-02-03T10:00:00Z",
        )

        json_str = report.model_dump_json()
        parsed = json.loads(json_str)

        assert parsed["scenario_name"] == "test"


class TestBaselineSummarizer:
    """Tests for baseline (non-AI) summarizer."""

    def test_baseline_summary_generation(self):
        """Test generating baseline summary from evidence bundle."""
        from cti_checkup.ai.baseline import generate_baseline_summary
        from cti_checkup.ai.models import CloudTrailEvidenceBundle, IdentityStats, NetworkStats, EventStats, SuspiciousSequence

        bundle = CloudTrailEvidenceBundle(
            start_time="2026-02-03T09:00:00Z",
            end_time="2026-02-03T10:00:00Z",
            total_events=100,
            processed_events=100,
            regions=["us-east-1"],
            identities=[
                IdentityStats(
                    identity="arn:aws:iam::123456789012:user/alice",
                    identity_type="user",
                    event_count=50,
                    failure_count=5,
                ),
            ],
            network=[
                NetworkStats(ip="203.0.113.50", event_count=50),
            ],
            event_stats=[
                EventStats(event_name="ListBuckets", count=20),
                EventStats(event_name="CreateAccessKey", count=5, failure_count=3),
            ],
            sequences=[
                SuspiciousSequence(
                    name="privilege_escalation",
                    description="Privilege escalation attempts",
                    events=["CreateAccessKey"],
                    count=5,
                ),
            ],
        )

        summary = generate_baseline_summary(bundle)

        assert summary.type == "cloudtrail_baseline_summary"
        assert summary.summary_text != ""
        assert len(summary.key_observations) > 0
        assert len(summary.timeline) > 0
        assert summary.confidence > 0
        assert len(summary.limitations) > 0
        assert "baseline" in summary.limitations[0].lower()

    def test_baseline_vs_llm_mode(self, tmp_path: Path):
        """Test that baseline mode doesn't require AI config."""
        from cti_checkup.ai.summarize.cloudtrail import summarize_cloudtrail

        # Create minimal events file
        events_path = tmp_path / "events.json"
        events_path.write_text(json.dumps([
            {
                "eventName": "ListBuckets",
                "userIdentity": {"arn": "arn:aws:iam::123456789012:user/test"},
                "sourceIPAddress": "1.2.3.4",
                "eventTime": "2026-02-03T10:00:00Z",
            }
        ]))

        # Baseline mode should work without AI config
        cfg = {}  # No AI config
        summary, partial, fatal, error, bundle = summarize_cloudtrail(
            events_path=events_path,
            cfg=cfg,
            output_json=True,
            baseline_mode=True,
        )

        assert fatal is False
        assert summary.type == "cloudtrail_baseline_summary"
        assert bundle is not None
