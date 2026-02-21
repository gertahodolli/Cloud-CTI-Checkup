"""Unit test for risk scoring."""
from __future__ import annotations

from cti_checkup.core.models import ScanResult, Summary
from cti_checkup.core.risk import compute_risk_score


def test_risk_score_from_config() -> None:
    result = ScanResult(provider="aws")
    result.summary = Summary(high=2, medium=1, low=0, info=0, skipped=0, errors=0)
    cfg = {
        "risk_scoring": {
            "cap": 100,
            "weights": {"high": 25, "medium": 10, "low": 3, "info": 0},
        }
    }
    score, explanation = compute_risk_score(result, cfg)
    assert score is not None
    assert score == min(100, 2 * 25 + 1 * 10)
    assert explanation is not None
    assert explanation["cap"] == 100
    assert explanation["weights"]["high"] == 25
    assert explanation["counts"]["high"] == 2
    assert explanation["contribution"]["high"] == 50
    assert explanation["contribution"]["medium"] == 10


def test_risk_score_none_when_no_config() -> None:
    result = ScanResult(provider="aws")
    score, explanation = compute_risk_score(result, {})
    assert score is None
    assert explanation is None


def test_risk_score_capped() -> None:
    result = ScanResult(provider="aws")
    result.summary = Summary(high=10, medium=0, low=0, info=0, skipped=0, errors=0)
    cfg = {"risk_scoring": {"cap": 100, "weights": {"high": 25, "medium": 0, "low": 0, "info": 0}}}
    score, explanation = compute_risk_score(result, cfg)
    assert score == 100
    assert explanation["contribution"]["high"] == 250
    assert explanation["cap"] == 100
