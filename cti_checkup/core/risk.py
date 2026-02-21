"""Config-driven risk scoring (0-100); no hardcoded weights."""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from cti_checkup.core.models import ScanResult
from cti_checkup.core.config_utils import get_int


def compute_risk_score(
    result: ScanResult, cfg: Dict[str, Any]
) -> Tuple[Optional[int], Optional[Dict[str, Any]]]:
    risk_cfg = cfg.get("risk_scoring")
    if not isinstance(risk_cfg, dict):
        return None, None

    weights = risk_cfg.get("weights")
    if not isinstance(weights, dict):
        return None, None

    w_critical = get_int(weights, ["critical"])
    w_high = get_int(weights, ["high"])
    w_medium = get_int(weights, ["medium"])
    w_low = get_int(weights, ["low"])
    w_info = get_int(weights, ["info"])
    if w_critical is None and w_high is None and w_medium is None and w_low is None and w_info is None:
        return None, None

    w_critical = w_critical if w_critical is not None else 0
    w_high = w_high if w_high is not None else 0
    w_medium = w_medium if w_medium is not None else 0
    w_low = w_low if w_low is not None else 0
    w_info = w_info if w_info is not None else 0

    cap = get_int(risk_cfg, ["cap"])
    if cap is None or cap < 0:
        return None, None

    counts = {
        "critical": result.summary.critical,
        "high": result.summary.high,
        "medium": result.summary.medium,
        "low": result.summary.low,
        "info": result.summary.info,
    }
    contribution = {
        "critical": result.summary.critical * w_critical,
        "high": result.summary.high * w_high,
        "medium": result.summary.medium * w_medium,
        "low": result.summary.low * w_low,
        "info": result.summary.info * w_info,
    }
    raw = contribution["critical"] + contribution["high"] + contribution["medium"] + contribution["low"] + contribution["info"]
    score = min(cap, max(0, raw))

    weights_out = {"critical": w_critical, "high": w_high, "medium": w_medium, "low": w_low, "info": w_info}
    explanation = {
        "cap": cap,
        "weights": weights_out,
        "counts": counts,
        "contribution": contribution,
    }
    return score, explanation
