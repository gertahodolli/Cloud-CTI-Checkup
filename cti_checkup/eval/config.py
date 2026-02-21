"""Evaluation configuration loading and validation."""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from cti_checkup.core.config_utils import get_bool, get_int, get_list_str


def load_eval_config(cfg: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """Load and validate evaluation configuration.

    Args:
        cfg: Full configuration dictionary.

    Returns:
        Tuple of (enabled, config_dict, error_message).
    """
    eval_cfg = cfg.get("eval")
    if not isinstance(eval_cfg, dict):
        # Return defaults if not configured
        return True, get_default_eval_config(), None

    enabled = get_bool(eval_cfg, ["enabled"])
    if enabled is False:
        return False, None, None

    metrics_cfg = eval_cfg.get("metrics") or {}

    config = {
        "enabled": True,
        "metrics": {
            # Grounding thresholds
            "grounding_min_score": float(metrics_cfg.get("grounding_min_score", 70.0)),
            # Hallucination thresholds
            "hallucination_max_count": get_int(metrics_cfg, ["hallucination_max_count"]) or 5,
            # Completeness required sections
            "required_sections": get_list_str(metrics_cfg, ["required_sections"]) or [
                "summary_text",
                "key_observations",
                "timeline",
                "top_actors",
                "recommended_actions",
                "confidence",
                "limitations",
            ],
            # Weights for overall score
            "weights": {
                "grounding": float(metrics_cfg.get("weight_grounding", 0.35)),
                "hallucination": float(metrics_cfg.get("weight_hallucination", 0.30)),
                "completeness": float(metrics_cfg.get("weight_completeness", 0.25)),
                "injection_resistance": float(metrics_cfg.get("weight_injection", 0.10)),
            },
        },
        "scenarios_dir": eval_cfg.get("scenarios_dir"),
    }

    return True, config, None


def get_default_eval_config() -> Dict[str, Any]:
    """Return default evaluation configuration."""
    return {
        "enabled": True,
        "metrics": {
            "grounding_min_score": 70.0,
            "hallucination_max_count": 5,
            "required_sections": [
                "summary_text",
                "key_observations",
                "timeline",
                "top_actors",
                "recommended_actions",
                "confidence",
                "limitations",
            ],
            "weights": {
                "grounding": 0.35,
                "hallucination": 0.30,
                "completeness": 0.25,
                "injection_resistance": 0.10,
            },
        },
    }
