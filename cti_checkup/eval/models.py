"""Pydantic models for evaluation harness."""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class GroundingScore(BaseModel):
    """Score for how well AI output is grounded in evidence."""

    score: float = 0.0  # 0-100
    total_claims: int = 0
    grounded_claims: int = 0
    ungrounded_claims: List[str] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)


class HallucinationCheck(BaseModel):
    """Results of hallucination detection."""

    score: float = 100.0  # 100 = no hallucinations, lower = more hallucinations
    hallucinated_ips: List[str] = Field(default_factory=list)
    hallucinated_identities: List[str] = Field(default_factory=list)
    hallucinated_events: List[str] = Field(default_factory=list)
    total_hallucinations: int = 0


class CompletenessScore(BaseModel):
    """Score for completeness of AI output sections."""

    score: float = 0.0  # 0-100
    required_sections: List[str] = Field(default_factory=list)
    present_sections: List[str] = Field(default_factory=list)
    missing_sections: List[str] = Field(default_factory=list)


class InjectionResistanceScore(BaseModel):
    """Score for injection resistance."""

    score: float = 100.0  # 100 = fully resistant
    injection_strings_in_input: int = 0
    warnings_generated: int = 0
    refusals_detected: int = 0
    passed: bool = True


class AIQualityMetrics(BaseModel):
    """Combined AI output quality metrics."""

    grounding: GroundingScore = Field(default_factory=GroundingScore)
    hallucination: HallucinationCheck = Field(default_factory=HallucinationCheck)
    completeness: CompletenessScore = Field(default_factory=CompletenessScore)
    injection_resistance: InjectionResistanceScore = Field(default_factory=InjectionResistanceScore)
    overall_score: float = 0.0  # Weighted average


class ScenarioArtifacts(BaseModel):
    """Paths to artifacts generated during scenario run."""

    aws_scan: Optional[str] = None
    cloudtrail_correlation: Optional[str] = None
    evidence_bundle: Optional[str] = None
    ai_summary: Optional[str] = None
    baseline_summary: Optional[str] = None
    exports_dir: Optional[str] = None
    exported_files: List[str] = Field(default_factory=list)


class RuntimeMetrics(BaseModel):
    """Runtime performance metrics."""

    total_seconds: float = 0.0
    posture_scan_seconds: Optional[float] = None
    correlation_seconds: Optional[float] = None
    ai_summary_seconds: Optional[float] = None
    baseline_summary_seconds: Optional[float] = None
    export_seconds: Optional[float] = None


class EvalReport(BaseModel):
    """Complete evaluation report for a scenario run."""

    scenario_name: str
    timestamp: str
    config_file: Optional[str] = None

    # Counts
    total_events: int = 0
    processed_events: int = 0
    truncated: bool = False
    actors_found: int = 0
    findings_count: int = 0
    exported_detections: int = 0

    # Runtime
    runtime: RuntimeMetrics = Field(default_factory=RuntimeMetrics)

    # AI quality metrics (if AI mode used)
    ai_metrics: Optional[AIQualityMetrics] = None

    # Baseline comparison (if both modes run)
    baseline_comparison: Optional[Dict[str, Any]] = None

    # Reproducibility metadata
    reproducibility: Dict[str, Any] = Field(default_factory=dict)

    # Artifacts
    artifacts: ScenarioArtifacts = Field(default_factory=ScenarioArtifacts)

    # Errors/warnings
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
