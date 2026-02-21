"""Pydantic models for AI-assisted analysis."""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IdentityStats(BaseModel):
    """Statistics for a single identity (user/role)."""

    identity: str
    identity_type: str = "unknown"  # user, role, root, service
    event_count: int = 0
    unique_events: int = 0
    failure_count: int = 0
    top_events: List[Dict[str, Any]] = Field(default_factory=list)


class NetworkStats(BaseModel):
    """Network-related statistics from CloudTrail events."""

    ip: str
    event_count: int = 0
    asn: Optional[str] = None
    org: Optional[str] = None
    cloud_provider: Optional[str] = None
    is_hosting: Optional[bool] = None
    abuse_confidence: Optional[int] = None


class EventStats(BaseModel):
    """Event-level statistics."""

    event_name: str
    count: int = 0
    failure_count: int = 0
    error_codes: List[str] = Field(default_factory=list)


class SuspiciousSequence(BaseModel):
    """A detected suspicious event sequence."""

    name: str
    description: str
    events: List[str] = Field(default_factory=list)
    count: int = 0


class CloudTrailEvidenceBundle(BaseModel):
    """Structured evidence bundle sent to the LLM (never raw logs).

    This is the core data structure that summarizes CloudTrail events
    into a small, stable representation for AI analysis.
    """

    # Metadata
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    total_events: int = 0
    processed_events: int = 0
    regions: List[str] = Field(default_factory=list)
    truncated: bool = False

    # Identity statistics
    identities: List[IdentityStats] = Field(default_factory=list)
    total_identities: int = 0

    # Network statistics
    network: List[NetworkStats] = Field(default_factory=list)
    total_ips: int = 0

    # Event statistics
    event_stats: List[EventStats] = Field(default_factory=list)
    total_unique_events: int = 0
    total_failures: int = 0
    failure_rate: float = 0.0

    # Top resources accessed
    resources: List[Dict[str, Any]] = Field(default_factory=list)
    total_resources: int = 0

    # Suspicious patterns detected (deterministic)
    sequences: List[SuspiciousSequence] = Field(default_factory=list)

    # Optional: correlation summary from intel correlate cloudtrail
    correlation_summary: Optional[Dict[str, Any]] = None


class TimelineItem(BaseModel):
    """A single item in the incident timeline."""

    time: str
    event: str
    severity: Optional[str] = None


class TopActor(BaseModel):
    """A top suspicious actor identified by the AI."""

    ip: Optional[str] = None
    identity: Optional[str] = None
    why: List[str] = Field(default_factory=list)
    risk_level: Optional[str] = None


class RecommendedDetection(BaseModel):
    """A recommended detection rule."""

    format: str  # sigma, splunk, kql, cloudwatch
    name: str
    description: Optional[str] = None
    source: Optional[str] = None


class ExtractedIndicatorsModel(BaseModel):
    """Deterministically extracted IOCs from CloudTrail events."""

    ips: List[str] = Field(default_factory=list)
    ips_count: int = 0
    access_key_ids: List[str] = Field(default_factory=list)  # Masked
    access_key_ids_count: int = 0
    identities: List[str] = Field(default_factory=list)
    identities_count: int = 0
    user_agents: List[str] = Field(default_factory=list)
    user_agents_count: int = 0
    domains: List[str] = Field(default_factory=list)
    domains_count: int = 0
    event_sources: List[str] = Field(default_factory=list)
    regions: List[str] = Field(default_factory=list)


class CloudTrailAISummary(BaseModel):
    """AI-generated summary of CloudTrail activity.

    This is the output model containing the AI's analysis.
    """

    type: str = "cloudtrail_ai_summary"

    # Input metadata
    input: Dict[str, Any] = Field(default_factory=dict)

    # AI-generated content
    summary_text: str = ""
    key_observations: List[str] = Field(default_factory=list)
    timeline: List[TimelineItem] = Field(default_factory=list)
    top_actors: List[TopActor] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    recommended_detections: List[RecommendedDetection] = Field(default_factory=list)

    # Confidence and limitations
    confidence: int = 0  # 0-100
    confidence_reason: Optional[str] = None
    limitations: List[str] = Field(default_factory=list)

    # Evidence tracking (not raw logs)
    evidence_used: Dict[str, Any] = Field(default_factory=dict)

    # Deterministically extracted IOCs (regex-based, not from AI)
    extracted_indicators: Optional[ExtractedIndicatorsModel] = None

    # Error handling
    errors: List[str] = Field(default_factory=list)
    partial_failure: bool = False
