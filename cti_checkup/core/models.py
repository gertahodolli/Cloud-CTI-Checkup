from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
Status = Literal["ok", "finding", "skipped", "error"]


class Finding(BaseModel):
    finding_id: Optional[str] = None
    service: str
    region: Optional[str] = None
    resource_type: str
    resource_id: str
    issue: str
    severity: Severity
    status: Status = "finding"
    evidence: Dict[str, Any] = Field(default_factory=dict)
    remediation: Optional[str] = None


class CheckRun(BaseModel):
    name: str
    status: Status
    message: Optional[str] = None


class Summary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    skipped: int = 0
    errors: int = 0


class ScanResult(BaseModel):
    provider: str = "aws"
    account_id: Optional[str] = None
    regions: List[str] = Field(default_factory=list)
    scan_date: Optional[str] = None  # ISO timestamp when scan was run
    checks: List[CheckRun] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    summary: Summary = Field(default_factory=Summary)

    # control flags for exit behavior
    partial_failure: bool = False
    fatal_error: bool = False

    # additive: rule-based risk score 0-100 (config-driven)
    risk_score: Optional[int] = None
    risk_score_explanation: Optional[Dict[str, Any]] = None
