"""Baseline (non-AI) summarizer for CloudTrail evidence bundles.

Provides a deterministic summary without LLM for comparison purposes.
This allows evaluation of "AI adds value beyond deterministic summarization."
"""
from __future__ import annotations

from typing import List

from cti_checkup.ai.models import (
    CloudTrailAISummary,
    CloudTrailEvidenceBundle,
    RecommendedDetection,
    TimelineItem,
    TopActor,
)


def generate_baseline_summary(
    evidence_bundle: CloudTrailEvidenceBundle,
) -> CloudTrailAISummary:
    """Generate a deterministic summary from evidence bundle without LLM.

    This baseline summarizer:
    - Produces structured output from evidence data directly
    - Uses rule-based logic for observations and recommendations
    - Provides a comparison point for LLM-generated summaries

    Args:
        evidence_bundle: The structured evidence bundle.

    Returns:
        CloudTrailAISummary with deterministic content.
    """
    summary = CloudTrailAISummary(
        type="cloudtrail_baseline_summary",
        input={
            "total_events": evidence_bundle.total_events,
            "processed_events": evidence_bundle.processed_events,
            "truncated": evidence_bundle.truncated,
            "regions": evidence_bundle.regions,
            "time_range": {
                "start": evidence_bundle.start_time,
                "end": evidence_bundle.end_time,
            },
            "mode": "baseline",
        },
        evidence_used={
            "identities_analyzed": evidence_bundle.total_identities,
            "ips_analyzed": evidence_bundle.total_ips,
            "unique_events": evidence_bundle.total_unique_events,
            "sequences_detected": len(evidence_bundle.sequences),
        },
    )

    # Generate summary text
    summary.summary_text = _generate_summary_text(evidence_bundle)

    # Generate key observations
    summary.key_observations = _generate_observations(evidence_bundle)

    # Generate timeline from sequences and high-activity events
    summary.timeline = _generate_timeline(evidence_bundle)

    # Generate top actors from evidence
    summary.top_actors = _generate_top_actors(evidence_bundle)

    # Generate recommended actions
    summary.recommended_actions = _generate_recommended_actions(evidence_bundle)

    # Generate recommended detections
    summary.recommended_detections = _generate_recommended_detections(evidence_bundle)

    # Calculate deterministic confidence
    summary.confidence = _calculate_baseline_confidence(evidence_bundle)
    summary.confidence_reason = "Baseline confidence based on data completeness and pattern detection"

    # Add limitations
    summary.limitations = _generate_limitations(evidence_bundle)

    return summary


def _generate_summary_text(bundle: CloudTrailEvidenceBundle) -> str:
    """Generate a summary paragraph from evidence data."""
    parts = []

    # Time range
    if bundle.start_time and bundle.end_time:
        parts.append(
            f"Analysis covers {bundle.processed_events:,} CloudTrail events "
            f"from {bundle.start_time} to {bundle.end_time}."
        )
    else:
        parts.append(f"Analysis covers {bundle.processed_events:,} CloudTrail events.")

    # Regions
    if bundle.regions:
        parts.append(f"Activity observed across {len(bundle.regions)} region(s): {', '.join(bundle.regions)}.")

    # Actors
    if bundle.total_identities > 0:
        parts.append(f"Identified {bundle.total_identities} unique identities and {bundle.total_ips} unique IPs.")

    # Failure rate
    if bundle.failure_rate > 0:
        severity = "elevated" if bundle.failure_rate > 10 else "normal"
        parts.append(f"Failure rate is {severity} at {bundle.failure_rate}% ({bundle.total_failures} failures).")

    # Suspicious sequences
    if bundle.sequences:
        sequence_names = [s.name for s in bundle.sequences]
        parts.append(f"Detected suspicious patterns: {', '.join(sequence_names)}.")

    return " ".join(parts)


def _generate_observations(bundle: CloudTrailEvidenceBundle) -> List[str]:
    """Generate key observations from evidence."""
    observations = []

    # High failure rate
    if bundle.failure_rate > 10:
        observations.append(
            f"High failure rate ({bundle.failure_rate}%) indicates potential unauthorized access attempts"
        )

    # Suspicious sequences detected
    for seq in bundle.sequences:
        observations.append(f"Detected {seq.name} pattern: {seq.description} ({seq.count} events)")

    # Multiple regions
    if len(bundle.regions) > 3:
        observations.append(f"Activity spans {len(bundle.regions)} regions, which may indicate reconnaissance")

    # Top identities with failures
    for identity in bundle.identities[:3]:
        if identity.failure_count > 0:
            observations.append(
                f"Identity '{identity.identity}' has {identity.failure_count} failed attempts "
                f"out of {identity.event_count} total events"
            )

    # High-risk event types
    high_risk_events = {"CreateAccessKey", "AttachRolePolicy", "PutRolePolicy", "DeleteTrail", "StopLogging"}
    for stat in bundle.event_stats:
        if stat.event_name in high_risk_events:
            observations.append(f"High-risk event detected: {stat.event_name} ({stat.count} occurrences)")

    return observations[:10]  # Limit to top 10


def _generate_timeline(bundle: CloudTrailEvidenceBundle) -> List[TimelineItem]:
    """Generate timeline from evidence data."""
    timeline = []

    # Add start/end markers
    if bundle.start_time:
        timeline.append(TimelineItem(
            time=bundle.start_time,
            event=f"Activity period begins ({bundle.total_events} total events)",
            severity="info",
        ))

    # Add sequence detections
    for seq in bundle.sequences:
        timeline.append(TimelineItem(
            time=bundle.start_time or "unknown",
            event=f"{seq.name}: {seq.description} ({seq.count} events detected)",
            severity="high" if seq.name in {"privilege_escalation", "defense_evasion"} else "medium",
        ))

    # Add high-failure identity activity
    for identity in bundle.identities[:3]:
        if identity.failure_count > 5:
            timeline.append(TimelineItem(
                time=bundle.start_time or "unknown",
                event=f"High failure activity from {identity.identity} ({identity.failure_count} failures)",
                severity="high",
            ))

    if bundle.end_time:
        timeline.append(TimelineItem(
            time=bundle.end_time,
            event="Activity period ends",
            severity="info",
        ))

    return timeline


def _generate_top_actors(bundle: CloudTrailEvidenceBundle) -> List[TopActor]:
    """Generate top suspicious actors from evidence."""
    actors = []

    # Combine identity and IP data
    for identity in bundle.identities[:5]:
        reasons = []

        # High event count
        if identity.event_count > 100:
            reasons.append(f"High activity: {identity.event_count} events")

        # Failure rate
        if identity.failure_count > 0:
            failure_pct = (identity.failure_count / identity.event_count) * 100
            if failure_pct > 10:
                reasons.append(f"High failure rate: {failure_pct:.1f}%")

        # Suspicious events
        suspicious_events = {"CreateAccessKey", "AttachRolePolicy", "GetSecretValue", "DeleteBucket"}
        for evt in identity.top_events:
            if evt.get("name") in suspicious_events:
                reasons.append(f"Performed {evt.get('name')}")

        if reasons:
            # Find matching IP if possible
            matching_ip = None
            for net in bundle.network:
                if net.event_count > 0:
                    matching_ip = net.ip
                    break

            actors.append(TopActor(
                identity=identity.identity,
                ip=matching_ip,
                why=reasons,
                risk_level="high" if len(reasons) >= 2 else "medium",
            ))

    # Add IPs without clear identity
    for net in bundle.network[:3]:
        if not any(a.ip == net.ip for a in actors):
            reasons = [f"Source of {net.event_count} events"]
            if net.is_hosting:
                reasons.append("Cloud/hosting provider IP")
            if net.abuse_confidence and net.abuse_confidence > 50:
                reasons.append(f"Abuse confidence: {net.abuse_confidence}%")

            if len(reasons) > 1:
                actors.append(TopActor(
                    ip=net.ip,
                    why=reasons,
                    risk_level="medium",
                ))

    return actors[:5]


def _generate_recommended_actions(bundle: CloudTrailEvidenceBundle) -> List[str]:
    """Generate recommended actions based on evidence patterns."""
    actions = []

    # Based on sequences detected
    sequence_names = {s.name for s in bundle.sequences}

    if "credential_access" in sequence_names:
        actions.append("Review and rotate credentials for affected identities")
        actions.append("Audit secrets accessed during the time period")

    if "privilege_escalation" in sequence_names:
        actions.append("Review IAM policy changes made during this period")
        actions.append("Verify no unauthorized permissions were granted")

    if "defense_evasion" in sequence_names:
        actions.append("Verify CloudTrail and logging configurations are intact")
        actions.append("Check for disabled security controls")

    if "persistence" in sequence_names:
        actions.append("Audit newly created users, roles, and access keys")
        actions.append("Verify all new identities are authorized")

    if "exfiltration" in sequence_names:
        actions.append("Review S3 and data access patterns")
        actions.append("Check for unauthorized data copies or snapshots")

    # Based on failure patterns
    if bundle.failure_rate > 10:
        actions.append("Investigate source of failed API calls")
        actions.append("Consider implementing rate limiting or IP blocking")

    # General recommendations
    if bundle.total_identities > 10:
        actions.append("Review least-privilege policies for active identities")

    return actions[:8]


def _generate_recommended_detections(bundle: CloudTrailEvidenceBundle) -> List[RecommendedDetection]:
    """Generate recommended detection rules based on evidence."""
    detections = []

    # Detection for each suspicious sequence
    for seq in bundle.sequences:
        detections.append(RecommendedDetection(
            format="sigma",
            name=f"CloudTrail {seq.name.replace('_', ' ').title()} Detection",
            description=f"Detects {seq.description.lower()} based on events: {', '.join(seq.events[:5])}",
        ))

    # Detection for high-failure identities
    for identity in bundle.identities[:2]:
        if identity.failure_count > 5:
            detections.append(RecommendedDetection(
                format="sigma",
                name="High Failure Rate Identity",
                description="Alert on identity with >5 failures in CloudTrail logs",
            ))
            break

    # Detection for suspicious event combinations
    suspicious_combos = [
        ({"ListUsers", "ListRoles", "GetAccountAuthorizationDetails"}, "IAM Enumeration"),
        ({"CreateAccessKey", "CreateLoginProfile"}, "Credential Creation"),
        ({"DeleteTrail", "StopLogging"}, "Logging Disruption"),
    ]

    evidence_events = {stat.event_name for stat in bundle.event_stats}
    for events, name in suspicious_combos:
        if events & evidence_events:
            detections.append(RecommendedDetection(
                format="sigma",
                name=f"CloudTrail {name} Detection",
                description=f"Detects {name.lower()} pattern",
            ))

    return detections[:5]


def _calculate_baseline_confidence(bundle: CloudTrailEvidenceBundle) -> int:
    """Calculate confidence score based on data quality."""
    score = 50  # Base score

    # More events = more confidence
    if bundle.processed_events > 1000:
        score += 15
    elif bundle.processed_events > 100:
        score += 10
    elif bundle.processed_events > 10:
        score += 5

    # Time range helps
    if bundle.start_time and bundle.end_time:
        score += 10

    # Sequences detected add confidence
    if bundle.sequences:
        score += min(len(bundle.sequences) * 5, 15)

    # Truncation reduces confidence
    if bundle.truncated:
        score -= 15

    # Multiple regions add context
    if len(bundle.regions) > 1:
        score += 5

    return min(max(score, 0), 100)


def _generate_limitations(bundle: CloudTrailEvidenceBundle) -> List[str]:
    """Generate list of analysis limitations."""
    limitations = [
        "Baseline mode: deterministic analysis without AI inference",
    ]

    if bundle.truncated:
        limitations.append(
            f"Events truncated: only {bundle.processed_events} of {bundle.total_events} events analyzed"
        )

    if not bundle.start_time or not bundle.end_time:
        limitations.append("Incomplete timestamp data in events")

    if bundle.total_ips == 0:
        limitations.append("No source IP data available")

    if not bundle.sequences:
        limitations.append("No suspicious patterns detected")

    # Standard limitations
    limitations.extend([
        "No VPC Flow Logs correlation",
        "No historical baseline for anomaly detection",
        "Cannot determine intent without additional context",
    ])

    return limitations
