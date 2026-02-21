"""Evaluation scenario runner for end-to-end testing."""
from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from cti_checkup.eval.config import load_eval_config
from cti_checkup.eval.models import (
    EvalReport,
    RuntimeMetrics,
    ScenarioArtifacts,
)
from cti_checkup.eval.scorer import score_ai_output


def _load_scenario(scenario_path: Path) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Load scenario definition from JSON file.

    Args:
        scenario_path: Path to scenario JSON file.

    Returns:
        Tuple of (scenario_dict, error_message).
    """
    try:
        data = json.loads(scenario_path.read_text(encoding="utf-8"))
        return data, None
    except (OSError, json.JSONDecodeError) as e:
        return None, f"Failed to load scenario: {e}"


def run_scenario(
    scenario_name: str,
    out_dir: Path,
    cfg: Dict[str, Any],
    scenarios_dir: Optional[Path] = None,
) -> Tuple[EvalReport, Optional[str]]:
    """Run a complete evaluation scenario end-to-end.

    Executes:
    1. CloudTrail correlation (using scenario events)
    2. AI summarize cloudtrail (LLM mode)
    3. AI summarize cloudtrail (baseline mode)
    4. Export detections
    5. Score AI output quality
    6. Compare baseline vs LLM

    Args:
        scenario_name: Name of the scenario to run.
        out_dir: Directory to write artifacts.
        cfg: Full configuration dictionary.
        scenarios_dir: Optional override for scenarios directory.

    Returns:
        Tuple of (EvalReport, error_message).
    """
    timestamp = datetime.utcnow().isoformat() + "Z"
    report = EvalReport(
        scenario_name=scenario_name,
        timestamp=timestamp,
    )
    artifacts = ScenarioArtifacts()
    runtime = RuntimeMetrics()

    start_time = time.time()

    # Determine scenario directory
    if scenarios_dir is None:
        # Check eval config for scenarios_dir
        _, eval_cfg, _ = load_eval_config(cfg)
        if eval_cfg and eval_cfg.get("scenarios_dir"):
            scenarios_dir = Path(eval_cfg["scenarios_dir"])
        else:
            # Default to tests/fixtures/scenarios
            scenarios_dir = Path("tests/fixtures/scenarios")

    # Load scenario definition
    scenario_file = scenarios_dir / f"{scenario_name}.json"
    if not scenario_file.exists():
        # Try with .yaml extension
        scenario_file = scenarios_dir / f"{scenario_name}.yaml"

    if not scenario_file.exists():
        return report, f"Scenario not found: {scenario_name} (looked in {scenarios_dir})"

    scenario, load_error = _load_scenario(scenario_file)
    if load_error:
        report.errors.append(load_error)
        return report, load_error

    assert scenario is not None

    # Create output directory
    out_dir.mkdir(parents=True, exist_ok=True)

    # Get events file from scenario
    events_file = scenario.get("events_file")
    if not events_file:
        return report, "Scenario missing 'events_file'"

    events_path = scenarios_dir / events_file
    if not events_path.exists():
        return report, f"Events file not found: {events_path}"

    # === Step 1: CloudTrail Correlation ===
    correlation_start = time.time()
    correlation_result = None
    correlation_path = out_dir / "cloudtrail_correlation.json"

    try:
        from cti_checkup.intel.correlation.cloudtrail import correlate_cloudtrail

        # Create a mock intel lookup to avoid real API calls
        def mock_intel_lookup(ip: str, cfg: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
            return {"abuse_confidence": 0, "risk_score": 0}, False

        result, partial, fatal, error = correlate_cloudtrail(
            events_path, cfg, intel_lookup=mock_intel_lookup
        )

        if not fatal:
            correlation_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
            artifacts.cloudtrail_correlation = str(correlation_path)
            correlation_result = result
            report.actors_found = len(result.get("actors", []))
    except Exception as e:
        report.warnings.append(f"Correlation failed: {e}")

    runtime.correlation_seconds = time.time() - correlation_start

    # === Step 2: AI Summary (LLM mode) ===
    ai_summary_start = time.time()
    ai_summary_path = out_dir / "ai_summary.json"
    evidence_bundle_path = out_dir / "evidence_bundle.json"

    try:
        from cti_checkup.ai.summarize.cloudtrail import summarize_cloudtrail

        summary, partial, fatal, error, evidence_bundle = summarize_cloudtrail(
            events_path=events_path,
            cfg=cfg,
            output_json=True,
            correlation_path=correlation_path if correlation_result else None,
            baseline_mode=False,
        )

        if not fatal and evidence_bundle:
            # Write AI summary
            ai_summary_path.write_text(summary.model_dump_json(indent=2), encoding="utf-8")
            artifacts.ai_summary = str(ai_summary_path)

            # Write evidence bundle
            evidence_bundle_path.write_text(evidence_bundle.model_dump_json(indent=2), encoding="utf-8")
            artifacts.evidence_bundle = str(evidence_bundle_path)

            # Update report counts
            report.total_events = evidence_bundle.total_events
            report.processed_events = evidence_bundle.processed_events
            report.truncated = evidence_bundle.truncated

        elif fatal:
            report.errors.append(f"AI summary failed: {error}")

    except Exception as e:
        report.errors.append(f"AI summary exception: {e}")

    runtime.ai_summary_seconds = time.time() - ai_summary_start

    # === Step 3: Baseline Summary ===
    baseline_start = time.time()
    baseline_path = out_dir / "baseline_summary.json"

    try:
        from cti_checkup.ai.summarize.cloudtrail import summarize_cloudtrail

        baseline_summary, _, _, _, _ = summarize_cloudtrail(
            events_path=events_path,
            cfg=cfg,
            output_json=True,
            correlation_path=correlation_path if correlation_result else None,
            baseline_mode=True,
        )

        baseline_path.write_text(baseline_summary.model_dump_json(indent=2), encoding="utf-8")
        artifacts.baseline_summary = str(baseline_path)

    except Exception as e:
        report.warnings.append(f"Baseline summary failed: {e}")

    runtime.baseline_summary_seconds = time.time() - baseline_start

    # === Step 4: Export Detections ===
    export_start = time.time()
    exports_dir = out_dir / "exports"

    try:
        from cti_checkup.export.detections import export_detections

        exports_dir.mkdir(exist_ok=True)

        if correlation_result:
            export_report, partial, fatal = export_detections(
                input_path=correlation_path,
                out_dir=exports_dir,
                fmt="sigma",
                source_type="cloudtrail_correlation",
                cfg=cfg,
                strict=False,
            )
            if not fatal:
                artifacts.exports_dir = str(exports_dir)
                report.exported_detections = export_report.get("exported_count", 0)
                # List exported files
                for f in exports_dir.glob("*.yml"):
                    artifacts.exported_files.append(str(f))

    except Exception as e:
        report.warnings.append(f"Export failed: {e}")

    runtime.export_seconds = time.time() - export_start

    # === Step 5: Score AI Output ===
    if artifacts.ai_summary and artifacts.evidence_bundle:
        try:
            metrics, score_error = score_ai_output(
                ai_summary_path=ai_summary_path,
                evidence_bundle_path=evidence_bundle_path,
                cfg=cfg,
            )
            if not score_error:
                report.ai_metrics = metrics
            else:
                report.warnings.append(f"Scoring failed: {score_error}")
        except Exception as e:
            report.warnings.append(f"Scoring exception: {e}")

    # === Step 6: Baseline Comparison ===
    if artifacts.ai_summary and artifacts.baseline_summary:
        try:
            ai_data = json.loads(ai_summary_path.read_text(encoding="utf-8"))
            baseline_data = json.loads(baseline_path.read_text(encoding="utf-8"))

            report.baseline_comparison = {
                "ai_confidence": ai_data.get("confidence", 0),
                "baseline_confidence": baseline_data.get("confidence", 0),
                "ai_observations_count": len(ai_data.get("key_observations", [])),
                "baseline_observations_count": len(baseline_data.get("key_observations", [])),
                "ai_actors_count": len(ai_data.get("top_actors", [])),
                "baseline_actors_count": len(baseline_data.get("top_actors", [])),
                "ai_actions_count": len(ai_data.get("recommended_actions", [])),
                "baseline_actions_count": len(baseline_data.get("recommended_actions", [])),
            }
        except Exception as e:
            report.warnings.append(f"Baseline comparison failed: {e}")

    # === Finalize ===
    runtime.total_seconds = time.time() - start_time
    report.runtime = runtime
    report.artifacts = artifacts

    # Add reproducibility info
    if artifacts.ai_summary:
        try:
            ai_data = json.loads(ai_summary_path.read_text(encoding="utf-8"))
            report.reproducibility = ai_data.get("input", {}).get("reproducibility", {})
        except Exception:
            pass

    # Write eval report
    report_path = out_dir / "eval_report.json"
    report_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")

    return report, None


def render_report_human(report: EvalReport) -> str:
    """Render evaluation report in human-readable format."""
    lines = []
    lines.append("=" * 60)
    lines.append(f"Evaluation Report: {report.scenario_name}")
    lines.append("=" * 60)
    lines.append(f"Timestamp: {report.timestamp}")
    lines.append("")

    # Counts
    lines.append("## Summary")
    lines.append(f"  Total events: {report.total_events}")
    lines.append(f"  Processed events: {report.processed_events}")
    lines.append(f"  Truncated: {report.truncated}")
    lines.append(f"  Actors found: {report.actors_found}")
    lines.append(f"  Exported detections: {report.exported_detections}")
    lines.append("")

    # Runtime
    lines.append("## Runtime")
    lines.append(f"  Total: {report.runtime.total_seconds:.2f}s")
    if report.runtime.correlation_seconds:
        lines.append(f"  Correlation: {report.runtime.correlation_seconds:.2f}s")
    if report.runtime.ai_summary_seconds:
        lines.append(f"  AI Summary: {report.runtime.ai_summary_seconds:.2f}s")
    if report.runtime.baseline_summary_seconds:
        lines.append(f"  Baseline Summary: {report.runtime.baseline_summary_seconds:.2f}s")
    if report.runtime.export_seconds:
        lines.append(f"  Export: {report.runtime.export_seconds:.2f}s")
    lines.append("")

    # AI Metrics
    if report.ai_metrics:
        lines.append("## AI Quality Metrics")
        lines.append(f"  Overall Score: {report.ai_metrics.overall_score}/100")
        lines.append(f"  Grounding: {report.ai_metrics.grounding.score}/100")
        lines.append(f"    Grounded claims: {report.ai_metrics.grounding.grounded_claims}/{report.ai_metrics.grounding.total_claims}")
        lines.append(f"  Hallucination: {report.ai_metrics.hallucination.score}/100")
        lines.append(f"    Total hallucinations: {report.ai_metrics.hallucination.total_hallucinations}")
        lines.append(f"  Completeness: {report.ai_metrics.completeness.score}/100")
        lines.append(f"    Missing sections: {', '.join(report.ai_metrics.completeness.missing_sections) or 'None'}")
        lines.append(f"  Injection Resistance: {report.ai_metrics.injection_resistance.score}/100")
        lines.append("")

    # Baseline Comparison
    if report.baseline_comparison:
        lines.append("## Baseline vs LLM Comparison")
        bc = report.baseline_comparison
        lines.append(f"  Confidence: LLM={bc.get('ai_confidence')} vs Baseline={bc.get('baseline_confidence')}")
        lines.append(f"  Observations: LLM={bc.get('ai_observations_count')} vs Baseline={bc.get('baseline_observations_count')}")
        lines.append(f"  Actors: LLM={bc.get('ai_actors_count')} vs Baseline={bc.get('baseline_actors_count')}")
        lines.append(f"  Actions: LLM={bc.get('ai_actions_count')} vs Baseline={bc.get('baseline_actions_count')}")
        lines.append("")

    # Reproducibility
    if report.reproducibility:
        lines.append("## Reproducibility")
        for key, value in report.reproducibility.items():
            lines.append(f"  {key}: {value}")
        lines.append("")

    # Artifacts
    lines.append("## Artifacts")
    if report.artifacts.cloudtrail_correlation:
        lines.append(f"  Correlation: {report.artifacts.cloudtrail_correlation}")
    if report.artifacts.ai_summary:
        lines.append(f"  AI Summary: {report.artifacts.ai_summary}")
    if report.artifacts.baseline_summary:
        lines.append(f"  Baseline Summary: {report.artifacts.baseline_summary}")
    if report.artifacts.evidence_bundle:
        lines.append(f"  Evidence Bundle: {report.artifacts.evidence_bundle}")
    if report.artifacts.exports_dir:
        lines.append(f"  Exports: {report.artifacts.exports_dir}")
    lines.append("")

    # Errors/Warnings
    if report.errors:
        lines.append("## Errors")
        for err in report.errors:
            lines.append(f"  - {err}")
        lines.append("")

    if report.warnings:
        lines.append("## Warnings")
        for warn in report.warnings:
            lines.append(f"  - {warn}")
        lines.append("")

    lines.append("=" * 60)
    return "\n".join(lines)
