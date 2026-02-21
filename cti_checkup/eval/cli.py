"""CLI commands for evaluation harness."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from cti_checkup.core.config import load_config
from cti_checkup.core.exit_codes import ExitCode
from cti_checkup.eval.runner import render_report_human, run_scenario
from cti_checkup.eval.scorer import score_ai_output

eval_app = typer.Typer(no_args_is_help=True, help="Evaluation harness commands")


@eval_app.command("run")
def eval_run(
    scenario: str = typer.Option(
        ..., "--scenario", help="Name of the scenario to run (e.g., 'privilege_escalation')"
    ),
    out: Path = typer.Option(
        ..., "--out", "-o", help="Output directory for artifacts"
    ),
    config: Optional[Path] = typer.Option(
        None, "--config", envvar="CTICHECKUP_CONFIG", help="Configuration file path"
    ),
    scenarios_dir: Optional[Path] = typer.Option(
        None, "--scenarios-dir", help="Directory containing scenario definitions"
    ),
    output: str = typer.Option(
        "human", "--output", help="Output format (human|json)"
    ),
) -> None:
    """Run an evaluation scenario end-to-end.

    Executes a complete workflow:
    1. CloudTrail correlation (using scenario events)
    2. AI summarize cloudtrail (LLM mode)
    3. AI summarize cloudtrail (baseline mode)
    4. Export detections
    5. Score AI output quality
    6. Compare baseline vs LLM

    Produces an artifacts directory with:
    - cloudtrail_correlation.json
    - ai_summary.json
    - baseline_summary.json
    - evidence_bundle.json
    - exports/ directory
    - eval_report.json

    Examples:
        cti-checkup eval run --scenario privilege_escalation --out ./eval_output
        cti-checkup eval run --scenario discovery --out ./eval_output --output json
    """
    cfg = load_config(config)

    report, error = run_scenario(
        scenario_name=scenario,
        out_dir=out,
        cfg=cfg,
        scenarios_dir=scenarios_dir,
    )

    if output.lower() == "json":
        typer.echo(report.model_dump_json(indent=2))
    else:
        typer.echo(render_report_human(report))

    if error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(code=ExitCode.ERROR)

    if report.errors:
        raise typer.Exit(code=ExitCode.PARTIAL_SUCCESS)

    raise typer.Exit(code=ExitCode.SUCCESS)


@eval_app.command("score")
def eval_score(
    input_path: Path = typer.Option(
        ..., "--input", help="Path to AI summary JSON file"
    ),
    evidence: Path = typer.Option(
        ..., "--evidence", help="Path to evidence bundle JSON file"
    ),
    out: Optional[Path] = typer.Option(
        None, "--out", "-o", help="Write score report to file"
    ),
    config: Optional[Path] = typer.Option(
        None, "--config", envvar="CTICHECKUP_CONFIG", help="Configuration file path"
    ),
    output: str = typer.Option(
        "human", "--output", help="Output format (human|json)"
    ),
) -> None:
    """Score AI output quality using deterministic checks.

    Evaluates:
    - Grounding: Do timeline items/actors reference evidence fields?
    - Hallucination: Are IPs/identities mentioned present in evidence?
    - Completeness: Are required sections present and populated?
    - Injection Resistance: If input had injections, were warnings generated?

    Examples:
        cti-checkup eval score --input ./ai_summary.json --evidence ./evidence.json
        cti-checkup eval score --input ./ai_summary.json --evidence ./evidence.json --output json
    """
    cfg = load_config(config)

    metrics, error = score_ai_output(
        ai_summary_path=input_path,
        evidence_bundle_path=evidence,
        cfg=cfg,
    )

    if error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(code=ExitCode.ERROR)

    if output.lower() == "json":
        text = metrics.model_dump_json(indent=2)
    else:
        text = _render_metrics_human(metrics)

    typer.echo(text)

    if out is not None:
        try:
            out.write_text(text, encoding="utf-8")
            typer.echo(f"Score report written to {out}")
        except OSError as e:
            typer.echo(f"Failed to write output: {e}", err=True)
            raise typer.Exit(code=ExitCode.ERROR)

    raise typer.Exit(code=ExitCode.SUCCESS)


def _render_metrics_human(metrics) -> str:
    """Render AI quality metrics in human-readable format."""

    lines = []
    lines.append("=" * 50)
    lines.append("AI Output Quality Score")
    lines.append("=" * 50)
    lines.append("")

    lines.append(f"Overall Score: {metrics.overall_score}/100")
    lines.append("")

    # Grounding
    lines.append("## Grounding")
    lines.append(f"  Score: {metrics.grounding.score}/100")
    lines.append(f"  Grounded claims: {metrics.grounding.grounded_claims}/{metrics.grounding.total_claims}")
    if metrics.grounding.ungrounded_claims:
        lines.append("  Ungrounded claims:")
        for claim in metrics.grounding.ungrounded_claims[:5]:
            lines.append(f"    - {claim}")
    lines.append("")

    # Hallucination
    lines.append("## Hallucination Check")
    lines.append(f"  Score: {metrics.hallucination.score}/100")
    lines.append(f"  Total hallucinations: {metrics.hallucination.total_hallucinations}")
    if metrics.hallucination.hallucinated_ips:
        lines.append(f"  Hallucinated IPs: {', '.join(metrics.hallucination.hallucinated_ips[:5])}")
    if metrics.hallucination.hallucinated_identities:
        lines.append(f"  Hallucinated identities: {', '.join(metrics.hallucination.hallucinated_identities[:3])}")
    lines.append("")

    # Completeness
    lines.append("## Completeness")
    lines.append(f"  Score: {metrics.completeness.score}/100")
    lines.append(f"  Present sections: {len(metrics.completeness.present_sections)}/{len(metrics.completeness.required_sections)}")
    if metrics.completeness.missing_sections:
        lines.append(f"  Missing: {', '.join(metrics.completeness.missing_sections)}")
    lines.append("")

    # Injection Resistance
    lines.append("## Injection Resistance")
    lines.append(f"  Score: {metrics.injection_resistance.score}/100")
    lines.append(f"  Passed: {metrics.injection_resistance.passed}")
    lines.append(f"  Injection attempts in input: {metrics.injection_resistance.injection_strings_in_input}")
    lines.append(f"  Warnings generated: {metrics.injection_resistance.warnings_generated}")
    lines.append("")

    lines.append("=" * 50)
    return "\n".join(lines)
