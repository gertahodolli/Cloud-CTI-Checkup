"""CLI commands for AI-assisted analysis."""
from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Optional

import typer

from cti_checkup.core.config import load_config
from cti_checkup.core.exit_codes import ExitCode
from cti_checkup.ai.summarize.cloudtrail import (
    summarize_cloudtrail,
    render_summary_human,
    render_summary_json,
)

ai_app = typer.Typer(no_args_is_help=True, help="AI-assisted analysis commands")
ai_summarize = typer.Typer(no_args_is_help=True, help="AI summarization commands")

ai_app.add_typer(ai_summarize, name="summarize")


class SummarizeMode(str, Enum):
    """Summarization mode."""

    llm = "llm"
    baseline = "baseline"


@ai_summarize.command("cloudtrail")
def ai_summarize_cloudtrail(
    events: Path = typer.Option(
        ..., "--events", help="Path to CloudTrail JSON array or JSONL file"
    ),
    config: Optional[Path] = typer.Option(
        None, "--config", envvar="CTICHECKUP_CONFIG", help="Configuration file path"
    ),
    output: str = typer.Option(
        "human", "--output", envvar="CTICHECKUP_OUTPUT", help="Output format (human|json)"
    ),
    out: Optional[Path] = typer.Option(
        None, "--out", "-o", help="Write output to file"
    ),
    correlation: Optional[Path] = typer.Option(
        None, "--correlation", help="Path to correlation results from intel correlate cloudtrail"
    ),
    mode: SummarizeMode = typer.Option(
        SummarizeMode.llm, "--mode", help="Summarization mode: llm (AI) or baseline (deterministic)"
    ),
    evidence_out: Optional[Path] = typer.Option(
        None, "--evidence-out", help="Write evidence bundle to file (for eval scoring)"
    ),
) -> None:
    """Analyze CloudTrail events and generate an incident-style summary.

    Supports two modes:
    - llm: Uses AI provider to generate intelligent summary (default)
    - baseline: Deterministic summary without AI for comparison

    This command:
    1. Parses CloudTrail events from the specified file
    2. Extracts structured features into an evidence bundle (no raw logs sent to AI)
    3. In LLM mode: sends evidence bundle to AI provider
       In baseline mode: generates deterministic summary from evidence
    4. Returns a narrative summary with timeline, suspicious actors, and recommendations

    The AI never sees raw log data; it only sees aggregated statistics and patterns.

    Examples:
        cti-checkup ai summarize cloudtrail --events ./cloudtrail.json --output json
        cti-checkup ai summarize cloudtrail --events ./logs.jsonl --mode baseline
        cti-checkup ai summarize cloudtrail --events ./ct.json --mode llm --evidence-out ./evidence.json
    """
    cfg = load_config(config)

    output_json = output.lower() == "json"
    use_baseline = mode == SummarizeMode.baseline

    summary, partial, fatal, error_msg, evidence_bundle = summarize_cloudtrail(
        events_path=events,
        cfg=cfg,
        output_json=output_json,
        correlation_path=correlation,
        baseline_mode=use_baseline,
    )

    # Write evidence bundle if requested
    if evidence_out is not None and evidence_bundle is not None:
        try:
            evidence_out.write_text(evidence_bundle.model_dump_json(indent=2), encoding="utf-8")
            typer.echo(f"Evidence bundle written to {evidence_out}")
        except OSError as e:
            typer.echo(f"Failed to write evidence bundle: {e}", err=True)

    # Render output
    if output_json:
        text = render_summary_json(summary)
    else:
        text = render_summary_human(summary)

    typer.echo(text)

    if out is not None:
        try:
            out.write_text(text, encoding="utf-8")
            typer.echo(f"Output written to {out}")
        except OSError as e:
            typer.echo(f"Failed to write output file: {e}", err=True)
            raise typer.Exit(code=ExitCode.ERROR)

    if fatal:
        raise typer.Exit(code=ExitCode.ERROR)
    if partial:
        raise typer.Exit(code=ExitCode.PARTIAL_SUCCESS)
    raise typer.Exit(code=ExitCode.SUCCESS)
