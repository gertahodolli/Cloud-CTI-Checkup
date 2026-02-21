from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List

import typer

from cti_checkup.core.config import load_config
from cti_checkup.core.output import render_human, render_json
from cti_checkup.core.exit_codes import ExitCode
from cti_checkup.core.redact import redact_scan_result
from cti_checkup.cloud.aws.runner import run_aws_scan
from cti_checkup.core.models import ScanResult
from cti_checkup.intel.ip import run_intel_ip
from cti_checkup.intel.domain import run_intel_domain
from cti_checkup.intel.virustotal import run_intel_hash
from cti_checkup.intel.correlation.cloudtrail import (
    correlate_cloudtrail,
    render_cloudtrail_human,
    render_cloudtrail_json,
)
from cti_checkup.aws.iam_identity_profile import (
    render_identity_profiles_human,
    run_iam_identity_profiles,
)
from cti_checkup.export.detections import export_detections
from cti_checkup.ai.cli import ai_app
from cti_checkup.eval.cli import eval_app

app = typer.Typer(no_args_is_help=True)
cloud = typer.Typer(no_args_is_help=True)
aws = typer.Typer(no_args_is_help=True)
intel = typer.Typer(no_args_is_help=True)
aws_iam = typer.Typer(no_args_is_help=False)
intel_correlate = typer.Typer(no_args_is_help=True)
export = typer.Typer(no_args_is_help=True)

cloud.add_typer(aws, name="aws")
app.add_typer(cloud, name="cloud")
app.add_typer(intel, name="intel")
app.add_typer(export, name="export")
app.add_typer(ai_app, name="ai")
app.add_typer(eval_app, name="eval")
aws.add_typer(aws_iam, name="iam")
intel.add_typer(intel_correlate, name="correlate")


def _split_csv(value: Optional[str]) -> Optional[List[str]]:
    if not value:
        return None
    return [x.strip() for x in value.split(",") if x.strip()]


@aws.command("scan")
def aws_scan(
    config: Optional[Path] = typer.Option(None, "--config", envvar="CTICHECKUP_CONFIG"),
    profile: Optional[str] = typer.Option(None, "--profile", envvar="AWS_PROFILE"),
    regions: Optional[str] = typer.Option(None, "--regions", envvar="AWS_REGIONS"),
    output: str = typer.Option("human", "--output", envvar="CTICHECKUP_OUTPUT"),
    fmt: str = typer.Option("table", "--format", envvar="CTICHECKUP_FORMAT"),
    strict: bool = typer.Option(False, "--strict", envvar="CTICHECKUP_STRICT"),
    exit_on_findings: bool = typer.Option(False, "--exit-on-findings", envvar="CTICHECKUP_EXIT_ON_FINDINGS"),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Write output to file"),
) -> None:
    cfg = load_config(config)
    region_list = _split_csv(regions)

    result: ScanResult = run_aws_scan(
        cfg=cfg,
        profile=profile,
        regions=region_list,
        strict=strict,
        services=None,
    )

    result_out = redact_scan_result(result)
    if out is not None and result_out.scan_date is None:
        result_out.scan_date = datetime.now(timezone.utc).isoformat()
    text = render_json(result_out) if output.lower() == "json" else render_human(result_out, fmt=fmt)
    typer.echo(text)
    if out is not None:
        out.write_text(text, encoding="utf-8")

    if result.fatal_error:
        raise typer.Exit(code=ExitCode.ERROR)

    if result.partial_failure:
        raise typer.Exit(code=ExitCode.PARTIAL_SUCCESS)

    if exit_on_findings and result.summary.high + result.summary.medium + result.summary.low > 0:
        raise typer.Exit(code=ExitCode.FINDINGS)

    raise typer.Exit(code=ExitCode.SUCCESS)


@aws.command("s3")
def aws_s3(
    config: Optional[Path] = typer.Option(None, "--config", envvar="CTICHECKUP_CONFIG"),
    profile: Optional[str] = typer.Option(None, "--profile", envvar="AWS_PROFILE"),
    regions: Optional[str] = typer.Option(None, "--regions", envvar="AWS_REGIONS"),
    output: str = typer.Option("human", "--output", envvar="CTICHECKUP_OUTPUT"),
    fmt: str = typer.Option("table", "--format", envvar="CTICHECKUP_FORMAT"),
    strict: bool = typer.Option(False, "--strict", envvar="CTICHECKUP_STRICT"),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Write output to file"),
) -> None:
    cfg = load_config(config)
    result = run_aws_scan(cfg=cfg, profile=profile, regions=_split_csv(regions), strict=strict, services=["s3"])
    result_out = redact_scan_result(result)
    if out is not None and result_out.scan_date is None:
        result_out.scan_date = datetime.now(timezone.utc).isoformat()
    text = render_json(result_out) if output.lower() == "json" else render_human(result_out, fmt=fmt)
    typer.echo(text)
    if out is not None:
        out.write_text(text, encoding="utf-8")
    raise typer.Exit(code=ExitCode.SUCCESS if not result.fatal_error else ExitCode.ERROR)


@aws_iam.callback(invoke_without_command=True)
def aws_iam_scan(
    ctx: typer.Context,
    config: Optional[Path] = typer.Option(None, "--config", envvar="CTICHECKUP_CONFIG"),
    profile: Optional[str] = typer.Option(None, "--profile", envvar="AWS_PROFILE"),
    output: str = typer.Option("human", "--output", envvar="CTICHECKUP_OUTPUT"),
    fmt: str = typer.Option("table", "--format", envvar="CTICHECKUP_FORMAT"),
    strict: bool = typer.Option(False, "--strict", envvar="CTICHECKUP_STRICT"),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Write output to file"),
) -> None:
    if ctx.invoked_subcommand is not None:
        return
    cfg = load_config(config)
    result = run_aws_scan(cfg=cfg, profile=profile, regions=None, strict=strict, services=["iam"])
    result_out = redact_scan_result(result)
    if out is not None and result_out.scan_date is None:
        result_out.scan_date = datetime.now(timezone.utc).isoformat()
    text = render_json(result_out) if output.lower() == "json" else render_human(result_out, fmt=fmt)
    typer.echo(text)
    if out is not None:
        out.write_text(text, encoding="utf-8")
    raise typer.Exit(code=ExitCode.SUCCESS if not result.fatal_error else ExitCode.ERROR)


@aws_iam.command("identities")
def aws_iam_identities(
    config: Optional[Path] = typer.Option(None, "--config", envvar="CTICHECKUP_CONFIG"),
    profile: Optional[str] = typer.Option(None, "--profile", envvar="AWS_PROFILE"),
    output: str = typer.Option("human", "--output", envvar="CTICHECKUP_OUTPUT"),
    fmt: str = typer.Option("table", "--format", envvar="CTICHECKUP_FORMAT"),
    strict: bool = typer.Option(False, "--strict", envvar="CTICHECKUP_STRICT"),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Write output to file"),
) -> None:
    cfg = load_config(config)
    result, partial, fatal = run_iam_identity_profiles(cfg, profile, strict)
    text = (
        json.dumps(result, indent=2, default=str)
        if output.lower() == "json"
        else render_identity_profiles_human(result, fmt=fmt)
    )
    typer.echo(text)
    if out is not None:
        out.write_text(text, encoding="utf-8")
    if fatal:
        raise typer.Exit(code=ExitCode.ERROR)
    if partial:
        raise typer.Exit(code=ExitCode.PARTIAL_SUCCESS)
    raise typer.Exit(code=ExitCode.SUCCESS)


@aws.command("ec2")
def aws_ec2(
    config: Optional[Path] = typer.Option(None, "--config", envvar="CTICHECKUP_CONFIG"),
    profile: Optional[str] = typer.Option(None, "--profile", envvar="AWS_PROFILE"),
    regions: Optional[str] = typer.Option(None, "--regions", envvar="AWS_REGIONS"),
    output: str = typer.Option("human", "--output", envvar="CTICHECKUP_OUTPUT"),
    fmt: str = typer.Option("table", "--format", envvar="CTICHECKUP_FORMAT"),
    strict: bool = typer.Option(False, "--strict", envvar="CTICHECKUP_STRICT"),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Write output to file"),
) -> None:
    cfg = load_config(config)
    result = run_aws_scan(cfg=cfg, profile=profile, regions=_split_csv(regions), strict=strict, services=["ec2"])
    result_out = redact_scan_result(result)
    if out is not None and result_out.scan_date is None:
        result_out.scan_date = datetime.now(timezone.utc).isoformat()
    text = render_json(result_out) if output.lower() == "json" else render_human(result_out, fmt=fmt)
    typer.echo(text)
    if out is not None:
        out.write_text(text, encoding="utf-8")
    raise typer.Exit(code=ExitCode.SUCCESS if not result.fatal_error else ExitCode.ERROR)


@intel.command("ip")
def intel_ip(
    ip_address: str = typer.Argument(..., help="IP address to look up"),
    config: Optional[Path] = typer.Option(None, "--config", envvar="CTICHECKUP_CONFIG"),
    output: str = typer.Option("human", "--output", envvar="CTICHECKUP_OUTPUT"),
    fmt: str = typer.Option("table", "--format", envvar="CTICHECKUP_FORMAT"),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Write output to file"),
) -> None:
    cfg = load_config(config)
    result = run_intel_ip(ip_address, cfg)
    result_out = redact_scan_result(result)
    text = render_json(result_out) if output.lower() == "json" else render_human(result_out, fmt=fmt)
    typer.echo(text)
    if out is not None:
        out.write_text(text, encoding="utf-8")
    if result.fatal_error:
        raise typer.Exit(code=ExitCode.ERROR)
    if result.partial_failure:
        raise typer.Exit(code=ExitCode.PARTIAL_SUCCESS)
    raise typer.Exit(code=ExitCode.SUCCESS)


@intel.command("domain")
def intel_domain(
    domain: str = typer.Argument(..., help="Domain to look up"),
    config: Optional[Path] = typer.Option(None, "--config", envvar="CTICHECKUP_CONFIG"),
    output: str = typer.Option("human", "--output", envvar="CTICHECKUP_OUTPUT"),
    fmt: str = typer.Option("table", "--format", envvar="CTICHECKUP_FORMAT"),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Write output to file"),
) -> None:
    cfg = load_config(config)
    result = run_intel_domain(domain, cfg)
    result_out = redact_scan_result(result)
    text = render_json(result_out) if output.lower() == "json" else render_human(result_out, fmt=fmt)
    typer.echo(text)
    if out is not None:
        out.write_text(text, encoding="utf-8")
    if result.fatal_error:
        raise typer.Exit(code=ExitCode.ERROR)
    if result.partial_failure:
        raise typer.Exit(code=ExitCode.PARTIAL_SUCCESS)
    raise typer.Exit(code=ExitCode.SUCCESS)


@intel.command("hash")
def intel_hash(
    hash_value: str = typer.Argument(..., help="MD5, SHA1, or SHA256 hash to look up"),
    config: Optional[Path] = typer.Option(None, "--config", envvar="CTICHECKUP_CONFIG"),
    output: str = typer.Option("human", "--output", envvar="CTICHECKUP_OUTPUT"),
    fmt: str = typer.Option("table", "--format", envvar="CTICHECKUP_FORMAT"),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Write output to file"),
) -> None:
    """Look up a file hash on VirusTotal."""
    cfg = load_config(config)
    result = run_intel_hash(hash_value, cfg)
    result_out = redact_scan_result(result)
    text = render_json(result_out) if output.lower() == "json" else render_human(result_out, fmt=fmt)
    typer.echo(text)
    if out is not None:
        out.write_text(text, encoding="utf-8")
    if result.fatal_error:
        raise typer.Exit(code=ExitCode.ERROR)
    if result.partial_failure:
        raise typer.Exit(code=ExitCode.PARTIAL_SUCCESS)
    raise typer.Exit(code=ExitCode.SUCCESS)


@intel_correlate.command("cloudtrail")
def intel_correlate_cloudtrail(
    events: Path = typer.Option(..., "--events", help="CloudTrail JSON array or JSONL file"),
    config: Optional[Path] = typer.Option(None, "--config", envvar="CTICHECKUP_CONFIG"),
    output: str = typer.Option("human", "--output", envvar="CTICHECKUP_OUTPUT"),
    fmt: str = typer.Option("table", "--format", envvar="CTICHECKUP_FORMAT"),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Write output to file"),
) -> None:
    cfg = load_config(config)
    result, partial, fatal, _ = correlate_cloudtrail(events, cfg)
    text = (
        render_cloudtrail_json(result)
        if output.lower() == "json"
        else render_cloudtrail_human(result, fmt=fmt)
    )
    typer.echo(text)
    if out is not None:
        out.write_text(text, encoding="utf-8")
    if fatal:
        raise typer.Exit(code=ExitCode.ERROR)
    if partial:
        raise typer.Exit(code=ExitCode.PARTIAL_SUCCESS)
    raise typer.Exit(code=ExitCode.SUCCESS)


@export.command("detections")
def export_detections_cmd(
    input_path: Path = typer.Option(..., "--input", help="Input JSON file"),
    fmt: str = typer.Option(..., "--format", help="Output format (sigma|splunk|kql|cloudwatch)"),
    out: Path = typer.Option(..., "--out", "-o", help="Output directory"),
    source_type: Optional[str] = typer.Option(
        None, "--source-type", help="Override input type (aws_scan|cloudtrail_correlation|iam_identities)"
    ),
    config: Optional[Path] = typer.Option(None, "--config", envvar="CTICHECKUP_CONFIG"),
    strict: bool = typer.Option(False, "--strict", envvar="CTICHECKUP_STRICT"),
) -> None:
    cfg = load_config(config)
    report, partial, fatal = export_detections(
        input_path=input_path,
        out_dir=out,
        fmt=fmt,
        source_type=source_type,
        cfg=cfg,
        strict=strict,
    )
    report_path = out / "export_report.json"
    try:
        report_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    except OSError as e:
        typer.echo(f"Failed to write export report: {e}")
        raise typer.Exit(code=ExitCode.ERROR)
    if report.get("errors"):
        for err in report.get("errors", []):
            typer.echo(f"Export error: {err}", err=True)
    typer.echo(f"Exported {report.get('exported_count', 0)} detections to {out}")
    if fatal:
        raise typer.Exit(code=ExitCode.ERROR)
    if partial:
        raise typer.Exit(code=ExitCode.PARTIAL_SUCCESS)
    raise typer.Exit(code=ExitCode.SUCCESS)
