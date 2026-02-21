"""Tests for detection export."""
from __future__ import annotations

import json
from pathlib import Path

import typer.testing

from cti_checkup.cli import app
from cti_checkup.export.detections import detect_source_type, export_detections, render_template, _hash_value


def test_detect_source_type() -> None:
    aws = {
        "provider": "aws",
        "account_id": "123",
        "checks": [],
        "findings": [],
        "summary": {},
    }
    cloudtrail = {"input": {}, "actors": []}
    iam = {"identities": [], "summary": {}}

    assert detect_source_type(aws, None)[0] == "aws_scan"
    assert detect_source_type(cloudtrail, None)[0] == "cloudtrail_correlation"
    assert detect_source_type(iam, None)[0] == "iam_identities"


def test_template_rendering() -> None:
    template = "hello {{finding.issue}} {{metadata.account_id}}"
    context = {"finding": {"issue": "s3_public"}, "metadata": {"account_id": "123"}}
    rendered = render_template(template, context)
    assert rendered == "hello s3_public 123"


def test_filename_determinism() -> None:
    assert _hash_value("abc") == _hash_value("abc")


def test_strict_vs_non_strict_missing_mapping(tmp_path: Path) -> None:
    input_data = {
        "provider": "aws",
        "account_id": "123",
        "checks": [],
        "findings": [
            {
                "service": "s3",
                "resource_type": "bucket",
                "resource_id": "public-bucket",
                "issue": "missing_mapping",
                "severity": "high",
                "status": "finding",
                "evidence": {},
            }
        ],
        "summary": {},
    }
    input_path = tmp_path / "input.json"
    input_path.write_text(json.dumps(input_data), encoding="utf-8")

    templates_dir = tmp_path / "templates"
    (templates_dir / "sigma").mkdir(parents=True)
    (templates_dir / "sigma" / "aws_scan.tpl").write_text("test {{finding.issue}}", encoding="utf-8")

    cfg = {
        "export": {
            "detections": {
                "enabled": True,
                "formats": {"enabled": ["sigma"]},
                "templates_dir": str(templates_dir),
                "mappings": {"aws_scan": {"by_check_id": {}}},
                "cloudtrail": {"min_actor_score": 10, "mode": "per_actor"},
                "iam": {"min_identity_score": 10},
            }
        }
    }

    report, partial, fatal = export_detections(
        input_path=input_path,
        out_dir=tmp_path / "out",
        fmt="sigma",
        source_type="aws_scan",
        cfg=cfg,
        strict=False,
    )
    assert fatal is False
    assert partial is True
    assert report["skipped_count"] == 1

    report, partial, fatal = export_detections(
        input_path=input_path,
        out_dir=tmp_path / "out2",
        fmt="sigma",
        source_type="aws_scan",
        cfg=cfg,
        strict=True,
    )
    assert fatal is True


def _write_config(tmp_path: Path, templates_dir: Path) -> Path:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "\n".join(
            [
                "export:",
                "  detections:",
                "    enabled: true",
                "    formats:",
                "      enabled: [sigma]",
                f"    templates_dir: {templates_dir}",
                "    cloudtrail:",
                "      min_actor_score: 50",
                "      mode: per_actor",
                "    iam:",
                "      min_identity_score: 50",
                "    mappings:",
                "      aws_scan:",
                "        by_check_id:",
                "          s3_public:",
                "            template: aws_scan.tpl",
                "            fields:",
                "              event_source: s3.amazonaws.com",
                "          mfa_not_enabled:",
                "            template: aws_scan.tpl",
                "            fields:",
                "              event_source: iam.amazonaws.com",
                "      cloudtrail_correlation:",
                "        actor_rule:",
                "          template: cloudtrail_actor.tpl",
                "          fields:",
                "            ip_field: ip",
                "            ua_field: evidence.user_agents",
                "            identity_field: identity",
                "            event_names_field: event_stats.top_events",
                "      iam_identities:",
                "        identity_rule:",
                "          template: iam_identity.tpl",
                "          fields:",
                "            identity_field: identity",
                "            risk_factors_field: risk_factors",
            ]
        ),
        encoding="utf-8",
    )
    return config_path


def test_export_cli_integration(tmp_path: Path) -> None:
    runner = typer.testing.CliRunner()
    templates_dir = Path("tests/fixtures/export/templates").resolve()
    config_path = _write_config(tmp_path, templates_dir)

    out_dir = tmp_path / "out_aws"
    result = runner.invoke(
        app,
        [
            "export",
            "detections",
            "--input",
            "tests/fixtures/export/aws_scan.json",
            "--format",
            "sigma",
            "--out",
            str(out_dir),
            "--config",
            str(config_path),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    report = json.loads((out_dir / "export_report.json").read_text(encoding="utf-8"))
    assert report["exported_count"] == 2

    out_dir = tmp_path / "out_cloudtrail"
    result = runner.invoke(
        app,
        [
            "export",
            "detections",
            "--input",
            "tests/fixtures/export/cloudtrail_correlation.json",
            "--format",
            "sigma",
            "--out",
            str(out_dir),
            "--config",
            str(config_path),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    report = json.loads((out_dir / "export_report.json").read_text(encoding="utf-8"))
    assert report["exported_count"] == 1
    assert report["skipped_count"] == 1

    out_dir = tmp_path / "out_iam"
    result = runner.invoke(
        app,
        [
            "export",
            "detections",
            "--input",
            "tests/fixtures/export/iam_identities.json",
            "--format",
            "sigma",
            "--out",
            str(out_dir),
            "--config",
            str(config_path),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    report = json.loads((out_dir / "export_report.json").read_text(encoding="utf-8"))
    assert report["exported_count"] == 1
    assert report["skipped_count"] == 1
