"""Integration test: run CLI, validate exit codes and JSON schema. Run only when RUN_INTEGRATION_TESTS=1."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import typer.testing

from cti_checkup.cli import app

RUN_INTEGRATION = os.environ.get("RUN_INTEGRATION_TESTS", "").strip() in ("1", "true", "yes")


def _run_cli(args: list[str]) -> tuple[int, str]:
    runner = typer.testing.CliRunner()
    result = runner.invoke(app, args, catch_exceptions=False)
    out = (result.stdout or "") + (result.stderr or "")
    exit_code = result.exit_code if result.exit_code is not None else 0
    return exit_code, out


def test_out_file_matches_stdout() -> None:
    if not RUN_INTEGRATION:
        return
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        out_path = f.name
    try:
        exit_code, stdout = _run_cli(["cloud", "aws", "s3", "--output", "json", "--out", out_path])
        file_content = Path(out_path).read_text(encoding="utf-8")
        assert file_content.strip() == stdout.strip()
        if stdout.strip():
            json.loads(file_content)
    finally:
        Path(out_path).unlink(missing_ok=True)


def test_cloud_aws_s3_json_schema() -> None:
    if not RUN_INTEGRATION:
        return
    exit_code, out = _run_cli(["cloud", "aws", "s3", "--output", "json"])
    data = json.loads(out)
    assert "provider" in data
    assert data["provider"] == "aws"
    assert "account_id" in data
    assert "regions" in data
    assert "checks" in data
    assert "findings" in data
    assert "summary" in data
    assert "partial_failure" in data
    assert "fatal_error" in data
    assert "high" in data["summary"]
    assert "medium" in data["summary"]
    assert "low" in data["summary"]


def test_cloud_aws_scan_exit_codes() -> None:
    if not RUN_INTEGRATION:
        return
    exit_code, _ = _run_cli(["cloud", "aws", "scan", "--output", "json"])
    assert exit_code in (0, 1, 2, 3)


def test_intel_ip_missing_key_exit_code() -> None:
    if not RUN_INTEGRATION:
        return
    exit_code, out = _run_cli(["intel", "ip", "1.2.3.4", "--output", "json"])
    assert exit_code == 1
    data = json.loads(out)
    assert data.get("fatal_error") is True
    assert "provider" in data
    assert data["provider"] == "intel"
