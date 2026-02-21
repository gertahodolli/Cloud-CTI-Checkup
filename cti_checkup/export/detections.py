"""Export detections from CTI-Checkup JSON outputs using config-driven mappings."""
from __future__ import annotations

import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cti_checkup.core.config_utils import get_bool, get_int, get_list_str

logger = logging.getLogger(__name__)

_ALLOWED_FORMATS = ("sigma", "splunk", "kql", "cloudwatch")
_ALLOWED_SOURCE_TYPES = ("aws_scan", "cloudtrail_correlation", "iam_identities")
_TEMPLATE_PATTERN = re.compile(r"\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}")
_ACCESS_KEY_PATTERN = re.compile(r"\b(A[A-Z0-9]{19})\b")


def _mask_access_key_id(value: str) -> str:
    if not value or len(value) < 4:
        return "****"
    return "****" + value[-4:]


def _redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _redact_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(v) for v in value]
    if isinstance(value, str):
        return _ACCESS_KEY_PATTERN.sub(lambda m: _mask_access_key_id(m.group(1)), value)
    return value


def _safe_filename(value: str) -> str:
    if not value:
        return "unknown"
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value)


def _hash_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _get_path_value(data: Any, path: str) -> Any:
    if data is None or not path:
        return None
    cur = data
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _resolve_template_value(context: Dict[str, Any], path: str) -> str:
    value = _get_path_value(context, path)
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, default=str)
    return str(value)


def render_template(text: str, context: Dict[str, Any]) -> str:
    def repl(match: re.Match) -> str:
        key = match.group(1)
        return _resolve_template_value(context, key)

    return _TEMPLATE_PATTERN.sub(repl, text)


def detect_source_type(data: Any, override: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    if override:
        if override not in _ALLOWED_SOURCE_TYPES:
            return None, f"Invalid source type '{override}'."
        return override, None
    if not isinstance(data, dict):
        return None, "Input JSON must be an object."

    matches: List[str] = []
    if all(k in data for k in ("provider", "account_id", "checks", "findings", "summary")):
        matches.append("aws_scan")
    if isinstance(data.get("actors"), list) and isinstance(data.get("input"), dict):
        matches.append("cloudtrail_correlation")
    if isinstance(data.get("identities"), list) and isinstance(data.get("summary"), dict):
        matches.append("iam_identities")

    if len(matches) == 1:
        return matches[0], None
    if len(matches) > 1:
        return None, "Ambiguous input type; provide --source-type."
    return None, "Unrecognized input type; provide --source-type."


def _load_export_config(cfg: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    export_cfg = cfg.get("export") or {}
    det_cfg = export_cfg.get("detections")
    if not isinstance(det_cfg, dict):
        return None, "Missing export.detections configuration."

    enabled = get_bool(det_cfg, ["enabled"])
    if enabled is None:
        return None, "Missing export.detections.enabled."
    if not enabled:
        return None, "export.detections is disabled."

    formats_cfg = det_cfg.get("formats")
    if not isinstance(formats_cfg, dict):
        return None, "Missing export.detections.formats."
    enabled_formats = get_list_str(formats_cfg, ["enabled"])
    if not enabled_formats:
        return None, "Missing export.detections.formats.enabled."
    for fmt in enabled_formats:
        if fmt not in _ALLOWED_FORMATS:
            return None, f"Unsupported export format '{fmt}'."

    templates_dir = det_cfg.get("templates_dir")
    if templates_dir is not None and not isinstance(templates_dir, str):
        return None, "export.detections.templates_dir must be a string."

    mappings = det_cfg.get("mappings")
    if not isinstance(mappings, dict):
        return None, "Missing export.detections.mappings."

    return {
        "enabled_formats": enabled_formats,
        "templates_dir": templates_dir,
        "mappings": mappings,
        "cloudtrail": det_cfg.get("cloudtrail") or {},
        "iam": det_cfg.get("iam") or {},
    }, None


def _resolve_templates_dir(config: Dict[str, Any]) -> Path:
    override = config.get("templates_dir")
    if isinstance(override, str) and override.strip():
        return Path(override).expanduser()
    return Path(__file__).resolve().parent / "templates"


def _load_template(
    templates_dir: Path, fmt: str, template_name: str
) -> Tuple[Optional[str], Optional[str]]:
    if not template_name or not isinstance(template_name, str):
        return None, "Missing template name."
    path = templates_dir / fmt / template_name
    try:
        return path.read_text(encoding="utf-8"), None
    except OSError as e:
        return None, f"Template read failed: {path} ({e})"


def _format_extension(fmt: str) -> str:
    return fmt


def _write_output(
    out_dir: Path, fmt: str, source_type: str, filename: str, content: str
) -> Optional[str]:
    try:
        target_dir = out_dir / fmt / source_type
        target_dir.mkdir(parents=True, exist_ok=True)
        target_path = target_dir / filename
        target_path.write_text(content, encoding="utf-8")
        return None
    except OSError as e:
        return str(e)


def _select_evidence(evidence: Any, filter_fields: Optional[List[str]]) -> Dict[str, Any]:
    if not isinstance(evidence, dict):
        return {}
    if not filter_fields:
        return evidence
    out: Dict[str, Any] = {}
    for field in filter_fields:
        if not isinstance(field, str) or not field.strip():
            continue
        value = _get_path_value(evidence, field.strip())
        if value is not None:
            out[field.strip()] = value
    return out


def _aws_check_id(finding: Dict[str, Any]) -> Optional[str]:
    issue = finding.get("issue")
    if isinstance(issue, str) and issue.strip():
        return issue.strip()
    fid = finding.get("finding_id")
    if isinstance(fid, str) and fid.strip():
        return fid.strip()
    return None


def _ensure_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _extract_actor_field(actor: Dict[str, Any], path: Optional[str]) -> Any:
    if not path or not isinstance(path, str):
        return None
    return _get_path_value(actor, path)


def export_detections(
    input_path: Path,
    out_dir: Path,
    fmt: str,
    source_type: Optional[str],
    cfg: Dict[str, Any],
    strict: bool,
) -> Tuple[Dict[str, Any], bool, bool]:
    report: Dict[str, Any] = {
        "input_file": str(input_path),
        "source_type": source_type,
        "format": fmt,
        "exported_count": 0,
        "skipped_count": 0,
        "skipped_reasons": [],
        "errors": [],
    }

    config, config_error = _load_export_config(cfg)
    if config_error:
        report["errors"].append(config_error)
        return report, False, True
    assert config is not None

    if fmt not in config["enabled_formats"]:
        report["errors"].append(f"Format '{fmt}' not enabled in config.")
        return report, False, True

    try:
        raw = input_path.read_text(encoding="utf-8")
    except OSError as e:
        report["errors"].append(str(e))
        return report, False, True

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        report["errors"].append(f"Invalid JSON: {e}")
        return report, False, True

    detected, detect_error = detect_source_type(data, source_type)
    if detect_error:
        report["errors"].append(detect_error)
        return report, True, False
    assert detected is not None
    report["source_type"] = detected

    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        report["errors"].append(str(e))
        return report, False, True

    templates_dir = _resolve_templates_dir(config)
    mappings = config["mappings"]

    exported = 0
    skipped = 0
    partial = False
    fatal = False

    if detected == "aws_scan":
        aws_map = _ensure_dict(mappings.get("aws_scan"))
        by_check_id = aws_map.get("by_check_id")
        if not isinstance(by_check_id, dict):
            report["errors"].append("Missing export.detections.mappings.aws_scan.by_check_id.")
            return report, False, True

        metadata = {
            "provider": data.get("provider"),
            "account_id": data.get("account_id"),
            "regions": data.get("regions"),
            "summary": data.get("summary"),
            "timestamp": data.get("timestamp"),
        }
        findings = data.get("findings") if isinstance(data, dict) else []
        if not isinstance(findings, list):
            findings = []

        for finding in findings:
            if not isinstance(finding, dict):
                continue
            check_id = _aws_check_id(finding)
            if not check_id:
                skipped += 1
                report["skipped_reasons"].append({"key": "unknown", "reason": "missing_check_id"})
                logger.debug("skip aws finding reason=missing_check_id")
                continue
            mapping = by_check_id.get(check_id)
            if not isinstance(mapping, dict):
                skipped += 1
                report["skipped_reasons"].append({"key": check_id, "reason": "missing_mapping"})
                logger.debug("skip aws finding check_id=%s reason=missing_mapping", check_id)
                partial = True
                if strict:
                    fatal = True
                continue
            template_name = mapping.get("template")
            template_text, template_error = _load_template(templates_dir, fmt, template_name)
            if template_error:
                skipped += 1
                report["skipped_reasons"].append({"key": check_id, "reason": "missing_template"})
                report["errors"].append(template_error)
                logger.debug("skip aws finding check_id=%s reason=missing_template", check_id)
                partial = True
                if strict:
                    fatal = True
                continue

            mapping_fields = mapping.get("fields") if isinstance(mapping.get("fields"), dict) else {}
            defaults = mapping.get("defaults") if isinstance(mapping.get("defaults"), dict) else {}
            filter_fields = mapping.get("filter_fields") if isinstance(mapping.get("filter_fields"), list) else []

            evidence = _select_evidence(finding.get("evidence"), filter_fields)
            fields = {**defaults, **mapping_fields}

            context = {
                "finding": _redact_value(finding),
                "evidence": _redact_value(evidence),
                "fields": _redact_value(fields),
                "metadata": _redact_value(metadata),
            }

            rendered = render_template(template_text or "", context)

            resource_id = str(finding.get("resource_id", "unknown"))
            filename = f"{_safe_filename(check_id)}__{_hash_value(resource_id)}.{_format_extension(fmt)}"
            write_error = _write_output(out_dir, fmt, detected, filename, rendered)
            if write_error:
                report["errors"].append(write_error)
                return report, partial, True
            exported += 1
            logger.debug("exported aws finding check_id=%s", check_id)

    elif detected == "cloudtrail_correlation":
        cloud_cfg = _ensure_dict(config.get("cloudtrail"))
        min_actor_score = get_int(cloud_cfg, ["min_actor_score"])
        mode = cloud_cfg.get("mode")
        if min_actor_score is None or min_actor_score < 0:
            report["errors"].append("Missing export.detections.cloudtrail.min_actor_score.")
            return report, False, True
        if mode not in ("per_actor", "combined"):
            report["errors"].append("Missing export.detections.cloudtrail.mode.")
            return report, False, True

        cloud_map = _ensure_dict(mappings.get("cloudtrail_correlation"))
        actor_rule = cloud_map.get("actor_rule")
        if not isinstance(actor_rule, dict):
            report["errors"].append("Missing export.detections.mappings.cloudtrail_correlation.actor_rule.")
            return report, True, bool(strict)
        template_name = actor_rule.get("template")
        template_text, template_error = _load_template(templates_dir, fmt, template_name)
        if template_error:
            report["errors"].append(template_error)
            return report, True, bool(strict)

        fields_cfg = actor_rule.get("fields") if isinstance(actor_rule.get("fields"), dict) else {}
        ip_field = fields_cfg.get("ip_field")
        ua_field = fields_cfg.get("ua_field")
        identity_field = fields_cfg.get("identity_field")
        event_names_field = fields_cfg.get("event_names_field")

        actors = data.get("actors") if isinstance(data, dict) else []
        if not isinstance(actors, list):
            actors = []

        selected = []
        for actor in actors:
            if not isinstance(actor, dict):
                continue
            score = actor.get("score")
            try:
                score_val = int(score)
            except (TypeError, ValueError):
                score_val = 0
            if score_val < min_actor_score:
                skipped += 1
                report["skipped_reasons"].append({"key": actor.get("actor", "unknown"), "reason": "below_threshold"})
                logger.debug("skip actor reason=below_threshold")
                continue
            selected.append(actor)

        metadata = data.get("input") if isinstance(data.get("input"), dict) else {}
        if mode == "combined":
            context = {
                "actors": _redact_value(selected),
                "fields": _redact_value(fields_cfg),
                "metadata": _redact_value(metadata),
            }
            rendered = render_template(template_text or "", context)
            filename = f"actors__combined.{_format_extension(fmt)}"
            write_error = _write_output(out_dir, fmt, detected, filename, rendered)
            if write_error:
                report["errors"].append(write_error)
                return report, partial, True
            exported += 1
            logger.debug("exported cloudtrail combined")
        else:
            for actor in selected:
                extracted = {
                    "ip": _extract_actor_field(actor, ip_field),
                    "identity": _extract_actor_field(actor, identity_field),
                    "user_agents": _extract_actor_field(actor, ua_field),
                    "event_names": _extract_actor_field(actor, event_names_field),
                }
                context = {
                    "actor": _redact_value(actor),
                    "extracted": _redact_value(extracted),
                    "fields": _redact_value(fields_cfg),
                    "metadata": _redact_value(metadata),
                }
                rendered = render_template(template_text or "", context)
                ip = str(actor.get("ip", "unknown"))
                identity = str(actor.get("identity", "unknown"))
                filename = (
                    f"actor__{_safe_filename(ip)}__{_hash_value(identity)}.{_format_extension(fmt)}"
                )
                write_error = _write_output(out_dir, fmt, detected, filename, rendered)
                if write_error:
                    report["errors"].append(write_error)
                    return report, partial, True
                exported += 1
                logger.debug("exported actor ip=%s", ip)

    elif detected == "iam_identities":
        iam_cfg = _ensure_dict(config.get("iam"))
        min_identity_score = get_int(iam_cfg, ["min_identity_score"])
        if min_identity_score is None or min_identity_score < 0:
            report["errors"].append("Missing export.detections.iam.min_identity_score.")
            return report, False, True

        iam_map = _ensure_dict(mappings.get("iam_identities"))
        identity_rule = iam_map.get("identity_rule")
        if not isinstance(identity_rule, dict):
            report["errors"].append("Missing export.detections.mappings.iam_identities.identity_rule.")
            return report, True, bool(strict)

        template_name = identity_rule.get("template")
        template_text, template_error = _load_template(templates_dir, fmt, template_name)
        if template_error:
            report["errors"].append(template_error)
            return report, True, bool(strict)

        fields_cfg = identity_rule.get("fields") if isinstance(identity_rule.get("fields"), dict) else {}
        identity_field = fields_cfg.get("identity_field")
        risk_factors_field = fields_cfg.get("risk_factors_field")

        identities = data.get("identities") if isinstance(data, dict) else []
        if not isinstance(identities, list):
            identities = []

        for identity in identities:
            if not isinstance(identity, dict):
                continue
            score = identity.get("risk_score")
            try:
                score_val = int(score)
            except (TypeError, ValueError):
                score_val = 0
            if score_val < min_identity_score:
                skipped += 1
                report["skipped_reasons"].append(
                    {"key": identity.get("identity", "unknown"), "reason": "below_threshold"}
                )
                logger.debug("skip identity reason=below_threshold")
                continue

            extracted = {
                "identity": _get_path_value(identity, identity_field or ""),
                "risk_factors": _get_path_value(identity, risk_factors_field or ""),
            }
            context = {
                "identity": _redact_value(identity),
                "extracted": _redact_value(extracted),
                "fields": _redact_value(fields_cfg),
                "metadata": _redact_value(data.get("summary") if isinstance(data.get("summary"), dict) else {}),
            }
            rendered = render_template(template_text or "", context)
            name = str(identity.get("identity", "unknown"))
            filename = f"identity__{_hash_value(name)}.{_format_extension(fmt)}"
            write_error = _write_output(out_dir, fmt, detected, filename, rendered)
            if write_error:
                report["errors"].append(write_error)
                return report, partial, True
            exported += 1
            logger.debug("exported identity name=%s", name)

    report["exported_count"] = exported
    report["skipped_count"] = skipped

    if report["errors"]:
        logger.info("export errors=%s", len(report["errors"]))
    logger.info("exported=%s skipped=%s", exported, skipped)

    return report, partial, fatal
