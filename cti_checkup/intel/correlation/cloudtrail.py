"""CloudTrail correlation with CTI enrichment (config-driven)."""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from cti_checkup.core.config_utils import get_bool, get_int
from cti_checkup.core.models import ScanResult
from cti_checkup.intel.ip import run_intel_ip


_ACCESS_KEY_PATTERN = re.compile(r"\b(A[A-Z0-9]{19})\b")


def _mask_access_key_id(value: str) -> str:
    if not value or len(value) < 4:
        return "****"
    return "****" + value[-4:]


def _redact_access_keys(value: str) -> str:
    if not value:
        return value
    return _ACCESS_KEY_PATTERN.sub(lambda m: _mask_access_key_id(m.group(1)), value)


def _parse_int(value: Any) -> Optional[int]:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        v = value.strip()
        if v.isdigit() or (v.startswith("-") and v[1:].isdigit()):
            return int(v)
    return None


def _require_str(cfg: Dict[str, Any], key: str, label: str) -> Tuple[Optional[str], Optional[str]]:
    raw = cfg.get(key)
    if not isinstance(raw, str) or not raw.strip():
        return None, f"Missing {label} (required)."
    return raw.strip(), None


def _load_cloudtrail_config(cfg: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    intel_cfg = cfg.get("intel") or {}
    corr_cfg = intel_cfg.get("correlation") or {}
    cloud_cfg = corr_cfg.get("cloudtrail")
    if not isinstance(cloud_cfg, dict):
        return False, None, "Missing intel.correlation.cloudtrail configuration."

    enabled = get_bool(cloud_cfg, ["enabled"])
    if enabled is None:
        return False, None, "Missing intel.correlation.cloudtrail.enabled."
    if not enabled:
        return False, None, None

    ip_field, err = _require_str(cloud_cfg, "ip_field", "intel.correlation.cloudtrail.ip_field")
    if err:
        return True, None, err
    ua_field, err = _require_str(cloud_cfg, "ua_field", "intel.correlation.cloudtrail.ua_field")
    if err:
        return True, None, err
    identity_field, err = _require_str(
        cloud_cfg, "identity_field", "intel.correlation.cloudtrail.identity_field"
    )
    if err:
        return True, None, err
    event_name_field, err = _require_str(
        cloud_cfg, "event_name_field", "intel.correlation.cloudtrail.event_name_field"
    )
    if err:
        return True, None, err

    max_events = get_int(cloud_cfg, ["max_events"])
    if max_events is None or max_events < 1:
        return True, None, "Invalid intel.correlation.cloudtrail.max_events (required)."
    max_indicators = get_int(cloud_cfg, ["max_indicators"])
    if max_indicators is None or max_indicators < 1:
        return True, None, "Invalid intel.correlation.cloudtrail.max_indicators (required)."

    scoring_cfg = cloud_cfg.get("scoring")
    if not isinstance(scoring_cfg, dict):
        return True, None, "Missing intel.correlation.cloudtrail.scoring (required)."
    weights_cfg = scoring_cfg.get("weights")
    if not isinstance(weights_cfg, dict):
        return True, None, "Missing intel.correlation.cloudtrail.scoring.weights (required)."
    rules_cfg = scoring_cfg.get("rules")
    if not isinstance(rules_cfg, list):
        return True, None, "Missing intel.correlation.cloudtrail.scoring.rules (required)."

    allowed_weights = {
        "event_count",
        "unique_event_count",
        "abuse_confidence",
        "hosting",
        "intel_risk_score",
    }
    weights: Dict[str, int] = {}
    for key, val in weights_cfg.items():
        if key not in allowed_weights:
            return True, None, f"Unsupported scoring weight '{key}'."
        parsed = _parse_int(val)
        if parsed is None:
            return True, None, f"Invalid scoring weight for '{key}'."
        weights[key] = parsed

    allowed_fields = {"event_name", "identity", "user_agent", "provider", "ip"}
    allowed_matches = {"equals", "contains", "prefix", "suffix"}
    rules: List[Dict[str, Any]] = []
    for idx, rule in enumerate(rules_cfg):
        if not isinstance(rule, dict):
            return True, None, f"Invalid scoring rule at index {idx}."
        field = rule.get("field")
        match = rule.get("match")
        value = rule.get("value")
        score = _parse_int(rule.get("score"))
        if field not in allowed_fields:
            return True, None, f"Invalid scoring rule field at index {idx}."
        if match not in allowed_matches:
            return True, None, f"Invalid scoring rule match at index {idx}."
        if not isinstance(value, str) or not value.strip():
            return True, None, f"Invalid scoring rule value at index {idx}."
        if score is None:
            return True, None, f"Invalid scoring rule score at index {idx}."
        rules.append(
            {
                "field": field,
                "match": match,
                "value": value.strip(),
                "score": score,
                "per_event": bool(rule.get("per_event", False)),
                "case_sensitive": bool(rule.get("case_sensitive", False)),
            }
        )

    return (
        True,
        {
            "ip_field": ip_field,
            "ua_field": ua_field,
            "identity_field": identity_field,
            "event_name_field": event_name_field,
            "max_events": max_events,
            "max_indicators": max_indicators,
            "weights": weights,
            "rules": rules,
        },
        None,
    )


def _get_path_value(event: Dict[str, Any], field_path: str) -> Any:
    cur: Any = event
    for part in field_path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _coerce_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        v = value.strip()
        return v or None
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, list) and value:
        for item in value:
            s = _coerce_str(item)
            if s:
                return s
    return None


def _read_events(path: Path, max_events: int) -> Tuple[List[Dict[str, Any]], int, bool]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as e:
        raise ValueError(str(e)) from e

    text = raw.strip()
    if not text:
        return [], 0, False

    try:
        data = json.loads(text)
        if isinstance(data, list):
            events = data
        elif isinstance(data, dict) and isinstance(data.get("Records"), list):
            events = data.get("Records") or []
        else:
            raise ValueError("CloudTrail input must be a JSON array or JSONL.")
        total_events = len(events)
        truncated = total_events > max_events
        return events[:max_events], total_events, truncated
    except json.JSONDecodeError:
        events = []
        total_events = 0
        for idx, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            total_events += 1
            try:
                event = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSONL at line {idx}: {e}") from e
            if len(events) < max_events:
                if isinstance(event, dict):
                    events.append(event)
                else:
                    raise ValueError(f"Invalid JSONL object at line {idx}.")
        truncated = total_events > max_events
        return events, total_events, truncated


def _is_probable_ip(value: str) -> bool:
    if not value or value == "unknown":
        return False
    return "." in value or ":" in value


def _match_value(
    candidate: str,
    target: str,
    match: str,
    case_sensitive: bool,
) -> bool:
    if not case_sensitive:
        candidate = candidate.lower()
        target = target.lower()
    if match == "equals":
        return candidate == target
    if match == "contains":
        return target in candidate
    if match == "prefix":
        return candidate.startswith(target)
    if match == "suffix":
        return candidate.endswith(target)
    return False


def _extract_intel_summary(result: ScanResult) -> Dict[str, Any]:
    abuse_confidence = None
    cloud_attr = None
    for f in result.findings:
        if f.issue == "ip_abuse_confidence":
            abuse_confidence = f.evidence.get("abuse_confidence_score")
            if "cloud_attribution" in f.evidence:
                cloud_attr = f.evidence.get("cloud_attribution")
            break
    return {
        "abuse_confidence": abuse_confidence,
        "cloud_attribution": cloud_attr,
        "risk_score": result.risk_score,
    }


def _default_intel_lookup(ip: str, cfg: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
    result = run_intel_ip(ip, cfg)
    summary = _extract_intel_summary(result)
    partial = bool(result.partial_failure or result.fatal_error)
    return summary, partial


def correlate_cloudtrail(
    events_path: Path,
    cfg: Dict[str, Any],
    intel_lookup: Optional[Callable[[str, Dict[str, Any]], Tuple[Dict[str, Any], bool]]] = None,
) -> Tuple[Dict[str, Any], bool, bool, Optional[str]]:
    enabled, config, config_error = _load_cloudtrail_config(cfg)
    if config_error:
        return {
            "input": {"source": str(events_path)},
            "actors": [],
            "errors": [config_error],
        }, True, False, None
    if not enabled:
        return {
            "input": {"source": str(events_path), "disabled": True},
            "actors": [],
        }, False, False, None

    assert config is not None
    try:
        events, total_events, truncated = _read_events(
            events_path, config["max_events"]
        )
    except ValueError as e:
        return {
            "input": {"source": str(events_path)},
            "actors": [],
            "errors": [str(e)],
        }, False, True, str(e)

    ip_field = config["ip_field"]
    ua_field = config["ua_field"]
    identity_field = config["identity_field"]
    event_name_field = config["event_name_field"]

    actors: Dict[Tuple[str, str], Dict[str, Any]] = {}
    seen_ips: set[str] = set()
    ip_order: List[str] = []

    for event in events:
        if not isinstance(event, dict):
            continue
        ip_raw = _coerce_str(_get_path_value(event, ip_field))
        identity_raw = _coerce_str(_get_path_value(event, identity_field))
        ua_raw = _coerce_str(_get_path_value(event, ua_field))
        event_name_raw = _coerce_str(_get_path_value(event, event_name_field))
        event_time_raw = _coerce_str(event.get("eventTime"))

        if not ip_raw and not identity_raw:
            continue

        ip = ip_raw or "unknown"
        identity = identity_raw or "unknown"
        user_agent = ua_raw or "unknown"
        event_name = event_name_raw or "unknown"

        key = (identity, ip)
        if key not in actors:
            actors[key] = {
                "identity": identity,
                "ip": ip,
                "event_counts": Counter(),
                "user_agent_counts": Counter(),
                "event_times": [],
                "event_count": 0,
            }
        actor = actors[key]
        actor["event_count"] += 1
        actor["event_counts"][event_name] += 1
        actor["user_agent_counts"][user_agent] += 1
        if event_time_raw:
            actor["event_times"].append(event_time_raw)

        if _is_probable_ip(ip) and ip not in seen_ips:
            seen_ips.add(ip)
            ip_order.append(ip)

    lookup = intel_lookup or _default_intel_lookup
    intel_cache: Dict[str, Dict[str, Any]] = {}
    intel_partial = False
    for ip in ip_order[: config["max_indicators"]]:
        summary, partial = lookup(ip, cfg)
        intel_cache[ip] = summary
        if partial:
            intel_partial = True

    weights = config["weights"]
    rules = config["rules"]

    actor_list: List[Dict[str, Any]] = []
    for (identity, ip), actor in actors.items():
        intel_summary = intel_cache.get(ip)
        cloud_attr = (intel_summary or {}).get("cloud_attribution") or {}
        provider = cloud_attr.get("provider", "unknown")
        hosting_flag = cloud_attr.get("hosting")

        abuse_conf = (intel_summary or {}).get("abuse_confidence") or 0
        intel_risk_score = (intel_summary or {}).get("risk_score") or 0

        features = {
            "event_count": actor["event_count"],
            "unique_event_count": len(actor["event_counts"]),
            "abuse_confidence": abuse_conf if isinstance(abuse_conf, (int, float)) else 0,
            "hosting": 1 if hosting_flag is True else 0,
            "intel_risk_score": intel_risk_score if isinstance(intel_risk_score, (int, float)) else 0,
        }

        score = 0
        for key, weight in weights.items():
            score += features.get(key, 0) * weight

        for rule in rules:
            field = rule["field"]
            match = rule["match"]
            value = rule["value"]
            per_event = rule["per_event"]
            case_sensitive = rule["case_sensitive"]

            if field == "event_name":
                if per_event:
                    for name, count in actor["event_counts"].items():
                        if _match_value(name, value, match, case_sensitive):
                            score += rule["score"] * count
                else:
                    if any(
                        _match_value(name, value, match, case_sensitive)
                        for name in actor["event_counts"]
                    ):
                        score += rule["score"]
            elif field == "user_agent":
                if per_event:
                    for ua, count in actor["user_agent_counts"].items():
                        if _match_value(ua, value, match, case_sensitive):
                            score += rule["score"] * count
                else:
                    if any(
                        _match_value(ua, value, match, case_sensitive)
                        for ua in actor["user_agent_counts"]
                    ):
                        score += rule["score"]
            elif field == "identity":
                if _match_value(identity, value, match, case_sensitive):
                    score += rule["score"]
            elif field == "provider":
                if _match_value(str(provider), value, match, case_sensitive):
                    score += rule["score"]
            elif field == "ip":
                if _match_value(ip, value, match, case_sensitive):
                    score += rule["score"]

        event_counts_sorted = sorted(
            actor["event_counts"].items(), key=lambda x: (-x[1], x[0])
        )
        user_agents_sorted = sorted(
            actor["user_agent_counts"].items(), key=lambda x: (-x[1], x[0])
        )

        actor_list.append(
            {
                "actor": _redact_access_keys(identity if identity != "unknown" else ip),
                "ip": ip,
                "identity": _redact_access_keys(identity),
                "score": int(score),
                "intel": intel_summary or {},
                "event_stats": {
                    "event_count": actor["event_count"],
                    "unique_events": len(actor["event_counts"]),
                    "top_events": [
                        {"name": name, "count": count} for name, count in event_counts_sorted
                    ],
                },
                "evidence": {
                    "event_names": [name for name, _ in event_counts_sorted],
                    "user_agents": [ua for ua, _ in user_agents_sorted],
                    "event_times": actor["event_times"],
                },
                "provider": provider,
                "abuse_confidence": abuse_conf,
            }
        )

    actor_list.sort(
        key=lambda a: (-a.get("score", 0), -a.get("event_stats", {}).get("event_count", 0), a.get("actor", ""))
    )

    result = {
        "input": {
            "source": str(events_path),
            "total_events": total_events,
            "processed_events": len(events),
            "truncated": truncated,
            "max_events": config["max_events"],
            "max_indicators": config["max_indicators"],
        },
        "actors": actor_list,
    }
    return result, intel_partial, False, None


def render_cloudtrail_human(result: Dict[str, Any], fmt: str = "table") -> str:
    actors = result.get("actors", [])
    input_meta = result.get("input", {})
    errors = result.get("errors") or []
    lines = []
    lines.append(
        f"cloudtrail correlation | events={input_meta.get('processed_events', 0)} actors={len(actors)}"
    )
    lines.append("")
    if errors:
        lines.append("Errors:")
        for err in errors:
            lines.append(f"- {err}")
        lines.append("")

    if fmt == "text":
        for actor in actors:
            lines.append(
                f"{actor.get('actor')} ip={actor.get('ip')} score={actor.get('score')}"
            )
        return "\n".join(lines)

    header = ["Actor", "IP", "Score", "Provider", "Abuse", "Top Events", "Event Count"]
    rows = []
    for actor in actors:
        top_events = ", ".join(
            f"{e['name']}({e['count']})" for e in actor.get("event_stats", {}).get("top_events", [])
        )
        rows.append(
            [
                actor.get("actor", ""),
                actor.get("ip", ""),
                str(actor.get("score", "")),
                str(actor.get("provider", "")),
                str(actor.get("abuse_confidence", "")),
                top_events,
                str(actor.get("event_stats", {}).get("event_count", "")),
            ]
        )

    if not rows:
        lines.append("No actors found.")
        return "\n".join(lines)

    widths = [len(h) for h in header]
    for r in rows:
        widths = [max(widths[i], len(str(r[i]))) for i in range(len(header))]

    def fmt_row(r: List[str]) -> str:
        return " | ".join(str(r[i]).ljust(widths[i]) for i in range(len(header)))

    lines.append(fmt_row(header))
    lines.append("-+-".join("-" * w for w in widths))
    for r in rows:
        lines.append(fmt_row(r))

    return "\n".join(lines)


def render_cloudtrail_json(result: Dict[str, Any]) -> str:
    return json.dumps(result, indent=2, default=str)
