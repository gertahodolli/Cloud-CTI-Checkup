from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, Optional

import yaml


_ENV_PATTERN = re.compile(r"\$\{([A-Z0-9_]+)\}")


def _expand_env(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _expand_env(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_expand_env(v) for v in obj]
    if isinstance(obj, str):
        def repl(match: re.Match) -> str:
            name = match.group(1)
            return os.environ.get(name, "")
        return _ENV_PATTERN.sub(repl, obj).strip() or obj
    return obj


def load_config(path: Optional[Path]) -> Dict[str, Any]:
    # No hardcoded endpoints/timeouts/thresholds here.
    if path is None:
        return {}

    raw = path.read_text(encoding="utf-8")
    data = yaml.safe_load(raw) or {}
    return _expand_env(data)
