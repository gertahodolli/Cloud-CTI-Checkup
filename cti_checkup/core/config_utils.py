"""Shared config value getters; no hardcoded defaults (defaults belong in config)."""
from __future__ import annotations

from typing import Any, Dict, List, Optional


def get_bool(cfg: Dict[str, Any], path: List[str]) -> Optional[bool]:
    cur: Any = cfg
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    if cur is None:
        return None
    if isinstance(cur, bool):
        return cur
    if isinstance(cur, str):
        v = cur.strip().lower()
        if v in ("true", "1", "yes", "y", "on"):
            return True
        if v in ("false", "0", "no", "n", "off"):
            return False
    return None


def get_int(cfg: Dict[str, Any], path: List[str]) -> Optional[int]:
    cur: Any = cfg
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    if cur is None:
        return None
    if isinstance(cur, int):
        return cur
    if isinstance(cur, str) and cur.strip().isdigit():
        return int(cur.strip())
    return None


def get_list_str(cfg: Dict[str, Any], path: List[str]) -> Optional[List[str]]:
    cur: Any = cfg
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    if cur is None:
        return None
    if isinstance(cur, list):
        out = [str(x).strip() for x in cur if x is not None and str(x).strip()]
        return out or None
    if isinstance(cur, str):
        parts = [p.strip() for p in cur.split(",") if p.strip()]
        return parts or None
    return None


def get_list_int(cfg: Dict[str, Any], path: List[str]) -> Optional[List[int]]:
    raw = get_list_str(cfg, path)
    if raw is None:
        return None
    out: List[int] = []
    for x in raw:
        if x.isdigit():
            out.append(int(x))
    return out or None
