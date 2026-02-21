"""Tests for core config_utils (get_bool, get_int, get_list_str, get_list_int)."""
from __future__ import annotations

from cti_checkup.core.config_utils import (
    get_bool,
    get_int,
    get_list_str,
    get_list_int,
)


def test_get_bool_missing_key() -> None:
    assert get_bool({}, ["a"]) is None
    assert get_bool({"a": {}}, ["a", "b"]) is None


def test_get_bool_true_values() -> None:
    assert get_bool({"enabled": True}, ["enabled"]) is True
    assert get_bool({"enabled": "true"}, ["enabled"]) is True
    assert get_bool({"enabled": "1"}, ["enabled"]) is True
    assert get_bool({"enabled": "yes"}, ["enabled"]) is True
    assert get_bool({"enabled": "on"}, ["enabled"]) is True


def test_get_bool_false_values() -> None:
    assert get_bool({"enabled": False}, ["enabled"]) is False
    assert get_bool({"enabled": "false"}, ["enabled"]) is False
    assert get_bool({"enabled": "0"}, ["enabled"]) is False
    assert get_bool({"enabled": "no"}, ["enabled"]) is False
    assert get_bool({"enabled": "off"}, ["enabled"]) is False


def test_get_bool_none_and_invalid() -> None:
    assert get_bool({"enabled": None}, ["enabled"]) is None
    assert get_bool({"enabled": "maybe"}, ["enabled"]) is None
    assert get_bool({"enabled": 1}, ["enabled"]) is None


def test_get_int_missing_key() -> None:
    assert get_int({}, ["x"]) is None
    assert get_int({"a": {"b": 1}}, ["a", "c"]) is None


def test_get_int_values() -> None:
    assert get_int({"n": 42}, ["n"]) == 42
    assert get_int({"n": "99"}, ["n"]) == 99
    assert get_int({"n": "  7  "}, ["n"]) == 7


def test_get_int_none_and_invalid() -> None:
    assert get_int({"n": None}, ["n"]) is None
    assert get_int({"n": "abc"}, ["n"]) is None
    assert get_int({"n": 3.14}, ["n"]) is None


def test_get_list_str_missing_key() -> None:
    assert get_list_str({}, ["tags"]) is None
    assert get_list_str({"a": {}}, ["a", "b"]) is None


def test_get_list_str_list() -> None:
    assert get_list_str({"items": ["a", "b", "c"]}, ["items"]) == ["a", "b", "c"]
    assert get_list_str({"items": ["  x  ", "y"]}, ["items"]) == ["x", "y"]


def test_get_list_str_comma_string() -> None:
    assert get_list_str({"items": "a,b,c"}, ["items"]) == ["a", "b", "c"]
    assert get_list_str({"items": " single "}, ["items"]) == ["single"]


def test_get_list_str_empty_and_none() -> None:
    assert get_list_str({"items": []}, ["items"]) is None
    assert get_list_str({"items": ""}, ["items"]) is None
    assert get_list_str({"items": None}, ["items"]) is None


def test_get_list_int() -> None:
    assert get_list_int({"ids": ["1", "2", "3"]}, ["ids"]) == [1, 2, 3]
    assert get_list_int({"ids": "10,20"}, ["ids"]) == [10, 20]
    assert get_list_int({"ids": ["1", "x", "2"]}, ["ids"]) == [1, 2]
    assert get_list_int({}, ["ids"]) is None
    assert get_list_int({"ids": []}, ["ids"]) is None
