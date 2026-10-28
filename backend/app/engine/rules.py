"""
Agni (अग्नि) - Declarative AST Rule Condition Evaluator
File: backend/app/engine/rules.py
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Any

# -----------------------------------------------------------------------------
# Regex Compilation Cache
# -----------------------------------------------------------------------------

@lru_cache(maxsize=1024)
def get_compiled_regex(pattern: str, flags: int = 0) -> re.Pattern | None:
    """Compiles and caches regular expressions safely."""
    try:
        return re.compile(pattern, flags)
    except re.error:
        return None


# -----------------------------------------------------------------------------
# Universal Field Extractor (Dot-Notation & Flat ORM Attribute Resolver)
# -----------------------------------------------------------------------------

FLAT_ATTRIBUTE_ALIASES: dict[str, str] = {
    "actor.name": "actor_name",
    "actor.cmdline": "actor_cmdline",
    "actor.pid": "actor_pid",
    "actor.path": "actor_path",
    "actor.user": "actor_user",
    "target.identifier": "target_identifier",
    "target.type": "target_type",
    "host.hostname": "hostname",
    "host.os": "os_name",
}


def extract_field(event: Any, field_path: str) -> Any:
    """
    Extracts a value from an event using a dot-delimited path (e.g. 'actor.name', 'details.remote_port').
    Works across dicts, Pydantic models, and SQLAlchemy ORM models.
    """
    if not event or not field_path:
        return None

    # Step 1: Check direct flat attribute alias on ORM object (e.g. actor.name -> event.actor_name)
    if hasattr(event, "__table__") and field_path in FLAT_ATTRIBUTE_ALIASES:
        alias = FLAT_ATTRIBUTE_ALIASES[field_path]
        if hasattr(event, alias):
            val = getattr(event, alias)
            if val is not None:
                return val

    # Step 2: Handle special 'details.<key>' and 'target.details.<key>' lookups on ORM
    if hasattr(event, "__table__"):
        if field_path.startswith("details."):
            key = field_path[8:]
            details_dict = getattr(event, "details", None)
            if isinstance(details_dict, dict):
                return details_dict.get(key)
        elif field_path.startswith("target.details."):
            key = field_path[15:]
            target_details_dict = getattr(event, "target_details", None)
            if isinstance(target_details_dict, dict):
                return target_details_dict.get(key)

    # Step 3: Generic recursive path traversal
    parts = field_path.split(".")
    current = event

    for part in parts:
        if current is None:
            return None

        if isinstance(current, dict):
            current = current.get(part)
        elif hasattr(current, part):
            current = getattr(current, part)
        else:
            joined_part = "_".join(parts)
            if hasattr(event, joined_part):
                return getattr(event, joined_part)
            return None

    return current


# -----------------------------------------------------------------------------
# Comparison Operators
# -----------------------------------------------------------------------------

def _op_equals(val: Any, expected: Any) -> bool:
    if val is None and expected is None:
        return True
    if val is None or expected is None:
        return False
    if isinstance(val, str) and isinstance(expected, str):
        return val.strip().lower() == expected.strip().lower()
    return val == expected


def _op_exact_equals(val: Any, expected: Any) -> bool:
    return val == expected


def _op_contains(val: Any, expected: Any) -> bool:
    if val is None or expected is None:
        return False
    if isinstance(val, (list, tuple, set)):
        return expected in val
    return str(expected).lower() in str(val).lower()


def _op_not_contains(val: Any, expected: Any) -> bool:
    return not _op_contains(val, expected)


def _op_startswith(val: Any, expected: Any) -> bool:
    if val is None or expected is None:
        return False
    return str(val).lower().startswith(str(expected).lower())


def _op_endswith(val: Any, expected: Any) -> bool:
    if val is None or expected is None:
        return False
    return str(val).lower().endswith(str(expected).lower())


def _op_in_list(val: Any, expected_list: Any) -> bool:
    if val is None or not isinstance(expected_list, (list, tuple, set)):
        return False
    if isinstance(val, str):
        val_lower = val.strip().lower()
        return any(val_lower == str(item).strip().lower() for item in expected_list)
    return val in expected_list


def _op_not_in_list(val: Any, expected_list: Any) -> bool:
    return not _op_in_list(val, expected_list)


def _op_regex(val: Any, pattern: Any) -> bool:
    if val is None or pattern is None:
        return False
    regex = get_compiled_regex(str(pattern))
    if not regex:
        return False
    return bool(regex.search(str(val)))


def _op_iregex(val: Any, pattern: Any) -> bool:
    if val is None or pattern is None:
        return False
    regex = get_compiled_regex(str(pattern), re.IGNORECASE)
    if not regex:
        return False
    return bool(regex.search(str(val)))


def _op_numeric_cmp(val: Any, expected: Any, cmp_fn) -> bool:
    try:
        num_val = float(val)
        num_exp = float(expected)
        return cmp_fn(num_val, num_exp)
    except (ValueError, TypeError):
        return False


OPERATOR_MAP = {
    "equals": _op_equals,
    "eq": _op_equals,
    "exact_equals": _op_exact_equals,
    "not_equals": lambda v, e: not _op_equals(v, e),
    "neq": lambda v, e: not _op_equals(v, e),
    "contains": _op_contains,
    "icontains": _op_contains,
    "not_contains": _op_not_contains,
    "startswith": _op_startswith,
    "endswith": _op_endswith,
    "in": _op_in_list,
    "in_list": _op_in_list,
    "not_in": _op_not_in_list,
    "regex": _op_regex,
    "matches": _op_regex,
    "iregex": _op_iregex,
    "gt": lambda v, e: _op_numeric_cmp(v, e, lambda a, b: a > b),
    "gte": lambda v, e: _op_numeric_cmp(v, e, lambda a, b: a >= b),
    "lt": lambda v, e: _op_numeric_cmp(v, e, lambda a, b: a < b),
    "lte": lambda v, e: _op_numeric_cmp(v, e, lambda a, b: a <= b),
    "is_null": lambda v, e: v is None,
    "not_null": lambda v, e: v is not None,
    "exists": lambda v, e: v is not None,
}


# -----------------------------------------------------------------------------
# AST Condition Evaluator
# -----------------------------------------------------------------------------

def evaluate_condition(condition: dict[str, Any], event: Any) -> bool:
    """
    Recursively evaluates an AST match condition against an event.
    Returns True if conditions are met, False otherwise.
    Never throws uncaught exceptions.
    """
    if not isinstance(condition, dict) or not condition:
        return False

    try:
        # 1. AND grouping
        if "and" in condition:
            sub_conds = condition["and"]
            if not isinstance(sub_conds, list) or not sub_conds:
                return False
            return all(evaluate_condition(sub, event) for sub in sub_conds)

        # 2. OR grouping
        if "or" in condition:
            sub_conds = condition["or"]
            if not isinstance(sub_conds, list) or not sub_conds:
                return False
            return any(evaluate_condition(sub, event) for sub in sub_conds)

        # 3. NOT negation
        if "not" in condition:
            sub_cond = condition["not"]
            return not evaluate_condition(sub_cond, event)

        # 4. Leaf Condition (field, operator, value)
        field = condition.get("field")
        if not field:
            return False

        operator = str(condition.get("operator", "equals")).lower()
        expected_val = condition.get("value")

        actual_val = extract_field(event, field)

        evaluator = OPERATOR_MAP.get(operator)
        if not evaluator:
            return False

        return evaluator(actual_val, expected_val)

    except Exception:
        return False


def validate_condition_ast(condition: dict[str, Any]) -> tuple[bool, str | None]:
    """
    Validates the syntax of an AST condition dictionary prior to rule loading.
    Returns (is_valid, error_message).
    """
    if not isinstance(condition, dict) or not condition:
        return False, "Condition must be a non-empty dictionary"

    if "and" in condition:
        items = condition["and"]
        if not isinstance(items, list) or not items:
            return False, "'and' clause must contain a non-empty list of conditions"
        for item in items:
            ok, err = validate_condition_ast(item)
            if not ok:
                return False, err
        return True, None

    if "or" in condition:
        items = condition["or"]
        if not isinstance(items, list) or not items:
            return False, "'or' clause must contain a non-empty list of conditions"
        for item in items:
            ok, err = validate_condition_ast(item)
            if not ok:
                return False, err
        return True, None

    if "not" in condition:
        item = condition["not"]
        if not isinstance(item, dict):
            return False, "'not' clause must be a dictionary condition"
        return validate_condition_ast(item)

    # Leaf check
    if "field" not in condition:
        return False, "Leaf condition must specify 'field'"

    op = str(condition.get("operator", "equals")).lower()
    if op not in OPERATOR_MAP:
        return False, f"Unsupported operator '{op}'"

    if op in ("regex", "iregex", "matches"):
        val = condition.get("value")
        if not isinstance(val, str):
            return False, f"Operator '{op}' requires a string pattern value"
        try:
            re.compile(val)
        except re.error as e:
            return False, f"Invalid regex pattern '{val}': {e}"

    return True, None
