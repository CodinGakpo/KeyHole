"""Validate that a produced output conforms to its declared schema.

This runs at the control-plane exit gate. A value that does not conform is *not released* —
nothing leaves. Validation is strict: types must match exactly (no coercion), because loose
coercion would silently widen the exit.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from mark1.schema.spec import OutputSchema, SchemaType


@dataclass
class ValidationResult:
    """Outcome of validating one value against one schema."""

    ok: bool
    errors: list[str] = field(default_factory=list)

    @classmethod
    def success(cls) -> ValidationResult:
        return cls(ok=True)

    @classmethod
    def failure(cls, *errors: str) -> ValidationResult:
        return cls(ok=False, errors=list(errors))


def validate_output(value: Any, schema: OutputSchema, _path: str = "$") -> ValidationResult:
    """Return whether ``value`` strictly conforms to ``schema``."""
    t = schema.type
    errs: list[str] = []

    if t is SchemaType.BOOLEAN:
        if not _is_bool(value):
            errs.append(f"{_path}: expected boolean, got {_typename(value)}")

    elif t is SchemaType.INTEGER:
        if not _is_int(value):
            errs.append(f"{_path}: expected integer, got {_typename(value)}")
        else:
            _check_range(value, schema, _path, errs)

    elif t is SchemaType.NUMBER:
        if not _is_number(value):
            errs.append(f"{_path}: expected number, got {_typename(value)}")
        else:
            _check_range(value, schema, _path, errs)

    elif t is SchemaType.ENUM:
        assert schema.choices is not None
        if value not in schema.choices:
            errs.append(f"{_path}: value not among enum choices")

    elif t is SchemaType.STRING:
        assert schema.max_length is not None
        if not isinstance(value, str):
            errs.append(f"{_path}: expected string, got {_typename(value)}")
        else:
            if len(value) > schema.max_length:
                errs.append(f"{_path}: string length {len(value)} exceeds max_length {schema.max_length}")
            if schema.charset is not None:
                allowed = set(schema.charset)
                if any(ch not in allowed for ch in value):
                    errs.append(f"{_path}: string contains characters outside the declared charset")
            if schema.pattern is not None and re.fullmatch(schema.pattern, value) is None:
                errs.append(f"{_path}: string does not match required pattern")

    elif t is SchemaType.ARRAY:
        assert schema.items is not None and schema.max_items is not None
        if not isinstance(value, list):
            errs.append(f"{_path}: expected array, got {_typename(value)}")
        else:
            if len(value) > schema.max_items:
                errs.append(
                    f"{_path}: array length {len(value)} exceeds max_items {schema.max_items}"
                )
            for i, elem in enumerate(value):
                child = validate_output(elem, schema.items, f"{_path}[{i}]")
                errs.extend(child.errors)

    elif t is SchemaType.OBJECT:
        assert schema.properties is not None
        if not isinstance(value, dict):
            errs.append(f"{_path}: expected object, got {_typename(value)}")
        else:
            declared = set(schema.properties)
            present = set(value)
            for extra in present - declared:
                errs.append(f"{_path}.{extra}: undeclared property (objects are closed)")
            for missing in declared - present:
                errs.append(f"{_path}.{missing}: missing required property")
            for name in declared & present:
                child = validate_output(value[name], schema.properties[name], f"{_path}.{name}")
                errs.extend(child.errors)

    else:  # pragma: no cover - spec validation prevents this
        errs.append(f"{_path}: unknown schema type {t!r}")

    return ValidationResult.success() if not errs else ValidationResult(ok=False, errors=errs)


def _check_range(value: float, schema: OutputSchema, path: str, errs: list[str]) -> None:
    if schema.minimum is not None and value < schema.minimum:
        errs.append(f"{path}: value {value} below minimum {schema.minimum}")
    if schema.maximum is not None and value > schema.maximum:
        errs.append(f"{path}: value {value} above maximum {schema.maximum}")


# Strict type predicates. Note bool is a subclass of int in Python, so we exclude it explicitly
# where an integer/number is required — a boolean is not an integer for exit-schema purposes.
def _is_bool(value: Any) -> bool:
    return isinstance(value, bool)


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _typename(value: Any) -> str:
    return type(value).__name__
