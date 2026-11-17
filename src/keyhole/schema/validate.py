"""Validate that a produced output conforms to its declared schema.

This runs at the control-plane exit gate. A value that does not conform is *not released* —
nothing leaves. Validation is strict: types must match exactly (no coercion), because loose
coercion would silently widen the exit.

What is released is never the code's own object but :func:`canonicalize` of it — a value rebuilt
from the schema. The code chooses *which* conforming value leaves, never how it is spelled
(``1`` vs ``1.0`` vs ``true``, key order), because every extra spelling is extra bandwidth.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any

from keyhole.common.hashing import canonical_json_bytes
from keyhole.schema.spec import OutputSchema, SchemaType

# An integer schema without both bounds is priced at 64 bits, so it must fit in 64 bits.
INT64_MIN, INT64_MAX = -(2**63), 2**63 - 1


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
        elif not _is_finite(value):
            errs.append(f"{_path}: number is not a finite double")
        else:
            _check_range(value, schema, _path, errs)

    elif t is SchemaType.ENUM:
        assert schema.choices is not None
        if not _matching_choice(value, schema.choices):
            errs.append(f"{_path}: value not among enum choices")

    elif t is SchemaType.STRING:
        assert schema.max_length is not None
        if not isinstance(value, str):
            errs.append(f"{_path}: expected string, got {_typename(value)}")
        elif (encoded := _utf8(value)) is None:
            errs.append(f"{_path}: string is not valid Unicode text")
        else:
            # With a charset, length counts characters (each worth log2(len(charset)) bits).
            # Without one, it counts UTF-8 bytes, so "8 bits per unit" is a true bound.
            length = len(value) if schema.charset is not None else len(encoded)
            if length > schema.max_length:
                errs.append(
                    f"{_path}: string length {length} exceeds max_length {schema.max_length}"
                )
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


def canonicalize(value: Any, schema: OutputSchema) -> Any:
    """The value to release for a ``value`` that already passed :func:`validate_output`."""
    t = schema.type
    if t is SchemaType.ENUM:
        assert schema.choices is not None
        return _matching_choice(value, schema.choices)[0]  # the schema's own spelling
    if t is SchemaType.NUMBER:
        return float(value)
    if t is SchemaType.ARRAY:
        assert schema.items is not None
        return [canonicalize(elem, schema.items) for elem in value]
    if t is SchemaType.OBJECT:
        assert schema.properties is not None
        return {name: canonicalize(value[name], sub) for name, sub in schema.properties.items()}
    return value


def _check_range(value: float, schema: OutputSchema, path: str, errs: list[str]) -> None:
    if schema.minimum is not None and value < schema.minimum:
        errs.append(f"{path}: value below minimum {schema.minimum}")
    if schema.maximum is not None and value > schema.maximum:
        errs.append(f"{path}: value above maximum {schema.maximum}")
    if (
        schema.type is SchemaType.INTEGER
        and (schema.minimum is None or schema.maximum is None)
        and not INT64_MIN <= value <= INT64_MAX
    ):
        errs.append(f"{path}: integer without both bounds must fit in 64 bits")


def _matching_choice(value: Any, choices: list[Any]) -> list[Any]:
    """The choice ``value`` is spelled exactly like, as a 0- or 1-element list.

    Compared by canonical JSON rather than ``==``, which would also accept ``True`` and ``1.0``
    for the choice ``1`` and so hand the code extra distinguishable outputs.
    """
    try:
        key = canonical_json_bytes(value)
    except (TypeError, ValueError, RecursionError):
        return []
    return [c for c in choices if canonical_json_bytes(c) == key][:1]


def _is_finite(value: float) -> bool:
    try:
        return math.isfinite(float(value))
    except OverflowError:  # an int too large for a double
        return False


def _utf8(value: str) -> bytes | None:
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError:  # lone surrogate
        return None


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
