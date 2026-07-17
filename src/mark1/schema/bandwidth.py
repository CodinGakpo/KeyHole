"""Exit-bandwidth accounting.

Given an :class:`~mark1.schema.spec.OutputSchema`, compute an upper bound on the information
content (in bits) that can leave the sandbox through a single conforming value. This number is
the quantitative form of Mark-1's core guarantee: if the schema permits at most N bits to
leave, then no more than N bits of the supplied data can be exfiltrated per run.

The estimates are deliberately *conservative upper bounds* — we would rather overstate the
channel width than understate it. Unbounded scalars fall back to fixed machine-width caps.
"""

from __future__ import annotations

import math

from mark1.schema.spec import OutputSchema, SchemaType

# Fallback widths for scalars whose range is not constrained.
UNBOUNDED_INTEGER_BITS = 64.0
NUMBER_BITS = 64.0  # IEEE-754 double


def bandwidth_bits(schema: OutputSchema) -> float:
    """Return an upper bound, in bits, on what a conforming value can carry."""
    t = schema.type

    if t is SchemaType.BOOLEAN:
        return 1.0

    if t is SchemaType.ENUM:
        assert schema.choices is not None  # guaranteed by spec validation
        n = len(schema.choices)
        return math.log2(n) if n > 1 else 0.0

    if t is SchemaType.INTEGER:
        if schema.minimum is not None and schema.maximum is not None:
            span = int(math.floor(schema.maximum)) - int(math.ceil(schema.minimum)) + 1
            return math.log2(span) if span > 1 else 0.0
        return UNBOUNDED_INTEGER_BITS

    if t is SchemaType.NUMBER:
        return NUMBER_BITS

    if t is SchemaType.STRING:
        assert schema.max_length is not None  # guaranteed by spec validation
        symbols = len(schema.charset) if schema.charset else 256
        per_symbol = math.log2(symbols) if symbols > 1 else 0.0
        return schema.max_length * per_symbol

    if t is SchemaType.OBJECT:
        assert schema.properties is not None  # guaranteed by spec validation
        return sum(bandwidth_bits(child) for child in schema.properties.values())

    raise ValueError(f"unknown schema type: {t!r}")


def bandwidth_bytes(schema: OutputSchema) -> float:
    """Bandwidth expressed in bytes, for human-readable reporting."""
    return bandwidth_bits(schema) / 8.0
