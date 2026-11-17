"""Exit-bandwidth accounting.

Given an :class:`~keyhole.schema.spec.OutputSchema`, compute an upper bound on the information
content (in bits) that can leave the sandbox through a single conforming value. This number is
the quantitative form of Keyhole's core guarantee: if the schema permits at most N bits to
leave, then no more than N bits of the supplied data can be exfiltrated per run.

The estimates are deliberately *conservative upper bounds* — we would rather overstate the
channel width than understate it. Each figure is log2 of (at least) the number of distinct values
:func:`keyhole.schema.validate.canonicalize` can release; ``tests/unit/test_bandwidth.py`` checks
that by brute force. Unbounded scalars are 64 bits, and validation holds them to 64 bits.
"""

from __future__ import annotations

import math

from keyhole.schema.spec import OutputSchema, SchemaType

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
        symbols = len(schema.charset) if schema.charset else 256  # no charset: UTF-8 bytes
        return _sequence_bits(math.log2(symbols), schema.max_length)

    if t is SchemaType.ARRAY:
        assert schema.items is not None and schema.max_items is not None  # guaranteed by spec
        return _sequence_bits(bandwidth_bits(schema.items), schema.max_items)

    if t is SchemaType.OBJECT:
        assert schema.properties is not None  # guaranteed by spec validation
        return sum(bandwidth_bits(child) for child in schema.properties.values())

    raise ValueError(f"unknown schema type: {t!r}")


def _sequence_bits(item_bits: float, max_len: int) -> float:
    """Bits carried by a sequence of 0..max_len items of ``item_bits`` each.

    The length is part of the message: there are sum(N**k for k in 0..max_len) such sequences
    (N = 2**item_bits), not N**max_len. For N = 1 that is max_len + 1 outcomes, not one.
    """
    if item_bits == 0:
        return math.log2(max_len + 1)
    geometric = (1 - 2.0 ** (-item_bits * (max_len + 1))) / (1 - 2.0**-item_bits)
    return item_bits * max_len + math.log2(geometric)


def bandwidth_bytes(schema: OutputSchema) -> float:
    """Bandwidth expressed in bytes, for human-readable reporting."""
    return bandwidth_bits(schema) / 8.0


def run_channel_bits(schema: OutputSchema) -> float:
    """Upper bound, in bits, on what one *run* reveals to its caller — the per-run budget charge.

    A run ends in one of the schema's conforming values or in "not released" (every non-release
    outcome looks identical to the caller), so it can signal one of N + 1 outcomes, where
    N = 2**bandwidth_bits. log2(N + 1) is computed as b + log2(1 + 2**-b) to stay finite for wide
    schemas.
    """
    b = bandwidth_bits(schema)
    return b + math.log2(1 + 2.0**-b)
