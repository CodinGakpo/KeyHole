"""Bandwidth accounting: the quantitative form of the guarantee."""

import itertools
import json
import math

import pytest

from keyhole.schema.bandwidth import bandwidth_bits, bandwidth_bytes
from keyhole.schema.spec import OutputSchema, SchemaType
from keyhole.schema.validate import canonicalize, validate_output


def test_boolean_is_one_bit():
    assert bandwidth_bits(OutputSchema(type=SchemaType.BOOLEAN)) == 1.0


def test_enum_is_log2_choices():
    s = OutputSchema(type=SchemaType.ENUM, choices=["a", "b", "c", "d"])
    assert bandwidth_bits(s) == 2.0  # log2(4)

    s3 = OutputSchema(type=SchemaType.ENUM, choices=["a", "b", "c"])
    assert math.isclose(bandwidth_bits(s3), math.log2(3))


def test_bounded_integer_range():
    s = OutputSchema(type=SchemaType.INTEGER, minimum=0, maximum=255)
    assert bandwidth_bits(s) == 8.0  # 256 values


def test_unbounded_integer_falls_back_to_cap():
    s = OutputSchema(type=SchemaType.INTEGER)
    assert bandwidth_bits(s) == 64.0


def test_string_scales_with_length_and_charset():
    s = OutputSchema(type=SchemaType.STRING, max_length=10, charset="01")
    # Every string of 0..10 binary digits: 2**11 - 1 of them, just under 11 bits.
    assert bandwidth_bits(s) == pytest.approx(math.log2(2**11 - 1))

    s_hex = OutputSchema(type=SchemaType.STRING, max_length=4, charset="0123456789abcdef")
    assert 16.0 < bandwidth_bits(s_hex) < 16.1  # 4 * 4 bits, plus the shorter strings


def test_object_sums_fields():
    s = OutputSchema(
        type=SchemaType.OBJECT,
        properties={
            "flag": OutputSchema(type=SchemaType.BOOLEAN),
            "label": OutputSchema(type=SchemaType.ENUM, choices=["x", "y", "z", "w"]),
        },
    )
    assert bandwidth_bits(s) == 1.0 + 2.0


def test_array_is_max_items_times_element_bits():
    s = OutputSchema(
        type=SchemaType.ARRAY,
        max_items=3,
        items=OutputSchema(type=SchemaType.STRING, max_length=4, charset="0123456789abcdef"),
    )
    assert 3 * 16.0 < bandwidth_bits(s) < 3 * 16.0 + 1  # 3 items * ~16 bits, plus shorter arrays


def test_array_nested_in_object_sums():
    s = OutputSchema(
        type=SchemaType.OBJECT,
        properties={
            "flag": OutputSchema(type=SchemaType.BOOLEAN),
            "labels": OutputSchema(
                type=SchemaType.ARRAY,
                max_items=5,
                items=OutputSchema(type=SchemaType.ENUM, choices=["a", "b", "c", "d"]),
            ),
        },
    )
    assert 1.0 + 5 * 2.0 < bandwidth_bits(s) < 1.0 + 5 * 2.0 + 1  # bool + 5 * log2(4) + lengths


def test_narrow_exit_is_tiny_vs_a_dataset():
    # A 3-way classification can leak at most ~1.58 bits: far too little for a dataset.
    s = OutputSchema(type=SchemaType.ENUM, choices=["spam", "ham", "other"])
    assert bandwidth_bytes(s) < 1.0


# --- The bound must be a bound -------------------------------------------------------------------
# Brute force: push a universe of candidate outputs through validation + canonicalization, count
# the distinct values that would actually be released, and require log2(count) <= bandwidth_bits.
# Any representation the code can choose between (1 vs 1.0 vs true, key order, length) shows up
# here as a count above the declared bound.

_ATOMS = [True, False, 0, 1, 2, -1, 0.0, 1.0, -0.0, 0.5, float("nan"), float("inf"), None,
          "", "a", "b", "aa", "ab", "ba", "bb", "aaa", "é", "\U0001f600", 10**30]


def _universe():
    yield from _ATOMS
    small = [True, False, 0, 1, "a", "x"]
    for n in range(4):
        for combo in itertools.product(small, repeat=n):
            yield list(combo)
    for va, vb in itertools.product([True, False, 0, 1], repeat=2):
        yield {"a": va, "b": vb}
        yield {"b": vb, "a": va}  # same content, other key order


def _released(schema: OutputSchema) -> set[str]:
    out = set()
    for candidate in _universe():
        if validate_output(candidate, schema).ok:
            out.add(json.dumps(canonicalize(candidate, schema)))
    return out


_SMALL_SCHEMAS = [
    {"type": "boolean"},
    {"type": "enum", "choices": [0, 1]},
    {"type": "enum", "choices": ["a", "b"]},
    {"type": "enum", "choices": ["a"]},
    {"type": "integer", "minimum": 0, "maximum": 1},
    {"type": "string", "max_length": 2, "charset": "ab"},
    {"type": "string", "max_length": 3, "charset": "a"},
    {"type": "array", "max_items": 3, "items": {"type": "boolean"}},
    {"type": "array", "max_items": 3, "items": {"type": "enum", "choices": ["x"]}},
    {"type": "object", "properties": {"a": {"type": "boolean"}, "b": {"type": "boolean"}}},
]


@pytest.mark.parametrize("raw", _SMALL_SCHEMAS, ids=lambda s: json.dumps(s))
def test_released_values_never_exceed_the_declared_bandwidth(raw):
    schema = OutputSchema.from_dict(raw)
    released = _released(schema)
    assert released, "universe should contain at least one conforming value"
    assert math.log2(len(released)) <= bandwidth_bits(schema) + 1e-9, sorted(released)


def test_length_is_priced_as_part_of_the_channel():
    # 0, 1, 2 or 3 copies of the only allowed character: four outcomes, two bits.
    s = OutputSchema(type=SchemaType.STRING, max_length=3, charset="a")
    assert bandwidth_bits(s) == pytest.approx(2.0)
    a = OutputSchema(type=SchemaType.ARRAY, max_items=3,
                     items=OutputSchema(type=SchemaType.ENUM, choices=["x"]))
    assert bandwidth_bits(a) == pytest.approx(2.0)


def test_string_without_charset_is_bounded_in_utf8_bytes():
    s = OutputSchema(type=SchemaType.STRING, max_length=4)
    assert validate_output("abcd", s).ok
    assert validate_output("\U0001f600", s).ok  # one code point, four bytes
    assert not validate_output("\U0001f600\U0001f600", s).ok  # two code points, eight bytes
    assert not validate_output("\ud800", s).ok  # lone surrogate: not text


def test_unbounded_scalars_really_fit_their_64_bits():
    for raw in ({"type": "integer"}, {"type": "integer", "minimum": 0}):
        s = OutputSchema.from_dict(raw)
        assert validate_output(2**63 - 1, s).ok
        assert not validate_output(2**63, s).ok
        assert not validate_output(10**1000, s).ok
    n = OutputSchema(type=SchemaType.NUMBER)
    assert not validate_output(float("nan"), n).ok
    assert not validate_output(float("inf"), n).ok
    assert not validate_output(10**1000, n).ok
    assert canonicalize(1, n) == 1.0 and isinstance(canonicalize(1, n), float)
