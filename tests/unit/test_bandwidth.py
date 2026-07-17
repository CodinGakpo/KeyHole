"""Bandwidth accounting: the quantitative form of the guarantee."""

import math

from mark1.schema.bandwidth import bandwidth_bits, bandwidth_bytes
from mark1.schema.spec import OutputSchema, SchemaType


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
    assert bandwidth_bits(s) == 10.0  # 10 chars * log2(2)

    s_hex = OutputSchema(type=SchemaType.STRING, max_length=4, charset="0123456789abcdef")
    assert bandwidth_bits(s_hex) == 16.0  # 4 * 4 bits


def test_object_sums_fields():
    s = OutputSchema(
        type=SchemaType.OBJECT,
        properties={
            "flag": OutputSchema(type=SchemaType.BOOLEAN),
            "label": OutputSchema(type=SchemaType.ENUM, choices=["x", "y", "z", "w"]),
        },
    )
    assert bandwidth_bits(s) == 1.0 + 2.0


def test_narrow_exit_is_tiny_vs_a_dataset():
    # A 3-way classification can leak at most ~1.58 bits: far too little for a dataset.
    s = OutputSchema(type=SchemaType.ENUM, choices=["spam", "ham", "other"])
    assert bandwidth_bytes(s) < 1.0
