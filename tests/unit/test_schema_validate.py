"""Schema validation: conforming values pass, non-conforming are rejected (no coercion)."""

import pytest

from mark1.schema.spec import OutputSchema, SchemaType
from mark1.schema.validate import validate_output


def _schema(**kw) -> OutputSchema:
    return OutputSchema(**kw)


def test_boolean_accepts_only_bool():
    s = _schema(type=SchemaType.BOOLEAN)
    assert validate_output(True, s).ok
    assert not validate_output(1, s).ok  # int is not bool
    assert not validate_output("true", s).ok


def test_integer_rejects_bool_and_float():
    s = _schema(type=SchemaType.INTEGER, minimum=0, maximum=10)
    assert validate_output(7, s).ok
    assert not validate_output(True, s).ok  # bool excluded
    assert not validate_output(7.0, s).ok  # float is not integer
    assert not validate_output(11, s).ok  # out of range
    assert not validate_output(-1, s).ok


def test_enum_membership():
    s = _schema(type=SchemaType.ENUM, choices=["spam", "ham", "other"])
    assert validate_output("spam", s).ok
    assert not validate_output("SPAM", s).ok
    assert not validate_output("nope", s).ok


def test_string_length_charset_pattern():
    s = _schema(type=SchemaType.STRING, max_length=5)
    assert validate_output("abcde", s).ok
    assert not validate_output("toolong", s).ok

    s2 = _schema(type=SchemaType.STRING, max_length=8, charset="0123456789")
    assert validate_output("12345", s2).ok
    assert not validate_output("12a45", s2).ok

    s3 = _schema(type=SchemaType.STRING, max_length=10, pattern=r"[a-f0-9]{2,10}")
    assert validate_output("deadbeef", s3).ok
    assert not validate_output("xyz", s3).ok


def test_object_is_closed():
    s = _schema(
        type=SchemaType.OBJECT,
        properties={
            "category": _schema(type=SchemaType.ENUM, choices=["a", "b"]),
            "score": _schema(type=SchemaType.INTEGER, minimum=0, maximum=100),
        },
    )
    assert validate_output({"category": "a", "score": 50}, s).ok
    assert not validate_output({"category": "a"}, s).ok  # missing property
    assert not validate_output({"category": "a", "score": 50, "extra": 1}, s).ok  # undeclared
    assert not validate_output({"category": "z", "score": 50}, s).ok  # bad enum


def test_string_requires_max_length():
    with pytest.raises(Exception):
        _schema(type=SchemaType.STRING)  # unbounded string is a wide exit -> rejected


def test_enum_requires_choices():
    with pytest.raises(Exception):
        _schema(type=SchemaType.ENUM)
