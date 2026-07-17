"""The typed narrow exit: schema definition, validation, and bandwidth accounting.

This package is the heart of Mark-1's guarantee. Untrusted code may only return a value
matching a caller-declared narrow schema; because the exit is only a few bytes wide, bulk
exfiltration is *structurally* impossible rather than merely scanned-for.
"""

from mark1.schema.bandwidth import bandwidth_bits
from mark1.schema.spec import OutputSchema, SchemaType
from mark1.schema.validate import ValidationResult, validate_output

__all__ = [
    "OutputSchema",
    "SchemaType",
    "bandwidth_bits",
    "validate_output",
    "ValidationResult",
]
