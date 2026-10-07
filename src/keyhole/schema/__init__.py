"""The typed narrow exit: schema definition, validation, and bandwidth accounting.

This package is the heart of Keyhole's guarantee. Untrusted code may only return a value
matching a caller-declared narrow schema; because the exit is only a few bytes wide, bulk
exfiltration is *structurally* impossible rather than merely scanned-for.
"""

from keyhole.schema.bandwidth import bandwidth_bits
from keyhole.schema.spec import OutputSchema, SchemaType
from keyhole.schema.validate import ValidationResult, validate_output

__all__ = [
    "OutputSchema",
    "SchemaType",
    "bandwidth_bits",
    "validate_output",
    "ValidationResult",
]
