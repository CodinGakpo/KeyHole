"""Output schema definition — the declared narrow exit.

A caller declares, in advance, the exact shape of the value untrusted code may return. The
set of allowed shapes is deliberately narrow: scalars, a fixed enum, a length-bounded string,
or a small fixed object of those. This narrowness is what makes the confidentiality guarantee
a bandwidth argument (see :mod:`mark1.schema.bandwidth`) rather than a content scan.
"""

from __future__ import annotations

import enum
from typing import Any

from pydantic import BaseModel, Field, model_validator

# A hard cap on how many fields a small fixed object may declare. Objects are meant to carry a
# handful of typed answers, never an open-ended record that could smuggle a dataset.
MAX_OBJECT_PROPERTIES = 16


class SchemaType(str, enum.Enum):
    """The closed set of output types Mark-1 permits."""

    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"
    ENUM = "enum"
    STRING = "string"
    ARRAY = "array"
    OBJECT = "object"


class OutputSchema(BaseModel):
    """A declaration of the single value untrusted code is allowed to return.

    Only the fields relevant to ``type`` may be set; the model validator enforces this so a
    schema cannot be quietly under-constrained (an under-constrained schema is a wide exit).
    """

    model_config = {"extra": "forbid"}

    type: SchemaType

    # INTEGER / NUMBER
    minimum: float | None = None
    maximum: float | None = None

    # ENUM
    choices: list[Any] | None = None

    # STRING
    max_length: int | None = Field(default=None, ge=0)
    charset: str | None = None  # explicit set of allowed characters; None => any byte (256)
    pattern: str | None = None  # optional regex the string must fully match

    # ARRAY
    items: OutputSchema | None = None
    max_items: int | None = Field(default=None, ge=0)

    # OBJECT
    properties: dict[str, OutputSchema] | None = None

    @model_validator(mode="after")
    def _check_per_type_constraints(self) -> OutputSchema:
        t = self.type

        def forbid(*names: str) -> None:
            for name in names:
                if getattr(self, name) is not None:
                    raise ValueError(f"'{name}' is not valid for schema type '{t.value}'")

        if t in (SchemaType.INTEGER, SchemaType.NUMBER):
            forbid("choices", "max_length", "charset", "pattern",
                   "items", "max_items", "properties")
            if (
                self.minimum is not None
                and self.maximum is not None
                and self.minimum > self.maximum
            ):
                raise ValueError("minimum must be <= maximum")
        elif t is SchemaType.BOOLEAN:
            forbid("minimum", "maximum", "choices", "max_length", "charset", "pattern",
                   "items", "max_items", "properties")
        elif t is SchemaType.ENUM:
            forbid("minimum", "maximum", "max_length", "charset", "pattern",
                   "items", "max_items", "properties")
            if not self.choices:
                raise ValueError("enum schema requires a non-empty 'choices' list")
            if len(self.choices) != len({_hashable(c) for c in self.choices}):
                raise ValueError("enum 'choices' must be unique")
        elif t is SchemaType.STRING:
            forbid("minimum", "maximum", "choices", "items", "max_items", "properties")
            if self.max_length is None:
                raise ValueError(
                    "string schema requires 'max_length' (an unbounded string is a wide exit)"
                )
            if self.charset is not None and len(self.charset) == 0:
                raise ValueError("charset, if given, must be non-empty")
        elif t is SchemaType.ARRAY:
            forbid("minimum", "maximum", "choices", "max_length", "charset", "pattern",
                   "properties")
            if self.items is None:
                raise ValueError("array schema requires an 'items' schema")
            if self.max_items is None:
                raise ValueError("array schema requires 'max_items' (unbounded array = wide exit)")
        elif t is SchemaType.OBJECT:
            forbid("minimum", "maximum", "choices", "max_length", "charset", "pattern",
                   "items", "max_items")
            if not self.properties:
                raise ValueError("object schema requires a non-empty 'properties' map")
            if len(self.properties) > MAX_OBJECT_PROPERTIES:
                raise ValueError(
                    f"object schema may declare at most {MAX_OBJECT_PROPERTIES} properties"
                )
        return self

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OutputSchema:
        """Load a schema from a plain dict (e.g. parsed JSON)."""
        return cls.model_validate(data)


def _hashable(value: Any) -> Any:
    """Best-effort hashable key for uniqueness checks over enum choices."""
    try:
        hash(value)
        return value
    except TypeError:
        return repr(value)


# Resolve the forward reference used in ``properties``.
OutputSchema.model_rebuild()
