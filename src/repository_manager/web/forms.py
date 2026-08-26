"""Form validation results, shaped for accessible re-rendering.

A rejected form is re-rendered rather than redirected, so nothing the user
typed is lost.  The template needs three things to do that accessibly
(specification.md 11): the list of errors for the summary region, a lookup from
field name to message for ``aria-describedby``, and the submitted values to put
back into the inputs.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class FieldError:
    #: The ``name``/``id`` of the input, so the summary can link straight to it.
    field: str
    message: str


@dataclass
class FormState:
    """What a template needs to redisplay a form the server rejected."""

    values: dict[str, Any] = field(default_factory=dict)
    errors: list[FieldError] = field(default_factory=list)

    def add(self, field_name: str, message: str) -> None:
        self.errors.append(FieldError(field=field_name, message=message))

    def extend(self, errors: Iterable[FieldError]) -> None:
        self.errors.extend(errors)

    @property
    def ok(self) -> bool:
        return not self.errors

    @property
    def messages(self) -> dict[str, str]:
        """First error per field, which is what the field's description shows."""
        found: dict[str, str] = {}
        for error in self.errors:
            found.setdefault(error.field, error.message)
        return found

    def value(self, field_name: str, default: str = "") -> str:
        raw = self.values.get(field_name, default)
        return "" if raw is None else str(raw)

    def as_context(self) -> Mapping[str, Any]:
        return {"form": self}


def required(state: FormState, field_name: str, value: str, label: str) -> str:
    cleaned = (value or "").strip()
    if not cleaned:
        state.add(field_name, f"{label} is required.")
    return cleaned
