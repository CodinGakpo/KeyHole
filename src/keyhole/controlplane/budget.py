"""Cumulative exit-bandwidth budget — the drip-exfiltration defense.

The per-run bandwidth bound (see :mod:`keyhole.schema.bandwidth`) caps a single answer. It says
nothing about *accumulation*: an adversary who calls the box N times, each within schema, can
leak N x bandwidth bits over time. This module bounds the total, per caller, over a window.

Pure policy (no cloud dependency), like :mod:`keyhole.controlplane.quotas`, so the rules are
unit-testable. Only *released* runs spend budget — a withheld run leaks nothing, so it charges 0.
On release we charge the schema's conservative upper bound (``bandwidth_bits``), matching the
"overstate the channel, never understate it" philosophy of the bandwidth accounting.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol

from keyhole.common.models import utcnow


@dataclass(frozen=True)
class BudgetPolicy:
    """A cap on released exit-bits per principal. ``window_seconds=None`` => cumulative forever."""

    max_exit_bits: float
    window_seconds: float | None = None


@dataclass(frozen=True)
class BudgetDecision:
    allowed: bool
    reason: str | None
    spent_before: float
    remaining: float


class Ledger(Protocol):
    """Records released exit-bits per principal and reports the spend within a window."""

    def spent(self, principal: str, window_seconds: float | None, now: datetime) -> float: ...
    def record(self, principal: str, bits: float, at: datetime) -> None: ...


def _within_window(at: datetime, window_seconds: float | None, now: datetime) -> bool:
    if window_seconds is None:
        return True
    return (now - at).total_seconds() < window_seconds


class InMemoryLedger:
    """Non-persistent ledger for local runs and tests."""

    def __init__(self) -> None:
        self._entries: dict[str, list[tuple[datetime, float]]] = {}

    def spent(self, principal: str, window_seconds: float | None, now: datetime) -> float:
        entries = self._entries.get(principal, [])
        return sum(bits for at, bits in entries if _within_window(at, window_seconds, now))

    def record(self, principal: str, bits: float, at: datetime) -> None:
        self._entries.setdefault(principal, []).append((at, bits))


class FileLedger:
    """JSON-file-backed ledger so spend accumulates across separate CLI processes.

    Stored under the ``~/.keyhole`` state dir (see :func:`keyhole.common.config.home_dir`). A
    missing or corrupt file is treated as an empty ledger — the budget is a best-effort guardrail,
    not a signed record, so it fails open to "no spend yet" rather than crashing a run.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    def _load(self) -> dict[str, list[tuple[datetime, float]]]:
        try:
            raw = json.loads(self._path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
        out: dict[str, list[tuple[datetime, float]]] = {}
        for principal, entries in raw.items():
            out[principal] = [(datetime.fromisoformat(at), float(bits)) for at, bits in entries]
        return out

    def _save(self, data: dict[str, list[tuple[datetime, float]]]) -> None:
        serializable = {
            principal: [[at.isoformat(), bits] for at, bits in entries]
            for principal, entries in data.items()
        }
        self._path.write_text(json.dumps(serializable))

    def spent(self, principal: str, window_seconds: float | None, now: datetime) -> float:
        entries = self._load().get(principal, [])
        return sum(bits for at, bits in entries if _within_window(at, window_seconds, now))

    def record(self, principal: str, bits: float, at: datetime) -> None:
        data = self._load()
        data.setdefault(principal, []).append((at, bits))
        self._save(data)


def check_budget(
    policy: BudgetPolicy,
    ledger: Ledger,
    principal: str,
    requested_bits: float,
    now: datetime | None = None,
) -> BudgetDecision:
    """Decide whether releasing ``requested_bits`` for ``principal`` stays within the budget."""
    now = now or utcnow()
    spent = ledger.spent(principal, policy.window_seconds, now)
    remaining = policy.max_exit_bits - spent
    if requested_bits > remaining:
        window = (
            "cumulatively"
            if policy.window_seconds is None
            else f"within the last {policy.window_seconds:g}s"
        )
        reason = (
            f"cumulative exit-bandwidth budget exceeded for principal '{principal}': "
            f"{spent:.2f} bits already released {window}, this run would add {requested_bits:.2f}, "
            f"over the {policy.max_exit_bits:.2f}-bit cap"
        )
        return BudgetDecision(False, reason, spent_before=spent, remaining=remaining)
    return BudgetDecision(True, None, spent_before=spent, remaining=remaining)
