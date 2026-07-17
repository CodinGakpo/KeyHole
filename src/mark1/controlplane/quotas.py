"""Cost and concurrency guardrails.

Pure policy logic (no cloud dependency) so the budget rules are unit-testable. The control plane
consults these before launching a task; an AWS Budgets alarm is the backstop for anything that
slips through.
"""

from __future__ import annotations

from dataclasses import dataclass

from mark1.common.models import Limits


@dataclass(frozen=True)
class QuotaPolicy:
    max_concurrent_runs: int = 5
    max_timeout_seconds: int = 300
    max_memory_mb: int = 2048
    max_data_bytes: int = 10 * 1024 * 1024  # cap supplied-data size to bound cost/time


@dataclass(frozen=True)
class QuotaDecision:
    allowed: bool
    reason: str | None = None


def check_quota(
    policy: QuotaPolicy,
    limits: Limits,
    current_concurrency: int,
    total_data_bytes: int,
) -> QuotaDecision:
    """Return whether a run may proceed under the policy."""
    if current_concurrency >= policy.max_concurrent_runs:
        return QuotaDecision(False, "max concurrent runs reached")
    if limits.timeout_seconds > policy.max_timeout_seconds:
        return QuotaDecision(False, "requested timeout exceeds policy maximum")
    if limits.memory_mb > policy.max_memory_mb:
        return QuotaDecision(False, "requested memory exceeds policy maximum")
    if total_data_bytes > policy.max_data_bytes:
        return QuotaDecision(False, "supplied data exceeds policy maximum size")
    return QuotaDecision(True)
