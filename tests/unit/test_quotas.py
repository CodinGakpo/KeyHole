"""Quota policy: budget/concurrency guardrails."""

from keyhole.common.models import Limits
from keyhole.controlplane.quotas import QuotaPolicy, check_quota


def test_allows_within_policy():
    d = check_quota(QuotaPolicy(), Limits(timeout_seconds=60, memory_mb=512), 0, 1000)
    assert d.allowed


def test_blocks_on_concurrency():
    d = check_quota(QuotaPolicy(max_concurrent_runs=2), Limits(), 2, 1000)
    assert not d.allowed and "concurrent" in d.reason


def test_blocks_on_timeout():
    d = check_quota(QuotaPolicy(max_timeout_seconds=100), Limits(timeout_seconds=200), 0, 1000)
    assert not d.allowed and "timeout" in d.reason


def test_blocks_on_data_size():
    d = check_quota(QuotaPolicy(max_data_bytes=10), Limits(), 0, 1_000_000)
    assert not d.allowed and "data" in d.reason
