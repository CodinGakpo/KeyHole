"""Cumulative exit-bandwidth budget: bounds total released bits per principal over a window."""

from datetime import datetime, timedelta, timezone

from mark1.controlplane.budget import (
    BudgetPolicy,
    FileLedger,
    InMemoryLedger,
    check_budget,
)

NOW = datetime(2026, 7, 19, 12, 0, 0, tzinfo=timezone.utc)


def test_allows_up_to_the_cap_then_denies():
    ledger = InMemoryLedger()
    policy = BudgetPolicy(max_exit_bits=5.0)

    d1 = check_budget(policy, ledger, "alice", 2.0, now=NOW)
    assert d1.allowed and d1.spent_before == 0.0
    ledger.record("alice", 2.0, NOW)

    d2 = check_budget(policy, ledger, "alice", 3.0, now=NOW)
    assert d2.allowed  # 2 + 3 == 5, exactly the cap
    ledger.record("alice", 3.0, NOW)

    d3 = check_budget(policy, ledger, "alice", 0.5, now=NOW)
    assert not d3.allowed
    assert d3.spent_before == 5.0
    assert "budget exceeded" in d3.reason


def test_budget_is_per_principal():
    ledger = InMemoryLedger()
    policy = BudgetPolicy(max_exit_bits=4.0)
    ledger.record("alice", 4.0, NOW)

    assert not check_budget(policy, ledger, "alice", 1.0, now=NOW).allowed
    assert check_budget(policy, ledger, "bob", 4.0, now=NOW).allowed  # bob's ledger is empty


def test_rolling_window_frees_budget_after_it_passes():
    ledger = InMemoryLedger()
    policy = BudgetPolicy(max_exit_bits=3.0, window_seconds=3600)

    ledger.record("alice", 3.0, NOW)
    assert not check_budget(policy, ledger, "alice", 1.0, now=NOW).allowed

    # An hour and a bit later, the old spend has aged out of the window.
    later = NOW + timedelta(seconds=3601)
    assert ledger.spent("alice", policy.window_seconds, later) == 0.0
    assert check_budget(policy, ledger, "alice", 3.0, now=later).allowed


def test_file_ledger_persists_across_instances(tmp_path):
    path = tmp_path / "ledger.json"

    first = FileLedger(path)
    first.record("alice", 2.5, NOW)

    # A fresh instance on the same path must see the earlier spend.
    second = FileLedger(path)
    assert second.spent("alice", None, NOW) == 2.5
    second.record("alice", 1.0, NOW)
    assert FileLedger(path).spent("alice", None, NOW) == 3.5


def test_file_ledger_treats_missing_or_corrupt_file_as_empty(tmp_path):
    missing = FileLedger(tmp_path / "nope.json")
    assert missing.spent("alice", None, NOW) == 0.0

    corrupt = tmp_path / "bad.json"
    corrupt.write_text("{ not json")
    assert FileLedger(corrupt).spent("alice", None, NOW) == 0.0
