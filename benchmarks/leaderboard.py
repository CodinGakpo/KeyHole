"""Leaderboard probing: recovering a hidden test set from its scores, and the budget that stops it.

A private benchmark scores submissions against hidden labels and reports accuracy. The known
attack (Whitehill 2017; Blum & Hardt's "ladder" work) needs no access to the labels: submit a
baseline, flip one prediction, and watch whether the score goes up or down — one hidden label
per query. Kaggle's daily submission limit is a blunt defense against exactly this.

Keyhole's version of that limit is measured in what actually leaves: each scoring run is charged
the bits its answer could carry, against the benchmark's own budget, whoever is asking.

    python benchmarks/leaderboard.py
"""

from __future__ import annotations

import json
import os
import random
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from keyhole.attest.sign import Ed25519Signer  # noqa: E402
from keyhole.controlplane.cleanroom import DatasetStore, run_in_cleanroom  # noqa: E402
from keyhole.schema.spec import OutputSchema  # noqa: E402

N = 64
LABELS = [random.Random(11).randint(0, 1) for _ in range(N)]
# Accuracy as a whole number of correct answers: N + 1 values, about 6 bits per query.
SCORE = OutputSchema.from_dict({"type": "integer", "minimum": 0, "maximum": N})


def scorer(preds: list[int]) -> str:
    """The submission: fixed predictions, scored inside the box against the hidden labels."""
    return ("import json, os\n"
            "labels = json.load(open('labels.json'))\n"
            f"preds = {preds!r}\n"
            "json.dump(sum(p == y for p, y in zip(preds, labels)), "
            "open(os.environ['KEYHOLE_OUTPUT'], 'w'))\n")


def attack(score) -> tuple[list[int | None], int]:
    """Recover labels one at a time from score differences. Returns (guesses, queries used)."""
    base = [0] * N
    s0 = score(base)
    guesses: list[int | None] = [None] * N
    queries = 1
    if s0 is None:
        return guesses, queries
    for i in range(N):
        flipped = base.copy()
        flipped[i] = 1
        s = score(flipped)
        queries += 1
        if s is None:  # refused: the budget is spent
            break
        guesses[i] = 1 if s > s0 else 0
    return guesses, queries


def main() -> int:
    with tempfile.TemporaryDirectory() as home:
        os.environ["KEYHOLE_HOME"] = home
        signer = Ed25519Signer.generate()
        results = {}
        for name, budget in (("no budget", 1e9), ("keyhole budget", 32.0)):
            store = DatasetStore(root=Path(home) / name.replace(" ", "-"))
            ds = store.add("benchmark-owner", {"labels.json": json.dumps(LABELS)},
                           max_bits_per_run=8, budget_bits=budget)
            grant = store.grant(ds.dataset_id, "*")

            def score(preds, store=store, ds=ds, grant=grant):
                out = run_in_cleanroom(store, ds.dataset_id, grant.grant_id, "attacker",
                                       scorer(preds), SCORE, signer)
                return out.result.output if out.result.status.value == "succeeded" else None

            guesses, queries = attack(score)
            recovered = sum(g == y for g, y in zip(guesses, LABELS, strict=True) if g is not None)
            results[name] = recovered
            print(f"{name:15} {queries:3} scoring queries -> {recovered}/{N} hidden labels "
                  f"recovered; {store.bits_spent(ds):.1f} bits charged")
        print("\nWith the budget, the attacker learns a handful of labels and is then refused,")
        print("no matter how many identities it uses: the budget belongs to the benchmark.")
        return 0 if results["no budget"] == N and results["keyhole budget"] < N // 4 else 1


if __name__ == "__main__":
    raise SystemExit(main())
