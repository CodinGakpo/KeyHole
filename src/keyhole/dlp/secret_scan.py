"""Secret detection over the (small) released output — a secondary backstop."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

# High-signal credential patterns. Kept small and precise on purpose.
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
]

# A token that looks random enough to be a credential.
_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")
_ENTROPY_THRESHOLD_BITS_PER_CHAR = 3.5


@dataclass(frozen=True)
class Finding:
    kind: str
    match: str


def scan_secrets(text: str) -> list[Finding]:
    """Return secret-shaped findings in ``text``."""
    findings: list[Finding] = []
    for kind, pattern in _SECRET_PATTERNS:
        for m in pattern.finditer(text):
            findings.append(Finding(kind=kind, match=_redact(m.group(0))))

    for m in _TOKEN_RE.finditer(text):
        token = m.group(0)
        if _shannon_entropy(token) >= _ENTROPY_THRESHOLD_BITS_PER_CHAR:
            findings.append(Finding(kind="high_entropy_token", match=_redact(token)))
    return findings


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _redact(s: str) -> str:
    if len(s) <= 8:
        return "*" * len(s)
    return f"{s[:3]}…{s[-2:]} ({len(s)} chars)"
