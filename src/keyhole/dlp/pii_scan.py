"""PII detection over the (small) released output — a secondary backstop."""

from __future__ import annotations

import re

from keyhole.dlp.secret_scan import Finding, _redact

_PII_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("us_ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("credit_card", re.compile(r"\b(?:\d[ -]?){13,16}\b")),
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
]


def scan_pii(text: str) -> list[Finding]:
    """Return PII-shaped findings in ``text``."""
    findings: list[Finding] = []
    for kind, pattern in _PII_PATTERNS:
        for m in pattern.finditer(text):
            candidate = m.group(0)
            if kind == "credit_card" and not _luhn_ok(candidate):
                continue
            findings.append(Finding(kind=kind, match=_redact(candidate)))
    return findings


def _luhn_ok(candidate: str) -> bool:
    digits = [int(c) for c in candidate if c.isdigit()]
    if not 13 <= len(digits) <= 16:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0
