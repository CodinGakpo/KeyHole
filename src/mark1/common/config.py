"""Local configuration and key locations.

The dev signing key lives under the user's home (never in the repo). In the cloud, attestation
signing uses KMS instead and this key is irrelevant.
"""

from __future__ import annotations

import os
from pathlib import Path


def home_dir() -> Path:
    root = Path(os.environ.get("MARK1_HOME", Path.home() / ".mark1"))
    root.mkdir(parents=True, exist_ok=True)
    return root


def dev_key_path() -> Path:
    return home_dir() / "dev-signing.key"


def dev_pubkey_path() -> Path:
    return home_dir() / "dev-signing.pub"


def api_endpoint() -> str | None:
    """Control-plane REST endpoint for the cloud path (unset in pure-local mode)."""
    return os.environ.get("MARK1_API_ENDPOINT")
