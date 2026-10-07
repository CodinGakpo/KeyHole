"""The executor: runs untrusted code and captures a single typed output.

The local executor here drives the fast development loop and exercises the exit gate. Network
containment and credential isolation are enforced by the image + infrastructure layer (read-only
root FS, no-NAT private subnet, egress-proxy sidecar, empty task role) — not by this subprocess
runner. The convention (user code writes its result to ``$KEYHOLE_OUTPUT`` as JSON) is identical
locally and in the cloud, so the same code path is exercised in both.
"""

from keyhole.executor.entrypoint import ExecResult, run_code

__all__ = ["ExecResult", "run_code"]
