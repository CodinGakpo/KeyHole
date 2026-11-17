"""The executor: runs untrusted code and captures a single typed output.

Locally the code runs under bubblewrap where available (no network, home and Keyhole state
hidden; see :mod:`keyhole.executor.sandbox`), and as a plain subprocess otherwise. In the cloud,
the Fargate task and its network provide the box. The convention (user code writes its result
to ``$KEYHOLE_OUTPUT`` as JSON) is identical
locally and in the cloud, so the same code path is exercised in both.
"""

from keyhole.executor.entrypoint import ExecResult, run_code

__all__ = ["ExecResult", "run_code"]
